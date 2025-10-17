# session_manager.py
import os
import redis
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from flask import Flask, request, make_response, jsonify, abort, redirect, url_for, render_template, flash # Added flash
from dotenv import load_dotenv
import logging
import re # Import re for RBAC check
from mac_fetcher import fetch_mac_for_ip # Assuming this function handles its own errors gracefully (e.g., returns None on failure)
from typing import Optional, Dict, Any, Tuple # Added for type hinting
import secrets # For secure token generation
from urllib.parse import urljoin # For constructing invite links


# --- Role Definitions ---
ADMIN_ROLE = "admin"
ANALYST_ROLE = "analyst"
GUEST_ROLE = "guest"
VALID_ROLES = {ADMIN_ROLE, ANALYST_ROLE, GUEST_ROLE}
# --- Configuration ---
load_dotenv() # Load environment variables from .env file

# Enhanced logging setup
log_level_name = os.getenv('LOG_LEVEL', 'INFO').upper()
log_level = getattr(logging, log_level_name, logging.INFO)
# Define log format for better readability
log_format = '%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] %(message)s'
logging.basicConfig(level=log_level, format=log_format)
# Get a logger instance for this module
logger = logging.getLogger(__name__) # Use module-specific logger

app = Flask(__name__)
# Use a strong, randomly generated key kept secret
secret_key_env = os.getenv('SECRET_KEY')
if not secret_key_env:
    logger.critical("FATAL: SECRET_KEY environment variable not set. Application cannot start securely.")
    # In a real app, raise an error or exit
    raise ValueError("SECRET_KEY environment variable is required for secure operation.")
# Note: Using the same key for Flask session signing and HMAC is acceptable for simplicity,
# but using separate, dedicated keys provides better cryptographic separation of concerns in high-security scenarios.
app.secret_key = secret_key_env # Used for Flask's session flash messages etc, if needed.
hmac_secret_key = secret_key_env.encode('utf-8') # Key for our HMAC signature

# --- Redis Configuration ---
redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_port = int(os.getenv('REDIS_PORT', 6379))
redis_db = int(os.getenv('REDIS_DB', 0))
redis_socket_timeout = int(os.getenv('REDIS_SOCKET_TIMEOUT', 5)) # Configurable timeout
redis_connect_timeout = int(os.getenv('REDIS_CONNECT_TIMEOUT', 5)) # Configurable connect timeout
redis_retry_on_timeout = os.getenv('REDIS_RETRY_ON_TIMEOUT', 'False').lower() == 'true' # Option to retry on timeout

# --- Session Configuration ---
session_cookie_name = os.getenv('ZT_SESSION_COOKIE_NAME', 'zt-session')
session_ttl_seconds = int(os.getenv('ZT_SESSION_TTL_SECONDS', 3600)) # 1 hour TTL
# Ensure TTL is reasonably positive
if session_ttl_seconds <= 0:
    logger.warning(f"ZT_SESSION_TTL_SECONDS is set to {session_ttl_seconds}. Using default 3600 seconds instead.")
    session_ttl_seconds = 3600

# --- Admin/Invite Configuration ---
invite_token_ttl_minutes = int(os.getenv('ANALYST_INVITE_TTL_MINUTES', 60)) # TTL for analyst invite tokens
# IMPORTANT: Set BASE_URL in your .env file or environment for correct invite links
# Example: BASE_URL=http://localhost:80 (if Nginx runs on 80) or https://your.domain.com
BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000') # Fallback, but should be set correctly

# --- Flask Configuration ---
flask_debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
app.config['DEBUG'] = flask_debug
session_cookie_config = os.getenv('SESSION_COOKIE_SECURE', 'auto').lower()
app.config['SESSION_COOKIE_SECURE'] = session_cookie_config != 'false' # Default to secure unless explicitly false
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Create a before_request handler to dynamically adjust cookie security based on the request
@app.before_request
def configure_secure_session():
    # Dynamically set secure flag based on request if configured to 'auto'
    if session_cookie_config == 'auto':
        is_secure = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
        app.config['SESSION_COOKIE_SECURE'] = is_secure
    # Ensure BASE_URL uses the correct scheme based on the request
    # This helps if BASE_URL in env doesn't specify scheme or needs overriding
    global BASE_URL
    if BASE_URL.startswith("http://") and app.config['SESSION_COOKIE_SECURE']:
        BASE_URL = BASE_URL.replace("http://", "https://", 1)
    elif BASE_URL.startswith("https://") and not app.config['SESSION_COOKIE_SECURE']:
         BASE_URL = BASE_URL.replace("https://", "http://", 1)

# --- Redis Connection ---
redis_client: Optional[redis.StrictRedis] = None # Initialize to None with type hint
try:
    redis_client = redis.StrictRedis(
        host=redis_host,
        port=redis_port,
        db=redis_db,
        decode_responses=True, # Important for handling strings directly
        socket_timeout=redis_socket_timeout,
        socket_connect_timeout=redis_connect_timeout,
        retry_on_timeout=redis_retry_on_timeout,
        # Add health check interval if needed (less critical for startup)
        # health_check_interval=30
    )
    # Perform a connection check
    redis_client.ping()
    logger.info(f"Successfully connected to Redis at {redis_host}:{redis_port}, DB: {redis_db}")
except redis.exceptions.TimeoutError as e:
    logger.critical(f"FATAL: Redis connection timed out ({redis_host}:{redis_port}, DB: {redis_db}). Check network/firewall/Redis load. Error: {e}")
    # Set client to None so startup check fails
    redis_client = None
except redis.exceptions.ConnectionError as e:
    logger.critical(f"FATAL: Could not connect to Redis at {redis_host}:{redis_port}, DB: {redis_db}. Check Redis server status and configuration. Error: {e}")
    redis_client = None
except Exception as e:
    logger.critical(f"FATAL: An unexpected error occurred during Redis connection setup ({redis_host}:{redis_port}, DB: {redis_db}). Error: {e}", exc_info=True)
    redis_client = None


# --- Helper Functions ---

def generate_session_id() -> str:
    """Generate a secure random session ID (32 bytes, hex encoded)."""
    return os.urandom(32).hex()

def generate_secure_token(length: int = 32) -> str:
    """Generates a cryptographically secure URL-safe token."""
    return secrets.token_urlsafe(length)

def create_session_signature(session_data: Dict[str, Any]) -> Optional[str]:
    """Creates an HMAC-SHA256 signature for the session data dictionary."""
    if not hmac_secret_key:
        logger.error("HMAC Secret Key is not configured! Cannot create session signature.")
        return None
    if not isinstance(session_data, dict):
        logger.error(f"Invalid input: session_data must be a dict, got {type(session_data)}. Cannot sign.")
        return None
    try:
        # Use a stable, canonical JSON representation for signing
        # separators=(',', ':') removes whitespace for consistency
        # sort_keys=True ensures key order doesn't affect the signature
        message = json.dumps(session_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = hmac.new(hmac_secret_key, message, hashlib.sha256).hexdigest()
        return signature
    except TypeError as e:
        logger.error(f"Error serializing session data for signature: {e}. Data: {session_data}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error creating session signature: {e}", exc_info=True)
        return None

def verify_session_signature(session_data: Dict[str, Any], provided_signature: Optional[str]) -> bool:
    """Verifies the HMAC-SHA256 signature using a timing-attack-resistant comparison."""
    if not provided_signature or not isinstance(session_data, dict):
        logger.warning("Verification failed: Missing provided signature or invalid session_data type.")
        return False

    expected_signature = create_session_signature(session_data)
    if expected_signature is None:
        # Error occurred during signature creation (likely logged already)
        logger.error("Verification failed: Could not generate expected signature for comparison.")
        return False

    # Use hmac.compare_digest to prevent timing attacks
    return hmac.compare_digest(expected_signature, provided_signature)

def get_role_for_ip(ip_address: Optional[str]) -> str:
    """
    [INSECURE DEMO] Determines user role based on IP address.
    Replace with proper authentication/authorization.
    """
    if not ip_address: return GUEST_ROLE
    # --- DEMO IP RANGES ---
    # Network for Admins
    if ip_address.startswith('192.168.22.'): return ADMIN_ROLE
    # Network for Analysts
    elif ip_address.startswith('192.168.23.'): return ANALYST_ROLE
    # Localhost access - Treat as Admin for dev/testing convenience
    elif ip_address == '127.0.0.1' or ip_address == '::1':
        logger.info(f"Assigning '{ADMIN_ROLE}' role for localhost access ({ip_address}).")
        return ADMIN_ROLE
    # Default Guest Network or specific IPs
    elif ip_address.startswith('10.10.'): return GUEST_ROLE
    else:
        logger.debug(f"Assigning default '{GUEST_ROLE}' role to IP: {ip_address}")
        return GUEST_ROLE # Default to least privilege

def get_access_level_for_role(role: str) -> str:
    """Maps role to a generic access level claim (Less granular than RBAC)."""
    role_access_map = {
        ADMIN_ROLE: "full",
        ANALYST_ROLE: "privileged", # Analyst has less than full admin access
        GUEST_ROLE: "read-only",
    }
    access_level = role_access_map.get(role, "none")
    if access_level == "none": logger.warning(f"Unknown role '{role}', assigning 'none' access level.")
    return access_level

def revoke_session(session_id: str):
    """Deletes session data from Redis. Handles Redis client availability and errors."""
    if not redis_client:
         logger.error("Cannot revoke session: Redis client is not available.")
         return # Cannot proceed without client

    if not session_id or not isinstance(session_id, str):
        logger.warning(f"Attempted to revoke session with invalid ID: {session_id}")
        return

    try:
        key = f"session:{session_id}"
        deleted_count = redis_client.delete(key)
        if deleted_count > 0:
            logger.info(f"Revoked session: {session_id} (Redis key: {key})")
        else:
            # This is not necessarily an error, the session might have expired naturally
            logger.info(f"Attempted to revoke session {session_id}, but it was not found in Redis (key: {key}). May have already expired.")
    except redis.exceptions.TimeoutError as e:
         logger.error(f"Redis timeout error while revoking session {session_id} (key: {key}): {e}")
         # Depending on policy, might need retry or alerting
    except redis.exceptions.RedisError as e:
         logger.error(f"Redis error revoking session {session_id} (key: {key}): {e}", exc_info=True)
         # Log the full error details
    except Exception as e:
         logger.error(f"Unexpected error revoking session {session_id} (key: {key}): {e}", exc_info=True)

def get_user_agent():
    """
    Get the complete User-Agent string from the request headers.
    
    Returns:
        str: The full User-Agent string or 'UNKNOWN_UA' if not found
    """
    # Direct access from headers is the most reliable method
    # This approach works in all Flask versions
    user_agent = request.headers.get('User-Agent', 'UNKNOWN_UA')
    
    return user_agent
# --- *** NEW ROUTE: Gateway Page *** ---
@app.route('/gateway')
def gateway():
    """Displays the gateway page with links to applications."""
    # You could potentially add checks here to ensure a valid session exists
    # before rendering, but the downstream apps will verify anyway.
    # For simplicity, just render the template.
    session_id = request.cookies.get(session_cookie_name)
    if not session_id:
        # If somehow user reaches gateway without cookie, redirect back to init
        logger.warning("Access attempt to /gateway without session cookie. Redirecting to /session/init.")
        return redirect(url_for('session_init'))

    logger.info(f"Rendering gateway page for session {session_id}.")
    return render_template('gateway.html')

# --- Invite Token Helpers ---
def store_invite_token(token: str, expiration_minutes: int) -> bool:
    """Stores a single-use invite token in Redis with TTL."""
    if not redis_client: logger.error("Cannot store invite token: Redis client unavailable."); return False
    try:
        key = f"invite:{token}"
        # Store a simple value (e.g., '1' or timestamp) with expiry
        ttl_seconds = expiration_minutes * 60
        success = redis_client.setex(key, ttl_seconds, "valid")
        if success:
            logger.info(f"Stored invite token (key: {key}) with TTL {ttl_seconds}s.")
            return True
        else:
            logger.error(f"Redis SETEX command failed for invite token (key: {key}).")
            return False
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error storing invite token (key: invite:{token}): {e}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"Unexpected error storing invite token (key: invite:{token}): {e}", exc_info=True)
        return False

def verify_and_consume_invite_token(token: str) -> bool:
    """Checks if an invite token exists in Redis and deletes it (consumes it)."""
    if not redis_client: logger.error("Cannot verify invite token: Redis client unavailable."); return False
    key = f"invite:{token}"
    try:
        # Use DELETE which returns the number of keys deleted (1 if found, 0 otherwise)
        deleted_count = redis_client.delete(key)
        if deleted_count > 0:
            logger.info(f"Successfully verified and consumed invite token (key: {key}).")
            return True
        else:
            logger.warning(f"Invite token verification failed: Token not found or already consumed (key: {key}).")
            return False
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error verifying/consuming invite token (key: {key}): {e}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"Unexpected error verifying/consuming invite token (key: {key}): {e}", exc_info=True)
        return False

# --- Step 2: Device Attestation Workflow (Session Initiation) ---
@app.route('/session/init', methods=['GET', 'POST'])
def session_init():
    """
    Handles initial session creation request.
    GET: Shows a simple page allowing manual POST (for testing/demo).
    POST: Creates the session based on request info, sets a secure cookie, and returns JSON status.
    """
    if not redis_client:
        logger.error("Session init failed: Redis client not available.")
        # 503 Service Unavailable is appropriate when the backend datastore is down
        return jsonify({"error": "Session backend temporarily unavailable"}), 503

    if request.method == 'GET':
        # Keep the simple HTML form for testing if needed
        return render_template('session_init.html')

    # --- POST Request Logic ---
    elif request.method == 'POST':
        # Prioritize X-Real-IP from trusted proxy (e.g., NGINX)
        # Fall back to remote_addr only if header is missing (e.g., direct access)
        client_ip = request.headers.get('X-Real-IP')
        if not client_ip:
            logger.warning("X-Real-IP header not found, falling back to request.remote_addr. Ensure proxy is configured correctly.")
            client_ip = request.remote_addr

        if not client_ip:
             logger.error("Session init failed: Could not determine client IP address.")
             return jsonify({"error": "Client IP address could not be determined"}), 400 # Bad Request

        # --- Enhanced Device Attributes Collection ---
        # Use the dedicated function to fetch MAC. Handle potential None return.
        try:
            # Assuming fetch_mac_for_ip handles its own exceptions and returns None on failure
            client_mac = fetch_mac_for_ip(client_ip)
            if client_mac is None:
                logger.warning(f"Could not fetch MAC address for IP: {client_ip}. Storing as null.")
                client_mac = None # Explicitly set to None for JSON storage
        except Exception as e:
            logger.error(f"Error calling fetch_mac_for_ip for IP {client_ip}: {e}", exc_info=True)
            client_mac = None # Ensure failure doesn't break session creation

        user_agent_string = get_user_agent()

        # Use it in your user_agent_details dictionary
        user_agent_details = {
            'string': user_agent_string,
            'platform': request.user_agent.platform if request.user_agent else None,
            'browser': request.user_agent.browser if request.user_agent else None,
            'version': request.user_agent.version if request.user_agent else None,
        }

        # Hostname from header - Explicitly mark as potentially unreliable
        # WARNING: X-Device-Hostname is easily spoofable if set by the client. Only trust if set by a reliable source (e.g., internal discovery tool).
        client_hostname = request.headers.get('X-Device-Hostname', 'UNKNOWN_HOSTNAME')
        if client_hostname != 'UNKNOWN_HOSTNAME':
            logger.debug(f"Received client hostname '{client_hostname}' from header (potentially unreliable).")

        logger.info(f"Session Init POST Request from IP: {client_ip}, MAC: {client_mac or 'Not Found'}, Hostname: {client_hostname}, UA: {user_agent_details['string']}")

        # --- Session Creation ---
        session_id = generate_session_id()
        now_utc = datetime.now(timezone.utc)
        expires_at = now_utc + timedelta(seconds=session_ttl_seconds)

        # Create comprehensive session data object
        session_data = {
            "session_id": session_id, # Include session ID in data for easier debugging/lookup if needed
            "user_id": f"user_{client_ip}", # Simplistic user ID based on IP. Replace with real user ID post-authentication.
            "role": get_role_for_ip(client_ip),
            "ip": client_ip,
            "mac": client_mac, # Store fetched MAC (can be None)
            "hostname": client_hostname, # Store potentially unreliable hostname
            "user_agent": user_agent_details, # Store detailed UA information
            "created_at": now_utc.isoformat(),
            "last_active": now_utc.isoformat(),
            "expires_at": expires_at.isoformat(),
            # Add other relevant context if available (e.g., geoip, IdP claims after authentication)
            "claims": {
                # Example: "auth_method": "ip_based"
            }
        }
        print(f"Session Data: {session_data}")
        # --- Cryptographic Binding (HMAC Signature) ---
        signature = create_session_signature(session_data)
        if not signature:
             logger.error(f"Failed to create session signature for session {session_id}, IP {client_ip}. Aborting session creation.")
             return jsonify({"error": "Internal server error: could not sign session"}), 500

        # Combine data and signature for storage
        session_data_with_sig = {
            "data": session_data,
            "signature": signature
        }

        # For debugging purposes - avoid printing sensitive data in production logs if possible
        # logger.debug(f"Session data for {session_id}: {session_data}") # Be cautious with logging full data

        # --- Store Session in Redis ---
        try:
            redis_key = f"session:{session_id}"
            # Use setex to store the value and set the expiration time atomically
            redis_client.setex(redis_key, session_ttl_seconds, json.dumps(session_data_with_sig))
            logger.info(f"Successfully created session {session_id} for IP {client_ip}, MAC: {client_mac or 'N/A'}, Role: {session_data['role']}. Stored in Redis key {redis_key} with TTL {session_ttl_seconds}s.")
        except redis.exceptions.TimeoutError as e:
            logger.error(f"Redis timeout error saving session {session_id} (key: {redis_key}): {e}")
            return jsonify({"error": "Could not save session due to backend timeout"}), 503 # Service Unavailable (or 500)
        except redis.exceptions.RedisError as e:
            logger.error(f"Redis error saving session {session_id} (key: {redis_key}): {e}", exc_info=True)
            return jsonify({"error": "Could not save session due to backend error"}), 500 # Internal Server Error
        except TypeError as e: # Catch JSON serialization errors
            logger.error(f"Error serializing session data for Redis storage (session {session_id}): {e}", exc_info=True)
            return jsonify({"error": "Internal server error: could not serialize session data"}), 500
        except Exception as e:
            logger.error(f"Unexpected error saving session {session_id} to Redis (key: {redis_key}): {e}", exc_info=True)
            return jsonify({"error": "Could not save session due to an unexpected internal error"}), 500

        # --- Create Response and Set Cookie ---
        # Return JSON success message
        response = make_response(jsonify({"status": "success", "session_id": session_id}), 200)

        # Set the session cookie with security attributes
        is_secure = app.config['SESSION_COOKIE_SECURE'] or request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
        response.set_cookie(
            session_cookie_name,
            session_id,
            max_age=session_ttl_seconds,
            httponly=app.config['SESSION_COOKIE_HTTPONLY'], # Crucial security measure
            secure=is_secure, # Set Secure flag only if served over HTTPS or configured explicitly
            samesite=app.config['SESSION_COOKIE_SAMESITE'] # 'Lax' or 'Strict'
            # domain=app.config.get('SESSION_COOKIE_DOMAIN'), # Set if needed
            # path=app.config.get('SESSION_COOKIE_PATH', '/') # Usually root path
        )
        logger.info(f"Set cookie '{session_cookie_name}' (HttpOnly={app.config['SESSION_COOKIE_HTTPONLY']}, Secure={is_secure}, SameSite={app.config['SESSION_COOKIE_SAMESITE']}) for session {session_id} in POST response.")
        return response


def get_verified_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Fetches session from Redis, validates structure, and verifies signature."""
    if not redis_client:
        logger.error(f"Session retrieval failed for {session_id}: Redis client not available.")
        abort(503) # Service Unavailable

    redis_key = f"session:{session_id}"
    session_json = None
    session_container = None
    session_data = None
    session_signature = None

    try:
        session_json = redis_client.get(redis_key)
    except redis.exceptions.TimeoutError as e:
         logger.error(f"Redis timeout error fetching session {session_id} from key {redis_key}: {e}")
         abort(503) # Service Unavailable
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error fetching session {session_id} from key {redis_key}: {e}", exc_info=True)
        abort(500) # Internal Server Error
    except Exception as e:
        logger.error(f"Unexpected error fetching session {session_id} from key {redis_key}: {e}", exc_info=True)
        abort(500)

    if not session_json:
        logger.warning(f"Session check/verify failed: Session ID {session_id} (from cookie) not found in Redis (key: {redis_key}). Might be expired or invalid.")
        abort(401) # Unauthorized

    try:
        session_container = json.loads(session_json)
        if not isinstance(session_container, dict) or "data" not in session_container or "signature" not in session_container:
             logger.error(f"Session check/verify failed: Malformed session container structure in Redis for {session_id}. Content: {session_json[:200]}...")
             revoke_session(session_id)
             abort(401)

        session_data = session_container.get("data")
        session_signature = session_container.get("signature")

        if not isinstance(session_data, dict) or not isinstance(session_signature, str):
             logger.error(f"Session check/verify failed: Malformed session data types (data: {type(session_data)}, signature: {type(session_signature)}) in Redis for {session_id}.")
             revoke_session(session_id)
             abort(401)

    except json.JSONDecodeError as e:
        logger.error(f"Session check/verify failed: Could not decode JSON session data for {session_id} from Redis. Error: {e}. Data: {session_json[:200]}...")
        revoke_session(session_id)
        abort(401)
    except Exception as e:
        logger.error(f"Unexpected error parsing/validating session structure {session_id}: {e}", exc_info=True)
        abort(500)

    # Verify Cryptographic Signature
    if not verify_session_signature(session_data, session_signature):
        logger.error(f"Session check/verify failed: Invalid HMAC signature for session {session_id}. Revoking session.")
        revoke_session(session_id)
        abort(401) # Treat as invalid/tampered session

    # If all checks pass so far, return the verified session data
    return session_data

    # --- NEW Step: Periodic Session Context Check Endpoint --- (NEW ROUTE)
@app.route('/session/check', methods=['GET', 'POST'])
def session_check_route():
    """
    Endpoint called periodically by client-side JS to check session validity
    and context consistency (IP, User-Agent).
    Returns 200 OK if valid, 401 if invalid/context mismatch.
    """
    # --- 1. Get Session ID from Cookie ---
    session_id = request.cookies.get(session_cookie_name)
    if not session_id:
        logger.info("Session check failed: No session cookie ('%s') found.", session_cookie_name)
        abort(401) # Unauthorized

    # --- 2. Fetch and Verify Session Structure/Signature ---
    # Uses the consolidated helper function
    session_data = get_verified_session(session_id) # Aborts on failure (401, 500, 503)

    # --- 3. Perform Context Consistency Checks ---
    current_ip = request.headers.get('X-Real-IP', request.remote_addr)
    current_ua_string = get_user_agent()
    current_mac = fetch_mac_for_ip(current_ip)

    stored_ip = session_data.get('ip')
    stored_ua_details = session_data.get('user_agent', {})
    stored_ua_string = stored_ua_details.get('string', 'UNKNOWN_UA') if isinstance(stored_ua_details, dict) else 'UNKNOWN_UA'
    stored_mac = session_data.get('mac')

    
    logging.error(f"PRINTING MAC {current_mac} and SAVED {stored_mac}")


    context_mismatch = False

    # --- Check IP Address Consistency ---
    if stored_ip != current_ip:
        logger.critical(f"CRITICAL: Session check failed for session {session_id}: IP address mismatch. Session bound to {stored_ip}, request from {current_ip}. Revoking session.")
        context_mismatch = True

    # --- Check User-Agent Consistency ---
    # Note: This is a strict check. Browser updates will trigger this.
    # Consider making this check configurable or less strict in production.
    if stored_ua_string != current_ua_string:
        logger.warning(f"Session check failed for session {session_id}: User agent mismatch. Stored: '{stored_ua_string}', Current: '{current_ua_string}'. Revoking session.")
        context_mismatch = True

    if stored_mac != current_mac:
        logger.warning(f"Session check failed for session {session_id}: Mac address mismatch. Stored: '{stored_mac}', Current: '{current_mac}'. Revoking session.")
        context_mismatch = True
    # --- Check MAC Address (Example - Highly Unreliable from Headers) ---
    # Only enable this if you have a *trusted* mechanism injecting X-Device-MAC
    # stored_mac = session_data.get('mac')
    # current_mac_header = request.headers.get('X-Device-MAC') # Usually UNTRUSTWORTHY
    # if stored_mac and current_mac_header and stored_mac != current_mac_header:
    #     logger.warning(f"Session check: MAC address header mismatch for session {session_id}. Stored: {stored_mac}, Header: {current_mac_header}. Revoking (if policy dictates).")
    #     # context_mismatch = True # Uncomment to enforce based on header

    # --- 4. Handle Mismatch or Update Session ---
    if context_mismatch:
        revoke_session(session_id)
        abort(401) # Context mismatch leads to unauthorized
    else:
        # --- Context is consistent, update activity and refresh TTL ---
        now_utc = datetime.now(timezone.utc)
        session_data['last_active'] = now_utc.isoformat()

        # Re-sign the session data (only last_active changed)
        new_signature = create_session_signature(session_data)
        if not new_signature:
            logger.error(f"Could not re-sign session {session_id} during session check update. Revoking to prevent inconsistent state.")
            revoke_session(session_id)
            abort(500)

        # Prepare updated container
        session_container = {
            "data": session_data,
            "signature": new_signature
        }

        try:
            redis_key = f"session:{session_id}"
            # Use setex to update data and refresh TTL atomically
            redis_client.setex(redis_key, session_ttl_seconds, json.dumps(session_container))
            logger.debug(f"Session check successful for {session_id}. Refreshed TTL ({session_ttl_seconds}s) and updated last_active time.")
        except redis.exceptions.TimeoutError as e:
            logger.error(f"Redis timeout error updating session {session_id} activity (key: {redis_key}) in /check: {e}")
            # Don't abort, but session might expire sooner than expected.
        except redis.exceptions.RedisError as e:
            logger.error(f"Redis error updating session {session_id} activity (key: {redis_key}) in /check: {e}", exc_info=True)
            # Don't abort, log error.
        except TypeError as e:
            logger.error(f"Error serializing session data for Redis update (session {session_id}) in /check: {e}", exc_info=True)
            abort(500) # Indicates a potential bug
        except Exception as e:
            logger.error(f"Unexpected error updating session {session_id} activity in Redis (key: {redis_key}) in /check: {e}", exc_info=True)
            abort(500)

        # --- Check Success ---
        return jsonify({"status": "ok"}), 200



@app.route('/session/verify')
def verify_session_route():
    """
    Endpoint for NGINX auth_request. Verifies session cookie, signature, context, and RBAC.
    Returns 200 OK if valid, 401/403 otherwise. Can also return 500/503 on internal errors.
    """
    # Check Redis availability *early* in the request
    if not redis_client:
        logger.error("Session verify failed: Redis client not available.")
        abort(503) # Service Unavailable

    # --- 1. Get Session ID from Cookie ---
    session_id = request.cookies.get(session_cookie_name)
    if not session_id:
        logger.info("Verification attempt failed: No session cookie ('%s') found in request.", session_cookie_name)
        abort(401) # Unauthorized - NGINX should trigger re-authentication flow

    redis_key = f"session:{session_id}"
    session_json = None
    session_container = None
    session_data = None
    session_signature = None

    # --- 2. Fetch Session from Redis ---
    try:
        session_json = redis_client.get(redis_key)
    except redis.exceptions.TimeoutError as e:
         logger.error(f"Redis timeout error fetching session {session_id} from key {redis_key}: {e}")
         abort(503) # Service Unavailable - backend datastore timeout
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error fetching session {session_id} from key {redis_key}: {e}", exc_info=True)
        abort(500) # Internal Server Error (indicates backend issue)
    except Exception as e:
        logger.error(f"Unexpected error fetching session {session_id} from key {redis_key}: {e}", exc_info=True)
        abort(500)

    if not session_json:
        # Session ID exists in cookie but not in Redis - likely expired or invalid/revoked
        logger.warning(f"Verification failed: Session ID {session_id} (from cookie) not found in Redis (key: {redis_key}). Might be expired or invalid.")
        # Consider explicitly clearing the cookie here? Difficult via auth_request.
        # NGINX handling the 401 should lead to a flow that replaces/clears it.
        abort(401) # Unauthorized

    # --- 3. Parse and Validate Session Structure ---
    try:
        session_container = json.loads(session_json)
        # Validate the structure retrieved from Redis
        if not isinstance(session_container, dict) or "data" not in session_container or "signature" not in session_container:
             logger.error(f"Verification failed: Malformed session container structure in Redis for {session_id}. Content: {session_json[:200]}...") # Log snippet
             revoke_session(session_id) # Clean up potentially bad data
             abort(401) # Treat as invalid session

        session_data = session_container.get("data")
        session_signature = session_container.get("signature")

        # Further check types of core components
        if not isinstance(session_data, dict) or not isinstance(session_signature, str):
             logger.error(f"Verification failed: Malformed session data types (data: {type(session_data)}, signature: {type(session_signature)}) in Redis for {session_id}.")
             revoke_session(session_id) # Clean up bad data
             abort(401) # Treat as invalid session

    except json.JSONDecodeError as e:
        logger.error(f"Verification failed: Could not decode JSON session data for {session_id} from Redis. Error: {e}. Data: {session_json[:200]}...")
        # Data might be corrupted in Redis. Attempt removal.
        revoke_session(session_id)
        abort(401) # Treat as invalid session
    except Exception as e: # Catch other potential errors during parsing/validation
        logger.error(f"Unexpected error parsing/validating session {session_id}: {e}", exc_info=True)
        abort(500)


    # --- 4. Verify Cryptographic Signature ---
    if not verify_session_signature(session_data, session_signature):
        logger.error(f"Verification failed: Invalid HMAC signature for session {session_id}. Data may have been tampered with or key mismatch. Revoking session.")
        revoke_session(session_id)
        # Ensure the invalid cookie is dealt with by the upstream Nginx redirect
        abort(401) # Treat as invalid/tampered session

    # --- 5. Continuous Verification Checks (Context Consistency) ---
    # Get current request context, prioritizing trusted headers
    current_ip = request.headers.get('X-Real-IP', request.remote_addr)
    # WARNING: These headers are UNRELIABLE if they can be set by the client. Only use for logging/context unless set by a trusted component.
    current_mac_header = request.headers.get('X-Device-MAC') # Highly unreliable
    current_hostname_header = request.headers.get('X-Device-Hostname') # Highly unreliable
    current_ua_string = request.user_agent.string if request.user_agent else 'UNKNOWN_UA'

    # Get stored context from session data
    stored_ip = session_data.get('ip')
    stored_mac = session_data.get('mac') # This was fetched via fetch_mac_for_ip if possible
    stored_hostname = session_data.get('hostname') # This came from header originally
    stored_ua_details = session_data.get('user_agent', {}) # Use get with default
    stored_ua_string = stored_ua_details.get('string', 'UNKNOWN_UA') if isinstance(stored_ua_details, dict) else 'UNKNOWN_UA'

    # --- Check Expiration (Application Level) ---
    # Redundant check in case Redis TTL is slightly delayed or for extra assurance
    session_expired = False
    try:
        # Ensure expires_at exists and is a string before parsing
        expires_at_str = session_data.get('expires_at')
        if isinstance(expires_at_str, str):
            expires_at = datetime.fromisoformat(expires_at_str)
            if datetime.now(timezone.utc) >= expires_at:
                session_expired = True
        else:
             logger.warning(f"Session {session_id}: expires_at timestamp is missing or not a string ('{expires_at_str}'). Cannot perform application-level expiry check.")
             # Decide policy: allow or deny? Allowing is potentially risky. Denying might lock out if data is bad.
             # For stability, maybe allow here but rely on Redis TTL and signature primarily.

    except (ValueError, TypeError) as e:
        logger.warning(f"Session {session_id}: Could not parse expires_at timestamp '{session_data.get('expires_at')}'. Error: {e}. Relying on Redis TTL.")
        # Consider revoking if timestamp is essential and malformed, but might cause issues if transient.

    if session_expired:
        logger.warning(f"Verification failed for session {session_id}: Session has logically expired at {session_data.get('expires_at')} (UTC). Revoking.")
        revoke_session(session_id)
        abort(401) # Session expired

    # --- Check IP Address Consistency ---
    # CRITICAL CHECK: Ensure the request IP matches the session's bound IP.
    if stored_ip != current_ip:
        logger.critical(f"CRITICAL: Verification failed for session {session_id}: IP address mismatch. Session bound to {stored_ip}, request from {current_ip}. Revoking session.")
        revoke_session(session_id)
        abort(401) # Re-authentication needed due to significant context change (IP changed)

    # --- Check Other Context Attributes (Use with Caution) ---
    # MAC Address Check: Compare fetched MAC (if available) with header (if available). VERY UNRELIABLE.
    # Primarily useful for logging/anomaly detection, not usually for blocking.
    # if stored_mac and current_mac_header and stored_mac != current_mac_header:
    #      logger.warning(f"Session {session_id}: MAC address discrepancy. Stored (fetched): {stored_mac}, Header (unreliable): {current_mac_header}. NOT blocking based on this.")
         # DO NOT revoke/abort based solely on header MAC mismatch unless you have high confidence in the header source.

    # Hostname Check: Compare stored hostname (from header at init) with current header. VERY UNRELIABLE.
    # if stored_hostname != 'UNKNOWN_HOSTNAME' and current_hostname_header and stored_hostname != current_hostname_header:
    #      logger.warning(f"Session {session_id}: Hostname discrepancy. Stored (header@init): {stored_hostname}, Current Header: {current_hostname_header}. NOT blocking based on this.")
         # DO NOT revoke/abort based solely on header hostname mismatch.

    # User-Agent Check: Basic string comparison. Log changes, but allow minor variations.
    if stored_ua_string != current_ua_string:
        # Log difference for potential analysis. Drastic changes might be suspicious.
        logger.info(f"Session {session_id}: User agent changed. Stored: '{stored_ua_string}', Current: '{current_ua_string}'. Allowing change.")
        # Optional: Update UA in session data if change is deemed acceptable and you want to track the latest.
        # Requires re-calculating signature and updating Redis.
        # session_data['user_agent']['string'] = current_ua_string # Example update
        # session_data['last_active'] = datetime.now(timezone.utc).isoformat() # Also update activity time
        # new_signature = create_session_signature(session_data)
        # if new_signature:
        #     session_container["data"] = session_data
        #     session_container["signature"] = new_signature
        # else: # Handle signing failure - perhaps abort 500
        #     logger.error(f"Could not re-sign session {session_id} after UA update. Aborting.")
        #     revoke_session(session_id)
        #     abort(500)

    # GeoIP Check Placeholder: Implement if needed using a GeoIP library/service.
    # current_geo = get_geoip(current_ip) # Fictional function
    # stored_geo = session_data.get('geoip_location')
    # if significant_geo_change(stored_geo, current_geo): # Fictional function
    #     logger.warning(f"Verification failed for session {session_id}: Significant GeoIP location change detected ({stored_geo} -> {current_geo}). Revoking.")
    #     revoke_session(session_id)
    #     abort(401)

    # --- 6. Update Session Activity and Refresh TTL ---
    now_utc = datetime.now(timezone.utc)
    session_data['last_active'] = now_utc.isoformat()

    # Re-sign the session data IF it was modified (e.g., UA update) OR if you want to rotate signatures periodically (more complex).
    # For simple activity update, re-signing might be skipped if performance is critical *and* no mutable fields were changed.
    # However, re-signing ensures integrity even if only last_active changed. Let's keep the re-sign for robustness.
    new_signature = create_session_signature(session_data)
    if not new_signature:
         # This is serious - failure to re-sign means the session cannot be safely updated.
         logger.error(f"Could not re-sign session {session_id} during verification update. Revoking to prevent inconsistent state.")
         revoke_session(session_id)
         abort(500) # Internal error led to invalid state
    else:
         # Update the container with potentially modified data and new signature
         session_container["data"] = session_data
         session_container["signature"] = new_signature

    try:
        # Update the session data in Redis and reset its TTL using setex
        redis_client.setex(redis_key, session_ttl_seconds, json.dumps(session_container))
        logger.debug(f"Refreshed session {session_id} TTL ({session_ttl_seconds}s) and updated last_active time.")
    except redis.exceptions.TimeoutError as e:
        logger.error(f"Redis timeout error updating session {session_id} activity (key: {redis_key}): {e}")
        # Don't necessarily abort, but the session might expire sooner than expected. Log it.
        # Consider aborting 500 if session persistence *must* be guaranteed on every verified request.
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error updating session {session_id} activity (key: {redis_key}): {e}", exc_info=True)
        # Log the error, but potentially allow the request to proceed.
    except TypeError as e: # Catch JSON serialization errors during update
        logger.error(f"Error serializing session data for Redis update (session {session_id}): {e}", exc_info=True)
        # This might indicate a bug. Aborting might be safer.
        abort(500)
    except Exception as e:
        logger.error(f"Unexpected error updating session {session_id} activity in Redis (key: {redis_key}): {e}", exc_info=True)
        # Handle based on policy - maybe abort 500

    # --- 7. Role Resolution & RBAC Check ---
    # Get role from the verified session data. Default to 'guest' if missing (shouldn't happen with good init).
    user_role = session_data.get('role', 'guest')
    if user_role == 'guest' and 'role' not in session_data:
        logger.warning(f"Session {session_id}: Role missing in session data, defaulting to 'guest'.")

    access_level = get_access_level_for_role(user_role)

    # Get the target resource details from NGINX headers
    original_uri = request.headers.get('X-Original-URI', '/')
    original_method = request.headers.get('X-Original-Method', 'GET')

    # Perform RBAC check based on role, method, and URI
    permission_granted = check_rbac_permissions(user_role, original_method, original_uri)

    if not permission_granted:
        logger.warning(f"RBAC Access Denied for session {session_id}: Role '{user_role}' is not authorized to perform {original_method} on '{original_uri}'.")
        # Return 403 Forbidden - NGINX will handle this via error_page directive typically
        abort(403)

    # --- Verification Success ---
    logger.info(f"Verification successful for session {session_id}. Role: {user_role}. Granted {original_method} access to '{original_uri}'.")

    # If all checks pass, return 200 OK.
    # Add custom headers for NGINX/upstream application to use (via auth_request_set)
    response = make_response("OK", 200)
    response.headers['X-ZT-Session-ID'] = session_id # Pass session ID if needed upstream
    response.headers['X-ZT-User-ID'] = session_data.get('user_id', 'unknown')
    response.headers['X-ZT-User-Role'] = user_role
    response.headers['X-ZT-Access-Level'] = access_level
    # Add any other claims or context needed by the upstream application
    # response.headers['X-ZT-Claims'] = json.dumps(session_data.get('claims', {})) # Example
    response.headers['X-ZT-Session-Verified'] = 'true' # Confirmation flag

    return response

@app.route('/admin', methods=['GET', 'POST'])
def admin_invite_page():
    """
    Admin panel to generate analyst invite links.
    Requires localhost access AND admin role session.
    """
    # --- Step 1: Enforce Localhost Access ---
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    allowed_admin_ips = {'127.0.0.1', '::1'}
    if client_ip not in allowed_admin_ips:
        logger.warning(f"Access Denied: Request to /admin from non-localhost IP {client_ip}.")
        abort(403) # Forbidden - Not localhost

    # --- Step 2: Verify Session and Admin Role ---
    session_data = get_verified_session() # Handles session validity checks, aborts if invalid
    user_role = session_data.get('role')
    session_id = session_data.get("session_id", "UNKNOWN")

    if user_role != ADMIN_ROLE:
        logger.warning(f"Access Denied: User from localhost (Session: {session_id}) attempted /admin access with role '{user_role}'.")
        abort(403) # Forbidden - Not an admin

    # --- Step 3: Handle POST Request (Generate Link) ---
    if request.method == 'POST':
        invite_link = None
        error_message = None
        expiration_minutes = invite_token_ttl_minutes

        try:
            invite_token = generate_secure_token(32)
            if store_invite_token(invite_token, expiration_minutes):
                # Assuming you will have a registration endpoint named 'register_analyst'
                # If not, adjust the endpoint name in url_for
                # registration_path = url_for('register_analyst', token=invite_token, _external=False)
                # Simpler approach if no dedicated registration endpoint: just provide the token
                registration_path = f"/register?token={invite_token}" # Example path, adjust as needed
                full_invite_url = urljoin(BASE_URL, registration_path)
                invite_link = full_invite_url

                logger.info(f"Admin (localhost, Session: {session_id}) generated analyst invite link: {invite_link} (Expires in {expiration_minutes} min)")
                flash(f"Invite link generated successfully! Expires in {expiration_minutes} minutes.", "success")
            else:
                error_message = "Failed to generate invite link due to a storage error. Please try again."
                logger.error(f"Admin (Session: {session_id}) failed to store invite token in Redis.")
                flash(error_message, "error")

        except Exception as e:
             error_message = "An unexpected error occurred while generating the link."
             logger.error(f"Error generating invite for admin (Session: {session_id}): {e}", exc_info=True)
             flash(error_message, "error")

        return render_template('admin.html',
                               invite_link=invite_link,
                               expiration_minutes=expiration_minutes if invite_link else None,
                               error_message=error_message)

    # --- Step 4: Handle GET Request (Show Page) ---
    else: # request.method == 'GET'
        logger.debug(f"Admin (localhost, Session: {session_id}) accessed /admin page.")
        return render_template('admin.html', invite_link=None, expiration_minutes=None, error_message=None)

# --- Placeholder for Analyst Registration ---
# You would need an endpoint like this to handle the invite token
@app.route('/register', methods=['GET', 'POST'])
def register_analyst():
     token = request.args.get('token')
     if not token:
         flash("Missing invite token.", "error")
         return redirect(url_for('session_init')) # Or wherever appropriate

     if request.method == 'GET':
         # Check if token is potentially valid *without consuming it* yet
         if not redis_client or not redis_client.exists(f"invite:{token}"):
              flash("Invalid or expired invite token.", "error")
              return redirect(url_for('session_init'))
         # Show registration form (e.g., asking for username/password for the analyst)
         return f"Show registration form for token: {token}" # Replace with render_template

     elif request.method == 'POST':
         # 1. Verify and Consume Token
         if not verify_and_consume_invite_token(token):
              flash("Invalid, expired, or already used invite token.", "error")
              return redirect(url_for('session_init'))

         # 2. Process registration form data (e.g., get username, hash password)
         # username = request.form.get('username')
         password_hash = hash_password(request.form.get('password')) # Implement hashing

         # 3. Create Analyst User Account (Store user info securely, NOT in session)
         # This part requires a proper user datastore (database, LDAP, etc.)
         store_analyst_user(username, password_hash, ANALYST_ROLE) # Fictional function

         flash("Analyst account created successfully. Please log in.", "success")
         logger.info(f"Analyst registration successful using token {token}.")
         # Redirect to login or maybe directly initiate a session if desired (less common)
         return redirect(url_for('session_init'))

# --- Step 4: Role-Based Access Control Matrix Logic ---
# Pre-compile regex patterns for potential performance improvement if ruleset is large
# This is optional for small rulesets but good practice.
# We define permissions inside the function for clarity in this example,
# but pre-compilation would happen outside if performance was critical.

def check_rbac_permissions(role: str, method: str, uri: str) -> bool:
    """
    Checks if a role has permission for a given HTTP method and URI path based on defined rules.
    Uses regex matching for flexibility.
    """
    logger.debug(f"RBAC Check: Role='{role}', Method='{method}', URI='{uri}'")

    if not role or not method or uri is None:
        logger.error(f"RBAC Check failed: Invalid inputs (Role: {role}, Method: {method}, URI: {uri is None})")
        return False

    # Normalize URI path: remove query string, ensure leading slash, handle empty path
    uri_path = uri.split('?', 1)[0]
    if not uri_path:
        uri_path = '/'
    elif not uri_path.startswith('/'):
        uri_path = '/' + uri_path

    # Normalize Method (convert to uppercase for consistent matching)
    normalized_method = method.upper()

    # --- Define Permissions Matrix ---
    # Structure: (HTTP_METHOD_REGEX, URI_PATH_REGEX): [LIST_OF_ALLOWED_ROLES]
    # Use raw strings (r'') for regex patterns.
    # Consider loading this from a configuration file (JSON, YAML) or database for dynamic updates.
    # More specific rules should generally come before broader rules if patterns overlap,
    # although `re.fullmatch` makes overlaps less ambiguous than `re.match`.
    #       ('GET', r'^/dashboard$'): ['guest', 'admin'], 
      #  ('GET', r'^/profile$'): ['guest', 'admin'], 
 
    
    permissions: Dict[Tuple[str, str], list[str]] = {
        # --- General Public/Guest Access ---
        ('GET', r'^/$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/session/init$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/session/init$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/static/.*'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/assets/.*'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/public/.*'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/favicon.ico$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/dashboard$'): [ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/profile$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/sast$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/sast/?$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/sast/?$'): [ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/analyze$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],

        ('POST', r'^/logout$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/vulnscan$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        # --- Gradio Core View / AI Scanner Read ---
        ('GET', r'^/file=.*'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/config$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE], # Assuming config is public/read-only
        ('GET', r'^/info$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],   # Assuming info is public/read-only
        ('HEAD', r'.*'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('OPTIONS', r'.*'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        # AI Scanner Chat Read Operations
        ('GET', r'^/chat/[a-zA-Z0-9_-]+$'): [ANALYST_ROLE, ADMIN_ROLE, GUEST_ROLE], # Allow reading specific chats

        # --- AI Scanner Chat Write/Interact Operations (Analysts & Admins) ---
        ('POST', r'^/chat/new$'): [ANALYST_ROLE, ADMIN_ROLE], # <<< ADDED THIS RULE
        ('POST', r'^/chat/[a-zA-Z0-9_-]+/message$'): [ANALYST_ROLE, ADMIN_ROLE], # <<< ADDED THIS RULE

        # --- Gradio Interactions (If separate from chat API - adapt as needed) ---
        ('GET', r'^/queue/join$'): [ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/queue/join$'): [ANALYST_ROLE, ADMIN_ROLE],
        ('GET', r'^/queue/data$'): [ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/run/predict$'): [ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/run/predict/\d+$'): [ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/api/predict$'): [ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/api/predict/.*'): [ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/call/.*'): [ANALYST_ROLE, ADMIN_ROLE],

        # --- Custom API Rules (Example) ---
        ('GET', r'^/api/scans$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('(POST|PUT|DELETE)', r'^/api/scans$'): [ANALYST_ROLE, ADMIN_ROLE],
        ('(GET|POST|PUT|DELETE)', r'^/api/scans/.*'): [ANALYST_ROLE, ADMIN_ROLE],

        # --- Session Check Endpoint ---
        ('GET', r'^/session/check$'): [ANALYST_ROLE, ADMIN_ROLE],

        # --- Admin ONLY Section ---
        ('(GET|POST)', r'^/admin$'): [ADMIN_ROLE],
        ('(GET|POST|PUT|DELETE)', r'^/api/users.*'): [ADMIN_ROLE],
        ('(GET|POST|PUT|DELETE)', r'^/api/audit.*'): [ADMIN_ROLE],
        ('GET', r'^/metrics$'): [ADMIN_ROLE],

        # --- Analyst Registration Endpoint ---
        ('GET', r'^/register$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
        ('POST', r'^/register$'): [GUEST_ROLE, ANALYST_ROLE, ADMIN_ROLE],
    }

    # --- Match Request against Rules ---
    matched_rule = False
    for (method_pattern, uri_pattern), allowed_roles in permissions.items():
        try:
            # Use re.fullmatch for precise matching of the entire string/path
            # Compile regex on the fly here. For very high performance, pre-compile outside the function.
            method_regex = re.compile(method_pattern)
            uri_regex = re.compile(uri_pattern)

            if method_regex.fullmatch(normalized_method) and uri_regex.fullmatch(uri_path):
                matched_rule = True # Found a matching rule pattern
                logger.debug(f"RBAC Rule Match: Request ({normalized_method} {uri_path}) matches rule ({method_pattern}, {uri_pattern})")
                if role in allowed_roles:
                    logger.debug(f"RBAC Allowed: Role '{role}' is in allowed roles {allowed_roles} for the matched rule.")
                    return True # Permission granted by this rule
                else:
                    # Role is NOT allowed by this specific matching rule.
                    # Since we found a match, and the role isn't listed, deny access based on this rule.
                    # This implements the principle that the first specific rule match dictates the outcome.
                    logger.warning(f"RBAC Denied: Role '{role}' IS NOT in allowed roles {allowed_roles} for matching rule ({method_pattern}, {uri_pattern}) on resource {normalized_method} {uri_path}.")
                    return False
        except re.error as e:
             logger.error(f"RBAC Regex error in pattern (Method: '{method_pattern}', URI: '{uri_pattern}'): {e}. Skipping this rule.", exc_info=True)
             # Fail securely - if a rule is broken, don't grant access based on it. Continue checking other rules.
             continue

    # If loop completes without finding any matching rule pattern
    if not matched_rule:
        logger.warning(f"RBAC Denied: No matching permission rule found for Role='{role}', Method='{normalized_method}', URI='{uri_path}'. Denying by default.")

    # Default deny if no rule explicitly granted permission
    return False


# --- Main Execution Guard ---
if __name__ == '__main__':
    # CRITICAL: Check Redis connection before starting the Flask app.
    if not redis_client:
        logger.critical("FATAL: Cannot start Flask application - Redis connection failed during initialization.")
        # Print to stderr as well, in case logging isn't fully set up or visible
        print("ERROR: Cannot start Flask app - Redis connection failed during initialization.", file=os.sys.stderr)
        exit(1) # Exit with a non-zero code to indicate failure

    logger.info(f"Starting Flask Session Manager...")
    logger.info(f"Flask Debug Mode: {flask_debug}")
    logger.info(f"Session Cookie: Name='{session_cookie_name}', TTL={session_ttl_seconds}s")
    logger.info(f"Log Level: {log_level_name}")
    logger.info(f"Redis Target: {redis_host}:{redis_port}, DB: {redis_db}")

    # --- Production Server Recommendation ---
    # Use a production-grade WSGI server like Gunicorn or Waitress instead of Flask's built-in development server.
    if flask_debug:
        # Running in debug mode - use Flask's development server (with reloader and debugger)
        logger.warning("Running in FLASK DEBUG mode. DO NOT use in production!")
        # Host '0.0.0.0' makes it accessible externally, '127.0.0.1' only locally. Use 127.0.0.1 for security unless needed otherwise.
        app.run(host='127.0.0.1', port=5000, debug=True)
    else:
        # Running in production mode - use Waitress (or Gunicorn)
        try:
            from waitress import serve
            logger.info("Running with Waitress production WSGI server.")
            # Adjust host, port, and threads as needed for your environment
            serve(app, host='127.0.0.1', port=5000, threads=8) # Example: 8 worker threads
        except ImportError:
            logger.error("Waitress not found. Falling back to Flask development server (NOT RECOMMENDED FOR PRODUCTION).")
            logger.error("Install waitress: pip install waitress")
            # Run with Flask's server but explicitly disable debug mode.
            app.run(host='127.0.0.1', port=5000, debug=False)
            
