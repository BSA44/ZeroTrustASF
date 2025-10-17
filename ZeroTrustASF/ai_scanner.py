# session_manager.py
import os
import redis
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from flask import Flask, request, make_response, jsonify, abort, redirect, url_for
from dotenv import load_dotenv
import logging

# --- Configuration ---
load_dotenv() # Load environment variables from .env file

# Basic logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') # Used for Flask's session if needed, but we use Redis mainly
redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_port = int(os.getenv('REDIS_PORT', 6379))
redis_db = int(os.getenv('REDIS_DB', 0))
session_cookie_name = os.getenv('ZT_SESSION_COOKIE_NAME', 'zt-session')
session_ttl_seconds = int(os.getenv('ZT_SESSION_TTL_SECONDS', 3600)) # 1 hour TTL

# --- IMPORTANT SECURITY NOTE ---
# The SECRET_KEY here is for the HMAC signature, NOT Flask's built-in session.
# Ensure it's strong and kept secret.
hmac_secret_key = os.getenv('SECRET_KEY').encode('utf-8')

# --- Redis Connection ---
try:
    redis_client = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)
    redis_client.ping()
    logging.info(f"Successfully connected to Redis at {redis_host}:{redis_port}")
except redis.exceptions.ConnectionError as e:
    logging.error(f"FATAL: Could not connect to Redis: {e}")
    # In a real app, you might exit or have a fallback, but here we'll let it fail later.
    redis_client = None # Ensure it's None if connection fails

# --- Helper Functions ---

def generate_session_id():
    # Generate a secure random session ID
    return os.urandom(32).hex()

def create_session_signature(session_data):
    """Creates an HMAC-SHA256 signature for the session data."""
    if not hmac_secret_key:
        logging.error("HMAC Secret Key is not configured!")
        return None
    # Use a stable representation for signing (e.g., sorted JSON)
    message = json.dumps(session_data, sort_keys=True).encode('utf-8')
    signature = hmac.new(hmac_secret_key, message, hashlib.sha256).hexdigest()
    return signature

def verify_session_signature(session_data, provided_signature):
    """Verifies the HMAC-SHA256 signature."""
    if not provided_signature:
        return False
    expected_signature = create_session_signature(session_data)
    if expected_signature is None:
        return False
    return hmac.compare_digest(expected_signature, provided_signature)

def get_role_for_ip(ip_address):
    """
    Determines user role based on IP address.
    THIS IS A SIMPLISTIC EXAMPLE - Real-world RBAC is more complex.
    It should integrate with identity providers (IdP), user directories, etc.
    """
    # Example logic: Map IP ranges defined in NGINX to roles
    # Note: This duplicates logic from NGINX 'geo'. A better approach might be
    # to have NGINX pass a group header based on 'geo' or have Flask query an external source.
    if ip_address.startswith('192.168.0.'):
        return "admin"
    elif ip_address.startswith('10.10.'):
        return "guest"
    elif ip_address == '127.0.0.1':
        return "admin" # Allow localhost admin for testing
    else:
        return "guest" # Default to least privilege

def get_access_level_for_role(role):
    """ Maps role to a generic access level claim. """
    if role == "admin":
        return "full"
    elif role == "guest":
        return "read-only"
    else:
        return "none"

def revoke_session(session_id):
    """Deletes session data from Redis."""
    if redis_client and session_id:
        try:
            redis_client.delete(f"session:{session_id}")
            logging.info(f"Revoked session: {session_id}")
        except redis.exceptions.RedisError as e:
            logging.error(f"Redis error revoking session {session_id}: {e}")


# --- Step 2: Device Attestation Workflow (Session Initiation) ---
@app.route('/session/init', methods=['GET', 'POST'])
def session_init():
    """
    Handles initial session creation request.
    In a real scenario, GET might serve a form, POST processes it.
    Here, we simulate collecting attributes from headers on POST.
    """
    if not redis_client:
        logging.error("Redis client not available for session init.")
        return "Internal Server Error: Session backend unavailable", 500

    if request.method == 'GET':
        # Optionally, return a simple HTML page explaining the process or asking for consent.
        # For this example, we'll assume the client knows to POST or is redirected.
        return """
        <html><body>
        <h1>Zero Trust Session Initialization</h1>
        <p>You are being redirected here to establish a secure session.</p>
        <p>Typically, device attributes would be collected now.</p>
        <p>For this demo, we will attempt to automatically create a session based on your request.</p>
        <p>If you see this page often, ensure your client sends necessary headers if required.</p>
        <button onclick="initiateSession()">Initiate Session Manually (POST)</button>
        <script>
          function initiateSession() {
            // Example of how a client *might* send headers (requires browser extensions or specific clients)
            fetch('/session/init', {
              method: 'POST',
              headers: {
                'X-Device-MAC': 'AA:BB:CC:DD:EE:FF', // ** BOGUS - Cannot get real MAC this way reliably **
                'X-Device-Hostname': 'my-laptop', // ** BOGUS - Cannot get real hostname this way reliably **
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({}) // Body might be empty or contain other info
            })
            .then(response => {
              if (response.ok) {
                // Session likely set, try accessing the main resource again
                window.location.href = '/';
              } else {
                alert('Session initiation failed. Status: ' + response.status);
              }
            })
            .catch(error => {
              console.error('Error initiating session:', error);
              alert('Error initiating session.');
            });
          }
          // Optionally auto-trigger POST after a delay or user action
          // initiateSession(); // Uncomment to try auto-POSTing
        </script>
        </body></html>
        """, 200

    elif request.method == 'POST':
        client_ip = request.headers.get('X-Real-IP', request.remote_addr) # Trust X-Real-IP from NGINX

        # --- !!! CRITICAL SECURITY WARNING !!! ---
        # Reading MAC/Hostname from headers is INSECURE and EASILY SPOOFED.
        # A real Zero Trust solution requires a trusted client-side agent,
        # OS-level APIs (e.g., via Intune/JAMF), or hardware attestation (TPM).
        # This implementation follows the blueprint but highlights the risk.
        client_mac = request.headers.get('X-Device-MAC', 'UNKNOWN_MAC')
        client_hostname = request.headers.get('X-Device-Hostname', 'UNKNOWN_HOSTNAME')
        user_agent = request.user_agent.string
        # --- End Security Warning ---

        logging.info(f"Session Init Request from IP: {client_ip}, MAC: {client_mac}, Hostname: {client_hostname}, UA: {user_agent}")

        session_id = generate_session_id()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=session_ttl_seconds)

        session_data = {
            "user_id": f"user_{client_ip}", # Simplistic user ID based on IP
            "role": get_role_for_ip(client_ip),
            "ip": client_ip,
            "mac": client_mac, # Storing potentially spoofed MAC
            "hostname": client_hostname, # Storing potentially spoofed hostname
            "user_agent": user_agent,
            "created_at": now.isoformat(),
            "last_active": now.isoformat(),
            "expires_at": expires_at.isoformat(),
        }

        # --- Phase 3: Cryptographic Binding (HMAC Signature) ---
        signature = create_session_signature(session_data)
        if not signature:
             return "Internal Server Error: Could not sign session", 500

        session_data_with_sig = {
            "data": session_data,
            "signature": signature
        }

        try:
            # Store the session data (including signature) in Redis
            redis_client.setex(f"session:{session_id}", session_ttl_seconds, json.dumps(session_data_with_sig))
            logging.info(f"Created session {session_id} for IP {client_ip}. Role: {session_data['role']}")
        except redis.exceptions.RedisError as e:
            logging.error(f"Redis error saving session {session_id}: {e}")
            return "Internal Server Error: Could not save session", 500

        # Set the session ID in a secure cookie
        response = make_response(redirect('/', 302)) # Redirect to the main resource after session creation
        response.set_cookie(
            session_cookie_name,
            session_id,
            max_age=session_ttl_seconds,
            httponly=True, # Prevent client-side script access
            secure=True,   # Send only over HTTPS
            samesite='Lax' # Mitigate CSRF
        )
        logging.info(f"Set cookie '{session_cookie_name}' for session {session_id}")
        return response

# --- Step 3: Session Integrity Engine (Verification Middleware via NGINX auth_request) ---
@app.route('/session/verify')
def verify_session_route():
    """
    Endpoint called by NGINX auth_request to verify the session cookie
    and perform continuous verification checks.
    """
    if not redis_client:
        logging.error("Redis client not available for session verification.")
        abort(500) # Internal Server Error

    session_id = request.cookies.get(session_cookie_name)
    if not session_id:
        logging.warning("Verification attempt failed: No session cookie found.")
        abort(401) # Unauthorized - Triggers NGINX @handle_unauthorized -> /session/init

    try:
        session_json = redis_client.get(f"session:{session_id}")
    except redis.exceptions.RedisError as e:
        logging.error(f"Redis error fetching session {session_id}: {e}")
        abort(500) # Internal Server Error

    if not session_json:
        logging.warning(f"Verification failed: Session ID {session_id} not found in Redis (expired or invalid).")
        # Instruct NGINX to clear the invalid cookie if possible (tricky from here)
        # NGINX will redirect to /session/init based on 401
        abort(401) # Unauthorized

    try:
        session_container = json.loads(session_json)
        session_data = session_container.get("data")
        session_signature = session_container.get("signature")

        if not session_data or not session_signature:
             logging.error(f"Verification failed: Malformed session data in Redis for {session_id}.")
             revoke_session(session_id)
             abort(401) # Treat as invalid session

        # --- Phase 3: Verify Cryptographic Binding ---
        if not verify_session_signature(session_data, session_signature):
            logging.error(f"Verification failed: Invalid HMAC signature for session {session_id}.")
            revoke_session(session_id)
            abort(401) # Treat as invalid/tampered session

    except json.JSONDecodeError:
        logging.error(f"Verification failed: Could not decode JSON session data for {session_id}.")
        revoke_session(session_id) # Clean up potentially corrupted data
        abort(401) # Treat as invalid session

    # --- Phase 3: Continuous Verification Checks ---
    current_ip = request.headers.get('X-Real-IP', request.remote_addr)
    current_mac = request.headers.get('X-Device-MAC', 'UNKNOWN_MAC') # Again, INSECURE header check
    current_hostname = request.headers.get('X-Device-Hostname', 'UNKNOWN_HOSTNAME') # INSECURE header check
    current_ua = request.user_agent.string

    stored_ip = session_data.get('ip')
    stored_mac = session_data.get('mac')
    stored_hostname = session_data.get('hostname')
    stored_ua = session_data.get('user_agent')

    # 1. IP Address Change Check
    if stored_ip != current_ip:
        logging.warning(f"Verification failed for session {session_id}: IP address changed ({stored_ip} -> {current_ip}).")
        revoke_session(session_id)
        abort(401) # Re-authentication needed due to IP change

    # 2. MAC Address Mismatch (INSECURE - Based on spoofable header)
    if stored_mac != 'UNKNOWN_MAC' and stored_mac != current_mac:
         logging.warning(f"Verification failed for session {session_id}: MAC address mismatch ({stored_mac} -> {current_mac}). Header based - POTENTIALLY SPOOFED.")
         # Decide whether to abort based on policy - might cause issues on WiFi/VPNs if not handled carefully
         # For demo, we'll abort:
         # revoke_session(session_id)
         # abort(401)

    # 3. Hostname Mismatch (INSECURE - Based on spoofable header)
    if stored_hostname != 'UNKNOWN_HOSTNAME' and stored_hostname != current_hostname:
         logging.warning(f"Verification failed for session {session_id}: Hostname mismatch ({stored_hostname} -> {current_hostname}). Header based - POTENTIALLY SPOOFED.")
         # Decide whether to abort based on policy
         # For demo, we'll allow this one through but log it.

    # 4. User-Agent Variance (Basic check - more complex logic needed for real threshold)
    # This is a very naive check. Real UA variance checks are complex.
    if stored_ua != current_ua:
        logging.info(f"Session {session_id}: User agent changed slightly ('{stored_ua}' -> '{current_ua}'). Allowing.")
        # Update UA in session if desired? Only if change is deemed acceptable.
        # session_data['user_agent'] = current_ua # Update UA if needed


    # 5. GeoIP Location Jump (Requires GeoIP database/service - omitted for simplicity)
    # geoip_check()

    # --- Contextual Refresh / Update Last Active Time ---
    # (The blueprint mentions re-authentication after 5 mins inactivity, but Redis TTL handles expiry.
    # We'll just update the 'last_active' timestamp and extend the Redis TTL)
    now = datetime.now(timezone.utc)
    session_data['last_active'] = now.isoformat()

    # Re-sign the potentially updated session data (e.g., if UA was updated)
    new_signature = create_session_signature(session_data)
    if not new_signature:
         logging.error(f"Could not re-sign session {session_id} during verification.")
         # Don't necessarily abort, but log it. The session might expire soon anyway.
    else:
         session_container["data"] = session_data
         session_container["signature"] = new_signature

    try:
        # Update the session data in Redis and reset its TTL
        redis_client.setex(f"session:{session_id}", session_ttl_seconds, json.dumps(session_container))
    except redis.exceptions.RedisError as e:
        logging.error(f"Redis error updating session {session_id} activity: {e}")
        # Don't necessarily abort, but log it. Session might expire.

    # --- Step 4 & 5: Role Resolution & Response Headers for NGINX ---
    user_role = session_data.get('role', 'guest') # Default to guest if role missing
    access_level = get_access_level_for_role(user_role)

    # Check if the user's role permits access to the *specific resource* they are trying to reach.
    # This requires knowing the target URI. NGINX provides X-Original-URI.
    original_uri = request.headers.get('X-Original-URI', '/')

    # Implement RBAC Matrix Logic
    permission_granted = check_rbac_permissions(user_role, request.method, original_uri)

    if not permission_granted:
        logging.warning(f"RBAC Denied for session {session_id}: Role '{user_role}' cannot {request.method} '{original_uri}'.")
        # Return 403 Forbidden - NGINX will handle this via error_page
        abort(403)

    # If all checks pass, return 200 OK.
    # Add custom headers for NGINX to capture via auth_request_set
    response = make_response("OK", 200)
    response.headers['X-User-Role'] = user_role
    response.headers['X-Access-Level'] = access_level
    response.headers['X-Session-Verified'] = 'true' # Example custom header
    logging.info(f"Verification successful for session {session_id}. Role: {user_role}. URI: {original_uri}")
    return response


# --- Step 4: Role-Based Access Control Matrix Logic ---
def check_rbac_permissions(role, method, uri):
    """Checks if a role has permission for a given HTTP method and URI path."""
    logging.debug(f"RBAC Check: Role='{role}', Method='{method}', URI='{uri}'")

    # Normalize URI - remove query params for matching rules
    uri_path = uri.split('?')[0]

    # Define Permissions (could be loaded from config)
    # Format: (HTTP_METHOD_REGEX, URI_PATH_REGEX): [ALLOWED_ROLES]
    permissions = {
        # Gradio usually handles its own internal API calls starting with /api, /queue, etc.
        # Allow general access to Gradio UI elements for logged-in users
        ('GET', r'^/$'): ['guest', 'admin'],
        ('GET', r'^/static/.*'): ['guest', 'admin'],
        ('GET', r'^/assets/.*'): ['guest', 'admin'],
        ('GET', r'^/file=.*'): ['guest', 'admin'], # Gradio file access
        ('GET', r'^/queue/join'): ['guest', 'admin'], # Gradio queueing
        ('POST', r'^/queue/join'): ['guest', 'admin'],
        ('GET', r'^/queue/data'): ['guest', 'admin'],
        ('POST', r'^/run/predict'): ['guest', 'admin'], # Core Gradio prediction endpoint

        # Example specific API rules based on blueprint
        ('GET', r'^/api/scans$'): ['guest', 'admin'],
        ('(POST|PUT|DELETE)', r'^/api/scans$'): ['admin'], # Allow write only for admin
        ('(GET|POST|PUT|DELETE)', r'^/api/scans/.*'): ['admin'], # Access to specific scans only for admin? (Example)

        # Admin only sections
        ('(GET|POST|PUT|DELETE)', r'^/api/audit.*'): ['admin'],
        ('(GET|POST|PUT|DELETE)', r'^/admin.*'): ['admin'],
        ('GET', r'^/metrics$'): ['admin'],

        # Deny by Default - No rule means no access implicitly
    }

    # Match against rules
    import re
    for (method_pattern, uri_pattern), allowed_roles in permissions.items():
        if re.fullmatch(method_pattern, method) and re.fullmatch(uri_pattern, uri_path):
            if role in allowed_roles:
                logging.debug(f"RBAC Allowed: Role '{role}' matches rule for {method} {uri_path}")
                return True # Permission granted
            else:
                # Rule matched, but role not allowed for *this* specific rule
                 logging.debug(f"RBAC Denied: Role '{role}' does not match allowed roles {allowed_roles} for rule {method} {uri_path}")
                 # Continue checking other rules in case of overlap (though less common with fullmatch)

    # If no rule matched
    logging.warning(f"RBAC Denied: No matching rule found for Role='{role}', Method='{method}', URI='{uri_path}'")
    return False


# --- Main Execution ---
if __name__ == '__main__':
    # Use Flask's built-in server for development (not recommended for production)
    # Note: Running with Flask dev server doesn't use Gunicorn settings.
    # For HTTPS with dev server: app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
    # But NGINX handles TLS, so run Flask on HTTP.
    if not redis_client:
         print("ERROR: Cannot start Flask app without Redis connection.")
    else:
        print("Starting Flask Session Manager on http://127.0.0.1:5000")
        # Use waitress or gunicorn for a more robust server even in dev
        # For Gunicorn (install it: pip install gunicorn):
        # gunicorn --bind 127.0.0.1:5000 session_manager:app
        # For simplicity here, use Flask's dev server:
        app.run(host='127.0.0.1', port=5000, debug=os.getenv('FLASK_DEBUG') == '1')
