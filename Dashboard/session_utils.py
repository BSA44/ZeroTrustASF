# session_utils.py
import os
import redis
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
import logging
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# --- Configuration Loading ---
load_dotenv()
logger = logging.getLogger(__name__) # Use logger passed from calling module or default

# --- Session Config ---
SESSION_COOKIE_NAME = os.getenv('ZT_SESSION_COOKIE_NAME', 'zt-session')
SESSION_TTL_SECONDS = int(os.getenv('ZT_SESSION_TTL_SECONDS', 3600))
if SESSION_TTL_SECONDS <= 0:
    logger.warning(f"ZT_SESSION_TTL_SECONDS invalid ({SESSION_TTL_SECONDS}). Using 3600.")
    SESSION_TTL_SECONDS = 3600

# --- HMAC Key ---
HMAC_SECRET_KEY_ENV = os.getenv('SECRET_KEY')
if not HMAC_SECRET_KEY_ENV:
    logger.critical("FATAL: SECRET_KEY environment variable not set.")
    raise ValueError("SECRET_KEY environment variable is required.")
HMAC_SECRET_KEY = HMAC_SECRET_KEY_ENV.encode('utf-8')

# --- Redis Config ---
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))
REDIS_SOCKET_TIMEOUT = int(os.getenv('REDIS_SOCKET_TIMEOUT', 5))
REDIS_CONNECT_TIMEOUT = int(os.getenv('REDIS_CONNECT_TIMEOUT', 5))
REDIS_RETRY_ON_TIMEOUT = os.getenv('REDIS_RETRY_ON_TIMEOUT', 'False').lower() == 'true'

# --- Global Redis Client Placeholder ---
# Avoids reconnecting constantly, but manage carefully in multi-threaded/process environments
_redis_client_instance: Optional[redis.StrictRedis] = None

def get_redis_client() -> Optional[redis.StrictRedis]:
    """Gets a Redis client instance, attempting connection if not already established."""
    global _redis_client_instance
    if _redis_client_instance:
        # Optional: Add a quick ping check here if needed, but might add latency
        # try:
        #     if _redis_client_instance.ping():
        #          return _redis_client_instance
        # except redis.exceptions.ConnectionError:
        #     logger.warning("Cached Redis client connection lost. Attempting reconnect.")
        #     _redis_client_instance = None # Force reconnect
        # except Exception as e:
        #      logger.error(f"Error pinging cached Redis client: {e}", exc_info=True)
        #      _redis_client_instance = None # Force reconnect
        return _redis_client_instance # Return cached client optimistically

    try:
        client = redis.StrictRedis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True,
            socket_timeout=REDIS_SOCKET_TIMEOUT,
            socket_connect_timeout=REDIS_CONNECT_TIMEOUT,
            retry_on_timeout=REDIS_RETRY_ON_TIMEOUT,
        )
        client.ping()
        logger.info(f"Successfully connected to Redis at {REDIS_HOST}:{REDIS_PORT}, DB: {REDIS_DB}")
        _redis_client_instance = client
        return _redis_client_instance
    except redis.exceptions.TimeoutError as e:
        logger.error(f"Redis connection timed out ({REDIS_HOST}:{REDIS_PORT}). Error: {e}")
        _redis_client_instance = None
        return None
    except redis.exceptions.ConnectionError as e:
        logger.error(f"Could not connect to Redis ({REDIS_HOST}:{REDIS_PORT}). Error: {e}")
        _redis_client_instance = None
        return None
    except Exception as e:
        logger.error(f"Unexpected error during Redis connection setup ({REDIS_HOST}:{REDIS_PORT}). Error: {e}", exc_info=True)
        _redis_client_instance = None
        return None

# --- Signature Functions ---

def create_session_signature(session_data: Dict[str, Any]) -> Optional[str]:
    """Creates an HMAC-SHA256 signature for the session data dictionary."""
    if not HMAC_SECRET_KEY:
        logger.error("HMAC Secret Key is not configured! Cannot create signature.")
        return None
    if not isinstance(session_data, dict):
        logger.error(f"Invalid input: session_data must be a dict, got {type(session_data)}. Cannot sign.")
        return None
    try:
        message = json.dumps(session_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = hmac.new(HMAC_SECRET_KEY, message, hashlib.sha256).hexdigest()
        return signature
    except TypeError as e:
        logger.error(f"Error serializing session data for signature: {e}. Data: {session_data}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error creating session signature: {e}", exc_info=True)
        return None

def verify_session_signature(session_data: Dict[str, Any], provided_signature: Optional[str]) -> bool:
    """Verifies the HMAC-SHA256 signature using timing-attack-resistant comparison."""
    if not provided_signature or not isinstance(session_data, dict):
        logger.warning("Signature verification failed: Missing signature or invalid session_data type.")
        return False

    expected_signature = create_session_signature(session_data)
    if expected_signature is None:
        logger.error("Signature verification failed: Could not generate expected signature.")
        return False

    return hmac.compare_digest(expected_signature, provided_signature)

# --- Session Operations ---

def revoke_session(redis_client: redis.StrictRedis, session_id: str):
    """Deletes session data from Redis using the provided client."""
    if not redis_client:
         logger.error("Cannot revoke session: Invalid Redis client provided.")
         return
    if not session_id or not isinstance(session_id, str):
        logger.warning(f"Attempted to revoke session with invalid ID: {session_id}")
        return

    try:
        key = f"session:{session_id}"
        deleted_count = redis_client.delete(key)
        if deleted_count > 0:
            logger.info(f"Revoked session: {session_id} (Redis key: {key})")
        else:
            logger.info(f"Attempted to revoke session {session_id}, but it was not found (key: {key}).")
    except redis.exceptions.TimeoutError as e:
         logger.error(f"Redis timeout error revoking session {session_id} (key: {key}): {e}")
    except redis.exceptions.RedisError as e:
         logger.error(f"Redis error revoking session {session_id} (key: {key}): {e}", exc_info=True)
    except Exception as e:
         logger.error(f"Unexpected error revoking session {session_id} (key: {key}): {e}", exc_info=True)


def get_verified_session_data(redis_client: redis.StrictRedis, session_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetches session from Redis, validates structure, verifies signature.
    Returns the verified 'data' dictionary on success, None on failure.
    Handles Redis errors internally and logs issues. Revokes session on signature mismatch or structural errors.
    """
    if not redis_client:
        logger.error(f"Session retrieval failed for {session_id}: Invalid Redis client provided.")
        return None # Cannot proceed without client

    if not session_id or not isinstance(session_id, str):
        logger.warning(f"Attempted to get session with invalid ID: {session_id}")
        return None

    redis_key = f"session:{session_id}"
    session_json = None

    # 1. Fetch from Redis
    try:
        session_json = redis_client.get(redis_key)
    except redis.exceptions.TimeoutError as e:
         logger.error(f"Redis timeout fetching session {session_id} (key: {redis_key}): {e}")
         return None # Treat as session unavailable
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error fetching session {session_id} (key: {redis_key}): {e}", exc_info=True)
        return None # Treat as session unavailable
    except Exception as e:
        logger.error(f"Unexpected error fetching session {session_id} (key: {redis_key}): {e}", exc_info=True)
        return None # Treat as session unavailable

    if not session_json:
        logger.info(f"Session verification failed: Session ID {session_id} not found in Redis (key: {redis_key}).")
        return None # Session doesn't exist or expired

    # 2. Parse and Validate Structure
    session_container = None
    session_data = None
    session_signature = None
    try:
        session_container = json.loads(session_json)
        if not isinstance(session_container, dict) or "data" not in session_container or "signature" not in session_container:
             logger.error(f"Verification failed: Malformed container structure in Redis for {session_id}. Content: {session_json[:200]}...")
             revoke_session(redis_client, session_id)
             return None

        session_data = session_container.get("data")
        session_signature = session_container.get("signature")

        if not isinstance(session_data, dict) or not isinstance(session_signature, str):
             logger.error(f"Verification failed: Malformed data types (data: {type(session_data)}, sig: {type(session_signature)}) in Redis for {session_id}.")
             revoke_session(redis_client, session_id)
             return None

    except json.JSONDecodeError as e:
        logger.error(f"Verification failed: Could not decode JSON for {session_id}. Error: {e}. Data: {session_json[:200]}...")
        revoke_session(redis_client, session_id)
        return None
    except Exception as e: # Catch other potential errors during parsing/validation
        logger.error(f"Unexpected error parsing/validating session {session_id}: {e}", exc_info=True)
        revoke_session(redis_client, session_id) # Revoke on unexpected error during validation
        return None

    # 3. Verify Signature
    if not verify_session_signature(session_data, session_signature):
        logger.error(f"Verification failed: Invalid HMAC signature for session {session_id}. Revoking session.")
        revoke_session(redis_client, session_id)
        return None # Signature mismatch

    # 4. Basic Expiration Check (Optional but recommended)
    try:
        expires_at_str = session_data.get('expires_at')
        if isinstance(expires_at_str, str):
            expires_at = datetime.fromisoformat(expires_at_str)
            if datetime.now(timezone.utc) >= expires_at:
                logger.info(f"Session {session_id} has logically expired at {expires_at_str}. Treating as invalid.")
                # No need to revoke, Redis TTL should handle it, but returning None prevents use.
                return None
        else:
            logger.warning(f"Session {session_id}: expires_at missing or not string. Cannot check expiration.")
            # Decide policy: allow or deny? Denying is safer if expiry is critical.
            # return None # Uncomment to deny if expires_at is mandatory

    except (ValueError, TypeError) as e:
        logger.warning(f"Session {session_id}: Could not parse expires_at '{expires_at_str}'. Error: {e}.")
        # Decide policy: allow or deny?
        # return None # Uncomment to deny if timestamp is malformed

    # --- Success ---
    logger.debug(f"Session {session_id} successfully verified.")
    return session_data # Return the verified session data payload