def generate_session_id() -> str:
    """Generate a secure random session ID (32 bytes, hex encoded)."""
    return os.urandom(32).hex()

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
