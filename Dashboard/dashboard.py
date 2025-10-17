# corporate_dashboard.py
import os
# Removed hmac, hashlib, json imports if they were only for verification simulation
from flask import Flask, request, make_response, jsonify, abort, redirect, url_for, render_template, g, flash
from dotenv import load_dotenv
import logging
from functools import wraps
import redis # Keep redis import if directly interacting beyond utils

# --- Import Utilities ---
import session_utils # Import the new utils module

# --- Configuration ---
load_dotenv()

# Logging Setup (keep as is)
log_level_name = os.getenv('DASHBOARD_LOG_LEVEL', 'INFO').upper()
log_level = getattr(logging, log_level_name, logging.INFO)
log_format = '%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] %(message)s'
logging.basicConfig(level=log_level, format=log_format)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('DASHBOARD_SECRET_KEY', os.urandom(24)) # Needed for flash messages

# --- Use Config from Utils ---
session_cookie_name = session_utils.SESSION_COOKIE_NAME
# Ensure the logger knows the expected cookie name
logger.info(f"Expecting session cookie named: '{session_cookie_name}'")

# --- Direct Redis Verification Decorator ---

def verify_session_via_redis(f):
    """
    Decorator to verify session validity directly using Redis via session_utils.
    Sets g.user_role and g.user_id on success.
    Redirects to login or aborts on failure.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = request.cookies.get(session_cookie_name)
        if not session_id:
            logger.debug(f"Access denied to {request.path}: No session cookie '{session_cookie_name}' found.")
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login_info', next=request.url))

        # Get Redis client instance
        redis_client = session_utils.get_redis_client()
        if not redis_client:
            logger.error(f"Access denied to {request.path}: Redis connection unavailable.")
            abort(503) # Service Unavailable

        # --- Perform Verification using Util Function ---
        session_data = session_utils.get_verified_session_data(redis_client, session_id)

        if session_data:
            # --- Verification Success ---
            g.user_role = session_data.get('role', 'guest') # Default role if missing?
            g.user_id = session_data.get('user_id', 'unknown')
            g.session_id = session_id # Store session ID in g if needed later
            logger.info(f"Session verified via Redis for {request.path}. Role='{g.user_role}', UserID='{g.user_id}'.")

            # Optional: Context check (e.g., IP binding) - less common if proxy isn't involved
            # current_ip = request.remote_addr # Note: Might not be reliable without trusted proxy
            # stored_ip = session_data.get('ip')
            # if stored_ip and stored_ip != current_ip:
            #     logger.critical(f"CRITICAL: IP mismatch during direct Redis check for {session_id}. Stored={stored_ip}, Current={current_ip}. Revoking.")
            #     session_utils.revoke_session(redis_client, session_id)
            #     flash("Your session is invalid due to a network change. Please log in again.", "danger")
            #     response = make_response(redirect(url_for('login_info')))
            #     response.set_cookie(session_cookie_name, '', expires=0) # Clear bad cookie
            #     return response

            return f(*args, **kwargs) # Proceed to the route function
        else:
            # --- Verification Failure ---
            # get_verified_session_data logs the specific reason (not found, bad sig, expired)
            logger.warning(f"Access denied to {request.path}: Session verification failed for cookie ID '{session_id}'.")
            flash("Your session is invalid or has expired. Please log in again.", "danger")
            # Clear the potentially invalid cookie from the browser
            response = make_response(redirect(url_for('login_info', next=request.url)))
            is_secure = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
            response.set_cookie(session_cookie_name, '', expires=0, httponly=True, samesite='Lax', path='/', secure=is_secure)
            return response

    return decorated_function

# --- Routes ---

@app.route('/dashboard')
@verify_session_via_redis # Use the new decorator
def dashboard():
    """Displays content based on the user's verified role (from g)."""
    user_role = g.user_role
    user_id = g.user_id

    dashboard_data = {
        "user_id": user_id,
        "role": user_role,
        "widgets": []
    }
    # (Dashboard content logic remains the same as before)
    if user_role == 'admin':
        dashboard_data["title"] = "Admin Control Panel"
        dashboard_data["widgets"] = [
            {"id": "users", "title": "User Management", "content": "Manage system users and roles."},
            {"id": "settings", "title": "System Settings", "content": "Configure application parameters."},
            {"id": "audit", "title": "Audit Logs", "content": "View system activity logs."},
            {"id": "reports", "title": "All Reports", "content": "Access all generated reports."},
        ]
        logger.info(f"Rendering admin dashboard for user '{user_id}'.")
    elif user_role == 'guest':
         dashboard_data["title"] = "Guest Information Portal"
         dashboard_data["widgets"] = [
             {"id": "welcome", "title": "Welcome", "content": f"Welcome, {user_id}! You have guest access."},
             {"id": "public_reports", "title": "Public Reports", "content": "View publicly available reports."},
             {"id": "docs", "title": "Documentation", "content": "Read user guides and documentation."},
         ]
         logger.info(f"Rendering guest dashboard for user '{user_id}'.")
    else:
        dashboard_data["title"] = "Standard User Dashboard"
        dashboard_data["widgets"] = [
            {"id": "info", "title": "Information", "content": f"Role '{user_role}' detected. Showing standard view."},
        ]
        logger.info(f"Rendering standard dashboard for user '{user_id}' with role '{user_role}'.")

    return render_template('dashboard.html', data=dashboard_data)

@app.route('/profile')
@verify_session_via_redis # Protect this route
def profile():
    """Displays the user's profile information using a styled template."""
    logger.info(f"Rendering profile page for user '{g.user_id}' (Role: {g.user_role}).")
    # Render the new profile.html template, passing data from g
    return render_template(
        'profile.html',
        user_id=g.user_id,
        role=g.user_role,
        session_id=g.session_id
    )

@app.route('/login_info')
def login_info():
    """Simulated login page."""
    session_manager_host = os.getenv('SESSION_MANAGER_HOST', '127.0.0.1')
    session_manager_port = os.getenv('SESSION_MANAGER_PORT', '5000')
    session_manager_init_url = f"http://{session_manager_host}:{session_manager_port}/session/init"
    logger.debug("Displaying login info page.")
    # Add next parameter handling if needed for redirection after login
    next_url = request.args.get('next')
    return render_template('login.html', session_init_url=session_manager_init_url, next_url=next_url)

@app.route('/logout', methods=['POST'])
def logout():
    """Clears the session cookie and redirects to the login info page."""
    # Optional: Explicitly revoke session in Redis on logout
    session_id = request.cookies.get(session_cookie_name)
    if session_id:
        redis_client = session_utils.get_redis_client()
        if redis_client:
            logger.info(f"Explicitly revoking session {session_id} on logout.")
            session_utils.revoke_session(redis_client, session_id)
        else:
            logger.warning(f"Could not revoke session {session_id} on logout: Redis client unavailable.")

    response = make_response(redirect(url_for('login_info')))
    logger.info(f"Processing logout. Clearing cookie: '{session_cookie_name}'")
    is_secure = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
    response.set_cookie(session_cookie_name, '', expires=0, httponly=True, samesite='Lax', path='/', secure=is_secure)
    flash("You have been logged out.", "info")
    return response


# --- Main Execution Guard ---
if __name__ == '__main__':
    # Check Redis connection on startup using the util function
    if not session_utils.get_redis_client():
        logger.critical("FATAL: Cannot start Dashboard app - initial Redis connection failed.")
        print("ERROR: Cannot start Dashboard app - Redis connection failed.", file=os.sys.stderr)
        exit(1)

    # Port 5002 as requested
    port = int(os.getenv('DASHBOARD_PORT', 5002))
    host = os.getenv('DASHBOARD_HOST', '127.0.0.1')
    debug_mode = os.getenv('DASHBOARD_DEBUG', 'False').lower() == 'true'

    logger.info(f"Starting Corporate Dashboard Application (Direct Redis Verification)...")
    logger.info(f"Mode: {'Debug' if debug_mode else 'Production'}")
    logger.info(f"Listening on http://{host}:{port}")
    logger.info("Verifying sessions directly against Redis.")

    if debug_mode:
        logger.warning("Running in FLASK DEBUG mode.")
        app.run(host=host, port=port, debug=True)
    else:
        try:
            from waitress import serve
            logger.info("Running with Waitress production WSGI server.")
            serve(app, host=host, port=port, threads=8)
        except ImportError:
            logger.error("Waitress not found. Falling back to Flask dev server (NOT FOR PRODUCTION).")
            app.run(host=host, port=port, debug=False)