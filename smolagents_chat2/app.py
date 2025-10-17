# app.py
import time
import json
import os
import subprocess
import sys
import requests
from typing import List, Optional, Literal, Dict, Any, Union
import traceback
import uuid # For generating unique chat IDs
from datetime import datetime # For timestamps

# Flask imports
from flask import Flask, render_template, request, Response, jsonify, abort

# Smol Agents and related imports
try:
    from smolagents import tool, Tool, CodeAgent, OpenAIServerModel, DuckDuckGoSearchTool
    SMOL_EVENTS_AVAILABLE = True
except ImportError:
    print("Warning: Could not import specific Smol Agent event types. Will count all yields as steps.")
    SMOL_EVENTS_AVAILABLE = False
    from smolagents import tool, Tool, CodeAgent, OpenAIServerModel, DuckDuckGoSearchTool


from dotenv import load_dotenv

# Network tool imports
import nmap
# requests import removed as it wasn't used

# --- Load environment variables ---
load_dotenv() # Load variables from .env file first

# --- Constants ---
CHAT_DIR = "./chats" # Directory to store chat files
# Role Definitions
ADMIN_ROLE = "admin"
ANALYST_ROLE = "analyst"
GUEST_ROLE = "guest"
ALLOWED_ROLES = {ADMIN_ROLE, ANALYST_ROLE, GUEST_ROLE}
ROLES_CAN_CREATE = {ADMIN_ROLE, ANALYST_ROLE}
ROLES_CAN_READ = {ADMIN_ROLE, ANALYST_ROLE, GUEST_ROLE}

# --- NEW: Agent Configuration ---
LOG_AFTER_N_STEPS = 10 # Print execution log after this many steps

# API Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")

TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')

API_KEY_TO_USE = None
API_BASE_TO_USE = None
MODEL_ID_TO_USE = None

if OPENAI_API_KEY:
    print("Using OpenAI Configuration from .env")
    API_KEY_TO_USE = OPENAI_API_KEY
    API_BASE_TO_USE = None
    MODEL_ID_TO_USE = "gpt-4o"
elif DEEPSEEK_API_KEY:
    print("Using Deepseek Configuration from .env")
    API_KEY_TO_USE = DEEPSEEK_API_KEY
    API_BASE_TO_USE = "https://api.deepseek.com"
    MODEL_ID_TO_USE = "gpt-4o" # Or appropriate Deepseek model
else:
    print("FATAL: No API Key found in environment variables (checked OPENAI_API_KEY, DEEPSEEK_API_KEY). Please set one in your .env file.", file=sys.stderr)
    sys.exit(1)


# --- Role Checking Function ---
def get_user_role(req):
    role = req.headers.get('X-Auth-User-Role', ANALYST_ROLE).lower()
    if role not in ALLOWED_ROLES:
        print(f"Warning: Invalid role '{role}' received in X-Auth-User-Role header. Defaulting to '{GUEST_ROLE}'.")
        return GUEST_ROLE
    print(f"User role identified as: {role} (from X-Auth-User-Role header)")
    return role

# --- Helper Functions for Chat Files ---
# (ensure_chat_dir, list_chat_files, load_chat, save_chat remain the same)
# ... (helper code omitted for brevity) ...
def ensure_chat_dir():
    """Creates the chat directory if it doesn't exist."""
    os.makedirs(CHAT_DIR, exist_ok=True)

def list_chat_files():
    """Lists chat files, returning basic info (id, timestamp)."""
    ensure_chat_dir()
    chats = []
    try:
        filenames = [f for f in os.listdir(CHAT_DIR) if f.startswith("chat_") and f.endswith(".json")]
        for filename in sorted(filenames, key=lambda f: os.path.getmtime(os.path.join(CHAT_DIR, f)), reverse=True):
             chat_id = filename.replace("chat_", "").replace(".json", "")
             filepath = os.path.join(CHAT_DIR, filename)
             try:
                 with open(filepath, 'r') as f:
                     data = json.load(f)
                     timestamp = data.get("created_at", datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat())
                 chats.append({"id": chat_id, "timestamp": timestamp})
             except (json.JSONDecodeError, IOError, OSError) as e:
                 print(f"Warning: Could not read or parse {filename}: {e}")
             except Exception as e: # Catch other potential errors
                 print(f"Warning: Unexpected error processing {filename}: {e}")
        return chats
    except Exception as e:
        print(f"Error listing chat files: {e}")
        return []


def load_chat(chat_id):
    """Loads chat data from a JSON file."""
    ensure_chat_dir()
    if not chat_id or not chat_id.replace('-', '').isalnum():
         print(f"Warning: Invalid chat_id format detected: {chat_id}")
         return None
    filename = f"chat_{chat_id}.json"
    filepath = os.path.join(CHAT_DIR, filename)
    if not os.path.abspath(filepath).startswith(os.path.abspath(CHAT_DIR)):
        print(f"Warning: Potential path traversal attempt blocked for chat_id: {chat_id}")
        return None
    if not os.path.exists(filepath):
        print(f"Info: Chat file not found: {filepath}")
        return None
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict) or "id" not in data or "messages" not in data:
            print(f"Warning: Invalid chat data structure in file: {filename}")
            return None
        return data
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from chat {chat_id}: {e}")
        return None
    except Exception as e:
        print(f"Error loading chat {chat_id}: {e}")
        return None


def save_chat(chat_id, data):
    """Saves chat data to a JSON file."""
    ensure_chat_dir()
    if not chat_id or not chat_id.replace('-', '').isalnum():
         print(f"Error: Invalid chat_id format for saving: {chat_id}")
         return False
    filename = f"chat_{chat_id}.json"
    filepath = os.path.join(CHAT_DIR, filename)
    if not os.path.abspath(filepath).startswith(os.path.abspath(CHAT_DIR)):
        print(f"Error: Potential path traversal attempt blocked for saving chat_id: {chat_id}")
        return False
    try:
        data["last_updated"] = datetime.now().isoformat()
        if "created_at" not in data:
            data["created_at"] = data["last_updated"]
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving chat {chat_id}: {e}")
        return False


# --- Tool Definitions ---
# (Keep existing tool definitions - open_file, fibonacci, sqlmap_scan, _format_nmap_results, scan_ports, discover_hosts, detect_os)
# ... (tool code omitted for brevity - unchanged) ...




@tool
def read_messages_from_tg()->str:
    """
    Reads new messages from the Telegram bot using getUpdates with offset stored in an environment variable.
    Returns only new messages since the last call.
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
    last_offset = os.environ.get("TG_OFFSET")
    params = {}
    if last_offset is not None:
        try:
            params['offset'] = int(last_offset)
        except ValueError:
            params['offset'] = None
    response = requests.get(url, params=params)
    response.raise_for_status()
    data = response.json()

    # If there are new updates, update the offset to last update_id + 1 in the env variable
    if data['ok'] and data['result']:
        new_offset = data['result'][-1]['update_id'] + 1
        os.environ["TG_OFFSET"] = str(new_offset)
    return str(data)


@tool
def open_file(path: str) -> str:
    """
    Reads the contents of a file. Returns file contents as a string.

    Args:
        path: Absolute path to a file. SECURITY: Path validation is CRITICAL here.
    """
    # SECURITY WARNING: This allows reading ANY file the server process can access.
    # Implement strict path validation based on allowed directories in a real application.
    # Example (very basic, needs improvement):
    # allowed_prefixes = ["/home/user/data/", "/app/shared_files/"]
    # if not any(os.path.abspath(path).startswith(prefix) for prefix in allowed_prefixes):
    #     return f"Error: Access denied to path {path}. Path is not in allowed directories."

    # Basic check against absolute paths starting with / or C:\ etc. might be needed depending on OS and intent
    # if not os.path.isabs(path):
    #    return f"Error: Please provide an absolute path."

    try:
        # Limit file size to prevent reading huge files (e.g., 1MB)
        MAX_FILE_SIZE = 1 * 1024 * 1024
        if os.path.getsize(path) > MAX_FILE_SIZE:
             return f"Error: File size exceeds the limit of {MAX_FILE_SIZE / 1024 / 1024} MB."

        with open(path, "r", encoding='utf-8', errors='ignore') as f: # Specify encoding
            content = f.read()
        # Consider truncating very long content before returning to LLM
        MAX_CONTENT_LEN = 10000 # Truncate to 10k chars
        if len(content) > MAX_CONTENT_LEN:
            return content[:MAX_CONTENT_LEN] + "\n... (file content truncated)"
        return content
    except FileNotFoundError:
        return f"Error: File not found at {path}"
    except IsADirectoryError:
        return f"Error: Path {path} is a directory, not a file."
    except PermissionError:
        return f"Error: Permission denied when trying to read {path}."
    except Exception as e:
        return f"Error reading file {path}: {str(e)}"

@tool
def fibonacci(n: int) -> str:
    """
    Computes the nth Fibonacci number. Returns the number as a string or an error message.

    Args:
        n: Position in Fibonacci sequence (must be an integer ≥ 1)
    """
    try:
        n_int = int(n) # Ensure n is an integer
        if n_int < 1:
            return "Error: Input 'n' must be >= 1"
        a, b = 0, 1
        if n_int == 1: return str(a) # Handle n=1 case
        for _ in range(n_int -1): # Adjust loop range
            a, b = b, a + b
        return str(a) # Return result as string
    except ValueError:
        return f"Error: Input 'n' ({n}) must be an integer."
    except Exception as e:
        return f"Error calculating Fibonacci: {str(e)}"

@tool
def send_msg_tg(msg:str,chat_id:str="293603784") -> str:
    '''Method to send a telegram message to person with chat_id specified
        Args:
            msg: string containing a message to send
            chat_id: it is a string that specifies to which chat send the message. It has Sarvar's chat id set by default.
    '''
    
    TELEGRAM_BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage?chat_id={chat_id}&text={msg}"
    response = requests.get(url)
    if response.status_code != 200:
        return "Error sending"
    return "Message successfully sent"

@tool
def sqlmap_scan(target: str) -> str:
    """
    Scans the target URL for SQL injection vulnerabilities using sqlmap.
    Returns a summary of the scan output or an error message.
    VERY DANGEROUS - Use with extreme caution in controlled environments only.

    Args:
        target: The target URL to scan (must start with http:// or https://).
    """
    if not isinstance(target, str) or not (target.startswith("http://") or target.startswith("https://")):
        return "Error: Target must be a valid URL string starting with http:// or https://"

    # Basic sanitization (more robust needed for production)
    safe_target = target.strip()
    # Consider library like `validators` for better URL validation

    # Security: Consider running sqlmap in a restricted environment/container
    # Limiting options: Avoid dangerous options like --os-shell, --sql-shell if possible
    command = ['sqlmap', '-u', safe_target, '--batch', '--random-agent', '--level=3', '--risk=2', '--dbs'] # Slightly less aggressive defaults
    print(f"Executing command: {' '.join(command)}")

    try:
        # Increased timeout, capture output as text
        result = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False) # check=False to handle non-zero exit codes

        output = f"--- SQLMap Scan Summary for {safe_target} ---\n"
        stdout = result.stdout if result.stdout else ""
        stderr = result.stderr if result.stderr else ""

        # Simple parsing: Look for key indicators
        if "the following databases are available:" in stdout:
             output += "Databases found:\n" + stdout.split("available databases [")[1].split("]")[0] # Basic extraction
        elif "seems to be vulnerable" in stdout:
             output += "Potential SQL injection vulnerability detected.\n"
        elif "does not seem to be injectable" in stdout:
             output += "Target does not seem to be injectable with current options.\n"
        else:
             output += "Scan completed. Review full output for details.\n"

        # Include errors if any
        if stderr:
            output += f"\n--- Errors/Warnings ---\n{stderr[:1000]}...\n" # Truncate long errors

        # Return code info
        output += f"\n--- Exit Code: {result.returncode} ---"

        # Truncate overall output if too long for the LLM
        MAX_OUTPUT_LEN = 4000
        if len(output) > MAX_OUTPUT_LEN:
            output = output[:MAX_OUTPUT_LEN] + "\n... (output truncated)"
        return output

    except FileNotFoundError:
        return "Error: sqlmap command not found. Is sqlmap installed and in the system PATH?"
    except subprocess.TimeoutExpired:
        return f"Error: sqlmap scan for {safe_target} timed out after 300 seconds."
    except Exception as e:
        # Log the full error internally
        print(f"Error running sqlmap command: {e}\n{traceback.format_exc()}", file=sys.stderr)
        return f"Error running sqlmap on {safe_target}: An unexpected error occurred ({type(e).__name__}). Check logs."

# --- Nmap Tools returning JSON strings ---

def _format_nmap_results(results_dict: Dict) -> str:
    """Helper to format Nmap dictionary results into a JSON string."""
    if not results_dict:
        return "{}" # Return empty JSON object string if no results
    try:
        # Convert to JSON string with indentation for better readability if needed
        # Limit depth? Truncate long strings within JSON?
        json_string = json.dumps(results_dict, indent=2)

        # Optional: Truncate very long JSON strings
        MAX_JSON_LEN = 5000
        if len(json_string) > MAX_JSON_LEN:
             # Find a reasonable place to truncate (e.g., after a complete object/array if possible)
             # Simple truncation for now:
             truncated_json = json_string[:MAX_JSON_LEN] + "\n... (JSON output truncated)"
             # Try to validate if the truncated version is still parsable (best effort)
             try:
                 json.loads(truncated_json + "}") # Attempt to make it valid-ish JSON
                 return truncated_json + "}"
             except json.JSONDecodeError:
                 try:
                    json.loads(truncated_json + "]}") # Try another common ending
                    return truncated_json + "]}"
                 except json.JSONDecodeError:
                    return truncated_json # Fallback to simple truncation
        return json_string
    except TypeError as e:
        print(f"Error serializing Nmap results to JSON: {e}")
        return f'{{"error": "Failed to serialize Nmap results to JSON.", "details": "{str(e)}"}}'
    except Exception as e:
        print(f"Unexpected error formatting Nmap results: {e}")
        return f'{{"error": "Unexpected error formatting Nmap results.", "details": "{str(e)}"}}'


@tool
def scan_ports(target: str, ports: Optional[str] = None, scan_type: str = "-sV") -> str:
    """
    Performs a network scan using Nmap and returns the results as a JSON string.
    Use with caution. Requires proper authorization.

    Args:
        target: IP address or hostname to scan.
        ports: Specific ports/range (e.g., "22,80,443", "1-1000"). Default: Nmap top 1000.
        scan_type: Nmap scan type arguments (e.g., "-sV -T4", "-sU"). Default: "-sV".
    """
    # Basic Input Validation (can be more robust)
    if not isinstance(target, str) or not target:
        return json.dumps({"error": "Invalid target specified."})
    if ports and not isinstance(ports, str):
        return json.dumps({"error": "Invalid ports format specified."})
    if not isinstance(scan_type, str):
        return json.dumps({"error": "Invalid scan_type specified."})

    print(f"Executing Nmap port scan: target={target}, ports={ports}, arguments='{scan_type}'")
    results_dict = {}
    try:
        scanner = nmap.PortScanner()
        # Add timeout to nmap scan itself if possible via arguments or library feature
        scanner.scan(hosts=target, ports=ports, arguments=scan_type, sudo=False) # Explicitly set sudo=False unless needed and handled

        for host in scanner.all_hosts():
            host_data = {
                "hostname": scanner[host].hostname(),
                "state": scanner[host].state(),
                "protocols": {}
            }
            for proto in scanner[host].all_protocols():
                port_list = sorted(scanner[host][proto].keys())
                host_data["protocols"][proto] = []
                for port in port_list:
                    port_info = scanner[host][proto][port]
                    port_data = {
                        "port": port,
                        "state": port_info.get("state", "unknown"),
                        "service": port_info.get("name", ""),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "extrainfo": port_info.get("extrainfo", ""),
                        "cpe": port_info.get("cpe", ""),
                    }
                    host_data["protocols"][proto].append(port_data)
            results_dict[host] = host_data

        if not results_dict:
             results_dict = {"message": f"No open ports or host info found for {target}. Host might be down, filtering, or scan options insufficient."}

        return _format_nmap_results(results_dict) # Return formatted JSON string

    except nmap.PortScannerError as e:
         err_msg = str(e)
         # Check for common errors like target resolution
         if "Failed to resolve" in err_msg:
             msg = f"Nmap scan failed: Could not resolve target hostname '{target}'."
         else:
             msg = f"Nmap scan failed. Error: {err_msg}. Check target, arguments, and Nmap installation."
         return json.dumps({"error": msg})
    except Exception as e:
        print(f"Unexpected error during Nmap port scan: {e}\n{traceback.format_exc()}", file=sys.stderr)
        return json.dumps({"error": f"An unexpected error occurred during the Nmap scan ({type(e).__name__})."})

@tool
def discover_hosts(network: str) -> str:
    """
    Discovers active hosts on a network using Nmap ping scan (-sn). Returns results as JSON string.
    Use with caution - requires proper authorization.

    Args:
        network: Network range in CIDR notation (e.g., "192.168.1.0/24") or IP list.
    """
    # Basic Input Validation
    if not isinstance(network, str) or not network:
         return json.dumps({"error": "Invalid network range specified."})
    # Add CIDR validation if needed

    print(f"Executing Nmap host discovery: network={network}")
    results_dict = {}
    try:
        scanner = nmap.PortScanner()
        # -sn: Ping Scan, -T4: Aggressive timing
        # Consider adding --host-timeout if scans take too long on large ranges
        scanner.scan(hosts=network, arguments='-sn -T4', sudo=False)
        discovered = []
        for host in scanner.all_hosts():
            if scanner[host].state() == 'up': # Only include hosts that are up
                 host_info = {
                     "ip": host,
                     "hostname": scanner[host].hostname() if scanner[host].hostname() else "N/A",
                     "state": scanner[host].state(),
                     # Optional: Add MAC address if available and needed (requires root usually)
                     # "mac": scanner[host]['addresses'].get('mac', 'N/A')
                 }
                 discovered.append(host_info)

        if not discovered:
            results_dict = {"hosts": [], "message": f"No active hosts discovered in {network} with ping scan."}
        else:
            results_dict = {"hosts": discovered}

        return _format_nmap_results(results_dict)

    except nmap.PortScannerError as e:
         err_msg = str(e)
         return json.dumps({"error": f"Nmap host discovery failed: {err_msg}. Check network range and Nmap installation."})
    except Exception as e:
        print(f"Unexpected error during Nmap host discovery: {e}\n{traceback.format_exc()}", file=sys.stderr)
        return json.dumps({"error": f"An unexpected error occurred during host discovery ({type(e).__name__})."})


@tool
def detect_os(target: str) -> str:
    """
    Detects the OS of a target using Nmap (-O). Requires root/admin privileges. Returns JSON string.
    Use with caution.

    Args:
        target: IP address or hostname.
    """
    if not isinstance(target, str) or not target:
        return json.dumps({"error": "Invalid target specified."})

    print(f"Executing Nmap OS detection: target={target} (Requires root/admin)")
    results_dict = {}
    try:
        scanner = nmap.PortScanner()
        # -O requires root privileges. Run the script with sudo or handle permissions.
        # Using nmap.PortScannerAsync and checking stderr might be better for privilege errors.
        # For simplicity, assume it might fail if not root.
        # Add --osscan-guess for potentially better results on tricky targets.
        scanner.scan(hosts=target, arguments='-O', sudo=True) # Explicitly use sudo=True

        if not scanner.all_hosts():
            return json.dumps({target: {"error": "Host seems down or unresponsive to OS detection probes."}})

        for host in scanner.all_hosts():
            host_result = {}
            if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                os_matches = []
                for match in scanner[host]['osmatch']:
                    os_matches.append({
                        "name": match.get("name", "Unknown OS"),
                        "accuracy": match.get("accuracy", "N/A"),
                        # Include OS class details if available and useful
                        # "osclass": [oc.get("type", "") + "/" + oc.get("vendor", "") + "/" + oc.get("osfamily", "") + "/" + oc.get("osgen", "") for oc in match.get("osclass", [])]
                    })
                host_result = {"os_matches": sorted(os_matches, key=lambda x: int(x["accuracy"]), reverse=True)} # Sort by accuracy
            else:
                error_msg = "No OS matches found."
                scaninfo = scanner.scaninfo()
                nmap_errors = scaninfo.get('error', [])
                if any('requires root privileges' in msg.lower() for msg in nmap_errors):
                    error_msg += " OS detection requires root/administrator privileges. Ensure the script is run with sufficient permissions."
                elif scanner[host].state() != 'up':
                     error_msg += f" Host state is '{scanner[host].state()}', cannot perform OS scan."
                elif 'tcpwrapped' in str(scanner[host].get('status', {}).get('reason', '')):
                    error_msg += " Port states suggest firewall interference (tcpwrapped)."

                host_result = {"os_matches": [], "note": error_msg}
            results_dict[host] = host_result

        return _format_nmap_results(results_dict)

    except nmap.PortScannerError as e:
         err_str = str(e)
         msg = "Nmap OS detection failed."
         if "requires root privileges" in err_str.lower():
             msg += " This scan requires root/administrator privileges. Run the script with sudo or equivalent."
         elif "mass_dns" in err_str:
             msg += f" Target resolution error: {err_str}"
         else:
             msg += f" Error: {err_str}. Check target and Nmap setup."
         return json.dumps({"error": msg})

    except Exception as e:
        print(f"Unexpected error during Nmap OS detection: {e}\n{traceback.format_exc()}", file=sys.stderr)
        return json.dumps({"error": f"An unexpected error occurred during OS detection ({type(e).__name__})."})

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Smol Agent Initialization ---
try:
    print(f"Initializing Smol Agent with Model: {MODEL_ID_TO_USE}, Base: {API_BASE_TO_USE or 'Default OpenAI'}")
    model_config = {
        "api_key": API_KEY_TO_USE,
        "model_id": MODEL_ID_TO_USE,
    }
    if API_BASE_TO_USE:
        model_config["api_base"] = API_BASE_TO_USE

    model = OpenAIServerModel(**model_config)

    available_tools = [
        fibonacci,
        DuckDuckGoSearchTool(),
        discover_hosts,
        open_file,
        detect_os,
        sqlmap_scan,
        scan_ports,
        send_msg_tg,
        read_messages_from_tg
    ]

    agent = CodeAgent(
        model=model,
        tools=available_tools,
        max_steps=5
    )
    print("Smol Agent initialized successfully.")
except Exception as e:
    print(f"FATAL: Failed to initialize Smol Agent: {e}\n{traceback.format_exc()}", file=sys.stderr)
    sys.exit(1)

# --- Flask Routes ---

@app.route('/')
def index():
    """Serves the main HTML page, passing initial chat list and permissions."""
    role = get_user_role(request)
    permissions = {
        "can_create_chat": role in ROLES_CAN_CREATE,
        "can_read_chat": role in ROLES_CAN_READ,
        "role": role
    }
    chats = list_chat_files() if permissions["can_read_chat"] else []
    print(f"Serving index page. Role: {role}, Permissions: {permissions}, Chats found: {len(chats)}")
    return render_template('index.html', chats=chats, permissions=permissions)

@app.route('/chat/<chat_id>', methods=['GET'])
def get_chat_content(chat_id):
    """Gets the content (messages) of a specific chat."""
    role = get_user_role(request)
    if role not in ROLES_CAN_READ:
        print(f"Permission denied for role '{role}' to read chat '{chat_id}'.")
        abort(403, description="Permission Denied: You cannot read chats.")

    print(f"Attempting to load chat: {chat_id}")
    chat_data = load_chat(chat_id)
    if chat_data:
        return jsonify(chat_data)
    else:
        print(f"Chat not found or error loading: {chat_id}")
        abort(404, description="Chat not found or error loading.")

@app.route('/chat/new', methods=['POST'])
def create_new_chat():
    """Creates a new empty chat file and returns its ID."""
    role = get_user_role(request)
    if role not in ROLES_CAN_CREATE:
         print(f"Permission denied for role '{role}' to create new chat.")
         abort(403, description="Permission Denied: You cannot create new chats.")

    new_chat_id = str(uuid.uuid4())
    new_chat_data = {
        "id": new_chat_id,
        "created_at": datetime.now().isoformat(),
        "messages": []
    }
    print(f"Creating new chat with ID: {new_chat_id}")
    if save_chat(new_chat_id, new_chat_data):
        return jsonify({"id": new_chat_id, "timestamp": new_chat_data["created_at"]})
    else:
        print(f"Failed to save new chat file for ID: {new_chat_id}")
        abort(500, description="Failed to create new chat file.")

# --- MODIFIED add_message_to_chat Function ---
@app.route('/chat/<chat_id>/message', methods=['POST'])
def add_message_to_chat(chat_id):
    """Adds a user message, runs agent with history, adds agent response, saves chat.
       Prints execution log to console after LOG_AFTER_N_STEPS iterations."""
    role = get_user_role(request)
    if role not in ROLES_CAN_CREATE:
        print(f"Permission denied for role '{role}' to add message to chat '{chat_id}'.")
        abort(403, description="Permission Denied: You cannot send messages.")

    data = request.json
    user_message_content = data.get('message')
    if not user_message_content or not isinstance(user_message_content, str) or not user_message_content.strip():
        return jsonify({"error": "Invalid or empty message provided."}), 400

    user_message_content = user_message_content.strip()
    print(f"Adding message to chat {chat_id}. User msg: '{user_message_content[:100]}...'")

    # 1. Load existing chat data
    chat_data = load_chat(chat_id)
    if not chat_data:
        print(f"Chat not found when trying to add message: {chat_id}")
        abort(404, description=f"Chat session {chat_id} not found.")

    # Create the user message object
    user_message = {"sender": "user", "content": user_message_content}

    # 2. Prepare history and prompt for the agent
    # (History preparation code remains the same)
    history = chat_data.get('messages', [])
    MAX_HISTORY_TURNS = 4
    condensed_history = []
    for msg in reversed(history):
        if isinstance(msg, dict) and "sender" in msg and "content" in msg:
            sender = msg['sender'].capitalize()
            content = str(msg['content'])
            max_hist_msg_len = 500
            if len(content) > max_hist_msg_len:
                content = content[:max_hist_msg_len] + "..."
            condensed_history.append(f"{sender}: {content}")
        if len(condensed_history) >= MAX_HISTORY_TURNS * 2:
            break
    condensed_history.reverse()
    history_prefix = "\n".join(condensed_history)

    prompt_instructions = (
        "You are a helpful security analysis assistant. "
        "When you use tools, analyze their output (which will be provided as text or JSON strings). "
        "Do not just repeat the raw tool output. Instead, interpret the results, summarize key findings, "
        "and answer the user's request based on that analysis. "
        "If a tool returns an error, report the error clearly. "
        "If a tool returns complex data (like JSON), extract the most important information."
    )
    prompt_for_agent = f"{prompt_instructions}\n\n--- Conversation History ---\n{history_prefix}\n\n--- Current User Request ---\nUser: {user_message_content}\n\n--- Your Response ---\nAgent:"

    # 3. Run the agent and handle logging trigger
    agent_response_content = ""
    agent_error = None
    start_time = time.time()

    # --- Log Tracking Logic ---
    reasoning_step_count = 5
    reasoning_log = [] # Store formatted steps for potential output
    full_agent_response_chunks = [] # Collect raw chunks for the final response
    log_printed = False # Flag to ensure log is printed only once

    try:
        print(f">>> Starting agent run for chat {chat_id}. Prompt length (approx): {len(prompt_for_agent)} chars. Log after: {LOG_AFTER_N_STEPS} steps.")
        generator = agent.run(prompt_for_agent)

        print(">>> Agent generator created. Collecting response chunks and monitoring steps...")
        for chunk in generator:
            reasoning_step_count += 1

            # Add to raw chunks list
            if isinstance(chunk, (dict, list)):
                 try:
                     # Use compact JSON for raw chunks list, pretty JSON for log
                     chunk_str_log = json.dumps(chunk, indent=2)
                     full_agent_response_chunks.append(json.dumps(chunk))
                 except TypeError:
                     chunk_str_log = str(chunk)
                     full_agent_response_chunks.append(chunk_str_log)
            else:
                 chunk_str_log = str(chunk)
                 full_agent_response_chunks.append(chunk_str_log)

            # Format log entry (similar heuristic as before)
            log_entry = f"Step {reasoning_step_count}: "
            chunk_preview = (chunk_str_log[:150] + '...') if len(chunk_str_log) > 150 else chunk_str_log
            if isinstance(chunk, dict) and ('tool_call' in chunk or 'tool_name' in chunk):
                log_entry += f"[Tool Call] {chunk_preview}"
            elif isinstance(chunk_str_log, str) and chunk_str_log.startswith("Error:"):
                log_entry += f"[Tool Error] {chunk_preview}"
            elif isinstance(chunk_str_log, str) and chunk_str_log.strip().startswith("{") and chunk_str_log.strip().endswith("}"):
                 log_entry += f"[Tool Result/JSON] {chunk_preview}"
            else:
                 log_entry += f"[Content/Thought] {chunk_preview}"
            reasoning_log.append(log_entry)

            # --- Check if it's time to print the log ---
            if reasoning_step_count == LOG_AFTER_N_STEPS and not log_printed:
                print(f"\n--- Agent Execution Log (First {LOG_AFTER_N_STEPS} Steps) for Chat {chat_id} ---")
                for entry in reasoning_log:
                    print(entry)
                print(f"--- End Agent Execution Log (Agent is continuing execution...) ---\n")
                log_printed = True # Ensure we only print once

            # --- NO break here - agent continues running ---

        end_time = time.time()
        duration = end_time - start_time

        # --- Format Final Response (Always use all chunks) ---
        agent_response_content = "".join(full_agent_response_chunks)
        agent_response_content = agent_response_content.strip()
        # Basic post-processing
        if agent_response_content.lower().startswith("agent:"):
            agent_response_content = agent_response_content[len("agent:"):].strip()

        print(f">>> Agent run finished. Duration: {duration:.2f} seconds. Total Steps: {reasoning_step_count}. Response length: {len(agent_response_content)} chars.")
        if reasoning_step_count >= LOG_AFTER_N_STEPS:
             print(f"    (Execution log for first {LOG_AFTER_N_STEPS} steps was printed to console during run)")

    except Exception as e:
        end_time = time.time()
        error_type = type(e).__name__
        print(f"!!! AGENT ERROR during execution for chat {chat_id} ({error_type}): {e}\n{traceback.format_exc()}", file=sys.stderr)
        agent_error = f"An error occurred during agent processing: {error_type} - {str(e)}"
        agent_response_content = f"Sorry, I encountered an error ({error_type}) and couldn't complete your request. Please check the application logs for details."
        # Also print the partial log collected so far if an error occurs after the log point
        if reasoning_step_count >= LOG_AFTER_N_STEPS and log_printed:
             print(f"--- Partial Log Before Error (Already Printed Earlier) ---")
        elif reasoning_log: # Print log if error occurred before the print point
             print(f"--- Agent Execution Log (Up to Error) for Chat {chat_id} ---")
             for entry in reasoning_log:
                 print(entry)
             print(f"--- End Agent Execution Log (Error Occurred) ---")


    # Create the agent message object
    agent_message = {"sender": "agent", "content": agent_response_content}

    # 4. Append messages to chat data
    if not isinstance(chat_data.get("messages"), list):
        print(f"Warning: Chat {chat_id} 'messages' field is not a list. Reinitializing.")
        chat_data["messages"] = []

    chat_data["messages"].append(user_message)
    chat_data["messages"].append(agent_message)

    # 5. Save updated chat data
    if not save_chat(chat_id, chat_data):
        print(f"Error saving chat {chat_id} after agent run.")
        return jsonify({
             "user_message": user_message,
             "agent_message": agent_message,
             "error": agent_error,
             "warning": "Failed to save updated chat state. Your message was processed, but the history may be inconsistent."
         }), 500

    print(f"Successfully added messages and saved chat {chat_id}")
    # 6. Return the new messages (the full agent response)
    return jsonify({
        "user_message": user_message,
        "agent_message": agent_message,
        "error": agent_error
        })


# --- Main execution block ---
if __name__ == '__main__':
    ensure_chat_dir()
    print("-----------------------------------------------------")
    print("Starting Flask development server...")
    print(f"Chat directory: {os.path.abspath(CHAT_DIR)}")
    print(f"Roles: Admin={ADMIN_ROLE}, Analyst={ANALYST_ROLE}, Guest={GUEST_ROLE}")
    print(f"API Key Loaded: {'Yes' if API_KEY_TO_USE else 'NO - Check .env!'}")
    print(f"Model ID: {MODEL_ID_TO_USE}")
    print(f"Agent Execution Log will be printed after {LOG_AFTER_N_STEPS} steps.") # Log the setting
    print("-----------------------------------------------------")
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=True)