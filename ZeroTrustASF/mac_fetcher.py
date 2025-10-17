import sys
import argparse
import socket # To validate IP address format

try:
    from getmac import get_mac_address
except ImportError:
    print("\nError: The 'getmac' library is not installed.")
    print("Please install it using: pip install getmac")
    sys.exit(1) # Exit if the dependency is missing

def is_valid_ip(ip_str):
    """Checks if the provided string is a valid IPv4 address."""
    try:
        socket.inet_aton(ip_str)
        return True
    except socket.error:
        return False

def fetch_mac_for_ip(ip_address):
    """
    Fetches the MAC address for a given IP address on the local network.

    Args:
        ip_address (str): The target IP address.

    Returns:
        str: The MAC address if found, otherwise None.
    """
    print(f"\nAttempting to resolve MAC address for {ip_address}...")

    # Validate the IP address format first
    if not is_valid_ip(ip_address):
        print(f"Error: '{ip_address}' is not a valid IPv4 address format.")
        return None

    try:
        # Use getmac to find the MAC address associated with the IP
        # This typically works by checking the system's ARP cache.
        # It might require the target host to be recently communicated with
        # (e.g., via ping) for the entry to be in the cache on some systems.
        mac = get_mac_address(ip=ip_address)
        return mac
    except Exception as e:
        # Catch potential exceptions from getmac (though it often returns None on failure)
        print(f"An unexpected error occurred: {e}")
        return None

# --- Main execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch the MAC address for a given IP address on the local network.")
    parser.add_argument("ip_address", help="The target IP address (e.g., 192.168.1.1)")

    args = parser.parse_args()
    target_ip = args.ip_address

    mac_address = fetch_mac_for_ip(target_ip)

    if mac_address:
        print(f"\nSuccess! MAC Address found: {mac_address.upper()}")
    else:
        print(f"\nFailed to retrieve MAC address for {target_ip}.")
        print("Possible reasons:")
        print("  - The host is down or unreachable.")
        print("  - The host is on a different network segment (not local).")
        print("  - The host is blocking ARP requests (firewall).")
        print("  - The entry is not present in the system's ARP cache.")
        print("  - You might need elevated privileges (run as administrator/root) on some OSes.")
        # You could try pinging the IP first (e.g., using os.system or subprocess)
        # print("\nTry pinging the IP address first to populate the ARP cache.")