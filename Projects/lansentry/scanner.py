# ============================================================
# scanner.py — Network scanning engine for LanSentry
# 
# This file handles:
#   1. Scanning the network for devices
#   2. Caching results for instant page loads
#   3. Running scans in the background every 30 seconds
#   4. Saving results to the database
#   5. Blocking/unblocking devices via Windows Firewall
#   6. Alert system for unknown devices
# ============================================================

import nmap          # Controls Nmap to scan the network
import socket        # Gets our IP address and resolves hostnames
import subprocess    # Runs Windows commands (ipconfig, netsh)
import threading     # Runs scanner in background parallel to web server
import time          # Controls timing (30 second intervals)

# Import our database functions
# We only import save_scan here — database.py handles the rest
from database import save_scan


# ============================================================
# SHARED STATE
# These variables are shared across the whole application
# 'set()' is like a list but doesn't allow duplicates
# ============================================================

known_devices  = set()   # IPs we've seen before (don't alert on these)
alert_log      = []      # List of alert dictionaries
blocked_devices = set()  # IPs currently blocked by firewall

# Cache stores the last scan results so pages load instantly
# Instead of waiting for a new scan, pages just read this list
cached_devices = []

# Timestamp of when the last scan finished
# time.time() returns seconds since Jan 1 1970 (Unix timestamp)
last_scan_time = 0

# Lock prevents two threads from writing to cache at the same time
# Like a "do not disturb" sign — only one thread writes at a time
scan_lock = threading.Lock()


# ============================================================
# HELPER FUNCTIONS
# Small utility functions used by the main scanner
# ============================================================

def get_local_ip():
    """
    Gets YOUR computer's IP address on the network.
    
    How it works:
    1. socket.gethostname() → gets your computer's name (e.g. 'MADHAV-PC')
    2. socket.gethostbyname() → converts name to IP (e.g. '192.168.43.105')
    
    Returns:
        str: Your IP address (e.g. '192.168.43.105')
    """
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip


def get_network_range():
    """
    Builds the IP range to scan.
    
    Example:
        Your IP:      192.168.43.105
        Network range: 192.168.43.0/24
        Meaning:       Scan all 255 addresses from .1 to .255
    
    How it works:
        '192.168.43.105'.rsplit('.', 1) → ['192.168.43', '105']
        [0] → '192.168.43'
        + '.0/24' → '192.168.43.0/24'
    
    Returns:
        str: Network range (e.g. '192.168.43.0/24')
    """
    local_ip = get_local_ip()
    network_range = local_ip.rsplit('.', 1)[0] + '.0/24'
    return network_range


def get_hostname(ip):
    """
    Tries to find the name of a device from its IP address.
    Uses Python's built-in reverse DNS lookup.
    
    Parameters:
        ip (str): IP address to look up
    
    Returns:
        str: Device name, or 'Unknown' if not found
    """
    try:
        # gethostbyaddr() does a reverse lookup: IP → name
        # It returns a tuple: (hostname, alias_list, ip_list)
        # [0] gets just the hostname
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        # Most devices don't share their name
        # so this will fail often — that's completely normal
        return "Unknown"


def get_gateway_ip():
    """
    Finds your router/hotspot's IP address (the 'gateway').
    
    The gateway is the device that connects you to the internet.
    We NEVER want to block this — it would cut your internet!
    
    We run 'ipconfig' (Windows command) and read its output.
    
    Problem: Sometimes Windows shows TWO gateway addresses:
        Default Gateway: fe80::a046%17   ← IPv6 (we skip this)
                         10.220.174.185  ← IPv4 (we want this!)
    
    Our solution: Check the same line AND the next line.
    
    Returns:
        str: Gateway IP address, or None if not found
    """
    try:
        # Run 'ipconfig' command — same as typing it in CMD
        # capture_output=True → save the output text
        # text=True → give us text, not raw bytes
        result = subprocess.run(
            ['ipconfig'],
            capture_output=True,
            text=True
        )
        
        # Split output into lines so we can read one by one
        lines = result.stdout.split('\n')
        
        # enumerate() gives us both the index (i) and value (line)
        # Example: [(0, 'line1'), (1, 'line2'), ...]
        for i, line in enumerate(lines):
            # strip() removes spaces from start and end of line
            line_stripped = line.strip()
            
            # Look for the line containing "Default Gateway"
            if 'Default Gateway' in line_stripped:
                
                # ── Check SAME line for IPv4 ──
                # Split at colon: "Default Gateway . . . : 10.0.0.1"
                # → ['Default Gateway . . . ', ' 10.0.0.1']
                parts = line_stripped.split(':')
                if len(parts) >= 2:
                    # parts[-1] gets the LAST part (after final colon)
                    gateway = parts[-1].strip()
                    
                    # IPv4 starts with a number and contains dots
                    # IPv6 starts with letters (like 'fe80...')
                    if gateway and gateway[0].isdigit() and '.' in gateway:
                        print(f"✅ Gateway detected (same line): {gateway}")
                        return gateway
                
                # ── Check NEXT line for IPv4 ──
                # This handles the two-line gateway format
                if i + 1 < len(lines):  # Make sure next line exists
                    next_line = lines[i + 1].strip()
                    if next_line and next_line[0].isdigit() and '.' in next_line:
                        print(f"✅ Gateway detected (next line): {next_line}")
                        return next_line
        
        print("⚠️ Could not auto-detect gateway")
        return None
    
    except Exception as e:
        print(f"Gateway detection error: {e}")
        return None


# ============================================================
# CORE SCAN FUNCTION
# Does the actual network scanning and caches results
# Called by the background thread every 30 seconds
# ============================================================

def run_scan():
    """
    Scans the entire network and:
    1. Finds all connected devices
    2. Saves results to cached_devices (for instant page loads)
    3. Saves results to MySQL database (for history)
    4. Checks for unknown devices (alerts)
    
    This runs in a background thread so the web server
    stays fast and responsive while scanning happens.
    """
    
    # 'global' tells Python we're modifying the module-level variables
    # Not creating new local variables
    global cached_devices, last_scan_time
    
    # Get network info before starting scan
    network_range = get_network_range()
    local_ip      = get_local_ip()
    gateway_ip    = get_gateway_ip()
    
    print(f"\n🔍 Background scan starting...")
    print(f"   Your IP : {local_ip}")
    print(f"   Gateway : {gateway_ip or 'Not detected'}")
    print(f"   Range   : {network_range}\n")
    
    try:
        # Create the Nmap scanner object
        nm = nmap.PortScanner()
        
        # Run the network scan
        # -sn            → ping scan only (don't scan ports — much faster!)
        # --host-timeout → skip devices that don't respond within 10 seconds
        nm.scan(hosts=network_range, arguments='-sn --host-timeout 10s')
        
        # Empty list — we'll fill it with device dictionaries
        devices = []
        
        # nm.all_hosts() returns list of all IPs that responded
        for host in nm.all_hosts():
            
            # Try to get MAC address
            # .get('mac', 'N/A') → return 'N/A' if mac not found
            mac = nm[host]['addresses'].get('mac', 'N/A')
            
            # Try to get device name from Nmap first
            hostname = nm[host].hostname()
            
            # If Nmap couldn't find it, try our own lookup
            if not hostname:
                hostname = get_hostname(host)
            
            # Give special labels to important devices
            if host == local_ip:
                # This is YOUR computer
                hostname = socket.gethostname() + " (You)"
            
            elif gateway_ip and host == gateway_ip:
                # This is your hotspot or router
                hostname = "My Hotspot 📱 (Gateway)"
            
            # Build a dictionary with all device info
            # This is one row of data for this device
            device = {
                'ip'        : host,
                'status'    : nm[host].state(),   # 'up' or 'down'
                'hostname'  : hostname,
                'mac'       : mac,
                'blocked'   : host in blocked_devices,
                                    # True if user blocked this device
                'is_gateway': gateway_ip is not None and host == gateway_ip,
                                    # True if this is the router/hotspot
                'is_me'     : host == local_ip
                                    # True if this is your device
            }
            
            # Add this device to our list
            devices.append(device)
        
        # ── Save to cache ──
        # 'with scan_lock' → lock the cache while writing
        # Prevents another thread from reading half-written data
        with scan_lock:
            cached_devices = devices           # Update the cache
            last_scan_time = time.time()       # Record scan time
        
        print(f"✅ Scan complete — {len(devices)} devices found")
        
        # ── Save to database ──
        # This saves the scan permanently so we can view history later
        save_scan(devices)
        
        # ── Check for new unknown devices ──
        check_for_alerts(devices)
    
    except Exception as e:
        # If anything goes wrong, print error but don't crash
        # The background thread must keep running!
        print(f"❌ Scan error: {e}")


# ============================================================
# PUBLIC FUNCTION — called by Flask routes
# Returns device data instantly from cache
# ============================================================

def scan_network():
    """
    Returns the cached device list instantly.
    
    This is what Flask calls when a page needs device data.
    Instead of running a new scan (slow!), it reads cached results.
    
    If cache is empty (very first startup), waits for first scan.
    
    Returns:
        list: List of device dictionaries
    """
    
    # Check if cache has data
    with scan_lock:
        if cached_devices:
            # Cache has data — return it instantly ⚡
            return cached_devices
    
    # Cache is empty — only happens on very first startup
    # Wait for one scan to complete before returning
    print("⏳ First scan in progress, please wait...")
    run_scan()
    return cached_devices


# ============================================================
# BACKGROUND SCANNER THREAD
# Runs scans automatically every 30 seconds forever
# ============================================================

def background_scanner():
    """
    Infinite loop that runs in the background:
    1. Scan immediately on startup
    2. Wait 30 seconds
    3. Scan again
    4. Repeat forever
    
    This runs as a 'daemon thread' — it automatically stops
    when the main Flask app stops.
    """
    print("🚀 Background scanner started!")
    
    # Run first scan immediately so cache has data right away
    run_scan()
    
    # Keep scanning forever with 30 second gaps
    while True:
        time.sleep(30)   # Wait 30 seconds
        run_scan()       # Scan the network again


def start_background_scanner():
    """
    Creates and starts the background scanner thread.
    Called once when Flask app launches.
    
    threading.Thread() creates a new thread
    target=background_scanner → function to run in the thread
    daemon=True → thread stops automatically when app stops
    """
    thread = threading.Thread(
        target=background_scanner,
        daemon=True      # Auto-stop when main app stops
    )
    thread.start()
    print("✅ Background scanner thread started")


# ============================================================
# ALERT SYSTEM
# Detects unknown/new devices joining the network
# ============================================================

def check_for_alerts(devices):
    """
    Checks if any device in the scan is new/unknown.
    If yes, adds it to the alert log.
    
    Never alerts on:
    - Your own device (is_me = True)
    - Your gateway/hotspot (is_gateway = True)
    
    Parameters:
        devices (list): List of device dictionaries from scan
    """
    global known_devices, alert_log
    
    my_ip      = get_local_ip()
    gateway_ip = get_gateway_ip()
    
    for device in devices:
        ip = device['ip']
        
        # Skip your own device and gateway — never flag these
        if ip == my_ip or (gateway_ip and ip == gateway_ip):
            known_devices.add(ip)   # Mark as known
            continue                 # Skip to next device
            # 'continue' means: skip rest of loop body, go to next item
        
        # If we haven't seen this device before
        if ip not in known_devices:
            
            # Only alert after first scan
            # First scan just 'learns' the network — doesn't alert
            if len(known_devices) > 0:
                alert = {
                    'ip'      : ip,
                    'hostname': device['hostname'],
                    'message' : f"New unknown device joined the network: {ip}"
                }
                # Append adds item to end of list
                alert_log.append(alert)
                print(f"🚨 ALERT: New device detected — {ip}")
            
            # Add to known devices so we don't alert again
            known_devices.add(ip)


def get_alerts():
    """Returns the complete list of all alerts."""
    return alert_log


# ============================================================
# BLOCK / UNBLOCK SYSTEM
# Uses Windows Firewall (netsh) to block/unblock devices
# ============================================================

def block_device(ip):
    """
    Blocks a device by adding a Windows Firewall rule.
    
    The firewall rule tells Windows to DROP all incoming
    traffic from that IP address — effectively cutting
    it off from communicating with your computer.
    
    Also immediately updates the cache so the UI shows
    'Blocked' status without waiting for the next scan.
    
    Parameters:
        ip (str): IP address to block
    
    Returns:
        dict: {'success': True/False, 'message': '...'}
    """
    gateway_ip = get_gateway_ip()
    my_ip      = get_local_ip()
    
    # ── Safety checks ──
    # Never allow blocking protected devices
    if ip == my_ip:
        return {
            'success': False,
            'message': 'Cannot block your own device!'
        }
    
    if gateway_ip and ip == gateway_ip:
        return {
            'success': False,
            'message': 'Cannot block your gateway — you would lose internet!'
        }
    
    try:
        # Build the Windows netsh command
        # This is the same as typing in CMD:
        # netsh advfirewall firewall add rule name=LANSENTRY_BLOCK_x.x.x.x
        #        dir=in action=block remoteip=x.x.x.x
        command = [
            'netsh',                         # Windows network tool
            'advfirewall',                   # Advanced firewall module
            'firewall',                      # Firewall subcommand
            'add', 'rule',                   # Add a new rule
            f'name=LANSENTRY_BLOCK_{ip}',    # Rule name (includes IP)
            'dir=in',                        # Block INCOMING traffic
            'action=block',                  # The action = block
            f'remoteip={ip}'                 # Target IP to block
        ]
        
        # subprocess.run() executes the command
        # capture_output=True → capture what the command prints
        # text=True → return output as readable text
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            # returncode 0 = command succeeded ✅
            
            # Add to our blocked set
            blocked_devices.add(ip)
            
            # ── Update cache immediately ──
            # So UI shows 'Blocked' right away without waiting for next scan
            with scan_lock:
                for device in cached_devices:
                    if device['ip'] == ip:
                        device['blocked'] = True
                        # Directly update the device in cache
            
            print(f"🚫 Blocked: {ip}")
            return {'success': True, 'message': f'{ip} has been blocked'}
        
        else:
            # returncode non-zero = command failed ❌
            return {
                'success': False,
                'message': f'Firewall error: {result.stderr}'
            }
    
    except Exception as e:
        return {'success': False, 'message': str(e)}


def unblock_device(ip):
    """
    Unblocks a device by removing its Windows Firewall rule.
    Also immediately updates the cache.
    
    Parameters:
        ip (str): IP address to unblock
    
    Returns:
        dict: {'success': True/False, 'message': '...'}
    """
    try:
        # Delete the firewall rule we created earlier
        # Same as: netsh advfirewall firewall delete rule name=LANSENTRY_BLOCK_x.x.x.x
        command = [
            'netsh', 'advfirewall', 'firewall',
            'delete', 'rule',
            f'name=LANSENTRY_BLOCK_{ip}'
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            # discard() removes from set — won't crash if IP isn't there
            # (unlike remove() which crashes if item is missing)
            blocked_devices.discard(ip)
            
            # ── Update cache immediately ──
            with scan_lock:
                for device in cached_devices:
                    if device['ip'] == ip:
                        device['blocked'] = False
            
            print(f"✅ Unblocked: {ip}")
            return {'success': True, 'message': f'{ip} has been unblocked'}
        
        else:
            return {
                'success': False,
                'message': f'Error: {result.stderr}'
            }
    
    except Exception as e:
        return {'success': False, 'message': str(e)}


def get_blocked_devices():
    """Returns list of all currently blocked IP addresses."""
    return list(blocked_devices)
    # list() converts set to list (JSON can't serialize sets)