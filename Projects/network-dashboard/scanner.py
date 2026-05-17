import nmap
import socket

# List of known trusted devices (their IPs)
# We'll update this automatically as devices are seen
known_devices = set()
alert_log = []

 #Gets your own IP Address
def get_local_ip():
    hostname = socket.gethostname()#Gets your computer's name
    local_ip = socket.gethostbyname(hostname)#Converts your computer's name into ip address
    return local_ip

def get_network_range():
    local_ip = get_local_ip()
    network_range = local_ip.rsplit('.', 1)[0] + '.0/24'
    return network_range
    '''It converts 192.168.1.5 into 192.168.1.0/24 
    which means "scan every address from 192.168.1.1 to 192.168.1.255" 
    — your entire network!'''

def get_hostname(ip):
    # Try to get hostname using Python's socket
    # This works better than Nmap on WiFi
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "Unknown"

#Scanning Network
def scan_network():
    network_range = get_network_range()
    local_ip = get_local_ip()
    print (f"Your IP Address is: {local_ip}")
    print(f"Scanning Range: {network_range}")
    print("Please wait...\n")

    nm = nmap.PortScanner() #Creates an Nmap scanner object
    nm.scan(hosts=network_range, arguments='-sn -PR')
    '''Runs the actual scan on your network range
    → arguments='-sn' tells Nmap to just ping devices 
    (check if they're online) without doing anything heavy'''


    # nm.all_hosts() gives us a list of all IP addresses found
    devices = [] #Empty list to store devices
    for host in nm.all_hosts(): #Loop throug every device found
        # Try to get MAC from Nmap first
        mac = nm[host]['addresses'].get('mac', 'N/A')# MAC address (if available, otherwise "N/A")

        # Try to get hostname from Nmap first
        # If not found, use our own socket method
        hostname = nm[host].hostname()
        if not hostname:
            hostname = get_hostname(host)

        # Label your own device
        if host == local_ip:
            hostname = socket.gethostname() + " (You)"
        device = {
            "ip" : host, # the IP address
            "status" : nm[host].state(), # is it "up" or "down"
            "hostname" : hostname,
            "mac" : mac 
        }
        devices.append(device) # Add device to our devices list
    
    return devices #Returns the full list of Devices

def display_devices(devices):
    print(f"{'IP Address':<20} {'Hostname':<30} {'MAC Address':<20} {'Status'}")
    # <20 means "make this text exactly 20 characters wide, left-aligned" 
    print("-" * 80)
    
    for device in devices:
        print(f"{device['ip']:<20} {device['hostname']:<30} {device['mac']:<20} {device['status']}")

'''if __name__ == "__main__" is a special line in Python. 
It means "only run this code if you directly run this file". 
When we import this scanner into our web app,
 we don't want it to automatically start scanning — this line prevents that.'''

def check_for_alerts(devices):
    global known_devices
    global alert_log

    new_alerts = []

    for device in devices:
        ip = device['ip']

        # If we've never seen this device before — it's an alert!
        if ip not in known_devices:
            if len(known_devices) > 0:  # Don't alert on first scan
                alert = {
                    'ip': ip,
                    'hostname': device['hostname'],
                    'message': f"Unknown device detected: {ip}"
                }
                new_alerts.append(alert)
                alert_log.append(alert)
                print(f"🚨 ALERT: New device detected — {ip}")

            # Add to known devices
            known_devices.add(ip)

    return new_alerts

def get_alerts():
    return alert_log

if __name__ == "__main__":
    devices = scan_network()
    print(f"\n Found {len(devices)} devices!\n")
    display_devices(devices)
    

'''On WiFi, MAC addresses being N/A is not a bug in your code. It's a hardware/OS limitation. 
Even professional tools like Wireshark struggle with this on WiFi.

When you present this project to employers or clients just say:
"MAC addresses are available on wired networks. 
On WiFi, Windows security policies restrict ARP scanning — this is standard behaviour across all network tools."'''