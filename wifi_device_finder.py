import nmap
import socket

def get_ip():
    """
    Returns the IP address of the local machine.
    """
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except socket.error as err:
        print(f"Error obtaining IP address: {err}")
        ip_address = None
    return ip_address

def scan_network(ip_range):
    """
    Scans the network for connected devices and retrieves their names using nmap.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-T4 -O')
    
    devices = []
    for host in nm.all_hosts():
        device_info = {
            'ip': host,
            'hostname': nm[host].hostname() if 'hostname' in nm[host] else 'N/A',
            'os': nm[host]['osclass'][0]['osfamily'] if 'osclass' in nm[host] else 'N/A'
        }
        devices.append(device_info)
    
    return devices

def display_results(devices):
    """
    Displays the list of devices found on the network.
    """
    print("IP Address\t\tHostname\t\tOS")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['hostname']}\t\t{device['os']}")

if __name__ == "__main__":
    local_ip = get_ip()
    if local_ip:
        # Assumes the local network uses a subnet mask of 255.255.255.0
        ip_range = f"{local_ip.rsplit('.', 1)[0]}.0/24"
        devices = scan_network(ip_range)
        display_results(devices)
    else:
        print("Unable to obtain local IP address.")
