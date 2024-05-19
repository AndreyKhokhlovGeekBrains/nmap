import nmap

def discover_devices(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()}) - {nm[host].state()}")

# Call the function with the desired IP range
discover_devices('192.168.0.0/24')


# The ip_range parameter in the script specifies the range of IP addresses to scan within a subnet. 
# In this case, 192.168.0.0/24 covers the entire range of addresses from 192.168.0.1 to 192.168.0.254. This comprehensive scan ensures that all devices in the subnet are discovered and reported.
# A /24 subnet mask corresponds to 255.255.255.0. This means the first 24 bits of the IP address are fixed, and the last 8 bits are available for host addresses.
