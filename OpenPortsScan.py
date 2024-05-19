import nmap

def scan_detailed(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024', '-sV')
    print(f"Scan results for {ip}:")
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            service = nm[ip][proto][port]['name']
            state = nm[ip][proto][port]['state']
            print(f"Port: {port}, State: {state}, Service: {service}")

# Example usage for a specific IP
scan_detailed('192.168.0.10')
