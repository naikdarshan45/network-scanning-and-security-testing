#!/usr/bin/env python3
"""
Network Port Scanner
Scans common ports on target hosts to identify open services
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse

# Common ports to scan
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt'
}

class PortScanner:
    def __init__(self, target, timeout=1):
        self.target = target
        self.timeout = timeout
        self.open_ports = []
        
    def scan_port(self, port):
        """Scan a single port on the target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                return (port, service, True)
            return (port, None, False)
        except socket.gaierror:
            print(f"Error: Could not resolve hostname {self.target}")
            sys.exit(1)
        except socket.error:
            return (port, None, False)
    
    def scan_ports(self, ports=None, max_workers=50):
        """Scan multiple ports using threading"""
        if ports is None:
            ports = COMMON_PORTS.keys()
        
        print(f"\n[*] Starting scan on {self.target}")
        print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port, service, is_open = future.result()
                if is_open:
                    self.open_ports.append((port, service))
                    print(f"[+] Port {port:5d} - {service:15s} - OPEN")
        
        print("-" * 60)
        print(f"[*] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Found {len(self.open_ports)} open ports")
        
        return self.open_ports
    
    def save_results(self, filename='scan_results.txt'):
        """Save scan results to a file"""
        with open(filename, 'w') as f:
            f.write(f"Port Scan Results for {self.target}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            if self.open_ports:
                f.write("Open Ports:\n")
                for port, service in self.open_ports:
                    f.write(f"  Port {port}: {service}\n")
            else:
                f.write("No open ports found.\n")
        
        print(f"\n[*] Results saved to {filename}")


def main():
    parser = argparse.ArgumentParser(description='Network Port Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80,443,8080 or 1-1000)', default=None)
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Connection timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file for results', default='scan_results.txt')
    
    args = parser.parse_args()
    
    # Parse port range
    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = range(start, end + 1)
        else:
            ports = [int(p) for p in args.ports.split(',')]
    else:
        ports = None
    
    # Create scanner and run
    scanner = PortScanner(args.target, timeout=args.timeout)
    scanner.scan_ports(ports)
    scanner.save_results(args.output)


if __name__ == '__main__':
    main()
