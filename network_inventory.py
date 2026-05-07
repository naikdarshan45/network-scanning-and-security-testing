#!/usr/bin/env python3
"""
Network Inventory & Security Report Generator
Automates network discovery, inventory management, and security reporting
"""

import socket
import ipaddress
import subprocess
import platform
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import json
import csv

class NetworkInventory:
    def __init__(self, network_range):
        self.network_range = network_range
        self.active_hosts = []
        self.host_details = {}
        
    def ping_host(self, ip):
        """Ping a single host to check if it's alive"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', '1', str(ip)]
        
        try:
            result = subprocess.run(
                command, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
    
    def discover_hosts(self, max_workers=50):
        """Discover active hosts in the network range"""
        print(f"[*] Discovering hosts in {self.network_range}")
        print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            network = ipaddress.ip_network(self.network_range, strict=False)
            hosts = list(network.hosts())
            
            print(f"[*] Scanning {len(hosts)} potential hosts...")
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                results = executor.map(self.ping_host, hosts)
                
                for ip, is_alive in zip(hosts, results):
                    if is_alive:
                        self.active_hosts.append(str(ip))
                        print(f"[+] Found active host: {ip}")
            
            print(f"\n[*] Discovery complete: {len(self.active_hosts)} active hosts found")
            
        except ValueError as e:
            print(f"[!] Invalid network range: {e}")
    
    def get_hostname(self, ip):
        """Attempt to resolve hostname for IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return "Unknown"
    
    def scan_common_ports(self, ip, ports=[21, 22, 23, 80, 443, 445, 3389]):
        """Quick scan of common ports"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        return open_ports
    
    def gather_host_details(self):
        """Gather detailed information about discovered hosts"""
        print("\n[*] Gathering host details...")
        
        for ip in self.active_hosts:
            print(f"  [*] Analyzing {ip}...")
            
            hostname = self.get_hostname(ip)
            open_ports = self.scan_common_ports(ip)
            
            self.host_details[ip] = {
                'ip': ip,
                'hostname': hostname,
                'open_ports': open_ports,
                'port_count': len(open_ports),
                'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'risk_level': self.calculate_risk(open_ports)
            }
    
    def calculate_risk(self, open_ports):
        """Calculate risk level based on open ports"""
        # Risky ports
        high_risk_ports = [21, 23, 445, 3389]  # FTP, Telnet, SMB, RDP
        medium_risk_ports = [80, 8080]  # HTTP
        
        high_risk = any(port in high_risk_ports for port in open_ports)
        medium_risk = any(port in medium_risk_ports for port in open_ports)
        
        if high_risk:
            return 'High'
        elif medium_risk or len(open_ports) > 3:
            return 'Medium'
        elif len(open_ports) > 0:
            return 'Low'
        else:
            return 'Info'
    
    def generate_json_report(self, filename='network_inventory.json'):
        """Generate JSON report"""
        report = {
            'scan_info': {
                'network_range': self.network_range,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_hosts': len(self.active_hosts)
            },
            'hosts': self.host_details,
            'summary': {
                'high_risk': len([h for h in self.host_details.values() if h['risk_level'] == 'High']),
                'medium_risk': len([h for h in self.host_details.values() if h['risk_level'] == 'Medium']),
                'low_risk': len([h for h in self.host_details.values() if h['risk_level'] == 'Low'])
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[*] JSON report saved to {filename}")
    
    def generate_csv_report(self, filename='network_inventory.csv'):
        """Generate CSV report for spreadsheet analysis"""
        with open(filename, 'w', newline='') as f:
            fieldnames = ['IP Address', 'Hostname', 'Open Ports', 'Port Count', 'Risk Level', 'Last Seen']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for details in self.host_details.values():
                writer.writerow({
                    'IP Address': details['ip'],
                    'Hostname': details['hostname'],
                    'Open Ports': ', '.join(map(str, details['open_ports'])),
                    'Port Count': details['port_count'],
                    'Risk Level': details['risk_level'],
                    'Last Seen': details['last_seen']
                })
        
        print(f"[*] CSV report saved to {filename}")
    
    def generate_text_report(self, filename='network_report.txt'):
        """Generate human-readable text report"""
        with open(filename, 'w') as f:
            f.write("="*70 + "\n")
            f.write("NETWORK INVENTORY & SECURITY REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Network Range: {self.network_range}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Active Hosts: {len(self.active_hosts)}\n\n")
            
            f.write("-"*70 + "\n")
            f.write("RISK SUMMARY\n")
            f.write("-"*70 + "\n")
            
            risk_summary = {
                'High': len([h for h in self.host_details.values() if h['risk_level'] == 'High']),
                'Medium': len([h for h in self.host_details.values() if h['risk_level'] == 'Medium']),
                'Low': len([h for h in self.host_details.values() if h['risk_level'] == 'Low']),
                'Info': len([h for h in self.host_details.values() if h['risk_level'] == 'Info'])
            }
            
            for level, count in risk_summary.items():
                f.write(f"{level:10s}: {count} hosts\n")
            
            f.write("\n" + "-"*70 + "\n")
            f.write("HOST DETAILS\n")
            f.write("-"*70 + "\n\n")
            
            # Sort by risk level
            risk_order = {'High': 0, 'Medium': 1, 'Low': 2, 'Info': 3}
            sorted_hosts = sorted(
                self.host_details.values(),
                key=lambda x: (risk_order.get(x['risk_level'], 4), x['ip'])
            )
            
            for details in sorted_hosts:
                f.write(f"IP Address:   {details['ip']}\n")
                f.write(f"Hostname:     {details['hostname']}\n")
                f.write(f"Risk Level:   {details['risk_level']}\n")
                f.write(f"Open Ports:   {', '.join(map(str, details['open_ports'])) if details['open_ports'] else 'None'}\n")
                f.write(f"Last Seen:    {details['last_seen']}\n")
                f.write("-"*70 + "\n")
            
            # Recommendations
            f.write("\n" + "="*70 + "\n")
            f.write("SECURITY RECOMMENDATIONS\n")
            f.write("="*70 + "\n\n")
            
            high_risk_hosts = [h for h in self.host_details.values() if h['risk_level'] == 'High']
            if high_risk_hosts:
                f.write("HIGH PRIORITY:\n")
                for host in high_risk_hosts:
                    f.write(f"  • {host['ip']} ({host['hostname']}): ")
                    if 21 in host['open_ports']:
                        f.write("Disable FTP or use SFTP. ")
                    if 23 in host['open_ports']:
                        f.write("Disable Telnet, use SSH. ")
                    if 445 in host['open_ports']:
                        f.write("Review SMB exposure. ")
                    if 3389 in host['open_ports']:
                        f.write("Secure RDP with VPN. ")
                    f.write("\n")
                f.write("\n")
            
            f.write("GENERAL RECOMMENDATIONS:\n")
            f.write("  • Close unnecessary ports and services\n")
            f.write("  • Implement network segmentation\n")
            f.write("  • Enable firewall on all hosts\n")
            f.write("  • Use strong authentication mechanisms\n")
            f.write("  • Keep systems updated with security patches\n")
            f.write("  • Monitor network traffic for anomalies\n")
        
        print(f"[*] Text report saved to {filename}")
    
    def print_summary(self):
        """Print summary to console"""
        print("\n" + "="*70)
        print("SCAN SUMMARY")
        print("="*70)
        print(f"Network Range:    {self.network_range}")
        print(f"Active Hosts:     {len(self.active_hosts)}")
        print(f"\nRisk Distribution:")
        
        risk_counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for details in self.host_details.values():
            risk_counts[details['risk_level']] += 1
        
        for level, count in risk_counts.items():
            print(f"  {level:10s}: {count} hosts")
        
        print("="*70)


def main():
    parser = argparse.ArgumentParser(description='Network Inventory & Security Scanner')
    parser.add_argument('network', help='Network range in CIDR notation (e.g., 192.168.1.0/24)')
    parser.add_argument('--json', default='network_inventory.json', help='JSON output file')
    parser.add_argument('--csv', default='network_inventory.csv', help='CSV output file')
    parser.add_argument('--txt', default='network_report.txt', help='Text report file')
    parser.add_argument('--workers', type=int, default=50, help='Number of concurrent workers')
    
    args = parser.parse_args()
    
    inventory = NetworkInventory(args.network)
    inventory.discover_hosts(max_workers=args.workers)
    
    if inventory.active_hosts:
        inventory.gather_host_details()
        inventory.generate_json_report(args.json)
        inventory.generate_csv_report(args.csv)
        inventory.generate_text_report(args.txt)
        inventory.print_summary()
    else:
        print("[!] No active hosts found in the specified range")


if __name__ == '__main__':
    main()
