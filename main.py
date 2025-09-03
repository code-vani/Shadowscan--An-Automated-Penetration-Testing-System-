#!/usr/bin/env python3
from recon import whois_lookup, ipinfo_lookup, nmap_scan
from vuln import nmap_vuln_scan, run_nikto_scan
from exploit2 import (
    ExploitEngine
)
import json
import time
# Create an instance of ExploitEngine with the target IP
msf = ExploitEngine('192.168.234.129')

def display_banner():

    print("""
    ╔══════════════════════════════════════════╗
    ║        Advanced Penetration Testing      ║
    ║              Framework v2.0              ║
    ║                                          ║
    ║  [1] Reconnaissance                      ║
    ║  [2] Vulnerability Assessment            ║
    ║  [3] Exploitation (Sandbox Only)         ║
    ║  [4] Full Assessment                     ║
    ╚══════════════════════════════════════════╝
    """)

def reconnaissance_phase():
    print("\n" + "="*50)
    print("PHASE 1: RECONNAISSANCE")
    print("="*50)
    
    domain = input("Enter a domain name (or press Enter to skip): ")
    if domain.strip():
        whois_lookup(domain)
    
    ip = input("\nEnter IP for scanning: ")
    open_ports = []
    if ip.strip():
        ipinfo_lookup(ip)
        open_ports = nmap_scan(ip)  # now returns list of open ports with services
    
    return ip, open_ports

def vulnerability_assessment(target_ip, open_ports):
    print("\n" + "="*50)
    print("PHASE 2: VULNERABILITY ASSESSMENT")
    print("="*50)
    
    vulnerable_services = nmap_vuln_scan(target_ip, open_ports)

    # Web vulnerability scan
    print("\n[+] Checking for web services...")
    web_ports = [80, 443, 8080, 8443]
    for service in vulnerable_services:
        if service['port'] in web_ports or 'http' in service['service'].lower():
            print(f"[+] Found web service on port {service['port']}")
            run_nikto_scan(target_ip)
            break
    
    return vulnerable_services


def exploitation_phase(target_ip, vulnerable_services):
    print("\n" + "="*50)
    print("PHASE 3: EXPLOITATION (SANDBOX ENVIRONMENT)")
    print("="*50)
    
    
    
    # Run exploits on the list of vulnerable services
    results = msf.run_exploits(vulnerable_services)

    print("\n[+] Exploitation Phase Summary:")
    
    if results['successful']:
        print("\n[*] Successful Exploits:")
        for exploit in results['successful']:
            print(f"  - {exploit['service']} on port {exploit['port']} ({exploit['method']}): {exploit['details']}")
    else:
        print("  No successful exploits.")

    if results['failed']:
        print("\n[*] Failed Exploits:")
        for exploit in results['failed']:
            print(f"  - {exploit['service']} on port {exploit['port']} ({exploit['method']}): {exploit['error']}")
    
    if results['credentials']:
        print("\n[*] Credentials Found:")
        for service, username, password in results['credentials']:
            print(f"  - {service}: {username}:{password}")
    else:
        print("\n[*] No credentials found.")
    return results


def full_assessment():
    print("\n" + "="*60)
    print("FULL PENETRATION TESTING ASSESSMENT")
    print("="*60)
    
    target_ip, open_ports = reconnaissance_phase()
    
    if not target_ip.strip():
        print("[-] No target IP provided. Exiting...")
        return
    
    vulnerable_services = vulnerability_assessment(target_ip, open_ports)
    
    if not vulnerable_services:
        print("\n[-] No vulnerable services found. Skipping exploitation phase.")
        return
    
    exploitation_results = exploitation_phase(target_ip, vulnerable_services)
    
    print("\n" + "="*50)
    print("PHASE 4: REPORT GENERATION")
    print("="*50)
    
    if exploitation_results:
        msf.generate_report(save_to_file=True, file_path="target_192.168.1.10.txt")
        #print(report)

def interactive_mode():
    while True:
        display_banner()
        choice = input("\nSelect an option (1-4) or 'q' to quit: ").strip()
        
        if choice == '1':
            reconnaissance_phase()
        elif choice == '2':
            target_ip = input("Enter target IP for vulnerability assessment: ")
            open_ports = nmap_scan(target_ip)
            vulnerability_assessment(target_ip, open_ports)
        elif choice == '3':
            target_ip = input("Enter target IP for exploitation: ")
            print("Note: For exploitation, run vulnerability assessment first")
            print("Using known vulnerable Metasploitable 2 services...")
            vulnerable_services = [
                {"port": 21, "service": "ftp", "version": "vsftpd 2.3.4"},
                {"port": 22, "service": "ssh", "version": "OpenSSH 4.7p1 Debian 8ubuntu1 protocol 2.0"},
                {"port": 25, "service": "smtp", "version": "Postfix smtpd"},
                {"port": 80, "service": "http", "version": "Apache 2.2.8"},
                {"port": 139, "service": "netbios-ssn", "version": ""},
                {"port": 445, "service": "microsoft-ds", "version": ""},
                {"port": 1524, "service": "bindshell", "version": "Metasploitable root shell"},
                {"port": 3306, "service": "mysql", "version": ""}
            ]
            exploitation_phase(target_ip, vulnerable_services)
        elif choice == '4':
            full_assessment()
        elif choice.lower() == 'q':
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == '--full':
            full_assessment()
        elif sys.argv[1] == '--help':
            print("Usage:")
            print("  python main.py           - Interactive mode")
            print("  python main.py --full    - Full assessment")
            print("  python main.py --help    - Show this help")
        else:
            print("Unknown argument. Use --help for usage information.")
    else:
        interactive_mode()
