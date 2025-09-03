#!/usr/bin/env python3

import nmap
import subprocess
import requests
from config import NMAP_PATH, CVE_API_URL

# Function to perform a targeted vulnerability scan using known open ports from Phase 1
def nmap_vuln_scan(target, open_ports):
    nm = nmap.PortScanner()
    nm.nmap_location = NMAP_PATH

    # Convert list of port numbers to comma-separated string
    port_str = ",".join(str(p['port']) for p in open_ports)

    print(f"\n[+] Running Nmap vulnerability scan on ports: {port_str}")
    nm.scan(hosts=target, arguments=f"-p {port_str} --script vuln -sV -T4")

    vulnerable_services = []

    if target in nm.all_hosts():
        for port in nm[target]['tcp'].keys():
            service_info = nm[target]['tcp'][port]
            name = service_info.get("name", "unknown")
            version = service_info.get("version", "unknown")

            # Fetch CVEs based on service name and version
            cves = fetch_cve_info(name, version)

            vulnerable_services.append({
                "port": port,
                "service": name,
                "version": version,
                "cves": cves
            })

            print(f"\n[+] Port {port}: {name} {version}")
            for cve in cves[:3]:  # limit preview to 3 CVEs
                cve_id = cve['cve']['CVE_data_meta']['ID']
                desc = cve['cve']['description']['description_data'][0]['value']
                print(f"  - {cve_id}: {desc[:100]}...")

    return vulnerable_services

# Function to query CVE API and return matching vulnerability data
def fetch_cve_info(service_name, version):
    query = f"{service_name} {version}"
    url = f"{CVE_API_URL}?keyword={query}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json().get("result", {}).get("CVE_Items", [])
    except Exception as e:
        print(f"[-] Error fetching CVE info: {e}")
    return []

# Function to run Nikto scan externally (web vulnerability scanner)
def run_nikto_scan(target):
    print("\n[+] Running Nikto Scan...")
    result = subprocess.run(["perl", "C:/path/to/nikto/nikto.pl", "-h", target], capture_output=True, text=True)
    print(result.stdout)
  
