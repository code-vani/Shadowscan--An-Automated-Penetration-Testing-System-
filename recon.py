#!/usr/bin/env python3
import requests
import nmap
import socket
from config import IPINFO_API_KEY, NMAP_PATH, WHOIS_API_KEY 

def whois_lookup(domain):
    #Perform a WHOIS lookup using API
    #Fetches domain registration details
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        print("\n[+] WHOIS Information:")
        print(f"Domain: {data.get('WhoisRecord', {}).get('domainName', 'N/A')}")
        print(f"Registrar: {data.get('WhoisRecord', {}).get('registrarName', 'N/A')}")
        print(f"Creation Date: {data.get('WhoisRecord', {}).get('createdDate', 'N/A')}")
        print(f"Expiration Date: {data.get('WhoisRecord', {}).get('expiresDate', 'N/A')}")
    else:
        print("[-] Failed to fetch WHOIS info")



def ipinfo_lookup(ip):
    url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        print("\n[+] IPinfo.io Results:")
        print(f"IP: {data.get('ip', 'N/A')}")
        print(f"Hostname: {data.get('hostname', 'N/A')}")
        print(f"Location: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}")
        print(f"Org: {data.get('org', 'N/A')}")
    else:
        print("[-] Error fetching data from IPinfo.io")




def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.nmap_location = NMAP_PATH  # Remove or comment this line if NMAP_PATH isn't needed

    print(f"\n[+] Starting full Nmap scan on: {target}")
    nm.scan(hosts=target, arguments='-A -T4 -p-')

    open_ports = []

    for host in nm.all_hosts():
        print(f"\n[+] Host: {host}")
        try:
            hostname = nm[host].hostname()
            print(f"Hostname: {hostname}")
        except:
            print("Hostname: Unknown")

        print(f"State: {nm[host].state()}")

        # MAC Address
        if 'addresses' in nm[host]:
            mac = nm[host]['addresses'].get('mac')
            if mac:
                print(f"MAC Address: {mac}")

        # OS Detection
        if 'osmatch' in nm[host]:
            print("\n[+] OS Detection:")
            for osmatch in nm[host]['osmatch']:
                print(f"- OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
                if 'osclass' in osmatch:
                    for osclass in osmatch['osclass']:
                        print(f"  Device Type: {osclass.get('type', 'Unknown')}")
                        print(f"  OS Family: {osclass.get('osfamily', 'Unknown')}")
                        print(f"  OS Generation: {osclass.get('osgen', 'Unknown')}")

        # Port and Service Info
        for proto in nm[host].all_protocols():
            print(f"\n[Protocol: {proto}]")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service_info = nm[host][proto][port]
                service = service_info.get('name', 'unknown')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                extrainfo = service_info.get('extrainfo', '')
                reason = service_info.get('reason', '')
                state = service_info.get('state', '')

                print(f"Port: {port} | State: {state} | Reason: {reason} | "
                      f"Service: {service} | Product: {product} {version} {extrainfo}".strip())

                open_ports.append({
                    'port': port,
                    'protocol': proto,
                    'state': state,
                    'service': service,
                    'product': product,
                    'version': version,
                    'extrainfo': extrainfo,
                    'reason': reason
                })

        # Script output (e.g., banner grabbing, vulns)
        if 'hostscript' in nm[host]:
            print("\n[+] Host Script Results:")
            for script in nm[host]['hostscript']:
                print(f"- {script['id']}: {script['output']}")

    return open_ports





def run_netdiscover(subnet: str):
    """
    Runs netdiscover on the given subnet and returns the output.

    Args:
        subnet (str): The subnet to scan (e.g., "192.168.1.0/24").

    Returns:
        str: Output of the netdiscover command.
    """
    command = ['sudo', 'netdiscover', '-r', subnet]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"
