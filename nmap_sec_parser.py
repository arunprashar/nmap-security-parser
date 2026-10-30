#!/usr/bin/env python3
"""
Tool Name: Nmap XML Security Parser & Executive Summary Generator
Author: Arun Kumar
Description: Parses Nmap XML scan outputs, dynamically evaluates service security 
             risks, extracts OS fingerprints, and exports reports in Markdown and/or JSON.
"""

import sys
import os
import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime

# Known static port risk mappings
HIGH_RISK_PORTS = {
    21: {"service": "FTP", "risk": "High", "issue": "Unencrypted file transfer. Cleartext credentials."},
    23: {"service": "Telnet", "risk": "High", "issue": "Unencrypted remote management. Cleartext traffic."},
    80: {"service": "HTTP", "risk": "Medium", "issue": "Unencrypted web traffic. Missing TLS/SSL enforcement."},
    445: {"service": "SMB", "risk": "High", "issue": "Directly exposed SMB port. Potential target for remote execution/Ransomware."},
    512: {"service": "exec", "risk": "High", "issue": "Legacy r-services exposure. Potential unauthenticated remote execution."},
    513: {"service": "login", "risk": "High", "issue": "Legacy rlogin protocol exposed. Insecure authentication."},
    514: {"service": "shell", "risk": "High", "issue": "Legacy rsh protocol exposed. Unencrypted remote shell access."},
    1524: {"service": "bindshell", "risk": "Critical", "issue": "Unauthenticated root bind shell detected on port."},
    3389: {"service": "RDP", "risk": "Medium", "issue": "Exposed Remote Desktop. Susceptible to brute-force attacks."},
    6667: {"service": "IRC", "risk": "Medium", "issue": "Exposed IRC service. Verify for backdoor signatures."},
}

def evaluate_risk(port_id, service_name, banner):
    """
    Dynamically evaluates risk level based on port ID, service name, and banner strings.
    Feature 1: Dynamic keyword and protocol matching for non-standard ports.
    """
    service_lower = service_name.lower()
    banner_lower = banner.lower()

    # 1. Direct Static Port Lookup
    if port_id in HIGH_RISK_PORTS:
        return HIGH_RISK_PORTS[port_id]

    # 2. Dynamic Critical Check: Shell/Backdoor Indicators
    if any(k in service_lower or k in banner_lower for k in ["bindshell", "root shell", "backdoor"]):
        return {
            "risk": "Critical",
            "issue": f"Critical remote shell / backdoor pattern detected in service '{service_name}'."
        }

    # 3. Dynamic High Check: Administrative / Management / Legacy Remote Access
    if any(k in service_lower or k in banner_lower for k in ["exec", "rlogin", "rsh", "vnc", "telnet", "admin"]):
        return {
            "risk": "High",
            "issue": f"Potential unencrypted management or remote execution service exposed ({service_name})."
        }

    # 4. Dynamic Medium Check: Unencrypted Web Traffic on Non-Standard Ports (e.g., 8080, 8180, 8000)
    if ("http" in service_lower or "web" in service_lower) and "https" not in service_lower and "ssl" not in service_lower:
        return {
            "risk": "Medium",
            "issue": f"Unencrypted web service ({service_name}) detected. Verify TLS enforcement and admin interfaces."
        }

    # Default fallback
    return {
        "risk": "Low/Info",
        "issue": "Standard service exposure. Verify patch levels and access controls."
    }

def parse_nmap_xml(xml_file):
    """Parses Nmap XML file and extracts host, OS, and port information."""
    if not os.path.exists(xml_file):
        print(f"[!] Error: Input file '{xml_file}' not found.")
        sys.exit(1)

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] XML Parsing Error: {e}")
        sys.exit(1)

    scan_data = []

    for host in root.findall('host'):
        # Extract Host IP
        address_elem = host.find('address')
        if address_elem is None or 'addr' not in address_elem.attrib:
            continue
        ip = address_elem.attrib['addr']

        # Check host status (skip down hosts)
        status = host.find('status')
        if status is not None and status.attrib.get('state') != 'up':
            continue

        # Feature 2: Extract OS Fingerprint Guess
        os_guess = "Not Scanned / Unknown"
        os_elem = host.find('os/osmatch')
        if os_elem is not None and 'name' in os_elem.attrib:
            accuracy = os_elem.attrib.get('accuracy', 'N/A')
            os_guess = f"{os_elem.attrib['name']} ({accuracy}% accuracy)"

        ports_data = []
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                state_elem = port.find('state')
                if state_elem is not None and state_elem.attrib.get('state') == 'open':
                    port_id = int(port.attrib.get('portid'))
                    protocol = port.attrib.get('protocol', 'tcp')

                    service_elem = port.find('service')
                    service_name = service_elem.attrib.get('name', 'unknown') if service_elem is not None else 'unknown'
                    product = service_elem.attrib.get('product', '') if service_elem is not None else ''
                    version = service_elem.attrib.get('version', '') if service_elem is not None else ''
                    
                    banner = f"{product} {version}".strip() if product or version else "No banner"

                    # Dynamic Risk Evaluation
                    risk_info = evaluate_risk(port_id, service_name, banner)

                    ports_data.append({
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "banner": banner,
                        "risk": risk_info["risk"],
                        "issue": risk_info["issue"]
                    })

        scan_data.append({
            "ip": ip,
            "os_detection": os_guess,
            "open_ports": ports_data
        })

    return scan_data

def generate_markdown_report(scan_data, output_file):
    """Generates a structured Markdown security report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md_content = "# 🛡️ Nmap Scan Security Analysis Report\n"
    md_content += f"**Generated On:** `{now}`\n\n"
    md_content += "---\n\n"
    
    # Executive Summary Calculation
    total_hosts = len(scan_data)
    total_ports = sum(len(h["open_ports"]) for h in scan_data)
    critical_count = sum(1 for h in scan_data for p in h["open_ports"] if p["risk"] == "Critical")
    high_count = sum(1 for h in scan_data for p in h["open_ports"] if p["risk"] == "High")
    medium_count = sum(1 for h in scan_data for p in h["open_ports"] if p["risk"] == "Medium")

    md_content += "## 1. Executive Summary\n"
    md_content += f"- **Total Active Hosts Scanned:** `{total_hosts}`\n"
    md_content += f"- **Total Open Ports Discovered:** `{total_ports}`\n"
    md_content += f"- **Critical Risk Flags:** `{critical_count}`\n"
    md_content += f"- **High Risk Flags:** `{high_count}`\n"
    md_content += f"- **Medium Risk Flags:** `{medium_count}`\n\n"

    md_content += "---\n\n"
    md_content += "## 2. Host & Service Findings\n\n"

    for host in scan_data:
        md_content += f"### Host: `{host['ip']}`\n"
        md_content += f"**OS Fingerprint:** `{host['os_detection']}`\n\n"

        if not host["open_ports"]:
            md_content += "_No open ports detected on this host._\n\n"
            continue

        md_content += "| Port | Protocol | Service | Banner | Risk Level | Initial Observation |\n"
        md_content += "| :--- | :--- | :--- | :--- | :--- | :--- |\n"

        for p in host["open_ports"]:
            risk_str = f"**{p['risk']}**"
            md_content += f"| `{p['port']}` | `{p['protocol']}` | `{p['service']}` | {p['banner']} | {risk_str} | {p['issue']} |\n"
        
        md_content += "\n"

    md_content += "---\n\n"
    md_content += "## 3. Manual Verification & Remediation Guidance\n"
    md_content += "1. **Validate Cleartext Protocols:** Ensure HTTP (80/8180) redirects to HTTPS (443) and legacy services (FTP/Telnet) are replaced with SSH/SFTP.\n"
    md_content += "2. **Immediate Containment:** Restrict access to critical shell exposures (e.g., port 1524) and exposed management interfaces (SMB/RDP) via local firewall policy.\n"
    md_content += "3. **Vulnerability Mapping:** Search extracted service banners (e.g., vsftpd 2.3.4, Apache 2.2.8) against vulnerability databases (NVD/Exploit-DB).\n\n"

    md_content += "> *Note: This tool provides dynamic banner-based prioritization. Pentesters must perform manual exploitation verification to confirm actionable security risk.*"

    with open(output_file, "w") as f:
        f.write(md_content)

    print(f"[+] Markdown report generated: {output_file}")

def generate_json_report(scan_data, output_file):
    """Feature 3: Outputs parsed results as structured JSON."""
    export_payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_hosts": len(scan_data),
        "hosts": scan_data
    }
    with open(output_file, "w") as f:
        json.dump(export_payload, f, indent=4)
    print(f"[+] JSON report generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Parse Nmap XML output into Markdown and/or JSON Security Reports.")
    parser.add_argument("-i", "--input", required=True, help="Path to input Nmap XML file (-oX file.xml)")
    parser.add_argument("-o", "--output", default="security_summary", help="Base name for output report file (without extension)")
    parser.add_argument("-f", "--format", choices=["markdown", "json", "both"], default="markdown", help="Output report format (default: markdown)")

    args = parser.parse_args()
    
    scan_results = parse_nmap_xml(args.input)

    # Feature 3: Format Selection Execution
    if args.format in ["markdown", "both"]:
        md_file = f"{args.output}.md" if not args.output.endswith(".md") else args.output
        generate_markdown_report(scan_results, md_file)

    if args.format in ["json", "both"]:
        json_file = f"{args.output}.json" if not args.output.endswith(".json") else args.output
        if json_file.endswith(".md.json"):
            json_file = json_file.replace(".md.json", ".json")
        generate_json_report(scan_results, json_file)

if __name__ == "__main__":
    main()
