# Nmap XML Security Parser & Executive Summary Generator

## 1. Project Name
**Nmap XML Security Parser & Executive Summary Generator** (`nmap_sec_parser.py`)

## 2. Security Problem Being Solved
During network penetration testing and vulnerability assessments, security professionals often generate massive, raw Nmap XML files (`-oX`). Manually reviewing these files to isolate open ports, extract service versions, and evaluate risk is tedious and error-prone under tight deadlines. 

This tool automates the ingestion and parsing of Nmap XML reports, dynamically assessing risk profiles, extracting OS detection fingerprints, and converting raw scan data into clean, client-ready **Markdown reports** and **structured JSON datasets** for dashboard integration.

## 3. Intended Users
- Penetration Testers & VAPT Consultants
- Internal Security Engineers & Network Auditors
- Bug Bounty Hunters and Red Teamers

## 4. Main Features
- **Zero External Dependencies:** Built entirely with Python's core standard libraries (`xml.etree.ElementTree`, `argparse`, `json`), requiring no external pip packages.
- **Dynamic Risk Evaluation Engine:** Combines a static port lookup database with heuristic keyword matching to catch high-risk services (e.g., FTP, Telnet, SMB) as well as unencrypted web traffic or administrative interfaces on non-standard ports (e.g., ports 8080/8180).
- **OS Fingerprint Extraction:** Automatically parses Nmap OS matching data (`<osmatch>`) along with confidence percentage metrics.
- **Flexible Multi-Format Export:** Supports generating human-readable Markdown (`.md`), machine-readable JSON (`.json`), or both formats simultaneously via command-line flags.

## 5. Technology Used
- **Programming Language:** Python 3.x
- **Standard Modules:** `xml.etree.ElementTree`, `argparse`, `json`, `os`, `sys`, `datetime`

## 6. Installation Instructions
Ensure Python 3.x is installed on your system. Clone the repository and navigate to the project directory:
Bash 

git clone [https://github.com/arunprashar/nmap-security-parser.git](https://github.com/arunprashar/nmap-security-parser.git)
cd nmap-security-parser

## 7. Usage Instructions & Syntax

Run the parser from the command line using the following syntax:
Bash

python nmap_sec_parser.py -i <input_xml_file> -o <output_filename> -f <format>

Argument Parameters:

    -i, --input: Path to the input Nmap XML file (Required).

    -o, --output: Base filename for the output report without extension (Default: security_summary).

    -f, --format: Choice of output format: markdown, json, or both (Default: markdown).

## 8. Sample Command

To generate both Markdown and JSON reports simultaneously from an Nmap scan file:
Bash

python nmap_sec_parser.py -i sample_scan.xml -o security_summary -f both

## 9. Sample Input and Output
Input Source

A standard Nmap scan file generated via:
Bash

nmap -sV -O -oX sample_scan.xml 192.168.1.8

Generated Output Snippet (security_summary.md)
Markdown

# 🛡️ Nmap Scan Security Analysis Report
**Generated On:** `2026-10-30 08:06:49`

---

## 1. Executive Summary
- **Total Active Hosts Scanned:** `1`
- **Total Open Ports Discovered:** `22`
- **Critical Risk Flags:** `1`
- **High Risk Flags:** `7`
- **Medium Risk Flags:** `3`

---

## 2. Host & Service Findings

### Host: `192.168.1.8`
**OS Fingerprint:** `Not Scanned / Unknown`

| Port | Protocol | Service | Banner | Risk Level | Initial Observation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `21` | `tcp` | `ftp` | vsftpd 2.3.4 | **High** | Unencrypted file transfer. Cleartext credentials. |
| `22` | `tcp` | `ssh` | OpenSSH 4.7p1 Debian 8ubuntu1 | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `23` | `tcp` | `telnet` | Linux telnetd | **High** | Unencrypted remote management. Cleartext traffic. |
| `25` | `tcp` | `smtp` | Postfix smtpd | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `80` | `tcp` | `http` | Apache httpd 2.2.8 | **Medium** | Unencrypted web traffic. Missing TLS/SSL enforcement. |
| `111` | `tcp` | `rpcbind` | 2 | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `139` | `tcp` | `netbios-ssn` | Samba smbd 3.X - 4.X | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `445` | `tcp` | `netbios-ssn` | Samba smbd 3.X - 4.X | **High** | Directly exposed SMB port. Potential target for remote execution/Ransomware. |
| `512` | `tcp` | `exec` | No banner | **High** | Legacy r-services exposure. Potential unauthenticated remote execution. |
| `513` | `tcp` | `login` | OpenBSD or Solaris rlogind | **High** | Legacy rlogin protocol exposed. Insecure authentication. |
| `514` | `tcp` | `shell` | No banner | **High** | Legacy rsh protocol exposed. Unencrypted remote shell access. |
| `1099` | `tcp` | `java-rmi` | GNU Classpath grmiregistry | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `1524` | `tcp` | `bindshell` | Metasploitable root shell | **Critical** | Unauthenticated root bind shell detected on port. |
| `2049` | `tcp` | `nfs` | 2-4 | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `2121` | `tcp` | `ftp` | ProFTPD 1.3.1 | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `3306` | `tcp` | `mysql` | MySQL 5.0.51a-3ubuntu5 | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `5432` | `tcp` | `postgresql` | PostgreSQL DB 8.3.0 - 8.3.7 | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `5900` | `tcp` | `vnc` | VNC | **High** | Potential unencrypted management or remote execution service exposed (vnc). |
| `6000` | `tcp` | `X11` | No banner | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `6667` | `tcp` | `irc` | UnrealIRCd | **Medium** | Exposed IRC service. Verify for backdoor signatures. |
| `8009` | `tcp` | `ajp13` | Apache Jserv | **Low/Info** | Standard service exposure. Verify patch levels and access controls. |
| `8180` | `tcp` | `http` | Apache Tomcat/Coyote JSP engine 1.1 | **Medium** | Unencrypted web service (http) detected. Verify TLS enforcement and admin interfaces. |

---

## 3. Manual Verification & Remediation Guidance
1. **Validate Cleartext Protocols:** Ensure HTTP (80/8180) redirects to HTTPS (443) and legacy services (FTP/Telnet) are replaced with SSH/SFTP.
2. **Immediate Containment:** Restrict access to critical shell exposures (e.g., port 1524) and exposed management interfaces (SMB/RDP) via local firewall policy.
3. **Vulnerability Mapping:** Search extracted service banners (e.g., vsftpd 2.3.4, Apache 2.2.8) against vulnerability databases (NVD/Exploit-DB).

> *Note: This tool provides dynamic banner-based prioritization. Pentesters must perform manual exploitation verification to confirm actionable security risk.*

## 10. Security Considerations

   - Data Sensitivity: Generated security reports contain target infrastructure details, open ports, and software versions. Reports should be transmitted and stored securely in compliance with data privacy standards.

   - Passive Processing: The utility operates strictly in offline read-only mode against local XML files; it does not perform active probing or generate network traffic.

## 11. Known Limitations

   - Banner-Dependent Heuristics: Risk categorization relies primarily on service banners and version strings provided by Nmap. Heavily customized or obfuscated banners may result in miscategorization.

   - Exploitability Verification: Banner-based findings indicate potential vulnerability exposure, not verified exploitability. Manual penetration testing and verification are always required.

## 12. Future Improvements

   -  Integrate CVSS scoring calculation for discovered service versions.

   - Expand parser capability to ingest multi-source scan formats (e.g., Nessus .nessus XML and Masscan outputs).

