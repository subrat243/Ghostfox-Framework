# **Auto Pentest Toolkit**

A powerful, organized, and automated penetration testing toolkit designed to streamline the process of reconnaissance, scanning, exploitation, post-exploitation, and wireless attacks. The toolkit integrates popular tools and techniques into a single Python script for seamless use during ethical hacking engagements.

## Features:

* **Banner & AutoPwn Mode**: Stylish banner and aggressive AutoPwn mode for quick testing.
* **Reconnaissance**: Active and passive scanning using tools like Nmap, Masscan, Amass, and more.
* **Scanning & Enumeration**: Web vulnerability scanning with Nikto, directory brute-forcing with Dirb, SMB enumeration, and more.
* **Exploitation**: Automated exploitation with SQLmap, Hydra, Medusa, and more.
* **Post-Exploitation**: Tools for credential dumping (Mimikatz), privilege escalation (PowerView), and tunneling.
* **Wireless Attacks**: Supports wireless testing using tools like Aircrack-ng, Fluxion, and more.
* **HTML Report Generation**: Generates a detailed HTML report of all findings.

## Tools Integrated:

* **Reconnaissance**: Nmap, Masscan, Amass, theHarvester, Shodan CLI, WHOIS, DNSenum, and more.
* **Scanning & Enumeration**: Nikto, Dirb, Gobuster, Enum4linux, SMBClient, RPCClient, LDAPsearch, and more.
* **Exploitation**: Metasploit, Searchsploit, SQLmap, Hydra, Medusa, and more.
* **Post-Exploitation**: Mimikatz, PowerView, Chisel, Ngrok, and more.
* **Wireless Attacks**: Aircrack-ng, Wifite, Fluxion, MDK4, and more.

## Requirements:

* Python 3.x
* Root/Administrator privileges (for certain tools like Masscan, Nikto, etc.)
* Tools installed on your system: Nmap, Masscan, theHarvester, Amass, Nikto, SQLmap, Hydra, Medusa, Mimikatz, and others (Refer to individual tool documentation for installation).

## Installation:

1. **Install Python 3.x**:
   If not already installed, download and install [Python 3](https://www.python.org/downloads/).

2. **Install Dependencies**:
   Some of the tools are external, so ensure they are installed. For example:

   ```bash
   sudo apt install nmap masscan theharvester amass nikto sqlmap hydra medusa mimikatz aircrack-ng
   ```

3. **Clone the Repository**:
   If you want to keep this script for version control or share it, clone it using git:

   ```bash
   git clone https://github.com/your-username/auto-pentest-toolkit.git
   ```

4. **Make the script executable** (optional):

   ```bash
   chmod +x auto_pentest_toolkit.py
   ```

## Usage:

Run the Python script using:

```bash
python3 auto_pentest_toolkit.py
```

### Main Menu:

* **1**: Start a full scan across all phases (Recon, Scanning, Exploitation, etc.).
* **2**: Trigger **AutoPwn Mode** (Aggressive quick testing using default attack methods).

#### Example usage:

```bash
Enter target IP/domain: 192.168.1.1
Select mode:
[1] Full Scan
[2] AutoPwn (Aggressive Quick Test)
> 2
```

The script will run the following stages automatically:

* **Active Recon** (Nmap, Masscan, ARP-Scan)
* **Passive Recon** (theHarvester, Amass, WHOIS, Shodan)
* **Scanning & Enumeration** (Nikto, Dirb, SMBClient)
* **Exploitation** (SQLmap, Hydra, Responder)
* **Post-Exploitation** (Mimikatz, Chisel)
* **Wireless Attacks** (Aircrack-ng, Fluxion, Wifite)

At the end of the scan, the script will generate a report in the `reports/` directory and save it as an HTML file.

## Generated Report:

The toolkit generates an HTML report of all scanned data, findings, and vulnerabilities. You can find it in the `reports/` folder:

```bash
reports/
└── 192.168.1.1_20230510_120500
    ├── Nmap_Full_Port_Scan.txt
    ├── Masscan_Fast_Scan.txt
    ├── Nikto_Web_Vuln_Scan.txt
    ├── SQLmap_SQLi.txt
    └── report.html
```

The `report.html` contains:

* All tool outputs categorized by type (e.g., Nmap, Nikto, SQLmap).
* Clean, readable formatting for easy assessment of vulnerabilities.

## Notes:

* **AutoPwn Mode** is aggressive and designed for quick testing. It should only be used on networks and systems that you have explicit permission to test.
* **Report Generation**: After the scan, an HTML report is generated and saved in the `reports/` folder.

## Important Warning:

**This tool should only be used for legal and ethical penetration testing.** Always have explicit permission before testing any network or system that you do not own. Unauthorized access to networks or systems is illegal and unethical.

## License:

This tool is open-source and free to use, modify, and distribute under the MIT License.

---
