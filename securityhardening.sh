#!/bin/bash

################################################################################
# Linux Mint 21 Security Hardening Script
# Purpose: Automated security hardening for CyberPatriot/competition environments
# Target: Linux Mint 21 (Ubuntu 22.04 base)
# Usage: sudo ./security_hardening.sh
################################################################################

set -e  # Exit on error
set -u  # Exit on undefined variable

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/security_hardening_$(date +%Y%m%d_%H%M%S).log"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    echo "[SUCCESS] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[WARNING] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    echo "[ERROR] $1" >> "$LOG_FILE"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
    echo "[INFO] $1" >> "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

################################################################################
# Main Hardening Functions
################################################################################

baseline_documentation() {
    print_header "Creating Baseline Documentation"
    
    print_info "Recording system information..."
    hostnamectl > /tmp/baseline_system.txt 2>&1
    
    print_info "Recording listening ports..."
    ss -tlnp > /tmp/baseline_ports.txt 2>&1 || netstat -tulpn > /tmp/baseline_ports.txt 2>&1
    
    print_info "Recording running processes..."
    ps -ef > /tmp/baseline_processes.txt 2>&1
    
    print_success "Baseline documentation saved to /tmp/baseline_*.txt"
}

update_system() {
    print_header "System Updates & Package Management"
    
    print_info "Updating package indices..."
    apt-get update >> "$LOG_FILE" 2>&1 && print_success "Package indices updated"
    
    print_info "Upgrading installed packages..."
    apt-get full-upgrade -y >> "$LOG_FILE" 2>&1 && print_success "Packages upgraded"
    
    print_info "Removing unnecessary packages..."
    apt-get autoremove -y >> "$LOG_FILE" 2>&1 && print_success "Autoremove completed"
    
    print_info "Cleaning package cache..."
    apt-get autoclean >> "$LOG_FILE" 2>&1 && print_success "Cache cleaned"
}

install_security_tools() {
    print_header "Installing Security Tools"
    
    print_info "Installing libpam-pwquality for password enforcement..."
    apt-get install -y libpam-pwquality >> "$LOG_FILE" 2>&1 && print_success "Password quality tools installed"
    
    print_info "Installing unattended-upgrades for automatic security updates..."
    apt-get install -y unattended-upgrades >> "$LOG_FILE" 2>&1
    dpkg-reconfigure -plow unattended-upgrades >> "$LOG_FILE" 2>&1 && print_success "Automatic updates configured"
    
    print_info "Installing tshark for forensics..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark >> "$LOG_FILE" 2>&1 && print_success "tshark installed"
}

remove_hacking_tools() {
    print_header "Removing Unauthorized Software"
    
    local hacking_tools=(
        "wireshark" "wireshark-common" "wireshark-qt"
        "nmap"
        "netcat" "netcat-traditional"
        "aircrack-ng"
        "sqlmap"
        "metasploit-framework"
        "armitage"
        "beef-xss"
        "doona"
        "xprobe"
    )
    
    for tool in "${hacking_tools[@]}"; do
        if dpkg -l | grep -q "^ii.*$tool"; then
            print_info "Removing $tool..."
            apt-get remove --purge -y "$tool" >> "$LOG_FILE" 2>&1 && print_success "Removed $tool"
        fi
    done
}

remove_media_software() {
    print_header "Removing Media & Entertainment Software"
    
    local media_apps=(
        "rhythmbox"
        "celluloid"
        "hypnotix"
        "freetv"
        "vlc"
        "totem"
        "zangband"
    )
    
    for app in "${media_apps[@]}"; do
        if dpkg -l | grep -q "^ii.*$app"; then
            print_info "Removing $app..."
            apt-get remove --purge -y "$app" >> "$LOG_FILE" 2>&1 && print_success "Removed $app"
        fi
    done
}

find_media_files() {
    print_header "Cataloging Media Files"
    
    print_info "Searching for media files (this may take a while)..."
    find / -type f \( \
        -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.avi" -o \
        -iname "*.mkv" -o -iname "*.flv" -o -iname "*.wav" -o \
        -iname "*.flac" -o -iname "*.ogg" -o -iname "*.mov" -o \
        -iname "*.wmv" \
    \) 2>/dev/null > /tmp/media_files.txt
    
    local count=$(wc -l < /tmp/media_files.txt)
    print_success "Found $count media files. List saved to /tmp/media_files.txt"
    print_warning "Review /tmp/media_files.txt and manually delete prohibited files"
    print_warning "Check the README for which media files are unauthorized"
}

configure_password_policy() {
    print_header "Configuring Password Policy"
    
    # Configure /etc/login.defs
    print_info "Configuring password aging in /etc/login.defs..."
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    10/' /etc/login.defs
    print_success "Password aging configured (90/7/14 days, min length 10)"
    
    # Configure /etc/security/pwquality.conf
    print_info "Configuring password complexity requirements..."
    cat > /etc/security/pwquality.conf << 'EOF'
# Password quality requirements
minlen = 10
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 3
EOF
    print_success "Password complexity requirements set"
    
    # Configure PAM for password quality and history
    print_info "Configuring PAM password module..."
    
    # Add pwquality if not present
    if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password
    fi
    
    # Add password history (remember=3)
    if grep -q "pam_unix.so" /etc/pam.d/common-password; then
        sed -i '/pam_unix.so/ s/$/ remember=3/' /etc/pam.d/common-password
    fi
    
    print_success "PAM configured for password quality and history"
    
    # Remove nullok from common-auth
    print_info "Removing nullok from PAM authentication..."
    sed -i 's/nullok//g' /etc/pam.d/common-auth
    print_success "Null password login disabled"
}

configure_account_lockout() {
    print_header "Configuring Account Lockout Policy"
    
    print_info "Creating faillock PAM configuration..."
    
    # Create faillock config
    cat > /usr/share/pam-configs/faillock << 'EOF'
Name: Faillock
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
    required pam_faillock.so preauth silent audit deny=5 unlock_time=900
    [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
Account-Type: Primary
Account:
    required pam_faillock.so
EOF
    
    print_info "Running pam-auth-update..."
    DEBIAN_FRONTEND=noninteractive pam-auth-update --package >> "$LOG_FILE" 2>&1
    print_success "Account lockout configured (5 attempts, 15 min lockout)"
}

apply_password_aging() {
    print_header "Applying Password Aging to Users"
    
    print_info "Password aging must be configured per-user manually"
    print_warning "Example: sudo chage -M 90 -m 7 -W 14 username"
    print_warning "Example: sudo passwd -e username (force password change)"
}

remove_unauthorized_users() {
    print_header "User Account Management"
    
    print_info "User removal must be done manually to avoid mistakes"
    print_warning "Review /etc/passwd for unauthorized accounts"
    print_warning "Example: sudo deluser --remove-home username"
    print_warning "Example: sudo userdel -r -f username"
}

manage_groups() {
    print_header "Managing Groups and Permissions"
    
    print_info "Group and permission changes must be done manually"
    print_warning "Review group memberships: cat /etc/group"
    print_warning "Example: sudo groupadd groupname"
    print_warning "Example: sudo usermod -aG groupname username"
    print_warning "Example: sudo gpasswd -d username groupname"
}

lock_root_account() {
    print_header "Securing Root Account"
    
    print_info "Checking root password status..."
    local root_status=$(getent shadow root | cut -d: -f2)
    
    if [[ -z "$root_status" ]] || [[ "$root_status" == "!" ]] || [[ "$root_status" == "*" ]]; then
        print_info "Root account has no password, locking..."
        passwd -l root >> "$LOG_FILE" 2>&1 && print_success "Root account locked"
    else
        print_warning "Root has a password set. Review if this is required."
    fi
}

disable_unnecessary_services() {
    print_header "Disabling Unnecessary Services"
    
    local services=(
        "bluetooth.service"
        "blueman-mechanism.service"
        "cups.service"
        "cups-browsed.service"
        "ModemManager.service"
        "openvpn.service"
        "avahi-daemon.service"
        "nginx.service"
        "squid.service"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            print_info "Disabling $service..."
            systemctl disable "$service" --now >> "$LOG_FILE" 2>&1 && print_success "Disabled $service"
        fi
    done
    
    print_info "Masking Ctrl+Alt+Del target..."
    systemctl mask ctrl-alt-del.target >> "$LOG_FILE" 2>&1 && print_success "Ctrl+Alt+Del disabled"
}

detect_backdoors() {
    print_header "Detecting Backdoors and Malware"
    
    print_info "Scanning for Python backdoors..."
    ps -ef | grep -i python | grep -v grep > /tmp/python_processes.txt
    if [[ -s /tmp/python_processes.txt ]]; then
        print_warning "Found Python processes. Review /tmp/python_processes.txt"
        cat /tmp/python_processes.txt
    else
        print_success "No suspicious Python processes found"
    fi
    
    print_info "Checking for common backdoor patterns..."
    local backdoor_patterns=(
        "/usr/share/*/kneelB4zod.py"
        "/usr/bin/xdg-notifierd"
        "/usr/games/*.zip"
    )
    
    for pattern in "${backdoor_patterns[@]}"; do
        local found_files=$(find / -path "$pattern" 2>/dev/null)
        if [[ -n "$found_files" ]]; then
            print_warning "Found suspicious files matching: $pattern"
            echo "$found_files"
            print_warning "Review these files and remove if unauthorized"
        fi
    done
    
    print_warning "Check README for specific backdoor files to remove"
}

harden_ssh() {
    print_header "Hardening SSH Configuration"
    
    local ssh_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "$ssh_config" ]]; then
        print_warning "SSH not installed, skipping SSH hardening"
        return
    fi
    
    print_info "Backing up SSH config..."
    cp "$ssh_config" "${ssh_config}.backup_$(date +%Y%m%d_%H%M%S)"
    
    print_info "Applying SSH hardening..."
    
    # Disable root login
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
    
    # Disable empty passwords
    sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$ssh_config"
    
    # Set max auth tries
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' "$ssh_config"
    
    # Disable X11 forwarding
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' "$ssh_config"
    
    print_success "SSH configuration hardened"
    
    print_info "Restarting SSH service..."
    systemctl restart sshd >> "$LOG_FILE" 2>&1 && print_success "SSH service restarted"
}

harden_apache() {
    print_header "Hardening Apache Web Server"
    
    if ! systemctl is-active --quiet apache2 2>/dev/null; then
        print_info "Apache2 not detected or not running"
        return
    fi
    
    local security_conf="/etc/apache2/conf-enabled/security.conf"
    
    if [[ -f "$security_conf" ]]; then
        print_info "Configuring Apache security headers..."
        
        # Backup
        cp "$security_conf" "${security_conf}.backup_$(date +%Y%m%d_%H%M%S)"
        
        # Set ServerTokens
        sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$security_conf"
        sed -i 's/^ServerSignature.*/ServerSignature Off/' "$security_conf"
        
        print_success "Apache security headers configured"
        
        print_info "Restarting Apache..."
        systemctl restart apache2 >> "$LOG_FILE" 2>&1 && print_success "Apache restarted"
    fi
}

secure_mysql() {
    print_header "Database Security"
    
    print_info "Database hardening must be done manually"
    print_warning "If MySQL/MariaDB is installed, run: sudo mysql_secure_installation"
}

enable_firewall() {
    print_header "Configuring Firewall"
    
    print_info "Enabling UFW..."
    ufw --force enable >> "$LOG_FILE" 2>&1 && print_success "UFW enabled"
    
    print_info "Setting default policies..."
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    print_success "Default firewall policies set"
    
    print_info "Firewall status:"
    ufw status verbose
}

echo "script by champ clark"
apply_kernel_hardening() {
    print_header "Applying Kernel Hardening"
    
    print_info "Configuring sysctl parameters..."
    
    # Backup sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.backup_$(date +%Y%m%d_%H%M%S)
    
    cat >> /etc/sysctl.conf << 'EOF'

# Security hardening parameters
kernel.randomize_va_space=2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
EOF
    
    print_info "Applying sysctl changes..."
    sysctl --system >> "$LOG_FILE" 2>&1 && print_success "Kernel hardening applied"
}

secure_wordpress() {
    print_header "Securing Web Applications"
    
    print_info "Web application security must be configured manually"
    print_warning "Check for WordPress, Drupal, or other web apps in /var/www/"
    print_warning "Example: sudo chmod 640 /var/www/wordpress/wp-config.php"
    print_warning "Example: sudo chown www-data:www-data /var/www/wordpress/wp-config.php"
}

clean_temp_directories() {
    print_header "Cleaning Temporary Directories"
    
    print_info "Cleaning /tmp..."
    find /tmp -mindepth 1 -maxdepth 1 ! -name 'baseline_*.txt' ! -name 'media_files.txt' ! -name 'python_processes.txt' -exec rm -rf {} + 2>/dev/null
    print_success "/tmp cleaned (preserved baseline files)"
    
    print_info "Cleaning /var/tmp..."
    rm -rf /var/tmp/* >> "$LOG_FILE" 2>&1 && print_success "/var/tmp cleaned"
}

audit_system() {
    print_header "Running System Audit"
    
    print_info "Checking for UID 0 accounts (other than root)..."
    local uid0=$(awk -F: '($3==0){print $1}' /etc/passwd | grep -v '^root$')
    if [[ -n "$uid0" ]]; then
        print_warning "Found UID 0 accounts: $uid0"
    else
        print_success "No unauthorized UID 0 accounts found"
    fi
    
    print_info "Checking for duplicate UIDs..."
    local dup_uid=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    if [[ -n "$dup_uid" ]]; then
        print_warning "Found duplicate UIDs: $dup_uid"
    else
        print_success "No duplicate UIDs"
    fi
    
    print_info "Checking for duplicate GIDs..."
    local dup_gid=$(cut -d: -f3 /etc/group | sort | uniq -d)
    if [[ -n "$dup_gid" ]]; then
        print_warning "Found duplicate GIDs: $dup_gid"
    else
        print_success "No duplicate GIDs"
    fi
    
    print_info "Listing enabled services..."
    systemctl list-unit-files --type=service --state=enabled | tee -a "$LOG_FILE"
    
    print_info "Checking for listening network services..."
    ss -tlnp 2>/dev/null | tee -a "$LOG_FILE" || netstat -tulpn 2>/dev/null | tee -a "$LOG_FILE"
}

set_default_browser() {
    print_header "Setting Default Browser to Chromium"
    
    print_info "Installing Chromium browser..."
    apt-get install -y chromium-browser >> "$LOG_FILE" 2>&1 && print_success "Chromium installed"
    
    print_info "Removing Firefox and DuckDuckGo..."
    apt-get remove --purge -y firefox 2>/dev/null || true
    apt-get remove --purge -y duckduckgo 2>/dev/null || true
    
    print_info "Setting Chromium as default browser..."
    update-alternatives --set x-www-browser /usr/bin/chromium-browser >> "$LOG_FILE" 2>&1 || true
    xdg-settings set default-web-browser chromium-browser.desktop 2>/dev/null || true
    print_success "Chromium set as default browser"
}

################################################################################
# Main Execution
################################################################################

main() {
    print_header "Linux Mint 21 Security Hardening Script - CyberPatriot Edition"
    print_info "Started: $(date)"
    print_info "Log file: $LOG_FILE"
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                    IMPORTANT REMINDERS                         ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  ⚠️  READ THE README FIRST - It contains critical information!"
    echo ""
    echo "  📋  CHECK THESE BEFORE RUNNING THIS SCRIPT:"
    echo "      - Which users are authorized/unauthorized"
    echo "      - Which files should be removed"
    echo "      - Which services should run"
    echo "      - Password policy requirements"
    echo "      - Group membership requirements"
    echo ""
    echo "  🔍  ANSWER FORENSICS QUESTIONS FIRST"
    echo "      - They're worth easy points"
    echo "      - System changes may affect answers"
    echo ""
    echo "Press Enter to continue or Ctrl+C to exit..."
    read -r
    
    check_root
    
    # Baseline documentation
    baseline_documentation
    
    # System updates
    update_system
    install_security_tools
    
    # Remove unauthorized software
    remove_hacking_tools
    remove_media_software
    find_media_files
    
    # Backdoor detection
    detect_backdoors
    
    # User and password management
    configure_password_policy
    configure_account_lockout
    apply_password_aging
    remove_unauthorized_users
    manage_groups
    lock_root_account
    
    # Service hardening
    disable_unnecessary_services
    harden_ssh
    harden_apache
    secure_mysql
    
    # Network security
    enable_firewall
    apply_kernel_hardening
    
    # Application security
    secure_wordpress
    set_default_browser
    
    # Cleanup
    clean_temp_directories
    
    # Final audit
    audit_system
    
    print_header "Hardening Complete"
    print_success "All automated hardening steps completed!"
    print_info "Log file saved to: $LOG_FILE"
    
    print_warning "MANUAL TASKS REMAINING:"
    echo ""
    echo "  ⚠️  CRITICAL: Review the competition README for specifics!"
    echo ""
    echo "  1. FORENSICS QUESTIONS (if not done yet):"
    echo "     - Answer all forensics questions on Desktop"
    echo ""
    echo "  2. USER ACCOUNT MANAGEMENT:"
    echo "     - Review users: cat /etc/passwd"
    echo "     - Check README for unauthorized users"
    echo "     - Remove unauthorized: sudo deluser --remove-home username"
    echo "     - Set password aging: sudo chage -M 90 -m 7 -W 14 username"
    echo "     - Force password change: sudo passwd -e username"
    echo ""
    echo "  3. GROUP MANAGEMENT:"
    echo "     - Review groups: cat /etc/group"
    echo "     - Check README for required groups"
    echo "     - Create groups: sudo groupadd groupname"
    echo "     - Add members: sudo usermod -aG groupname username"
    echo "     - Remove from sudo: sudo gpasswd -d username sudo"
    echo ""
    echo "  4. MEDIA FILES & UNAUTHORIZED SOFTWARE:"
    echo "     - Review: /tmp/media_files.txt"
    echo "     - Check README for prohibited files"
    echo "     - Delete manually: sudo rm -f /path/to/file"
    echo ""
    echo "  5. BACKDOORS & MALWARE:"
    echo "     - Review: /tmp/python_processes.txt"
    echo "     - Check README for specific backdoor locations"
    echo "     - Kill processes: sudo pkill -9 process_name"
    echo "     - Remove files: sudo rm -f /path/to/backdoor"
    echo ""
    echo "  6. DATABASE SECURITY (if applicable):"
    echo "     - Check if MySQL/MariaDB installed"
    echo "     - Run: sudo mysql_secure_installation"
    echo ""
    echo "  7. WEB APPLICATION SECURITY (if applicable):"
    echo "     - Check /var/www/ for applications"
    echo "     - Secure configs: sudo chmod 640 config.php"
    echo "     - Fix ownership: sudo chown www-data:www-data files"
    echo ""
    echo "  8. VERIFICATION:"
    echo "     - Firewall: sudo ufw status verbose"
    echo "     - Users: cat /etc/passwd"
    echo "     - Groups: cat /etc/group"
    echo "     - Cron jobs: sudo crontab -l"
    echo "     - Listeners: sudo ss -tlnp"
    echo "     - Services: systemctl list-unit-files --type=service --state=enabled"
    echo ""
    echo "  9. BASELINE REVIEW:"
    echo "     - /tmp/baseline_system.txt"
    echo "     - /tmp/baseline_ports.txt"
    echo "     - /tmp/baseline_processes.txt"
    echo ""
    
    print_info "Completed: $(date)"
}

# Run main function
main "$@"
