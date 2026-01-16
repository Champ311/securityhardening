# securityhardening
#!/bin/bash

# Enhanced Security Script for Linux Mint 21
# Run with: sudo bash script.sh

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Start timer
startTime=$(date +"%s")

# Logging function
printTime() {
    endTime=$(date +"%s")
    diffTime=$(($endTime-$startTime))
    minutes=$(printf "%02d" $(($diffTime / 60)))
    seconds=$(printf "%02d" $(($diffTime % 60)))
    echo -e "${GREEN}[$minutes:$seconds]${NC} $1" | tee -a ~/Desktop/Security_Script.log
}

printWarning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a ~/Desktop/Security_Script.log
}

printError() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a ~/Desktop/Security_Script.log
}

# Initialize log file
touch ~/Desktop/Security_Script.log
echo "=== Security Script Started: $(date) ===" > ~/Desktop/Security_Script.log
chmod 600 ~/Desktop/Security_Script.log

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    printError "This script must be run as root (use sudo)."
    exit 1
fi
printTime "Script running with root privileges."

# ============================================================================
# BACKUP SECTION
# ============================================================================
clear
echo -e "${GREEN}=== Creating Backups ===${NC}"

mkdir -p ~/Desktop/backups
chmod 700 ~/Desktop/backups
printTime "Backup directory created."

# Backup critical system files
declare -a backup_files=(
    "/etc/hosts"
    "/etc/hosts.allow"
    "/etc/hosts.deny"
    "/etc/crontab"
    "/etc/fstab"
)

for file in "${backup_files[@]}"; do
    if [ -f "$file" ]; then
        cp -n "$file" ~/Desktop/backups/$(basename "$file").bak 2>/dev/null
        printTime "Backed up: $file"
    fi
done

# ============================================================================
# USER MANAGEMENT
# ============================================================================
clear
echo -e "${GREEN}=== User Account Management ===${NC}"

echo "Enter usernames to manage (space-separated):"
read -a users
usersLength=${#users[@]}

for (( i=0; i<$usersLength; i++ )); do
    clear
    username="${users[${i}]}"
    echo -e "${YELLOW}Processing: $username${NC}"
    
    if ! id "$username" &>/dev/null; then
        echo "User $username does not exist. Skip? (yes/no)"
        read skip
        [ "$skip" == "yes" ] && continue
    fi
    
    echo "Delete $username? (yes/no)"
    read delete_user
    
    if [ "$delete_user" == "yes" ]; then
        userdel -r "$username" 2>/dev/null
        printTime "User $username deleted."
    else
        echo "Make $username an administrator? (yes/no)"
        read make_admin
        
        if [ "$make_admin" == "yes" ]; then
            usermod -aG sudo,adm,lpadmin,sambashare "$username"
            printTime "$username added to admin groups."
        else
            gpasswd -d "$username" sudo 2>/dev/null
            gpasswd -d "$username" adm 2>/dev/null
            gpasswd -d "$username" lpadmin 2>/dev/null
            gpasswd -d "$username" sambashare 2>/dev/null
            printTime "$username removed from admin groups."
        fi
        
        echo "Set custom password for $username? (yes/no)"
        read custom_pw
        
        if [ "$custom_pw" == "yes" ]; then
            passwd "$username"
        else
            echo "$username:CyberPatriot2025!" | chpasswd
            printTime "$username password set to default."
        fi
        
        # Set password aging
        chage -M 90 -m 7 -W 14 "$username"
        printTime "Password policy applied to $username."
    fi
done

# Add new users
clear
echo "Enter new usernames to create (space-separated, or press Enter to skip):"
read -a new_users

for username in "${new_users[@]}"; do
    if [ -n "$username" ]; then
        adduser --gecos "" "$username"
        echo "$username:CyberPatriot2025!" | chpasswd
        chage -M 90 -m 7 -W 14 "$username"
        
        echo "Make $username an administrator? (yes/no)"
        read make_admin
        
        if [ "$make_admin" == "yes" ]; then
            usermod -aG sudo,adm,lpadmin,sambashare "$username"
            printTime "New admin user $username created."
        else
            printTime "New standard user $username created."
        fi
    fi
done

# ============================================================================
# ADDITIONAL SECURITY CHECKS
# ============================================================================
clear
echo -e "${GREEN}=== Additional Security Checks ===${NC}"

# Check for world-writable files
printTime "Scanning for world-writable files (this may take time)..."
find / -xdev -type f -perm -0002 2>/dev/null > ~/Desktop/world_writable_files.txt
count=$(wc -l < ~/Desktop/world_writable_files.txt)
if [ $count -gt 0 ]; then
    printWarning "Found $count world-writable files. List saved to ~/Desktop/world_writable_files.txt"
else
    printTime "No world-writable files found."
fi

# Check for SUID/SGID files
printTime "Scanning for SUID/SGID files..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null > ~/Desktop/suid_sgid_files.txt
count=$(wc -l < ~/Desktop/suid_sgid_files.txt)
printTime "Found $count SUID/SGID files. List saved to ~/Desktop/suid_sgid_files.txt"

# Check /etc/hosts for suspicious entries
printTime "Checking /etc/hosts for suspicious entries..."
if grep -v "^#" /etc/hosts | grep -v "^$" | grep -v "127.0.0.1\|::1\|localhost" > ~/Desktop/suspicious_hosts.txt 2>/dev/null; then
    printWarning "Found non-standard /etc/hosts entries. Review ~/Desktop/suspicious_hosts.txt"
else
    printTime "/etc/hosts appears clean."
fi

# Check for suspicious cron jobs
printTime "Checking for cron jobs..."
crontab -l > ~/Desktop/root_crontab.txt 2>/dev/null || echo "No root crontab" > ~/Desktop/root_crontab.txt
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l >> ~/Desktop/all_crontabs.txt 2>/dev/null
done
printTime "Cron jobs saved to ~/Desktop/root_crontab.txt and ~/Desktop/all_crontabs.txt"

# Check for .rhosts and .netrc files
printTime "Checking for .rhosts and .netrc files..."
find /home -name ".rhosts" -o -name ".netrc" 2>/dev/null > ~/Desktop/rhosts_netrc.txt
count=$(wc -l < ~/Desktop/rhosts_netrc.txt)
if [ $count -gt 0 ]; then
    printWarning "Found $count .rhosts or .netrc files. Review ~/Desktop/rhosts_netrc.txt"
else
    printTime "No .rhosts or .netrc files found."
fi

# ============================================================================
# NETWORK SECURITY
# ============================================================================
clear
echo -e "${GREEN}=== Network Security Configuration ===${NC}"

# Configure /etc/hosts.allow and /etc/hosts.deny
printTime "Configuring TCP Wrappers..."
echo "ALL: ALL" > /etc/hosts.deny
echo "ALL: 127.0.0.1" > /etc/hosts.allow
chmod 644 /etc/hosts.deny /etc/hosts.allow
printTime "TCP Wrappers configured (deny all except localhost)."

# Disable IPv6 if not needed
echo "Disable IPv6? (yes/no)"
read disable_ipv6

if [ "$disable_ipv6" == "yes" ]; then
    cat >> /etc/sysctl.conf <<EOF

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    sysctl -p >/dev/null 2>&1
    printTime "IPv6 disabled."
fi

# ============================================================================
# FILESYSTEM SECURITY
# ============================================================================
clear
echo -e "${GREEN}=== Filesystem Security ===${NC}"

# Secure /tmp with noexec
echo "Remount /tmp with noexec, nosuid, nodev? (yes/no)"
read secure_tmp

if [ "$secure_tmp" == "yes" ]; then
    if ! grep -q "tmpfs /tmp" /etc/fstab; then
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0" >> /etc/fstab
        printTime "/tmp will be mounted with security flags on next boot."
    else
        printWarning "/tmp already configured in /etc/fstab. Review manually."
    fi
fi

# Set umask for users
printTime "Setting secure default umask (027)..."
if ! grep -q "umask 027" /etc/profile; then
    echo "umask 027" >> /etc/profile
fi
if ! grep -q "umask 027" /etc/bash.bashrc; then
    echo "umask 027" >> /etc/bash.bashrc
fi
printTime "Default umask set to 027."

# ============================================================================
# SERVICE-SPECIFIC CONFIGURATIONS
# ============================================================================
clear
echo -e "${GREEN}=== Service Configuration ===${NC}"

# FTP Security
if systemctl is-active --quiet vsftpd 2>/dev/null; then
    printWarning "vsftpd (FTP) is running."
    echo "Configure vsftpd securely? (yes/no)"
    read config_ftp
    
    if [ "$config_ftp" == "yes" ]; then
        if [ -f /etc/vsftpd.conf ]; then
            cp /etc/vsftpd.conf ~/Desktop/backups/vsftpd.conf.bak
            sed -i 's/^anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
            sed -i 's/^#chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf
            systemctl restart vsftpd
            printTime "vsftpd configured: anonymous disabled, chroot enabled."
        fi
    fi
fi

# Samba Security
if systemctl is-active --quiet smbd 2>/dev/null; then
    printWarning "Samba is running."
    echo "Secure Samba configuration? (yes/no)"
    read config_samba
    
    if [ "$config_samba" == "yes" ]; then
        if [ -f /etc/samba/smb.conf ]; then
            cp /etc/samba/smb.conf ~/Desktop/backups/smb.conf.bak
            if ! grep -q "min protocol = SMB2" /etc/samba/smb.conf; then
                sed -i '/\[global\]/a min protocol = SMB2' /etc/samba/smb.conf
                printTime "Samba: minimum protocol set to SMB2."
            fi
            systemctl restart smbd
        fi
    fi
fi

# ============================================================================
# APPLICATION SECURITY
# ============================================================================
clear
echo -e "${GREEN}=== Application Security ===${NC}"

# Disable apport (crash reporting)
printTime "Disabling apport crash reporting..."
sed -i 's/enabled=1/enabled=0/' /etc/default/apport 2>/dev/null
systemctl stop apport 2>/dev/null
systemctl disable apport 2>/dev/null
printTime "Apport disabled."

# Secure Firefox profiles (if exists)
printTime "Checking Firefox profiles..."
for profile_dir in /home/*/.mozilla/firefox/*.default*; do
    if [ -d "$profile_dir" ]; then
        prefs_file="$profile_dir/prefs.js"
        if [ -f "$prefs_file" ]; then
            # Disable password saving
            if ! grep -q "signon.rememberSignons" "$prefs_file"; then
                echo 'user_pref("signon.rememberSignons", false);' >> "$prefs_file"
            fi
            # Clear history on exit
            if ! grep -q "privacy.sanitize.sanitizeOnShutdown" "$prefs_file"; then
                echo 'user_pref("privacy.sanitize.sanitizeOnShutdown", true);' >> "$prefs_file"
            fi
            printTime "Firefox profile secured: $(basename $profile_dir)"
        fi
    fi
done

echo "script made by mountainview highschool"
# ============================================================================
# ADVANCED AUDITING
# ============================================================================
clear
echo -e "${GREEN}=== Advanced System Auditing ===${NC}"

# Check for files with no owner
printTime "Checking for files with no owner..."
find / -xdev -nouser -o -nogroup 2>/dev/null > ~/Desktop/no_owner_files.txt
count=$(wc -l < ~/Desktop/no_owner_files.txt)
if [ $count -gt 0 ]; then
    printWarning "Found $count files with no owner. Review ~/Desktop/no_owner_files.txt"
else
    printTime "All files have valid owners."
fi

# List all startup programs
printTime "Listing startup programs..."
ls -la /etc/init.d/ > ~/Desktop/init_services.txt
ls -la /etc/systemd/system/ >> ~/Desktop/startup_programs.txt 2>/dev/null
systemctl list-unit-files --type=service >> ~/Desktop/startup_programs.txt
printTime "Startup programs listed in ~/Desktop/startup_programs.txt"

# Check bash history for all users
printTime "Checking bash history for suspicious commands..."
for user_home in /home/*; do
    if [ -f "$user_home/.bash_history" ]; then
        username=$(basename "$user_home")
        grep -iE "nc|netcat|wget|curl|chmod 777|/dev/tcp" "$user_home/.bash_history" >> ~/Desktop/suspicious_history.txt 2>/dev/null && \
        printWarning "Suspicious commands in $username's bash history"
    fi
done

# ============================================================================
# COMPLIANCE CHECKS
# ============================================================================
clear
echo -e "${GREEN}=== Running Compliance Checks ===${NC}"

# Check sudo configuration
printTime "Checking sudo configuration..."
if [ -f /etc/sudoers ]; then
    if grep -q "NOPASSWD" /etc/sudoers; then
        printWarning "NOPASSWD found in /etc/sudoers - review this configuration"
    fi
    
    # Check sudoers.d directory
    if [ -d /etc/sudoers.d ]; then
        sudoers_d_count=$(ls -1 /etc/sudoers.d/ 2>/dev/null | wc -l)
        if [ $sudoers_d_count -gt 0 ]; then
            printWarning "Found $sudoers_d_count files in /etc/sudoers.d/ - review these"
            ls -la /etc/sudoers.d/ > ~/Desktop/sudoers_d_files.txt
        fi
    fi
fi

# Verify critical file permissions
printTime "Verifying critical file permissions..."
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow
chmod 600 /boot/grub/grub.cfg 2>/dev/null
chmod 600 /etc/ssh/sshd_config 2>/dev/null
printTime "Critical file permissions verified."

# ============================================================================
# FINAL CHECKS AND REPORT
# ============================================================================
clear
echo -e "${GREEN}=== Security Script Complete ===${NC}"

# Generate summary report
cat >> ~/Desktop/Security_Script.log <<EOF

=== FINAL SECURITY SUMMARY ===
Script completed: $(date)
Total runtime: $(($(date +"%s")-$startTime)) seconds

FILES CREATED FOR REVIEW:
- ~/Desktop/world_writable_files.txt
- ~/Desktop/suid_sgid_files.txt
- ~/Desktop/suspicious_hosts.txt
- ~/Desktop/root_crontab.txt
- ~/Desktop/all_crontabs.txt
- ~/Desktop/rhosts_netrc.txt
- ~/Desktop/no_owner_files.txt
- ~/Desktop/startup_programs.txt
- ~/Desktop/suspicious_history.txt
- ~/Desktop/sudoers_d_files.txt

MANUAL TASKS REMAINING:
1. Review all generated files above
2. Check for unauthorized open ports: sudo ss -tulpn
3. Review Apache/web server configuration (if applicable)
4. Review database security (if applicable)
5. Check for unauthorized scheduled tasks
6. Verify all network shares are properly secured
7. Review application-specific configurations
8. Test critical services after hardening
9. Verify firewall rules are appropriate
10. Document all changes made

SECURITY RECOMMENDATIONS:
- Regularly monitor /var/log/auth.log for failed login attempts
- Keep system updated with security patches
- Periodically re-run security scans
- Review user access quarterly
- Maintain backups of critical data
- Test incident response procedures

For CyberPatriot: Remember to check the README and scoring report!
EOF

printTime "Security hardening completed!"
echo ""
echo -e "${GREEN}Log file saved to: ~/Desktop/Security_Script.log${NC}"
echo -e "${YELLOW}Please review all generated files and complete manual tasks.${NC}"
echo ""
echo "Reboot required for all changes to take effect. Reboot now? (yes/no)"
read reboot_now

if [ "$reboot_now" == "yes" ]; then
    printTime "System rebooting..."
    reboot
fi

exit 0
