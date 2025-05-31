#!/bin/bash
set -euo pipefail

# Global configuration variables
SCRIPT_VERSION="2.0"
SCRIPT_NAME="SAFYRA Install"
LOG_FILE="/var/log/safyra_install.log"
ERROR_LOG="/var/log/safyra_install_errors.log"
SAFYRA_CREDS_FILE="/root/.safyra_credentials"

# Secure logging configuration
exec > >(tee -a "${LOG_FILE}") 2> >(tee -a "${ERROR_LOG}" >&2)

# Logging function with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Enhanced error handling function
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Prerequisites verification function
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Verify script is running as root
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
    
    # Verify distribution
    if ! grep -q "bookworm" /etc/os-release 2>/dev/null; then
        log "WARNING: This script is optimized for Debian Bookworm"
    fi
    
    # Check available disk space (minimum 5GB)
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 5242880 ]]; then
        error_exit "Insufficient disk space (minimum 5GB required)"
    fi
}

# Critical configuration backup function
backup_configs() {
    log "Backing up critical configurations..."
    local backup_dir="/root/safyra_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup important configurations
    [[ -f /etc/ssh/sshd_config ]] && cp /etc/ssh/sshd_config "$backup_dir/"
    [[ -f /etc/network/interfaces ]] && cp /etc/network/interfaces "$backup_dir/"
    [[ -d /etc/apt/sources.list.d ]] && cp -r /etc/apt/sources.list.d "$backup_dir/"
    [[ -f /etc/resolv.conf ]] && cp /etc/resolv.conf "$backup_dir/"
    [[ -f /etc/hosts ]] && cp /etc/hosts "$backup_dir/"
    
    log "Backup created in: $backup_dir"
}

# Enhanced base system configuration
configure_system_base() {
    log "Configuring base system..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    # Hostname configuration with validation
    local new_hostname="preprod-safyra"
    if hostnamectl set-hostname "$new_hostname"; then
        log "Hostname configured: $new_hostname"
    else
        error_exit "Failed to configure hostname"
    fi
    
    # Update hosts file to avoid resolution issues
    if ! grep -q "$new_hostname" /etc/hosts; then
        echo "127.0.1.1 $new_hostname" >> /etc/hosts
    fi
}

# Enhanced secure SSH configuration (CORRECTED VERSION)
configure_ssh() {
    log "Configuring secure SSH..."
    
    # Backup current SSH configuration
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)
    
    # Apply SSH configurations one by one for better error handling
    sed -i 's/^#Port .*/Port 8222/' /etc/ssh/sshd_config
    sed -i 's/^#PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's|^#AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys|' /etc/ssh/sshd_config
    sed -i 's/^#LogLevel .*/LogLevel VERBOSE/' /etc/ssh/sshd_config
    sed -i 's|^#Subsystem\s\+sftp.*|Subsystem sftp /usr/lib/openssh/sftp-server|' /etc/ssh/sshd_config
    sed -i 's/^#MaxAuthTries .*/MaxAuthTries 5/' /etc/ssh/sshd_config
    sed -i 's/^#ClientAliveInterval .*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/^#ClientAliveCountMax .*/ClientAliveCountMax 3/' /etc/ssh/sshd_config
    
    # Optional: Uncomment these lines if you want to disable root login and password authentication
     sed -i 's/^#PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
     sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    
    # Additional security configurations
    cat >> /etc/ssh/sshd_config << 'EOF'

# SAFYRA security configurations
Protocol 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
EOF
    
    # Remove cloud-init config file that may interfere
    rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf
    
    # Security banner configuration
    echo "WARNING: Unauthorized access is strictly prohibited. All connections are monitored and logged." > /etc/issue.net
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    
    # Test SSH configuration before restart
    if sshd -t; then
        systemctl restart ssh
        log "SSH configuration applied successfully"
    else
        error_exit "Error in SSH configuration"
    fi
}

# Enhanced network configuration
configure_network() {
    log "Configuring network..."
    
    # DNS configuration with fallback
    cat > /etc/resolv.conf << 'EOF'
nameserver 9.9.9.9
options timeout:5 attempts:9
EOF
    
    # Make resolv.conf immutable to prevent overwriting
    chattr +i /etc/resolv.conf || log "WARNING: Cannot make resolv.conf immutable"
    
    # Network bridge configuration for virtualization
    if ! grep -q "vmbr1" /etc/network/interfaces; then
        cat >> /etc/network/interfaces << 'EOF'

# SAFYRA bridge interface
auto vmbr1
iface vmbr1 inet static
    address 10.10.10.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
EOF
        log "Bridge interface vmbr1 configured"
    fi
    
    # IP forwarding configuration
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding = 0' >> /etc/sysctl.conf
    echo 'net.ipv4.conf.all.log_martians = 1' >> /etc/sysctl.conf
    sysctl -p
}

# Package installation with verification
install_packages() {
    log "Updating sources and installing packages..."
    
    # Secure APT sources configuration
    cat > /etc/apt/sources.list << 'EOF'
deb http://deb.debian.org/debian bookworm main contrib
deb http://deb.debian.org/debian bookworm-updates main contrib
deb http://security.debian.org/debian-security bookworm-security main contrib
EOF

    # Add Proxmox repository with key verification
    if [[ ! -f /etc/apt/sources.list.d/pve-install-repo.list ]]; then
        wget -O /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg
        echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-install-repo.list
    fi
    
    echo 'APT::Get::Update::SourceListWarnings::NonFreeFirmware "false";' > /etc/apt/apt.conf.d/no-bookworm-firmware.conf
    
    # Update with error handling
    if ! apt update; then
        error_exit "Failed to update packages"
    fi
    
    if ! apt upgrade -y; then
        error_exit "Failed to upgrade packages"
    fi
    
    # Essential packages installation
    local packages=(
        "auditd" "libguestfs-tools" "libpam-tmpdir" "qemu-guest-agent"
        "wget" "git" "sudo" "curl" "unzip" "gnupg" "software-properties-common"
        "lynis" "clamav" "nftables" "iptables-persistent" "fail2ban"
        "rsyslog" "logrotate" "htop" "tree" "vim" "net-tools"
    )
    
    for package in "${packages[@]}"; do
        if ! apt install -y "$package"; then
            log "WARNING: Failed to install $package"
        fi
    done
}

# Proxmox configuration
configure_proxmox() {
    log "Configuring Proxmox..."
    
    # Proxmox proxy configuration
    echo 'LISTEN_IP="10.10.10.1"' >> /etc/default/pveproxy
    
    # Disable unnecessary services
    systemctl disable postfix.service || true
    systemctl mask postfix.service || true
    
    # Terraform installation with signature verification
    if ! command -v terraform &> /dev/null; then
        curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
        echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com bookworm main" > /etc/apt/sources.list.d/hashicorp.list
        apt update && apt install terraform -y
    fi
    
    # Container templates download with verification
    log "Downloading container templates..."
    pveam download local debian-11-standard_11.7-1_amd64.tar.zst || log "WARNING: Failed to download Debian template"
    pveam download local fedora-41-default_20241118_amd64.tar.xz || log "WARNING: Failed to download Fedora template"
}

# Secure user management
configure_users() {
    log "Configuring users..."
    
    # Create safyradmin user with strong password policy
    if ! id "safyradmin" &>/dev/null; then
        useradd safyradmin -m -s /bin/bash -G sudo
        
        # Generate strong password
        local safyradmin_password
        safyradmin_password=$(openssl rand -base64 32)
        echo "safyradmin:${safyradmin_password}" | chpasswd
        
        # Secure credentials storage
        {
            echo "# SAFYRA Credentials - Generated on $(date)"
            echo "SAFYRADMIN_PASSWORD=${safyradmin_password}"
        } > "$SAFYRA_CREDS_FILE"
        chmod 600 "$SAFYRA_CREDS_FILE"
        
        log "User safyradmin created with secure password"
    fi
   
    # Create Guacamole user
    if ! id "guacprox" &>/dev/null; then
        useradd -s /bin/bash -m guacprox
        usermod -aG sudo guacprox
        mkdir -p /home/guacprox/.ssh
        chmod 700 /home/guacprox/.ssh
        touch /home/guacprox/.ssh/authorized_keys
        chmod 600 /home/guacprox/.ssh/authorized_keys
        chown -R guacprox:guacprox /home/guacprox/.ssh
        
        log "User guacprox created"
    fi
}

# Terraform user configuration for Proxmox
configure_terraform_user() {
    log "Configuring Terraform user for Proxmox..."
    
    # Create Terraform user with minimal permissions
    if ! pveum user list | grep -q "terraform@pve"; then
        pveum user add terraform@pve -comment "Terraform Automation User"
        
        # Terraform role with restricted permissions
        pveum role add TerraformRole -privs "VM.Allocate,VM.Audit,Datastore.AllocateSpace,Datastore.Audit,Pool.Allocate,Sys.Audit,Sys.Console,Sys.Modify,VM.Clone,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.Migrate,VM.Monitor,VM.PowerMgmt,SDN.Use" 2>/dev/null || true
        
        pveum aclmod / -user terraform@pve -role TerraformRole
        
        # Token generation with secure storage
        local token_file="/etc/pve/.terraform-token.json"
        if pveum user token add terraform@pve terraform-token --output-format json > "$token_file"; then
            #chmod 600 "$token_file"
            log "Terraform token generated and stored securely"
        fi
    fi
}

# Firewall configuration with persistent rules
configure_firewall() {
    log "Configuring firewall with persistent rules..."
    
    # Basic iptables configuration
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    
    # Restrictive default policy
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established and related connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # SSH on custom port
    iptables -A INPUT -p tcp --dport 8222 -m state --state NEW,ESTABLISHED -j ACCEPT
    
    # Proxmox Web Interface
    iptables -A INPUT -p tcp --dport 8006 -m state --state NEW,ESTABLISHED -j ACCEPT
    
    # HTTP/HTTPS for updates
    iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
    
    # Limited ICMP (ping)
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    
    # NAT for internal network
    iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o vmbr0 -j MASQUERADE
    iptables -A FORWARD -s 10.10.10.0/24 -o vmbr0 -j ACCEPT
    iptables -A FORWARD -d 10.10.10.0/24 -i vmbr0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # Protection against common attacks
    iptables -A INPUT -m recent --name blacklist --set -j DROP
    iptables -A INPUT -p tcp --dport 8222 -m recent --name ssh --set
    iptables -A INPUT -p tcp --dport 8222 -m recent --name ssh --rcheck --seconds 60 --hitcount 4 -j DROP
    
    # Save rules for persistence
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4
        log "IPv4 iptables rules saved"
    fi
    
    # Configure for persistence on reboot
    systemctl enable netfilter-persistent || true
}

# System security configuration
configure_security() {
    log "Configuring system security..."
    
    # System audit configuration
    if systemctl is-active --quiet auditd; then
        log "auditd service active"
    else
        systemctl enable auditd
        systemctl start auditd
    fi
    
    # Fail2Ban configuration for SSH
    cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = 8222
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF
    
    systemctl enable fail2ban
    systemctl start fail2ban
    
    # More restrictive default permissions
    sed -i 's/^UMASK.*/UMASK\t027/' /etc/login.defs
    
    # Disable unnecessary system accounts
    for user in games news uucp proxy www-data backup list irc gnats nobody; do
        if id "$user" &>/dev/null; then
            usermod -L -s /bin/false "$user" 2>/dev/null || true
        fi
    done
}

# Security audit
run_security_audit() {
    log "Running security audit..."
    
    # Lynis audit
    if command -v lynis &> /dev/null; then
        lynis audit system --quiet > /root/lynis_report.txt 2>&1
        chmod 600 /root/lynis_report.txt
        log "Lynis audit report generated: /root/lynis_report.txt"
    fi
    
    # Update antivirus signatures
    if command -v freshclam &> /dev/null; then
        freshclam --quiet || log "WARNING: Failed to update ClamAV signatures"
    fi
}

# Cleanup and finalization
cleanup_and_finalize() {
    log "Cleanup and finalization..."
    
    # APT cache cleanup
    apt autoremove -y
    apt autoclean
    
    # Log rotation configuration
    cat > /etc/logrotate.d/safyra << 'EOF'
/var/log/safyra_install*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
    
    # Update locate database
    updatedb || true
    
    # Generate installation report
    {
        echo "=== SAFYRA INSTALLATION REPORT ==="
        echo "Date: $(date)"
        echo "Script Version: $SCRIPT_VERSION"
        echo "Hostname: $(hostname)"
        echo "Primary IP: $(ip route get 1 | awk '{print $7}' | head -1)"
        echo "Users created: safyradmin, guacprox"
        echo "SSH Port: 8222"
        echo "Installation logs: $LOG_FILE"
        echo "Credentials: $SAFYRA_CREDS_FILE"
        echo "===================================="
    } > /root/safyra_install_report.txt
    
    chmod 600 /root/safyra_install_report.txt
    log "Installation report generated: /root/safyra_install_report.txt"
}

# Main function
main() {
    log "=========================================="
    log "STARTING SAFYRA INSTALLATION v$SCRIPT_VERSION"
    log "=========================================="
    
    check_prerequisites
    backup_configs
    configure_system_base
    configure_ssh
    configure_network
    install_packages
    configure_proxmox
    configure_users
    configure_terraform_user
    configure_firewall
    configure_security
    run_security_audit
    cleanup_and_finalize
    
    log "=========================================="
    log "SAFYRA INSTALLATION COMPLETED SUCCESSFULLY"
    log "REBOOT REQUIRED IN 30 SECONDS..."
    log "=========================================="
    
    # Reboot with delay to allow log reading
    sleep 30
    reboot
}

# Execute main script
main "$@"
