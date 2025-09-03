#!/bin/bash
set -euo pipefail

# Global configuration variables
SCRIPT_VERSION="2.1"
SCRIPT_NAME="SAFYRA Install Enhanced"
LOG_FILE="/var/log/safyra_install.log"
ERROR_LOG="/var/log/safyra_install_errors.log"
SAFYRA_CREDS_FILE="/root/.safyra_credentials"
BASTION_HOST="preprod.safyra.io"
BASTION_PORT="2222"
BASTION_USER="safyradmin"

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
    
    # Check available disk space (minimum 10GB for Proxmox + basic VMs)
    # Using df -BG to get space in GB for easier calculation
    AVAILABLE_SPACE_GB=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    TOTAL_SPACE_GB=$(df -BG / | awk 'NR==2 {print $2}' | sed 's/G//')
    
    log "Available disk space: ${AVAILABLE_SPACE_GB}GB / ${TOTAL_SPACE_GB}GB total"
    
    if [[ $AVAILABLE_SPACE_GB -lt 10 ]]; then
        error_exit "Insufficient disk space (minimum 10GB required, found ${AVAILABLE_SPACE_GB}GB available)"
    else
        log "Disk space check passed: ${AVAILABLE_SPACE_GB}GB available"
    fi
    
    # Additional checks for Proxmox requirements
    MEMORY_GB=$(free -g | awk 'NR==2{print $2}')
    log "Available RAM: ${MEMORY_GB}GB"
    
    if [[ $MEMORY_GB -lt 4 ]]; then
        log "WARNING: Less than 4GB RAM available. Proxmox may have performance issues."
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

# Enhanced secure SSH configuration - Keep root password access
configure_ssh() {
    log "Configuring secure SSH..."
    
    # Backup current SSH configuration
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)
    
    # Apply SSH configurations one by one for better error handling
    sed -i 's/^#\?Port .*/Port 8222/' /etc/ssh/sshd_config
    sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's|^#\?AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys|' /etc/ssh/sshd_config
    sed -i 's/^#\?LogLevel .*/LogLevel VERBOSE/' /etc/ssh/sshd_config
    sed -i 's|^#\?Subsystem\s\+sftp.*|Subsystem sftp /usr/lib/openssh/sftp-server|' /etc/ssh/sshd_config
    sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 5/' /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveInterval .*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 3/' /etc/ssh/sshd_config
    
    # IMPORTANT: Ensure root login with password is allowed
    sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    
    # SSH Forwarding configuration for bastion functionality
    sed -i 's/^#\?AllowTcpForwarding .*/AllowTcpForwarding yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?AllowAgentForwarding .*/AllowAgentForwarding yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?PermitTunnel .*/PermitTunnel yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?GatewayPorts .*/GatewayPorts no/' /etc/ssh/sshd_config
    
    # If the lines don't exist, add them
    grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    grep -q "^PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    grep -q "^AllowTcpForwarding" /etc/ssh/sshd_config || echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config
    grep -q "^AllowAgentForwarding" /etc/ssh/sshd_config || echo "AllowAgentForwarding yes" >> /etc/ssh/sshd_config
    grep -q "^PermitTunnel" /etc/ssh/sshd_config || echo "PermitTunnel yes" >> /etc/ssh/sshd_config
    grep -q "^GatewayPorts" /etc/ssh/sshd_config || echo "GatewayPorts no" >> /etc/ssh/sshd_config
    grep -q "^AllowStreamLocalForwarding" /etc/ssh/sshd_config || echo "AllowStreamLocalForwarding yes" >> /etc/ssh/sshd_config
    
    # Additional security configurations
    cat >> /etc/ssh/sshd_config << 'EOF'

# SAFYRA security configurations
Protocol 2
X11Forwarding no
PermitUserEnvironment no
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512

# Ensure password authentication stays enabled
PasswordAuthentication yes
PermitRootLogin yes
LogLevel VERBOSE

# Bastion functionality
AllowTcpForwarding yes
AllowAgentForwarding yes
PermitTunnel yes
GatewayPorts no
AllowStreamLocalForwarding yes
EOF
    
    # Remove cloud-init config file that may interfere
    rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf
    
    # IMPORTANT: Remove any drop-in files that might override our settings
    rm -f /etc/ssh/sshd_config.d/*-no-password.conf
    rm -f /etc/ssh/sshd_config.d/*-disable-root.conf
    
    # Security banner configuration
    echo "WARNING: Unauthorized access is strictly prohibited. All connections are monitored and logged." > /etc/issue.net
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    
    # Test SSH configuration before restart
    if sshd -t; then
        systemctl restart ssh
        log "SSH configuration applied successfully"
        log "Root login with password is ENABLED on port 8222"
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
#    chattr +i /etc/resolv.conf || log "WARNING: Cannot make resolv.conf immutable"
    
    # Network bridge configuration for virtualization
    if ! grep -q "vmbr1" /etc/network/interfaces; then
        cat >> /etc/network/interfaces << 'EOF'

# SAFYRA bridge interface for internal VMs
auto vmbr1
iface vmbr1 inet static
    address 10.10.10.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
EOF
        log "Bridge interface vmbr1 configured in /etc/network/interfaces"
    fi
    
    # Create the bridge immediately if it doesn't exist
    if ! ip link show vmbr1 &>/dev/null; then
        log "Creating bridge vmbr1 immediately..."
        ip link add name vmbr1 type bridge
        ip addr add 10.10.10.1/24 dev vmbr1
        ip link set vmbr1 up
        
        # Configure bridge properties
        echo 0 > /sys/class/net/vmbr1/bridge/stp_state
        echo 0 > /sys/class/net/vmbr1/bridge/forward_delay
        
        log "Bridge vmbr1 created and configured"
    else
        log "Bridge vmbr1 already exists"
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
    
    # Essential packages installation (including nginx for bastion proxy)
    local packages=(
        "auditd" "libguestfs-tools" "libpam-tmpdir" "qemu-guest-agent"
        "wget" "git" "sudo" "curl" "unzip" "gnupg" "software-properties-common"
        "lynis" "clamav" "nftables" "iptables-persistent" "fail2ban"
        "rsyslog" "logrotate" "htop" "tree" "vim" "net-tools"
        "nginx" "socat"
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



# Secure user management with SSH keys
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
            echo "BASTION_HOST=${BASTION_HOST}"
            echo "BASTION_PORT=${BASTION_PORT}"
            echo "BASTION_USER=${BASTION_USER}"
        } > "$SAFYRA_CREDS_FILE"
        chmod 600 "$SAFYRA_CREDS_FILE"
        
        log "User safyradmin created with secure password and SSH key"
    fi
}

# VM Template creation and bastion setup
setup_vm_infrastructure() {
    log "Setting up VM infrastructure..."
    
    # Wait for Proxmox to be ready
    sleep 30
    
    # Download Debian cloud image
    cd /tmp
    if [[ ! -f debian-12-generic-amd64.qcow2 ]]; then
        wget https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2 || {
            log "WARNING: Failed to download Debian cloud image"
            return 1
        }
    fi
    
    # Create VM template if it doesn't exist
    if ! qm list | grep -q "9000"; then
        log "Creating Debian 12 cloud-init template..."
        
        # Create the template VM
        qm create 9000 --name debian-12-cloudinit-template --memory 2048 --cores 2 --net0 virtio,bridge=vmbr1
        
        # Import disk
        qm importdisk 9000 debian-12-generic-amd64.qcow2 local
        
        # Configure template
        qm set 9000 --scsihw virtio-scsi-pci --scsi0 local:9000/vm-9000-disk-0.raw
        qm set 9000 --ide2 local:cloudinit
        qm set 9000 --boot c --bootdisk scsi0
        qm set 9000 --serial0 socket --vga serial0
        
        # Convert to template
        qm template 9000
        
        log "VM template 9000 created successfully"
    fi
    
    # Create bastion VM if it doesn't exist
    if ! qm list | grep -q "200"; then
        log "Creating bastion VM..."
        
        # Clone template for bastion
        qm clone 9000 200 --name bastion-safyra --full
        
        # Configure bastion VM
        qm set 200 \
            --memory 4096 \
            --cores 2 \
            --onboot 1 \
            --ciuser ${BASTION_USER} \
            --ipconfig0 ip=10.10.10.100/24,gw=10.10.10.1 \
            --nameserver 9.9.9.9 \
            --sshkeys /root/.ssh/authorized_keys
        
        # Resize disk to 32GB
        qm disk resize 200 scsi0 32G
        qm rescan
        
        # Start the VM
        qm start 200
        
        log "Bastion VM 200 created and started"
    fi
    
    # Clean up
    rm -f /tmp/debian-12-generic-amd64.qcow2
}

# Terraform user configuration for Proxmox
# Terraform user configuration for Proxmox - FIXED VERSION
configure_terraform_user() {
    log "Configuring Terraform user for Proxmox..."
    
    # Create Terraform user with minimal permissions
    if ! pveum user list | grep -q "terraform@pve"; then
        log "Terraform user does not exist. Creating it now..."
        if pveum user add terraform@pve -comment "Terraform Automation User"; then
            log "Terraform user created successfully"
        else
            log "Warning: Failed to create Terraform user. It might already exist or there was another issue."
        fi
    else
        log "Terraform user already exists. Skipping user creation."
    fi
    
    # Create comprehensive Terraform role with ALL necessary permissions
    if ! pveum role list | grep -q "TerraformRole"; then
        log "TerraformRole does not exist. Creating it now..."
        if pveum role add TerraformRole -privs \
"VM.Allocate,VM.Audit,VM.Clone,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.Console,VM.Migrate,VM.Monitor,VM.PowerMgmt,\
Datastore.Allocate,Datastore.AllocateSpace,Datastore.Audit,\
Pool.Allocate,Pool.Audit,\
Sys.Audit,Sys.Console,Sys.Modify,Sys.PowerMgmt,\
SDN.Use,\
User.Modify"; then
            log "TerraformRole created with comprehensive permissions"
        else
            log "Warning: Failed to create TerraformRole. It might already exist or there was another issue."
        fi
    else
        log "TerraformRole already exists. Skipping role creation."
    fi  
    
    # Assign role to user with proper path permissions
    log "Assigning TerraformRole to user..."
    pveum aclmod / -user terraform@pve -role TerraformRole
    pveum aclmod /nodes -user terraform@pve -role TerraformRole
    pveum aclmod /storage -user terraform@pve -role TerraformRole
    pveum aclmod /pool -user terraform@pve -role TerraformRole
    
    # CRITICAL: Add specific permission for VM template 9000
    pveum aclmod /vms/9000 -user terraform@pve -role TerraformRole
    log "Specific permissions granted for VM template 9000"
    
    # Check if a token with the specific ID already exists
    local token_exists=0
    if pveum user token list terraform@pve 2>/dev/null | grep -q "terraform-token"; then
        token_exists=1
    fi
    
    if [ "$token_exists" -eq 0 ]; then
        log "Terraform API token does not exist. Generating a new one..."
        local token_info
        if token_info=$(pveum user token add terraform@pve terraform-token --privsep 0 --output-format json 2>/dev/null); then
            local token_value=$(echo "$token_info" | grep -o '"value":"[^"]*"' | cut -d'"' -f4)
            
            # Store in secure file with proper format
            cat > "/root/.terraform-credentials" << EOF
# Terraform Proxmox Credentials
# Generated: $(date)
export TF_VAR_proxmox_api_url="https://localhost:8006/api2/json"
export TF_VAR_proxmox_user="terraform@pve"
export TF_VAR_proxmox_token="PVEAPIToken=terraform@pve!terraform-token=${token_value}"
# Don't set password when using token
# export TF_VAR_proxmox_password=""

# Usage: source this file before running terraform
# source /root/.terraform-credentials
EOF
            chmod 600 "/root/.terraform-credentials"
            
            log "✅ Terraform token generated and stored in /root/.terraform-credentials"
            log "📋 Token format: PVEAPIToken=terraform@pve!terraform-token=${token_value}"
            
            # Test the token
            log "🧪 Testing token authentication..."
            if curl -k -H "Authorization: PVEAPIToken=terraform@pve!terraform-token=${token_value}" \
               "https://localhost:8006/api2/json/version" >/dev/null 2>&1; then
                log "✅ Token authentication test successful"
            else
                log "⚠️ Token authentication test failed"
            fi
        else
            log "❌ Failed to generate token. This could be due to a race condition or a transient error."
            return 1
        fi
    else
        log "Terraform API token already exists. Skipping token generation."
        log "Note: If you need to regenerate the token, delete it first with:"
        log "pveum user token remove terraform@pve terraform-token"
    fi
    
    # Verify permissions are correctly set
    log "📋 Verifying Terraform user permissions..."
    pveum user list terraform@pve || log "Warning: User verification failed"
    pveum acl list | grep "terraform@pve" || log "Warning: No ACL entries found for terraform user"
}

# Enhanced firewall configuration with NAT rules for bastion
configure_firewall() {
    log "Configuring firewall with persistent rules and NAT for bastion..."
    
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
    
    # NAT for internal network (general)
    iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o vmbr0 -j MASQUERADE
    iptables -A FORWARD -s 10.10.10.0/24 -o vmbr0 -j ACCEPT
    iptables -A FORWARD -d 10.10.10.0/24 -i vmbr0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # NAT rules for bastion access
    # SSH to bastion
    iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 2222 -j DNAT --to-destination 10.10.10.100:22
    iptables -A FORWARD -p tcp -d 10.10.10.100 --dport 22 -j ACCEPT
    
    # Web interfaces through bastion
    iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 8080 -j DNAT --to-destination 10.10.10.100:8080
    iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 8081 -j DNAT --to-destination 10.10.10.100:8081
    iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 8082 -j DNAT --to-destination 10.10.10.100:8082
    
    iptables -A FORWARD -p tcp -d 10.10.10.100 --dport 8080 -j ACCEPT
    iptables -A FORWARD -p tcp -d 10.10.10.100 --dport 8081 -j ACCEPT
    iptables -A FORWARD -p tcp -d 10.10.10.100 --dport 8082 -j ACCEPT
    
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

# Configure Nginx as reverse proxy for bastion
configure_nginx_proxy() {
    log "Configuring Nginx reverse proxy..."
    
    # Create nginx configuration for VM proxy
    cat > /etc/nginx/sites-available/vm-proxy << 'EOF'
# Proxmox Web UI
server {
    listen 8080;
    server_name _;

    location / {
        proxy_pass https://10.10.10.1:8006;
        proxy_ssl_verify off;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for Proxmox
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
    }
}

# Template for future VMs - example VM web on 10.10.10.101:80
server {
    listen 8081;
    server_name _;

    location / {
        proxy_pass http://10.10.10.101:80;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Template for VM with HTTPS interface - example on 10.10.10.102:443
server {
    listen 8082;
    server_name _;

    location / {
        proxy_pass https://10.10.10.102:443;
        proxy_ssl_verify off;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

    # Remove default nginx sites and enable our proxy
    rm -f /etc/nginx/sites-enabled/*
    ln -s /etc/nginx/sites-available/vm-proxy /etc/nginx/sites-enabled/
    
    # Test nginx configuration
    if nginx -t; then
        systemctl restart nginx
        systemctl enable nginx
        log "Nginx reverse proxy configured successfully"
    else
        log "WARNING: Nginx configuration test failed"
    fi
}

# Generate SSH client configuration helper
generate_ssh_config() {
    log "Generating SSH client configuration..."
    
    cat > /root/generate-ssh-config.sh << EOF
#!/bin/bash

BASTION_HOST="${BASTION_HOST}"
BASTION_PORT="${BASTION_PORT}"
BASTION_USER="${BASTION_USER}"

cat > /root/ssh-client-config << SSHEOF
# Configuration SSH pour Safyra
# Copiez ce contenu dans votre fichier ~/.ssh/config

Host safyra-bastion
    HostName \${BASTION_HOST}
    Port \${BASTION_PORT}
    User \${BASTION_USER}
    # Tunnels automatiques vers les interfaces web
    LocalForward 8080 localhost:8080  # Proxmox Web UI
    LocalForward 8081 localhost:8081  # VM Web 1
    LocalForward 8082 localhost:8082  # VM Web 2

Host safyra-proxmox
    HostName 10.10.10.1
    Port 8222
    User root
    ProxyJump safyra-bastion

# Alias rapides
Host pve
    HostName 10.10.10.1
    Port 8222
    User root
    ProxyJump safyra-bastion

Host bastion
    HostName \${BASTION_HOST}
    Port \${BASTION_PORT}
    User \${BASTION_USER}
SSHEOF

echo "Configuration SSH générée dans /root/ssh-client-config"
echo ""
echo "=== Instructions pour le client ==="
echo "1. Téléchargez le fichier:"
echo "   scp \${BASTION_USER}@\${BASTION_HOST}:\${BASTION_PORT}/root/ssh-client-config ~/.ssh/config-safyra"
echo ""
echo "2. Ajoutez le contenu à votre ~/.ssh/config:"
echo "   cat ~/.ssh/config-safyra >> ~/.ssh/config"
echo ""
echo "3. Connectez-vous avec les tunnels:"
echo "   ssh safyra-bastion"
echo ""
echo "4. Accédez aux interfaces web:"
echo "   http://localhost:8080  -> Proxmox"
echo "   http://localhost:8081  -> VM Web 1"
echo "   http://localhost:8082  -> VM Web 2"
EOF

    chmod +x /root/generate-ssh-config.sh
    
    # Generate the configuration immediately with proper variable substitution
    cat > /root/ssh-client-config << EOF
# Configuration SSH pour Safyra
# Copiez ce contenu dans votre fichier ~/.ssh/config

Host safyra-bastion
    HostName ${BASTION_HOST}
    Port ${BASTION_PORT}
    User ${BASTION_USER}
    # Tunnels automatiques vers les interfaces web
    LocalForward 8080 localhost:8080  # Proxmox Web UI
    LocalForward 8081 localhost:8081  # VM Web 1
    LocalForward 8082 localhost:8082  # VM Web 2

Host safyra-proxmox
    HostName 10.10.10.1
    Port 8222
    User root
    ProxyJump safyra-bastion

# Alias rapides
Host pve
    HostName 10.10.10.1
    Port 8222
    User root
    ProxyJump safyra-bastion

Host bastion
    HostName ${BASTION_HOST}
    Port ${BASTION_PORT}
    User ${BASTION_USER}
EOF
    
    log "SSH client configuration generated at /root/ssh-client-config"
}

# System security configuration
configure_security() {
    log "Configuring system security with comprehensive audit rules..."
    
    # System audit configuration
    if systemctl is-active --quiet auditd; then
        log "auditd service already active"
    else
        systemctl enable auditd
        systemctl start auditd
        log "auditd service enabled and started"
    fi
    
    # Main auditd configuration
    cat > /etc/audit/auditd.conf << 'EOF'
# SAFYRA Audit Configuration
# Main audit configuration for SAFYRA environment

# Log location and format
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = adm

# Log size and rotation settings
max_log_file = 100
num_logs = 10
max_log_file_action = ROTATE

# Actions when low on disk space
space_left = 500
space_left_action = SYSLOG
admin_space_left = 100
admin_space_left_action = SUSPEND

# Actions on disk errors
disk_full_action = SUSPEND
disk_error_action = SUSPEND

# Performance and security settings
freq = 50
flush = INCREMENTAL_ASYNC
verify_email = yes
name_format = HOSTNAME
priority_boost = 4

# Dispatcher for centralization (optional)
dispatcher = /sbin/audispd
disp_qos = lossy
EOF

    # SAFYRA-specific audit rules
    cat > /etc/audit/rules.d/safyra-audit.rules << 'EOF'
# SAFYRA Comprehensive Audit Rules
# Complete audit rules for SAFYRA environment
# Auto-generated by SAFYRA installation script

# Delete existing rules
-D

# Buffer configuration
-b 8192

# Fail if unable to load rules
-f 1

# ==== CRITICAL SYSTEM MONITORING ====

# 1. Monitor critical system files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# 2. Monitor authorization system
-w /etc/sudoers -p wa -k privilege-escalation
-w /etc/sudoers.d/ -p wa -k privilege-escalation

# 3. Monitor network configuration (critical for Proxmox)
-w /etc/network/interfaces -p wa -k network-config
-w /etc/hosts -p wa -k network-config
-w /etc/hostname -p wa -k network-config
-w /etc/resolv.conf -p wa -k network-config

# 4. Monitor SSH (custom port 8222)
-w /etc/ssh/sshd_config -p wa -k ssh-config
-w /etc/ssh/sshd_config.d/ -p wa -k ssh-config
-w /root/.ssh/ -p wa -k ssh-keys
-w /home/safyradmin/.ssh/ -p wa -k ssh-keys

# ==== PROXMOX SPECIFIC MONITORING ====

# 5. Proxmox configuration
-w /etc/pve/ -p wa -k proxmox-config
-w /etc/default/pveproxy -p wa -k proxmox-proxy

# 6. VM and container monitoring
-w /var/lib/vz/ -p wa -k vm-storage
-w /etc/pve/qemu-server/ -p wa -k vm-config
-w /etc/pve/lxc/ -p wa -k container-config

# 7. Monitor certificates and keys
-w /etc/pve/priv/ -p wa -k proxmox-certs
-w /etc/ssl/certs/ -p wa -k ssl-certs
-w /etc/ssl/private/ -p wa -k ssl-private

# ==== NGINX & REVERSE PROXY MONITORING ====

# 8. Nginx configuration (used for reverse proxy)
-w /etc/nginx/nginx.conf -p wa -k nginx-config
-w /etc/nginx/sites-available/ -p wa -k nginx-sites
-w /etc/nginx/sites-enabled/ -p wa -k nginx-sites

# ==== SYSTEM SECURITY MONITORING ====

# 9. Monitor login attempts
-w /var/log/auth.log -p wa -k auth-logs
-w /var/log/secure -p wa -k auth-logs

# 10. Monitor service modifications
-w /etc/systemd/system/ -p wa -k systemd-config
-w /lib/systemd/system/ -p wa -k systemd-config

# 11. Monitor firewall
-w /etc/iptables/ -p wa -k firewall-config
-a always,exit -F arch=b64 -S socket -F a0=10 -k network-socket-creation
-a always,exit -F arch=b32 -S socket -F a0=10 -k network-socket-creation

# ==== SENSITIVE COMMANDS MONITORING ====

# 12. System administration commands
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mount
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mount
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=4294967295 -k mount
-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=4294967295 -k mount
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=4294967295 -k mount

# 13. Monitor permission modifications
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# ==== PROXMOX COMMANDS MONITORING ====

# 14. Critical Proxmox commands
-a always,exit -F path=/usr/bin/qm -F perm=x -F auid>=1000 -F auid!=4294967295 -k proxmox-vm
-a always,exit -F path=/usr/bin/pct -F perm=x -F auid>=1000 -F auid!=4294967295 -k proxmox-container
-a always,exit -F path=/usr/bin/pveum -F perm=x -F auid>=1000 -F auid!=4294967295 -k proxmox-user
-a always,exit -F path=/usr/bin/pvesh -F perm=x -F auid>=1000 -F auid!=4294967295 -k proxmox-shell

# ==== TERRAFORM MONITORING ====

# 15. Monitor Terraform actions (for automation)
-a always,exit -F path=/usr/bin/terraform -F perm=x -F auid>=1000 -F auid!=4294967295 -k terraform
-w /root/.terraform.d/ -p wa -k terraform-config

# ==== SENSITIVE PROCESS MONITORING ====

# 16. Monitor critical daemon processes
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/sshd -k ssh-daemon
-a always,exit -F arch=b32 -S execve -F path=/usr/sbin/sshd -k ssh-daemon
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/nginx -k nginx-daemon
-a always,exit -F arch=b32 -S execve -F path=/usr/sbin/nginx -k nginx-daemon

# ==== SENSITIVE FILE ACCESS MONITORING ====

# 17. Monitor system logs
-w /var/log/messages -p wa -k system-logs
-w /var/log/syslog -p wa -k system-logs
-w /var/log/daemon.log -p wa -k daemon-logs

# 18. Monitor security configurations
-w /etc/fail2ban/ -p wa -k fail2ban-config
-w /etc/iptables/rules.v4 -p wa -k iptables-rules
-w /etc/iptables/rules.v6 -p wa -k iptables-rules

# ==== FINALIZATION ====

# 19. Make rules immutable (disable modifications)
-e 2
EOF
    # Configure dispatcher for real-time alerts (modern auditd)
    # Check if audisp directory exists (older systems) or use audispd (newer systems)
    if [[ -d /etc/audisp/plugins.d/ ]]; then
        # Older auditd versions
        cat > /etc/audisp/plugins.d/safyra.conf << 'EOF'
# SAFYRA Real-time Alert Plugin
active = yes
direction = out
path = /usr/local/bin/safyra-audit-alert
type = always
args = 
format = string
EOF
    else
        # Create the directory if it doesn't exist and use modern path
        mkdir -p /etc/audit/plugins.d/
        cat > /etc/audit/plugins.d/safyra.conf << 'EOF'
# SAFYRA Real-time Alert Plugin
active = yes
direction = out
path = /usr/local/bin/safyra-audit-alert
type = always
args = 
format = string
EOF
        log "Created audit plugins directory and configured plugin"
    fi
    # Log all the commands executed by all users
    cat >> ~/.bashrc << 'BASHRC_END'
export PROMPT_COMMAND='RETRN_VAL=$?;logger -t LinuxCommandsWazuh -p local6.debug "User $(whoami) [$$]: $(history 1 | sed "s/^[ ]*[0–9]\+[ ]*//" )"'
BASHRC_END

    echo "local6.*   /var/log/commands.log" >> /etc/rsyslog.d/bash.conf
    sed -i 's|*.*;auth,authpriv.none|*.*;auth,authpriv.none,local6.none|g' /etc/rsyslog.conf
    systemctl restart rsyslog
    # Real-time alert script for critical events
    cat > /usr/local/bin/safyra-audit-alert << 'EOF'
#!/bin/bash
# SAFYRA Audit Alert Script
# Real-time processing of critical audit events

LOG_FILE="/var/log/safyra-security-alerts.log"
CRITICAL_EVENTS=("ssh-config" "proxmox-config" "privilege-escalation" "network-config")

while read line; do
    # Check if event contains critical keywords
    for event in "${CRITICAL_EVENTS[@]}"; do
        if echo "$line" | grep -q "$event"; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] CRITICAL AUDIT EVENT: $line" >> "$LOG_FILE"
            # Optional: send alert via email or webhook
            # curl -X POST -H "Content-Type: application/json" \
            #      -d "{\"text\":\"SAFYRA Security Alert: $line\"}" \
            #      YOUR_WEBHOOK_URL
            break
        fi
    done
done
EOF

    chmod +x /usr/local/bin/safyra-audit-alert

    # Configure audit log rotation
    cat > /etc/logrotate.d/safyra-audit << 'EOF'
/var/log/audit/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root adm
    postrotate
        /sbin/service auditd restart 2>/dev/null || true
    endscript
}

/var/log/safyra-security-alerts.log {
    daily
    rotate 90
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

    # Restart auditd to apply new rules
    log "Reloading audit rules..."
    if systemctl restart auditd; then
        log "✅ Audit rules loaded successfully"
    else
        log "⚠️ Warning: Failed to restart auditd, trying to reload rules manually"
        auditctl -R /etc/audit/rules.d/safyra-audit.rules || true
    fi

    # Verify applied rules
    log "Verifying audit rules..."
    RULES_COUNT=$(auditctl -l | wc -l)
    log "📊 Active audit rules: $RULES_COUNT"
    
    # Fail2Ban configuration for SSH
    cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = 8222
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[nginx-http-auth]
enabled = true
port = 8080,8081,8082
logpath = /var/log/nginx/error.log
maxretry = 5
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
        lynis audit system > /root/lynis_report.txt 2>&1 
        chmod 600 /root/lynis_report.txt
        log "Lynis audit report generated: /root/lynis_report.txt"
    fi
    
    # Update antivirus signatures
    if command -v freshclam &> /dev/null; then
        freshclam || log "WARNING: Failed to update ClamAV signatures"
    fi
}

# Wait for bastion VM to be ready and configure it
configure_bastion_vm() {
    log "Waiting for bastion VM to be ready..."
    
    local max_attempts=60
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if ping -c 1 10.10.10.100 &>/dev/null; then
            log "Bastion VM is reachable"
            break
        fi
        
        log "Waiting for bastion VM... attempt $attempt/$max_attempts"
        sleep 10
        ((attempt++))
    done
    
    if [[ $attempt -gt $max_attempts ]]; then
        log "WARNING: Bastion VM did not become reachable within expected time"
        return 1
    fi
    
    # Wait a bit more for SSH to be ready
    sleep 30
    
    # Create a script to configure the bastion VM with nginx reverse proxy
    cat > /tmp/configure_bastion.sh << 'EOF'
#!/bin/bash
set -e

echo "Configuring bastion VM..."

# Update the system
apt update && apt upgrade -y

# Install essential packages including nginx
apt install -y curl nginx wget git vim htop net-tools fail2ban ufw socat auditd rsyslog

# Configure nginx as reverse proxy
cat > /etc/nginx/sites-available/vm-proxy << 'NGINXEOF'
# Proxmox Web UI
server {
    listen 8080;
    server_name _;

    location / {
        proxy_pass https://10.10.10.1:8006;
        proxy_ssl_verify off;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for Proxmox
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
    }
}

# Template for future VMs - example VM web on 10.10.10.101:80
server {
    listen 8081;
    server_name _;

    location / {
        proxy_pass http://10.10.10.101:80;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Template for VM with HTTPS interface - example on 10.10.10.102:443
server {
    listen 8082;
    server_name _;

    location / {
        proxy_pass https://10.10.10.102:443;
        proxy_ssl_verify off;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINXEOF

# Remove default nginx site and enable our proxy
rm -f /etc/nginx/sites-enabled/default
ln -s /etc/nginx/sites-available/vm-proxy /etc/nginx/sites-enabled/

# Test nginx configuration
if nginx -t; then
    systemctl restart nginx
    systemctl enable nginx
    echo "Nginx reverse proxy configured successfully"
else
    echo "ERROR: Nginx configuration test failed"
    exit 1
fi

# Configure SSH to allow forwarding (should already be configured by cloud-init)
if ! grep -q "AllowTcpForwarding yes" /etc/ssh/sshd_config; then
    echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config
    echo "AllowAgentForwarding yes" >> /etc/ssh/sshd_config
    echo "PermitTunnel yes" >> /etc/ssh/sshd_config
    echo "GatewayPorts no" >> /etc/ssh/sshd_config
    echo "AllowStreamLocalForwarding yes" >> /etc/ssh/sshd_config
    systemctl restart sshd
fi

# Configure basic firewall
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 8080/tcp
ufw allow 8081/tcp
ufw allow 8082/tcp
ufw allow from 10.10.10.0/24

# Log all the commands executed by all users
cat >> ~/.bashrc << 'BASHRC_END'
export PROMPT_COMMAND='RETRN_VAL=$?;logger -t LinuxCommandsWazuh -p local6.debug "User $(whoami) [$$]: $(history 1 | sed "s/^[ ]*[0–9]\+[ ]*//" )"'
BASHRC_END

echo "local6.*   /var/log/commands.log" >> /etc/rsyslog.d/bash.conf
sed -i 's|*.*;auth,authpriv.none|*.*;auth,authpriv.none,local6.none|g' /etc/rsyslog.conf
systemctl restart rsyslog

# Verify nginx is listening on the correct ports
sleep 5
echo "Nginx status:"
systemctl status nginx --no-pager
echo "Listening ports:"
netstat -tlnp | grep nginx

echo "Bastion VM configuration completed successfully"
EOF

    # Copy and execute the script on the bastion
    if scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /tmp/configure_bastion.sh ${BASTION_USER}@10.10.10.100:/tmp/; then
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${BASTION_USER}@10.10.10.100 "sudo bash /tmp/configure_bastion.sh"; then
            log "Bastion VM configured successfully with nginx reverse proxy"
        else
            log "WARNING: Failed to configure bastion VM"
            return 1
        fi
    else
        log "WARNING: Failed to copy configuration script to bastion VM"
        return 1
    fi
    
    # Clean up
    rm -f /tmp/configure_bastion.sh
    
    # Verify nginx is working on the bastion
    log "Verifying nginx configuration on bastion..."
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${BASTION_USER}@10.10.10.100 "curl -s -o /dev/null -w '%{http_code}' http://localhost:8080" | grep -q "200\|302\|401"; then
        log "✅ Nginx reverse proxy is working on bastion"
    else
        log "⚠️  Nginx may not be responding correctly on bastion"
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
        echo "Users created: safyradmin"
        echo "SSH Port: 8222"
        echo "Bastion SSH Port: ${BASTION_PORT}"
        echo "Bastion User: ${BASTION_USER}"
        echo "Installation logs: $LOG_FILE"
        echo "Credentials: $SAFYRA_CREDS_FILE"
        echo "SSH Config Generator: /root/generate-ssh-config.sh"
        echo "VM Template ID: 9000 (Debian 12 Cloud-Init)"
        echo "Bastion VM ID: 200 (IP: 10.10.10.100)"
        echo "===================================="
        echo "Access Instructions:"
        echo "1. SSH to bastion: ssh ${BASTION_USER}@${BASTION_HOST} -p ${BASTION_PORT}"
        echo "2. SSH to Proxmox via bastion: ssh root@10.10.10.1 -p 8222 -o ProxyJump=${BASTION_USER}@${BASTION_HOST}:${BASTION_PORT}"
        echo "3. Web access (via SSH tunnels):"
        echo "   - Proxmox UI: http://localhost:8080"
        echo "   - VM Web 1: http://localhost:8081"
        echo "   - VM Web 2: http://localhost:8082"
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
    configure_nginx_proxy
    generate_ssh_config
    configure_security
    
    # VM setup (with error handling)
    if setup_vm_infrastructure; then
        log "VM infrastructure setup completed"
        # Wait and configure bastion VM
        sleep 60  # Give more time for VM to fully boot
        configure_bastion_vm
    else
        log "WARNING: VM infrastructure setup failed, continuing without bastion VM"
    fi
    
    run_security_audit
    cleanup_and_finalize
    
    log "=========================================="
    log "SAFYRA INSTALLATION COMPLETED SUCCESSFULLY"
    log "Check /root/safyra_install_report.txt for access instructions"
    log "REBOOT REQUIRED IN 60 SECONDS..."
    log "=========================================="
    
    # Display important information before reboot
    echo ""
    echo "=== IMPORTANT ACCESS INFORMATION ==="
    echo "SSH to bastion: ssh ${BASTION_USER}@${BASTION_HOST} -p ${BASTION_PORT}"
    echo "SSH config helper: /root/generate-ssh-config.sh"
    echo "Credentials file: $SAFYRA_CREDS_FILE"
    echo "Installation report: /root/safyra_install_report.txt"
    echo "===================================="
    
    # Reboot with delay to allow log reading
    sleep 60
    reboot
}

# Execute main script
main "$@"
