#!/bin/bash

set -e

# === LOGGING ===
LOG_FILE="/var/log/TEST_install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# === HEADER ===
echo -e "\n========================="
echo "TEST FULL POSTINSTALL"
echo "Started at: $(date)"
echo "========================="

# === REQUIREMENTS ===
export DEBIAN_FRONTEND=noninteractive
if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] This script must be run as root." >&2
  exit 1
fi

# === SET HOSTNAME ===
hostnamectl set-hostname preprod-TEST

# === SSH HARDENING ===
sed -i \
  -e 's/^#*Port.*/Port 8222/' \
  -e 's/^#*PermitRootLogin.*/PermitRootLogin yes/' \
  -e 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' \
  -e 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' \
  -e 's/^#*MaxAuthTries.*/MaxAuthTries 3/' \
  -e 's/^#*X11Forwarding.*/X11Forwarding no/' \
  /etc/ssh/sshd_config
echo '⚠️ WARNING: Unauthorized access is prohibited ⚠️' > /etc/issue.net
sed -i 's/^UMASK\s\+022/UMASK\t027/' /etc/login.defs
systemctl restart ssh

# === DISABLING SERVICES ===
systemctl disable postfix
systemctl mask postfix

# === DNS SETUP ===
echo "nameserver 9.9.9.9" > /etc/resolv.conf

# === APT SETUP ===
cat > /etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian bookworm main contrib
deb http://deb.debian.org/debian bookworm-updates main contrib
deb http://security.debian.org/debian-security bookworm-security main contrib
EOF

cat > /etc/apt/sources.list.d/pve-install-repo.list <<EOF
deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription
EOF

echo 'APT::Get::Update::SourceListWarnings::NonFreeFirmware "false";' > /etc/apt/apt.conf.d/no-bookworm-firmware.conf

apt update && apt upgrade -y

# === INSTALL TOOLS ===
apt install -y auditd libguestfs-tools libpam-tmpdir qemu-guest-agent wget git sudo curl unzip gnupg software-properties-common lynis clamav

# === NETWORK CONFIG ===
if ! grep -q "vmbr1" /etc/network/interfaces; then
  cat >> /etc/network/interfaces <<EOL

auto vmbr1
iface vmbr1 inet static
    address 10.10.10.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
EOL
fi

if ! grep -q "LISTEN_IP" /etc/default/pveproxy; then
  echo 'LISTEN_IP="10.10.10.1"' >> /etc/default/pveproxy
fi

grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

# === INSTALL TERRAFORM ===
curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
apt update && apt install terraform -y

# === FEDORA CLOUD IMAGE ===
mkdir -p /var/lib/vz/template/iso
cd /var/lib/vz/template/iso
wget -q https://mirror.in2p3.fr/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2
cd ~

# === CREATE admin ===
useradd admin -m -s /bin/bash
ADMIN_PASS=$(openssl rand -base64 18)
echo "admin:$ADMIN_PASS" | chpasswd
usermod -aG sudo admin

mkdir -p /home/admin/.ssh /root/.ssh
chmod 700 /home/admin/.ssh /root/.ssh

cat /root/.ssh/authorized_keys > /home/admin/.ssh/authorized_keys
chmod 600 /home/admin/.ssh/authorized_keys /root/.ssh/authorized_keys
chown -R admin:admin /home/admin/.ssh

# === TERRAFORM USER SETUP ===
pveum user add terraform@pve -comment "Terraform Automation"
pveum role add TerraformRole -privs "VM.Allocate VM.Audit Datastore.AllocateSpace Datastore.Audit Pool.Allocate Sys.Audit Sys.Console Sys.Modify VM.Clone VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Migrate VM.Monitor VM.PowerMgmt SDN.Use"
pveum aclmod / -user terraform@pve -role TerraformRole
pveum user token add terraform@pve terraform-token --output-format json > /etc/pve/.terraform-token.json
chmod 600 /etc/pve/.terraform-token.json

TF_PASS=$(openssl rand -base64 18)
echo "$TF_PASS" | pveum passwd terraform@pve --crypted 0
echo "TERRAFORM_PASSWORD=${TF_PASS}" >> /root/.TEST_credentials
chmod 600 /root/.TEST_credentials

# === SECURITY AUDIT ===
lynis audit system --quiet > /root/lynis_report.txt
chmod 600 /root/lynis_report.txt

# === SUMMARY ===
SERVER_IP=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d/ -f1 | head -n1)
cat > /root/server_provisioning_info.txt << EOF
==== TEST PROVISIONING SUMMARY ====
Date: $(date)
Hostname: $(hostname)
IP Address: $SERVER_IP
SSH Port: 8222

Admin user: admin
Admin password: stored in /root/.TEST_credentials
SSH key injected for admin and root

Terraform user: terraform@pve
Terraform token: /etc/pve/.terraform-token.json
Terraform password: stored in /root/.TEST_credentials

Lynis security report: /root/lynis_report.txt
EOF
chmod 600 /root/server_provisioning_info.txt


echo "[OK] TEST postinstall complete."
echo "Finished at: $(date)" >> "$LOG_FILE"
