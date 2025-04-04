set -e
export DEBIAN_FRONTEND=noninteractive

exec > /var/log/safyra_install.log 2>&1

echo "[START] SAFYRA INSTALL - $(date)"

hostnamectl set-hostname preprod-safyra

echo "Port 8222
PermitRootLogin yes
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no" > /etc/ssh/sshd_config

echo "WARNING: Unauthorized access is prohibited " > /etc/issue.net
sed -i 's/^UMASK.*/UMASK\t027/' /etc/login.defs
systemctl restart ssh

systemctl disable postfix
systemctl mask postfix

echo "nameserver 9.9.9.9" > /etc/resolv.conf

echo "deb http://deb.debian.org/debian bookworm main contrib
deb http://deb.debian.org/debian bookworm-updates main contrib
deb http://security.debian.org/debian-security bookworm-security main contrib" > /etc/apt/sources.list

echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-install-repo.list
echo 'APT::Get::Update::SourceListWarnings::NonFreeFirmware "false";' > /etc/apt/apt.conf.d/no-bookworm-firmware.conf

apt update
apt upgrade -y

apt install -y auditd libguestfs-tools libpam-tmpdir qemu-guest-agent wget git sudo curl unzip gnupg software-properties-common lynis clamav

echo "
auto vmbr1
iface vmbr1 inet static
    address 10.10.10.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0" >> /etc/network/interfaces

echo 'LISTEN_IP="10.10.10.1"' >> /etc/default/pveproxy
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
sysctl -p

curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com bookworm main" > /etc/apt/sources.list.d/hashicorp.list
apt update
apt install terraform -y

mkdir -p /var/lib/vz/template/iso
cd /var/lib/vz/template/iso
wget -q https://mirror.in2p3.fr/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2
cd ~

useradd safyradmin -m -s /bin/bash
echo "safyradmin:$(openssl rand -base64 18)" | chpasswd
usermod -aG sudo safyradmin

mkdir -p /home/safyradmin/.ssh /root/.ssh
chmod 700 /home/safyradmin/.ssh /root/.ssh
cp /root/.ssh/authorized_keys /home/safyradmin/.ssh/authorized_keys || true
chmod 600 /home/safyradmin/.ssh/authorized_keys /root/.ssh/authorized_keys
chown -R safyradmin:safyradmin /home/safyradmin/.ssh

pveum user add terraform@pve -comment "Terraform Automation"
pveum role add TerraformRole -privs "VM.Allocate VM.Audit Datastore.AllocateSpace Datastore.Audit Pool.Allocate Sys.Audit Sys.Console Sys.Modify VM.Clone VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Migrate VM.Monitor VM.PowerMgmt SDN.Use"
pveum aclmod / -user terraform@pve -role TerraformRole
pveum user token add terraform@pve terraform-token --output-format json > /etc/pve/.terraform-token.json
chmod 600 /etc/pve/.terraform-token.json

echo "TERRAFORM_PASSWORD=$(openssl rand -base64 18)" > /root/.safyra_credentials
chmod 600 /root/.safyra_credentials

lynis audit system > /root/lynis_report.txt
chmod 600 /root/lynis_report.txt

systemctl restart pveproxy ssh networking

echo "[DONE] SAFYRA INSTALL - $(date)"
