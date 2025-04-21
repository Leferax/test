set -e
export DEBIAN_FRONTEND=noninteractive

exec > /var/log/safyra_install.log 2>&1

echo "[START] SAFYRA INSTALL - $(date)"

hostnamectl set-hostname preprod-safyra

mkdir -p /var/lib/vz/template/iso
cd /var/lib/vz/template/iso
wget -q https://mirror.in2p3.fr/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2
cd ~

#systemctl stop pve-cluster pvedaemon pvestatd

#sleep 10 

#umount -lf /var/lib/vz
#lvremove -y vg/data
#lvcreate -l 100%FREE -T vg/data

#sleep 20

#systemctl start pve-cluster pvedaemon pvestatd
#pvesm add lvmthin local-lvm --vgname vg --thinpool data
#pvesm status


pveam download local debian-12-standard_12.7-1_amd64.tar.zst
pveam download local fedora-41-default_20241118_amd64.tar.xz

echo "
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# To modify the system-wide sshd configuration, create a  *.conf  file under
#  /etc/ssh/sshd_config.d/  which will be automatically included below
Include /etc/ssh/sshd_config.d/*.conf

# If you want to change the port on a SELinux system, you have to tell
# SELinux about this change.
# semanage port -a -t ssh_port_t -p tcp #PORTNUMBER
#
Port 8222
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
LogLevel VERBOSE

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to no to disable s/key passwords
#KbdInteractiveAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#KerberosUseKuserok yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
#GSSAPIEnablek5users no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of 'PermitRootLogin prohibit-password'.
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
# WARNING: 'UsePAM no' is not supported in this build and may cause several
# problems.
#UsePAM no

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
#X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem	sftp	/usr/libexec/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server" > /etc/ssh/sshd_config
rm -rf /etc/ssh/sshd_config.d/50-cloud-init.conf
echo "WARNING: Unauthorized access is prohibited " > /etc/issue.net
#sed -i 's/^UMASK.*/UMASK\t027/' /etc/login.defs
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




useradd safyradmin -m -s /bin/bash
SAFYRADMIN_PASSWORD=$(openssl rand -base64 18)
echo "safyradmin:${SAFYRADMIN_PASSWORD}" | chpasswd
usermod -aG sudo safyradmin
echo "SAFYRADMIN_PASSWORD=${SAFYRADMIN_PASSWORD}" >> /root/.safyra_credentials

cp -r /root/.ssh /root/.ssh.bak
mkdir -p /home/safyradmin/.ssh
chmod 700 /home/safyradmin/.ssh
cat /root/.ssh/authorized_keys >> /home/safyradmin/.ssh/authorized_keys 
chmod 600 /home/safyradmin/.ssh/authorized_keys
chown -R safyradmin:safyradmin /home/safyradmin/.ssh

pveum user add terraform@pve -comment "Terraform Automation"
pveum role add TerraformRole -privs "VM.Allocate VM.Audit Datastore.AllocateSpace Datastore.Audit Pool.Allocate Sys.Audit Sys.Console Sys.Modify VM.Clone VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Migrate VM.Monitor VM.PowerMgmt SDN.Use"
pveum aclmod / -user terraform@pve -role TerraformRole
pveum user token add terraform@pve terraform-token --output-format json > /etc/pve/.terraform-token.json
#chmod 600 /etc/pve/.terraform-token.json

#echo "TERRAFORM_PASSWORD=$(openssl rand -base64 18)" > /root/.safyra_credentials
chmod 600 /root/.safyra_credentials

lynis audit system > /root/lynis_report.txt
chmod 600 /root/lynis_report.txt

reboot 

echo "[DONE] SAFYRA INSTALL - $(date)"
