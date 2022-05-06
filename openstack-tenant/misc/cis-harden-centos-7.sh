#!/bin/bash
# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PATH='/usr/bin:/bin:/usr/sbin:/sbin'; export PATH

log() {
	echo
	echo "================================================================================"
	echo "$*"
}

# Abort on errors
set -e

log "1.1.1.x Disabling mounting of unnecessary filesystems"
sudo tee /etc/modprobe.d/CIS.conf <<EOT
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOT

for FS in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
	sudo rmmod "$FS" || true
done

log "1.1.17 Ensure noexec option set on /dev/shm partition"
echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" \
	| sudo tee -a /etc/fstab
sudo mount -o remount,noexec /dev/shm

log "1.3.1 Ensure AIDE is installed"
sudo yum -y install aide
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

log "1.3.2 Ensure filesystem integrity is regularly checked"
sudo tee /etc/cron.daily/aide <<'EOT'
#!/bin/sh
umask 027
/usr/sbin/aide --check >/var/log/aide-check.log 2>&1
EOT
sudo chmod a+rx /etc/cron.daily/aide

log "1.4.1 Ensure permissions on bootloader config are configured"
for GRUB_CFG in /boot/efi/EFI/centos/grub.cfg \
	        /boot/efi/EFI/centos/user.cfg \
		/boot/grub2/grub.cfg \
		/boot/grub2/user.cfg; do
	sudo chown root:root "$GRUB_CFG" || true
	sudo chmod og-rwx "$GRUB_CFG" || true
done

log "1.6.4 Ensure core dumps are restricted"
echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
echo "fs.suid_dumpable = 0" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w fs.suid_dumpable=0

log "1.5.3 Ensure address space layout randomization (ASLR) is enabled"
echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
sysctl -w kernel.randomize_va_space=2

log "2.2.7 Ensure NFS and RPC are not enabled"
sudo systemctl disable nfs
sudo systemctl disable nfs-server
sudo systemctl disable rpcbind

log "3.1.1 Ensure IP forwarding is disabled"
echo "net.ipv4.ip_forward = 0" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv4.route.flush=1

log "3.1.2 Ensure packet redirect sending is disabled"
sudo tee -a /etc/sysctl.conf <<EOT
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOT
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
sudo sysctl -w net.ipv4.route.flush=1

log "3.2.1 Ensure source routed packets are not accepted"
sudo tee -a /etc/sysctl.conf <<EOT
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOT
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
sudo sysctl -w net.ipv4.route.flush=1

log "3.2.2 Ensure ICMP redirects are not accepted"
sudo tee -a /etc/sysctl.conf <<EOT
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOT
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.route.flush=1

log "3.2.3 Ensure secure ICMP redirects are not accepted"
sudo tee -a /etc/sysctl.conf <<EOT
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
EOT
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
sudo sysctl -w net.ipv4.route.flush=1

log "3.2.4 Ensure suspicious packets are logged"
sudo tee -a /etc/sysctl.conf <<EOT
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOT
sudo sysctl -w net.ipv4.conf.all.log_martians=1
sudo sysctl -w net.ipv4.conf.default.log_martians=1
sudo sysctl -w net.ipv4.route.flush=1

log "3.2.5 Ensure broadcast ICMP requests are ignored"
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sudo sysctl -w net.ipv4.route.flush=1

log "3.2.6 Ensure bogus ICMP responses are ignored"
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sudo sysctl -w net.ipv4.route.flush=1

log "3.2.7 Ensure Reverse Path Filtering is enabled"
sudo tee -a /etc/sysctl.conf <<EOT
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOT
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
sudo sysctl -w net.ipv4.route.flush=1

log "3.2.8 Ensure TCP SYN Cookies is enabled"
echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.route.flush=1

log "3.6.3 Ensure loopback traffic is configured"
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP

log "4.2.1.3 Ensure rsyslog default file permissions configured"
echo '$FileCreateMode 0640' | sudo tee /etc/rsyslog.d/50-CIS.conf
sudo pkill -HUP rsyslogd

log "4.2.4 Ensure permissions on all logfiles are configured"
sudo find /var/log -type f -exec chmod g-wx,o-rwx {} +

log "5.1.x Ensure permissions on crontab fiiles"
for CFILE in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
	sudo chown root:root "$CFILE"
	sudo chmod og-rwx "$CFILE"
done

log "5.1.8 Ensure at/cron is restricted to authorized users"
sudo  rm /etc/cron.deny || true
sudo  rm /etc/at.deny || true
sudo  touch /etc/cron.allow || true
sudo  touch /etc/at.allow || true
sudo  chmod og-rwx /etc/cron.allow || true || true
sudo  chmod og-rwx /etc/at.allow || true
sudo  chown root:root /etc/cron.allow || true
sudo  chown root:root /etc/at.allow || true

echo "Authorized uses only. All activity may be monitored and reported." \
	| sudo tee /etc/issue

echo "Authorized uses only. All activity may be monitored and reported." \
	| sudo tee /etc/issue.net

set_sshd_param() {
	param="$1"
	value="$2"
	if sudo grep "^#*${param}" /etc/ssh/sshd_config >/dev/null; then
		sudo sed -i -e "/^#${param}/s/^#//" \
			    -e "s|^${param}.*$|${param} ${value}|" \
			    /etc/ssh/sshd_config
	else
		echo "$param $value" | sudo tee -a /etc/ssh/sshd_config
	fi
}

echo | sudo tee -a /etc/ssh/sshd_config

log "5.2.2 Ensure SSH Protocol is set to 2"
set_sshd_param Protocol 2

log "5.2.3 Ensure SSH LogLevel is set to INFO"
set_sshd_param LogLevel INFO

log "5.2.4 Ensure SSH X11 forwarding is disabled"
set_sshd_param X11Forwarding no

log "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less"
set_sshd_param MaxAuthTries 4

log "5.2.6 Ensure SSH IgnoreRhosts is enabled"
set_sshd_param IgnoreRhosts yes

log "5.2.7 Ensure SSH HostbasedAuthentication is disabled"
set_sshd_param HostbasedAuthentication no

log "5.2.8 Ensure SSH root login is disabled"
set_sshd_param PermitRootLogin no

log "5.2.9 Ensure SSH PermitEmptyPasswords is disabled"
set_sshd_param PermitEmptyPasswords no

log "5.2.10 Ensure SSH PermitUserEnvironment is disabled"
set_sshd_param PermitUserEnvironment no

log "5.2.11 Ensure only approved MAC algorithms are used"
set_sshd_param MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

log "5.2.12 Ensure SSH Idle Timeout Interval is configured"
set_sshd_param ClientAliveInterval 300
set_sshd_param ClientAliveCountMax 0

log "5.2.13 Ensure SSH LoginGraceTime is set to one minute or less"
set_sshd_param LoginGraceTime 60

log "5.2.14 Ensure SSH access is limited"
set_sshd_param AllowUsers centos

log "5.2.15 Ensure SSH warning banner is configured"
set_sshd_param Banner /etc/issue.net

sudo sshd -t
sudo systemctl reload sshd

log "5.3.1 Ensure password creation requirements are configured"
sudo tee /etc/security/pwquality.conf <<'EOT'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOT

set_login_defs_param() {
	param="$1"
	value="$2"
	if sudo grep "^#*${param}" /etc/login.defs >/dev/null; then
		sudo sed -i -e "/^#${param}/s/^#//" \
			    -e "s|^${param}.*$|${param} ${value}|" \
			    /etc/login.defs
	else
		echo "$param $value" | sudo tee -a /etc/login.defs
	fi
}

log "5.4.1.1 Ensure password expiration is 365 days or less"
set_login_defs_param PASS_MAX_DAYS 365
for PWUSER in centos; do
	sudo chage --maxdays 365 "$PWUSER"
done

log "5.4.1.2 Ensure minimum days between password changes is 7 or more"
set_login_defs_param PASS_MIN_DAYS 7
for PWUSER in centos; do
	sudo chage --mindays 7 "$PWUSER"
done

log "5.4.1.x Password policies"
sudo tee /etc/pam.d/password-auth <<EOT
auth        required      pam_env.so
auth        required      pam_faildelay.so delay=2000000

auth        required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth        [success=1 default=bad] pam_unix.so
auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth        sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900

auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5


password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOT

sudo tee /etc/pam.d/system-auth <<EOT
auth        required      pam_env.so
auth        required      pam_faildelay.so delay=2000000

auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth        [success=1 default=bad] pam_unix.so
auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900

auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOT

log "5.4.1.4 Ensure inactive password lock is 30 days or less"
sudo useradd -D -f 30
for PWUSER in centos; do
	chage --inactive 30 "$PWUSER"
done

log "5.4.4 Ensure default user umask is 027 or more restrictive"
for RCFILE in /etc/profile /etc/bashrc; do
	sed -i "s/\(^[ 	]*umask\) 0..$/\1 027/" "$RCFILE"
done
echo "umask 027" | sudo tee /etc/profile.d/default-umask.sh

log "5.6 Ensure access to the su command is restricted"
sudo sed -i '/^#auth[ 	]*required[ 	]*pam_wheel.so/s/^#//' /etc/pam.d/su

### Manual action required ###

log "1.4.2 Ensure bootloader password is set"
echo -e "\n\n**TODO** Run the following to set up a GRUB password:"
echo "# grub2-setpassword"
