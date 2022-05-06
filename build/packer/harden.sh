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

log "1.1.1.1 Ensure mounting of cramfs filesystems is disabled"
echo "install cramfs /bin/true" | sudo tee /etc/modprobe.d/cramfs.conf

log "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled"
echo "install freevxfs /bin/true" | sudo tee /etc/modprobe.d/freevxfs.conf

log "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled"
echo "install jffs2 /bin/true" | sudo tee /etc/modprobe.d/jffs2.conf

log "1.1.1.4 Ensure mounting of hfs filesystems is disabled"
echo "install hfs /bin/true" | sudo tee /etc/modprobe.d/hfs.conf

log "1.1.1.5 Ensure mounting of hfsplus filesystems is disabled"
echo "install hfsplus /bin/true" | sudo tee /etc/modprobe.d/hfsplus.conf

log "1.1.1.6 Ensure mounting of squashfs filesystems is disabled"
echo "install squashfs /bin/true" | sudo tee /etc/modprobe.d/squashfs.conf

log "1.1.1.7 Ensure mounting of udf filesystems is disabled"
echo "install udf /bin/true" | sudo tee /etc/modprobe.d/udf.conf

log "1.1.16 Ensure noexec option set on /dev/shm partition"
echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" \
	| sudo tee -a /etc/fstab

log "1.1.2 Ensure /tmp is configured"
echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" \
	| sudo tee -a /etc/fstab

log "1.1.23 Disable USB Storage"
echo "install usb-storage /bin/true" | sudo tee /etc/modprobe.d/usb-storage.conf

log "1.3.2 Ensure sudo commands use pty"
echo "Defaults use_pty" | sudo tee /etc/sudoers.d/10-use-pty

log "1.3.3 Ensure sudo log file exists"
echo 'Defaults logfile="/var/log/sudo.log"' | sudo tee /etc/sudoers.d/15-logfile

log "1.4.1 Ensure AIDE is installed"
echo "postfix postfix/mailname string localhost" \
	| sudo debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Local only'" \
	| sudo debconf-set-selections
sudo apt-get install -y aide

log "1.4.2 Ensure filesystem integrity is regularly checked"
sudo rm -f /etc/cron.daily/aide
sudo tee /etc/cron.weekly/aide <<'EOT'
#!/bin/sh
umask 027
/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check >/var/log/aide-check.log 2>&1
EOT
sudo chmod a+rx /etc/cron.weekly/aide

log "1.5.1 Ensure permissions on bootloader config are configured"
sudo chown root:root /boot/grub/grub.cfg
sudo chmod og-rwx /boot/grub/grub.cfg

log "1.6.2 Ensure address space layout randomization (ASLR) is enabled"
echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf

log "1.6.4 Ensure core dumps are restricted"
echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
echo "fs.suid_dumpable = 0" | sudo tee -a /etc/sysctl.conf

log "1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration"
sudo sed -i 's/^\(GRUB_CMDLINE_LINUX="\)/\1apparmor=1 security=apparmor /' \
	/etc/default/grub
sudo update-grub

log "1.8.1.2 Ensure local login warning banner is configured properly"
echo "Authorized uses only. All activity may be monitored and reported." \
	| sudo tee /etc/issue

log "1.8.1.3 Ensure remote login warning banner is configured properly"
echo "Authorized uses only. All activity may be monitored and reported." \
	| sudo tee /etc/issue.net

log "1.8.1.4 Ensure permissions on /etc/motd are configured"
sudo touch /etc/motd
sudo chown root:root /etc/motd
sudo chmod 644 /etc/motd

log "2.2.7 Ensure NFS and RPC are not enabled"
sudo systemctl disable nfs-server
sudo systemctl disable rpcbind

log "2.2.15 Ensure mail transfer agent is configured for local-only mode"
sudo sed -i "/^inet_interfaces/s/=.*/= loopback-only/" /etc/postfix/main.cf

log "2.2.16 Ensure rsync service is not enabled"
sudo systemctl disable rsync

log "2.3.4 Ensure telnet client is not installed"
sudo apt-get purge -y telnet

log "3.1.1 Ensure packet redirect sending is disabled"
sudo tee /etc/sysctl.d/50-packet-redirect-sending.conf <<'EOT'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOT

log "3.2.1 Ensure source routed packets are not accepted"
sudo tee /etc/sysctl.d/50-source-routed-packets.conf <<'EOT'
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOT

log "3.2.2 Ensure ICMP redirects are not accepted"
sudo tee /etc/sysctl.d/50-icmp-redirects.conf <<'EOT'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOT

log "3.2.3 Ensure secure ICMP redirects are not accepted"
sudo tee /etc/sysctl.d/50-secure-icmp-redirects.conf <<'EOT'
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
EOT

log "3.2.4 Ensure suspicious packets are logged"
sudo tee /etc/sysctl.d/50-log-suspicious-packets.conf <<'EOT'
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOT

log "3.2.5 Ensure broadcast ICMP requests are ignored"
sudo tee /etc/sysctl.d/50-broadcast-icmp-requests.conf <<'EOT'
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOT

log "3.2.6 Ensure bogus ICMP responses are ignored"
sudo tee /etc/sysctl.d/50-bogus-icmp-reponses.conf <<'EOT'
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOT

log "3.2.9 Ensure IPv6 router advertisements are not accepted"
sudo tee /etc/sysctl.d/50-router-advertisements.conf <<'EOT'
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOT

log "3.4.1 Ensure TCP Wrappers is installed"
sudo apt-get install -y tcpd

log "3.6.3 Ensure loopback traffic is configured"
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP
sudo iptables-save | sudo tee /etc/iptables/rules.v4

set_journald_param() {
	param="$1"
	value="$2"
	if sudo grep "^#*${param}=" /etc/systemd/journald.conf >/dev/null; then
		sudo sed -i -e "/^#${param}=/s/^#//" \
			    -e "s|^${param}=.*$|${param}=${value}|" \
			    /etc/systemd/journald.conf
	else
		echo "$param=$value" | sudo tee -a /etc/systemd/journald.conf
	fi
}

log "4.2.2.1 Ensure journald is configured to send logs to rsyslog"
set_journald_param ForwardToSyslog yes

log "4.2.2.2 Ensure journald is configured to compress large log files"
set_journald_param Compress yes

log "4.2.2.3 Ensure journald is configured to write logfiles to persistent disk"
set_journald_param Storage persistent

log "4.2.3 Ensure permissions on all logfiles are configured"
sudo chmod -R g-wx,o-rwx /var/log/*

log "5.1.2 Ensure permissions on /etc/crontab are configured"
sudo chown root:root /etc/crontab
sudo chmod og-rwx /etc/crontab

log "5.1.3 Ensure permissions on /etc/cron.hourly are configured"
sudo chown root:root /etc/cron.hourly
sudo chmod og-rwx /etc/cron.hourly

log "5.1.4 Ensure permissions on /etc/cron.daily are configured"
sudo chown root:root /etc/cron.daily
sudo chmod og-rwx /etc/cron.daily

log "5.1.5 Ensure permissions on /etc/cron.weekly are configured"
sudo chown root:root /etc/cron.weekly
sudo chmod og-rwx /etc/cron.weekly

log "5.1.6 Ensure permissions on /etc/cron.monthly are configured"
sudo chown root:root /etc/cron.monthly
sudo chmod og-rwx /etc/cron.monthly

log "5.1.7 Ensure permissions on /etc/cron.d are configured"
sudo chown root:root /etc/cron.d
sudo chmod og-rwx /etc/cron.d

log "5.1.8 Ensure at/cron is restricted to authorized users"
sudo rm -f /etc/cron.deny
sudo rm -f /etc/at.deny
sudo touch /etc/cron.allow
sudo touch /etc/at.allow
sudo chmod og-rwx /etc/cron.allow
sudo chmod og-rwx /etc/at.allow
sudo chown root:root /etc/cron.allow
sudo chown root:root /etc/at.allow

log "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured"
sudo chown root:root /etc/ssh/sshd_config
sudo chmod og-rwx /etc/ssh/sshd_config

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

log "5.2.14 Ensure only approved MAC algorithms are used"
set_sshd_param MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

log "5.2.15 Ensure only strong Key Exchange algorithms are used"
set_sshd_param KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

log "5.2.12 Ensure SSH Idle Timeout Interval is configured"
set_sshd_param ClientAliveInterval 300
set_sshd_param ClientAliveCountMax 0

log "5.2.13 Ensure SSH LoginGraceTime is set to one minute or less"
set_sshd_param LoginGraceTime 60

log "5.2.14 Ensure SSH access is limited"
set_sshd_param AllowUsers ubuntu

log "5.2.15 Ensure SSH warning banner is configured"
set_sshd_param Banner /etc/issue.net

log "5.2.22 Ensure SSH MaxStartups is configured"
set_sshd_param MaxStartups 10:30:60

log "5.2.23 Ensure SSH MaxSessions is set to 4 or less"
set_sshd_param MaxSessions 4

log "5.3.1 Ensure password creation requirements are configured"
sudo apt-get install -y libpam-pwquality
sudo tee /etc/security/pwquality.conf <<'EOT'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
usercheck = 1
EOT

log "5.3.2 Ensure lockout for failed password attempts is configured"
sudo tee /usr/share/pam-configs/tally2 <<'EOT'
Name: Failed login counter module
Default: yes
Priority: 500
Auth-Type: Primary
Auth:
	required			pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
Auth-Initial:
	required			pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
Account-Type: Primary
Account:
	required			pam_tally2.so
Account-Initial:
	required			pam_tally2.so
EOT
sudo pam-auth-update --enable tally2

log "5.3.3 Ensure password reuse is limited"
sudo tee /usr/share/pam-configs/pwhistory <<'EOT'
Name: Module to remember last passwords
Default: yes
Priority: 1000
Password-Type: Primary
Password:
        required			pam_pwhistory.so remember=5
Password-Initial:
	required			pam_pwhistory.so remember=5
EOT
sudo pam-auth-update --enable pwhistory

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
for user in `awk -F: '($3 > 0) {print $1 }' /etc/passwd`; do
	sudo chage --maxdays 365 "$user"
done
# Ensure that the root and ubuntu passwords do not expire
for user in root ubuntu; do
	sudo chage -m 0 -M 99999 -I -1 -E -1 "$user"
done

log "5.4.1.2 Ensure minimum days between password changes is 7 or more"
set_login_defs_param PASS_MIN_DAYS 7
for user in `awk -F: '($3 > 0) {print $1 }' /etc/passwd`; do
	sudo chage --mindays 7 "$user"
done

log "5.4.1.4 Ensure inactive password lock is 30 days or less"
sudo useradd -D -f 30

log "5.4.2 Ensure system accounts are non-login"
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
	if [ $user != "root" ]; then
		sudo usermod -L $user >/dev/null
		if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
			sudo usermod -s /usr/sbin/nologin $user
		fi
	fi
done

log "5.4.4 Ensure default user umask is 027 or more restrictive"
for rcfile in /etc/profile /etc/bash.bashrc; do
	echo "umask 027" | sudo tee -a "$rcfile"
done
echo "umask 027" | sudo tee /etc/profile.d/default-umask.sh

log "5.4.5 Ensure default user shell timeout is 900 seconds or less"
for rcfile in /etc/profile /etc/bash.bashrc; do
	echo '[ -z "$TMOUT" ] && readonly TMOUT=900; export TMOUT' | sudo tee -a "$rcfile"
done
echo '[ -z "$TMOUT" ] && readonly TMOUT=900; export TMOUT' | sudo tee /etc/profile.d/default-tmout.sh

log "5.6 Ensure access to the su command is restricted"
sudo groupadd sugroup
sudo sed -i 's/^# *\(auth[ 	]*required[ 	]*pam_wheel.so$\)/\1 use_uid group=sugroup/' \
	/etc/pam.d/su

log "6.1.6 Ensure permissions on /etc/passwd- are configured"
sudo chown root:root /etc/passwd-
sudo chmod u-x,go-rwx /etc/passwd-

log "6.1.7 Ensure permissions on /etc/shadow- are configured"
sudo chown root:shadow /etc/shadow-
sudo chmod u-x,go-rwx /etc/shadow-

log "6.2.8 Ensure users' home directories permissions are 750 or more restrictive"
sudo chmod 750 /home/ubuntu

# Final step
log "Initialize the AIDE database"
sudo aideinit
