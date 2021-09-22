#!/bin/bash
PASSWD="/etc/passwd"
LOGIN_DEFS="/etc/login.defs"
SYSTEM_AUTH="/etc/pam.d/system-auth"
PASSWORD_AUTH="/etc/pam.d/password-auth"
PWQUALITY="/etc/security/pwquality.conf"
#LOGIN="$PASSWORD_POLICY"
AUDIT_RULE="/etc/audit/rules.d/*.rules"
SYSCTL_CONF="/etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf"
#PROC_NET_DEV="/proc/net/dev"
IPTABLES="/etc/sysconfig/iptables"
#NTP="/etc/ntp.conf"
LOGWATCH="/etc/cron.daily/0logwatch"
output="$(hostname -s)_$(date +%Y%m%d).txt"
touch $output
exec 3>&1 1>$output
exec 2>&1
#echo "{--Checking file--}"
#ls $PASSWD
#ls $LOGIN_DEFS
#ls $PASSWORD_POLICY
#ls $LOGIN
#ls $AUDIT_RULE
#ls $PROC_NET_DEV
#ls $NTP
echo "{----}"
echo "{--OS infomation--}" && rpm -q centos-release && ip address|grep "inet ";echo "{----}"
#echo "{--Configurations--}" &&
#grep -H "" $PASSWD;
#grep -H "" $LOGIN_DEFS;
#grep -H "" $SYSTEM_AUTH;
#grep -H "" $PASSWORD_AUTH;
#grep -H "" $PWQUALITY;
#echo "{----}"
echo "{--01--}" && cat $PASSWD|awk -F: '($3=="0"){print $1}';echo "{----}"
echo "{--02--}" && awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' $LOGIN_DEFS)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print $1}' $PASSWD|while read -r item;do printf "$item|";done|sed 's/|$//g';echo;echo "{----}"
echo "{--03--}" && grep -E "/var/log/messages|/var/log/secure|/var/log/maillog|/var/log/spooler|/var/log/cron" /etc/logrotate.d/syslog|while read -r item;do printf "$item|";done|sed 's/|$//g';echo;echo "{----}"
#echo "{--04--}" && ls -la $LOGWATCH |grep "0logwatch->/usr/share/logwatch/scripts/logwatch.pl"|wc -l;echo "{----}"
echo "{--04--}" && echo "N.A.";echo "{----}"
echo "{--05--}" && cat $PASSWD|awk -F: '($2==""){print}';echo "{----}"
echo "{--06--}" && cat $PASSWD|awk -F: '($2!="x"){print}';echo "{----}"
echo "{--07--}" && cat $LOGIN_DEFS|grep ^PASS_MIN_DAYS;echo "{----}"
echo "{--08--}" && cat $LOGIN_DEFS|grep ^PASS_WARN_AGE;echo "{----}"
echo "{--09--}" && cat $LOGIN_DEFS|grep ^PASS_MAX_DAYS;echo "{----}"
echo "{--10--}" && cat $PWQUALITY|grep '^\s*minlen\s*';echo "{----}"
echo "{--11--}" && grep -P '^\s*password\s+(?:requisite|required)\s+pam_pwquality\.so\s+(?:\S+\s+)*(?!\2)(retry=[1-3]|try_first_pass)\s+(?:\S+\s+)*(?!\1)(retry=[1-3]|try_first_pass)\s*(?:\s+\S+\s*)*(?:\s+#.*)?$' $PASSWORD_AUTH $SYSTEM_AUTH;echo "{----}"
echo "{--12--}" && cat $PWQUALITY|grep -E '^\s*minclass\s*|^\s*dcredit\s*';echo "{----}"
echo "{--13--}" && cat $PWQUALITY|grep -E '^\s*minclass\s*|^\s*ucredit\s*';echo "{----}"
echo "{--14--}" && cat $PWQUALITY|grep -E '^\s*minclass\s*|^\s*lcredit\s*';echo "{----}"
echo "{--15--}" && cat $PWQUALITY|grep -E '^\s*minclass\s*|^\s*ocredit\s*';echo "{----}"
echo "{--17--}" && grep -P '^\s*password\s+(requisite|required)\s+pam_(pwhistory|unix)\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' $PASSWORD_AUTH $SYSTEM_AUTH|sort;echo "{----}"
echo "{--18--}" && grep -P '^\h*password\h+(sufficient|requisite|required)\h+pam_unix\.so\h+([^#\n\r]+)?sha512(\h+.*)?$' $PASSWORD_AUTH $SYSTEM_AUTH|sort;echo "{----}"
echo "{--19--}" && grep -E '(^\s*auth\s+\S+\s+pam_(faillock|unix|tally2)\.so|^\s*account\s+required\s+pam_(faillock|tally2).so\s*)' $PASSWORD_AUTH $SYSTEM_AUTH;echo "{----}"
echo "{--20--}" && systemctl is-enabled auditd;systemctl status auditd | grep 'Active: active (running)';echo "{----}"
echo "{--21--}" && grep -H "\-k time-change" /etc/audit/rules.d/*.rules;auditctl -l | grep "\-k time-change";echo "{----}"
echo "{--22--}" && grep -H "\-k identity" /etc/audit/rules.d/*.rules;auditctl -l | grep "\-k identity";echo "{----}"
echo "{--23--}" && grep -H "\-k system-locale" /etc/audit/rules.d/*.rules;auditctl -l | grep "\-k system-locale";echo "{----}"
echo "{--24--}" && grep -H "\-k MAC-policy" /etc/audit/rules.d/*.rules;auditctl -l | grep "\-k MAC-policy";echo "{----}"
echo "{--25--}" && grep -EH "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\-k perm_mod" /etc/audit/rules.d/*.rules;auditctl -l | grep -E "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\key=perm_mod";echo "{----}"
echo "{--26--}" && grep -EH "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\-k access" /etc/audit/rules.d/*.rules;auditctl -l | grep -E "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\-k access";echo "{----}"
echo "{--27--}" && find `blkid |awk -F: '{print $1}'` -xdev \( -perm -4000 -o -perm -2000 \) -type f;echo "{----}"
echo "{--28--}" && grep -EH "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\-k mounts" /etc/audit/rules.d/*.rules;auditctl -l | grep -E "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\-k mounts";echo "{----}"
echo "{--29--}" && grep -EH "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\-k delete" /etc/audit/rules.d/*.rules;auditctl -l | grep -E "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\-k delete";echo "{----}"
echo "{--30--}" && grep -EH "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\-k actions" /etc/audit/rules.d/*.rules;auditctl -l | grep -E "auid>=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`.*\-k actions";echo "{----}"
echo "{--31--}" && grep -H "\-k modules" /etc/audit/rules.d/*.rules;auditctl -l | grep "\-k modules";echo "{----}"
echo "{--32--}" && grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1;echo "{----}"
echo "{--33--}" && grep -H "\-k logins" /etc/audit/rules.d/*.rules;auditctl -l | grep "\-k logins";echo "{----}"
echo "{--34--}" && grep -E '(session|logins)' /etc/audit/rules.d/*.rules;echo "{----}"
#echo "{--35--}" && gconftool-2 -R /apps/gnome-screensaver;echo "{----}"
echo "{--35--}" && echo "N.A.";echo "{----}"
echo "{--36--}" && systemctl is-enabled firewalld;firewall-cmd --state;echo "{----}"
#echo "{--37--}" && cat $IPTABLES|grep -E "*filter|:INPUT|:FORWARD";echo "{----}"
echo "{--37--}" && echo "N.A.";echo "{----}"
echo "{--38--}" && sysctl net.ipv4.ip_forward;grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" $SYSCTL_CONF;echo "{----}"
echo "{--39--}" && sysctl net.ipv4.conf.all.send_redirects;grep -s "net\.ipv4\.conf\.all\.send_redirects" $SYSCTL_CONF;echo "{----}"
echo "{--40--}" && sysctl net.ipv4.conf.default.send_redirects;grep -s "net\.ipv4\.conf\.default\.send_redirects" $SYSCTL_CONF;echo "{----}"
echo "{--41--}" && sysctl net.ipv4.conf.all.secure_redirects;grep -s "net\.ipv4\.conf\.all\.secure_redirects" $SYSCTL_CONF ;echo "{----}"
echo "{--42--}" && sysctl net.ipv4.conf.default.secure_redirects;grep -s "net\.ipv4\.conf\.default\.secure_redirects" $SYSCTL_CONF ;echo "{----}"
echo "{--43--}" && sysctl net.ipv4.conf.all.accept_redirects;grep -s "net\.ipv4\.conf\.all\.accept_redirects" $SYSCTL_CONF ;echo "{----}"
echo "{--44--}" && sysctl net.ipv4.conf.default.accept_redirects;grep -s "net\.ipv4\.conf\.default\.accept_redirects" $SYSCTL_CONF ;echo "{----}"
echo "{--45--}" && sysctl net.ipv4.conf.all.accept_source_route;grep -s "net\.ipv4\.conf\.all\.accept_source_route" $SYSCTL_CONF ;echo "{----}"
echo "{--46--}" && sysctl net.ipv4.conf.default.accept_source_route;grep -s "net\.ipv4\.conf\.default\.accept_source_route" $SYSCTL_CONF ;echo "{----}"
echo "{--47--}" && sysctl net.ipv4.icmp_ignore_bogus_error_responses;grep -s "net.ipv4.icmp_ignore_bogus_error_responses" $SYSCTL_CONF ;echo "{----}"
echo "{--48--}" && sysctl net.ipv4.icmp_echo_ignore_broadcasts;grep -s "net\.ipv4\.icmp_echo_ignore_broadcasts" $SYSCTL_CONF;echo "{----}"
echo "{--49--}" && sysctl net.ipv4.conf.all.log_martians;grep -s "net\.ipv4\.conf\.all\.log_martians" $SYSCTL_CONF ;sysctl net.ipv4.conf.default.log_martians;grep -s "net\.ipv4\.conf\.default\.log_martians" $SYSCTL_CONF ;echo "{----}"
echo "{--50--}" && sysctl net.ipv4.conf.all.rp_filter;grep -s "net\.ipv4\.conf\.all\.rp_filter" $SYSCTL_CONF ;echo "{----}"
echo "{--51--}" && sysctl net.ipv4.conf.default.rp_filter;grep -s "net\.ipv4\.conf\.default\.rp_filter" $SYSCTL_CONF ;echo "{----}"
echo "{--52--}" && sysctl net.ipv4.tcp_syncookies;grep -s "net\.ipv4\.tcp_syncookies" $SYSCTL_CONF ;echo "{----}"
echo "{--53--}" && nmcli radio wwan;nmcli radio wifi;echo "{----}"
#echo "{--54--}" && cat $NTP|grep -E "^server";echo "{----}"
echo "{--54--}" && rpm -q chrony ntp;grep -HEs "^(server|pool)" /etc/chrony.conf;grep -HEs ^OPTIONS /etc/sysconfig/chronyd;systemctl is-enabled ntpd;grep -HEs "^restrict" /etc/ntp.conf;grep -HEs  "^(server|pool)" /etc/ntp.conf ;grep -HEs "^OPTIONS" /etc/sysconfig/ntpd;grep -HEs "^ExecStart" /usr/lib/systemd/system/ntpd.service;echo "{----}"
#echo "{--55--}" && cat /etc/security/pwquality.conf;echo "{----}"
#echo "{--56--}" && auditctl -l;echo "{----}"
exec 1>&3 3>&-
cat $output



