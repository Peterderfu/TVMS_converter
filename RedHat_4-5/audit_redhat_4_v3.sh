#!/bin/bash
PASSWD="/etc/passwd"
LOGIN_DEFS="/etc/login.defs"
PASSWORD_POLICY="/etc/pam.d/system-auth"
LOGIN="$PASSWORD_POLICY"
AUDIT_RULE="/etc/audit.rules"
PROC_NET_DEV="/proc/net/dev"
IPTABLES="/etc/sysconfig/iptables"
NTP="/etc/ntp.conf"
LOGWATCH="/etc/cron.daily/0logwatch"
echo "{--Checking file--}"
ls $PASSWD
ls $LOGIN_DEFS
ls $PASSWORD_POLICY
ls $LOGIN
ls $AUDIT_RULE
ls $PROC_NET_DEV
ls $NTP
echo "{----}"
echo "{--OS infomation--}" && rpm -q redhat-release && /sbin/./ifconfig |grep "inet ";echo "{----}"
sleep 0.5
echo "{--01--}" && cat $PASSWD|awk -F: '($3=="0"){print $1}';echo "{----}"
sleep 0.5
echo "{--02--}" &&  awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' $LOGIN_DEFS)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print $1}' $PASSWD|while read -r item;do printf "$item|";done|sed 's/|$//g';echo;echo "{----}"
sleep 0.5
echo "{--03--}" && grep -E "/var/log/messages|/var/log/secure|/var/log/maillog|/var/log/spooler|/var/log/cron" /etc/logrotate.d/syslog|while read -r item;do printf "$item|";done|sed 's/|$//g';echo;echo "{----}"
sleep 0.5
echo "{--04--}" && ls -la $LOGWATCH;echo "{----}"
sleep 0.5
echo "{--05--}" && cat $PASSWD|awk -F: '($2==""){print}';echo "{----}"
sleep 0.5
echo "{--06--}" && cat $PASSWD|awk -F: '($2!="x"){print}';echo "{----}"
sleep 0.5
echo "{--07--}" && cat $LOGIN_DEFS|grep ^PASS_MIN_DAYS;echo "{----}"
sleep 0.5
echo "{--08--}" && cat $LOGIN_DEFS|grep ^PASS_WARN_AGE;echo "{----}"
sleep 0.5
echo "{--09--}" && cat $LOGIN_DEFS|grep ^PASS_MAX_DAYS;echo "{----}"
sleep 0.5
echo "{--10--}" && cat $LOGIN_DEFS|grep ^PASS_MIN_LEN;echo "{----}"
sleep 0.5
echo "{--11--}" && cat $PASSWORD_POLICY|grep "pam_cracklib.so|grep retry";echo "{----}"
sleep 0.5
echo "{--12--}" && cat $PASSWORD_POLICY|grep "pam_cracklib.so|grep credit";echo "{----}"
sleep 0.5
echo "{--13--}" && cat $PASSWORD_POLICY|grep "pam_cracklib.so|grep ucredit";echo "{----}"
sleep 0.5
echo "{--14--}" && cat $PASSWORD_POLICY|grep "pam_cracklib.so|grep lcredit";echo "{----}"
sleep 0.5
echo "{--15--}" && cat $PASSWORD_POLICY|grep "pam_cracklib.so|grep ocredit";echo "{----}"
sleep 0.5
echo "{--16--}" && cat $PASSWORD_POLICY|grep "pam_cracklib.so|grep difok";echo "{----}"
sleep 0.5
echo "{--17--}" && cat $PASSWORD_POLICY|grep "remember=24";echo "{----}"
sleep 0.5
echo "{--18--}" &&  grep ^PASSWDALGORITHM= /etc/sysconfig/authconfig;echo "{----}"
sleep 0.5
echo "{--19--}" && cat $LOGIN|grep "pam_tally2.so"|grep deny;echo "{----}"
sleep 0.5
echo "{--20--}" && /sbin/./chkconfig --list auditd;echo "{----}"
sleep 0.5
echo "{--21--}" && cat $AUDIT_RULE|grep -E "\-k time-change";echo "{----}"
sleep 0.5
echo "{--22--}" && cat $AUDIT_RULE|grep -E "\-k identity";echo "{----}"
sleep 0.5
echo "{--23--}" && cat $AUDIT_RULE|grep -E "\-k system-locale";echo "{----}"
sleep 0.5
echo "{--24--}" && cat $AUDIT_RULE|grep -E "\-k MAC-policy";echo "{----}"
sleep 0.5
echo "{--25--}" && cat $AUDIT_RULE|grep -E "\-k perm_mod";echo "{----}"
sleep 0.5
echo "{--26--}" && cat $AUDIT_RULE|grep -E "\-k access";echo "{----}"
sleep 0.5
echo "{--27--}" && find `blkid |awk -F: '{print $1}'` -xdev \( -perm -4000 -o -perm -2000 \) -type f;cat $AUDIT_RULE|grep -E "\-k privileged";echo "{----}"
sleep 0.5
echo "{--28--}" && cat $AUDIT_RULE|grep -E "\-k export";echo "{----}"
sleep 0.5
echo "{--29--}" && cat $AUDIT_RULE|grep -E "\-k delete";echo "{----}"
sleep 0.5
echo "{--30--}" && cat $AUDIT_RULE|grep -E "\-k actions";echo "{----}"
sleep 0.5
echo "{--31--}" && cat $AUDIT_RULE|grep -E "\-k modules";echo "{----}"
sleep 0.5
echo "{--32--}" && cat $AUDIT_RULE|tail -n1;echo "{----}"
sleep 0.5
echo "{--33--}" && cat $AUDIT_RULE|grep -E "\-k logins";echo "{----}"
sleep 0.5
echo "{--34--}" && cat $AUDIT_RULE|grep -E "\-k session";echo "{----}"
sleep 0.5
echo "{--35--}" && gconftool-2 -R /apps/gnome-screensaver;echo "{----}"
sleep 0.5
echo "{--36--}" && /sbin/./chkconfig --list iptable;echo "{----}"
sleep 0.5
echo "{--37--}" && cat $IPTABLES|grep -E "*filter|:INPUT|:FORWARD";echo "{----}"
sleep 0.5
echo "{--38--}" && /sbin/./sysctl net.ipv4.ip_forward;echo "{----}"
sleep 0.5
echo "{--39--}" && /sbin/./sysctl net.ipv4.conf.all.send_redirects;echo "{----}"
sleep 0.5
echo "{--40--}" && /sbin/./sysctl net.ipv4.conf.default.send_redirects;echo "{----}"
sleep 0.5
echo "{--41--}" && /sbin/./sysctl net.ipv4.conf.all.secure_redirects;echo "{----}"
sleep 0.5
echo "{--42--}" && /sbin/./sysctl net.ipv4.conf.default.secure_redirects;echo "{----}"
sleep 0.5
echo "{--43--}" && /sbin/./sysctl net.ipv4.conf.all.accept_redirects;echo "{----}"
sleep 0.5
echo "{--44--}" && /sbin/./sysctl net.ipv4.conf.default.accept_redirects;echo "{----}"
sleep 0.5
echo "{--45--}" && /sbin/./sysctl net.ipv4.conf.all.accept_source_route;echo "{----}"
sleep 0.5
echo "{--46--}" && /sbin/./sysctl net.ipv4.conf.default.accept_source_route;echo "{----}"
sleep 0.5
echo "{--47--}" && /sbin/./sysctl net.ipv4.icmp_ignore_bogus_error_responses;echo "{----}"
sleep 0.5
echo "{--48--}" && /sbin/./sysctl net.ipv4.icmp_echo_ignore_broadcasts;echo "{----}"
sleep 0.5
echo "{--49--}" && /sbin/./sysctl net.ipv4.conf.all.log_martians;echo "{----}"
sleep 0.5
echo "{--50--}" && /sbin/./sysctl net.ipv4.conf.all.rp_filter;echo "{----}"
sleep 0.5
echo "{--51--}" && /sbin/./sysctl net.ipv4.conf.default.rp_filter;echo "{----}"
sleep 0.5
echo "{--52--}" && /sbin/./sysctl net.ipv4.tcp_syncookies;echo "{----}"
sleep 0.5
echo "{--53--}" && cat $PROC_NET_DEV|grep -iE "wlan|wifi";echo "{----}"
sleep 0.5
echo "{--54--}" && cat $NTP|grep -E "^server";echo "{----}"



