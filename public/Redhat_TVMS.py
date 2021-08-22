# -*- coding: utf-8 -*-
import re,openpyxl,sys,argparse,os
from datetime import datetime
TVMS_HEADERS = {"A":"弱點發現時間",\
                "B":"弱點所在網路位址",\
                "C":"弱點所在網路埠號",\
                "D":"檔案名稱/URL",\
                "E":"弱點所在之網路協定",\
                "F":"弱點名稱",\
                "G":"弱點嚴重性或合規檢測結果",\
                "H":"弱點類別",\
                "I":"弱點CVE ID清單",\
                "J":"評估工具原廠之弱點編號",\
                "K":"弱點說明",\
                "L":"弱點意見",\
                "M":"弱點修補建議",\
                "N":"弱點證據描述",\
                "O":"類型(弱點或合規)"}
INFO_TABLES=[["項次","評估工具原廠之弱點編號","弱點類別","弱點說明","弱點修補建議"],\
["1","Linux 伺服器安全基準檢核表步驟-01","伺服主機帳號及功能設定/Administrator帳號設定","Administrator帳號設定","確認僅root帳號之UID為0"],\
["2","Linux 伺服器安全基準檢核表步驟-02","伺服主機帳號及功能設定/SSH服務設定","SSH服務設定","確認UID小於UID_MIN之非root系統帳號的登入shell皆設為「/sbin/nologin」"],\
["3","Linux 伺服器安全基準檢核表步驟-03","日誌檔輪替服務","日誌檔輪替服務","編輯/etc/logrotate.d/syslog檔案新增或修改成以下內容：/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron"],\
["4","Linux 伺服器安全基準檢核表步驟-04","日誌檔輪替服務","日誌檔檢視服務","啟用日誌檔檢視(logwatch)服務"],\
["5","Linux 伺服器安全基準檢核表步驟-05","密碼原則","使用空白密碼之帳號登入方式","禁止使用空白密碼之帳號"],\
["6","Linux 伺服器安全基準檢核表步驟-06","密碼原則","所有帳號的密碼遮蔽","確認沒有儲存密碼雜湊於/etc/passwd中"],\
["7","Linux 伺服器安全基準檢核表步驟-07","密碼原則","密碼最短使用期限","PASS_MIN_DAYS設為1"],\
["8","Linux 伺服器安全基準檢核表步驟-08","密碼原則","密碼到期前提醒使用者變更密碼","PASS_WARN_AGE設為14"],\
["9","Linux 伺服器安全基準檢核表步驟-09","密碼原則","密碼最長使用期限","PASS_MAX_DAYS設為60"],\
["10","Linux 伺服器安全基準檢核表步驟-10","密碼原則","密碼最小長度","PASS_MIN_LEN設為12"],\
["11","Linux 伺服器安全基準檢核表步驟-11","密碼原則","可嘗試密碼次數","retry設為3"],\
["12","Linux 伺服器安全基準檢核表步驟-12","密碼原則","密碼必須至少包含數字個數","dcredit設為1"],\
["13","Linux 伺服器安全基準檢核表步驟-13","密碼原則","密碼必須至少包含大寫字母個數","ucredit設為1"],\
["14","Linux 伺服器安全基準檢核表步驟-14","密碼原則","密碼必須至少包含小寫字母個數","lcredit設為1"],\
["15","Linux 伺服器安全基準檢核表步驟-15","密碼原則","密碼必須至少包含特殊字元個數","ocredit設為1"],\
["16","Linux 伺服器安全基準檢核表步驟-16","密碼原則","新密碼與舊密碼最少相異字元數","difok設為3"],\
["17","Linux 伺服器安全基準檢核表步驟-17","密碼原則","強制執行密碼歷程記錄","remember設為24"],\
["18","Linux 伺服器安全基準檢核表步驟-18","密碼原則","密碼雜湊演算法","密碼雜湊演算法設為sha512"],\
["19","Linux 伺服器安全基準檢核表步驟-19","帳戶鎖定原則","帳戶鎖定閾值","deny設為5"],\
["20","Linux 伺服器安全基準檢核表步驟-20","日誌與稽核","auditd服務","啟用auditd服務(chkconfig auditd on)"],\
["21","Linux 伺服器安全基準檢核表步驟-21","日誌與稽核","記錄變更日期與時間事件","記錄變更日期與時間事件( -k time-change)"],\
["22","Linux 伺服器安全基準檢核表步驟-22","日誌與稽核","記錄變更使用者或群組資訊事件","記錄變更使用者或群組資訊之事件(-k identity)"],\
["23","Linux 伺服器安全基準檢核表步驟-23","日誌與稽核","記錄變更系統網路環境事件","記錄變更系統網路環境之事件(-k system-locale)"],\
["24","Linux 伺服器安全基準檢核表步驟-24","日誌與稽核","記錄變更系統強制性存取控制事件","記錄變更系統強制性存取控制事件(-k MAC-policy)"],\
["25","Linux 伺服器安全基準檢核表步驟-25","日誌與稽核","記錄變更自主式存取控制權限事件","記錄變更自主式存取控制權限事件(-k perm_mod)"],\
["26","Linux 伺服器安全基準檢核表步驟-26","日誌與稽核","記錄不成功的未經授權檔案存取","記錄不成功的未經授權檔案存取(-k access)"],\
["27","Linux 伺服器安全基準檢核表步驟-27","日誌與稽核","記錄特權指令使用情形","記錄特權指令使用情形(-k privileged)"],\
["28","Linux 伺服器安全基準檢核表步驟-28","日誌與稽核","記錄資料匯出至媒體","記錄資料匯出至媒體(-k export)"],\
["29","Linux 伺服器安全基準檢核表步驟-29","日誌與稽核","記錄檔案刪除事件","記錄檔案刪除事件(-k delete)"],\
["30","Linux 伺服器安全基準檢核表步驟-30","日誌與稽核","記錄系統管理者活動","記錄系統管理者活動(-k actions)"],\
["31","Linux 伺服器安全基準檢核表步驟-31","日誌與稽核","記錄核心模組掛載與卸載事件","記錄核心模組掛載與卸載事件(-k modules)"],\
["32","Linux 伺服器安全基準檢核表步驟-32","日誌與稽核","auditd設定不變模式","/etc/audit/audit.rules最後一行設為「-e 2」"],\
["33","Linux 伺服器安全基準檢核表步驟-33","日誌與稽核","記錄變更登入與登出資訊事件","記錄變更登入與登出資訊事件(-k logins)"],\
["34","Linux 伺服器安全基準檢核表步驟-34","日誌與稽核","記錄程序與會談啟始資訊","記錄程序與會談啟始資訊(-k session)"],\
["35","Linux 伺服器安全基準檢核表步驟-35","螢幕保護裝置設定","螢幕保護裝置設定(GNOME螢幕保護裝置逾時)","idle_delay設為15"],\
["36","Linux 伺服器安全基準檢核表步驟-36","開啟防火牆","iptables服務","啟用iptables服務(chkconfig iptables on)"],\
["37","Linux 伺服器安全基準檢核表步驟-37","防火牆進階設定","INPUT與FORWARD防火牆規則鏈的預設規則","將INPUT與FORWARD防火牆規則鏈預設規則變更為DROP"],\
["38","Linux 伺服器安全基準檢核表步驟-38","防火牆進階設定","IP轉送","於/etc/sysctl.conf中設定net.ipv4.ip_forward = 0"],\
["39","Linux 伺服器安全基準檢核表步驟-39","防火牆進階設定","所有網路介面傳送ICMP重新導向封包","於/etc/sysctl.conf中設定net.ipv4.conf.all.send_redirects=0"],\
["40","Linux 伺服器安全基準檢核表步驟-40","防火牆進階設定","預設網路介面傳送ICMP重新導向封包","於/etc/sysctl.conf中設定net.ipv4.conf.default.send_redirects = 0"],\
["41","Linux 伺服器安全基準檢核表步驟-41","防火牆進階設定","所有網路介面接受安全的ICMP重新導向封包","於/etc/sysctl.conf中設定net.ipv4.conf.all.secure_redirects = 0"],\
["42","Linux 伺服器安全基準檢核表步驟-42","防火牆進階設定","預設網路介面接受安全的ICMP重新導向封包","於/etc/sysctl.conf中設定net.ipv4.conf.default.secure_redirects = 0"],\
["43","Linux 伺服器安全基準檢核表步驟-43","防火牆進階設定","所有網路介面接受ICMP重新導向封包","於/etc/sysctl.conf中設定net.ipv4.conf.all.accept_redirects = 0"],\
["44","Linux 伺服器安全基準檢核表步驟-44","防火牆進階設定","預設網路介面接受ICMP重新導向封包","於/etc/sysctl.conf中設定net.ipv4.conf.default.accept_redirects = 0"],\
["45","Linux 伺服器安全基準檢核表步驟-45","防火牆進階設定","所有網路介面接受來源路由封包","於/etc/sysctl.conf中設定net.ipv4.conf.all.accept_source_route = 0"],\
["46","Linux 伺服器安全基準檢核表步驟-46","防火牆進階設定","預設網路介面接受來源路由封包","於/etc/sysctl.conf中設定net.ipv4.conf.default.accept_source_route = 0"],\
["47","Linux 伺服器安全基準檢核表步驟-47","防火牆進階設定","忽略偽造的ICMP錯誤訊息","於/etc/sysctl.conf中設定net.ipv4.icmp_ignore_bogus_error_responses = 1"],\
["48","Linux 伺服器安全基準檢核表步驟-48","防火牆進階設定","不回應ICMP廣播要求","於/etc/sysctl.conf中設定net.ipv4.icmp_echo_ignore_broadcasts = 1"],\
["49","Linux 伺服器安全基準檢核表步驟-49","防火牆進階設定","紀錄可疑封包","於/etc/sysctl.conf中設定net.ipv4.conf.all.log_martians = 1"],\
["50","Linux 伺服器安全基準檢核表步驟-50","防火牆進階設定","所有網路介面啟用逆向路徑過濾功能","於/etc/sysctl.conf中設定net.ipv4.conf.all.rp_filter = 1"],\
["51","Linux 伺服器安全基準檢核表步驟-51","防火牆進階設定","預設網路介面啟用逆向路徑過濾功能","於/etc/sysctl.conf中設定net.ipv4.conf.default.rp_filter = 1"],\
["52","Linux 伺服器安全基準檢核表步驟-52","防火牆進階設定","TCP SYN cookies","於/etc/sysctl.conf中設定net.ipv4.tcp_syncookies = 1"],\
["53","Linux 伺服器安全基準檢核表步驟-53","防火牆進階設定","無線網路介面卡","停用無線網路介面卡"],\
["54","Linux 伺服器安全基準檢核表步驟-54","時戳及校時(NTP)","設定NTP server","於/etc/ntp.conf中設定NTP server IP"]]
PASS_MIN_DAYS                               ='1'
PASS_WARN_AGE                               ='14'
PASS_MAX_DAYS                               ='60'
PASS_MIN_LEN                                ='12'
RETRY                                       ='3'
DCREDIT                                     ='1'
UCREDIT                                     ='1'
LCREDIT                                     ='1'
OCREDIT                                     ='1'
DIFOK                                       ='3'
REMEMBER                                    ='24'
SHA512                                      ='sha512'
DENY                                        ='5'
NET_IPV4_IP_FORWARD                         ='0'
NET_IPV4_CONF_ALL_SEND_REDIRECTS            ='0'
NET_IPV4_CONF_DEFAULT_SEND_REDIRECTS        ='0'
NET_IPV4_CONF_ALL_SECURE_REDIRECTS          ='0'
NET_IPV4_CONF_DEFAULT_SECURE_REDIRECTS      ='0'
NET_IPV4_CONF_ALL_ACCEPT_REDIRECTS          ='0'
NET_IPV4_CONF_DEFAULT_ACCEPT_REDIRECTS      ='0'
NET_IPV4_CONF_ALL_ACCEPT_SOURCE_ROUTE       ='0'
NET_IPV4_CONF_DEFAULT_ACCEPT_SOURCE_ROUTE   ='0'
NET_IPV4_ICMP_IGNORE_BOGUS_ERROR_RESPONSES  ='1'
NET_IPV4_ICMP_ECHO_IGNORE_BROADCASTS        ='1'
NET_IPV4_CONF_ALL_LOG_MARTIANS              ='1'
NET_IPV4_CONF_ALL_RP_FILTER                 ='1'
NET_IPV4_CONF_DEFAULT_RP_FILTER             ='1'
NET_IPV4_TCP_SYNCOOKIES                     ='1'
auditFunc = []
def auditSearch(id,log):
    pattern = '(?<=^{--'+id+'--}).*?(?=\n{)'
    return re.search(pattern,log,re.MULTILINE|re.DOTALL)
    
def getLogtime(log):
    m = re.search('\d{4}\.\d{2}\.\d{2}\s\d{2}:\d{2}:\d{2}',log)
    if m:
        t = datetime.strptime(m.group(0),'%Y.%m.%d %H:%M:%S')
        return t.strftime('%Y/%m/%d %H:%M:%S')
    return ""
def getOS(log):
    [OS,IP] = [None,'']
    m0 = re.search('^{--OS infomation--}.*?^{',log,re.MULTILINE|re.DOTALL)
    if m0:
        m1 = re.search('centos.*',m0.group(0)) # find OS version
        if m1:
            OS = m1.group(0)
        
        for line in m0.group(0).split("\n"):  # find IP
            s = line.strip()
            if s.startswith('inet') and not s.endswith('lo'): # find inet and ignore lo interface
                IP = s.split()[1].split('/')[0]
                break
        
    return [OS,IP]
def getAuditResult(id,log):
    m = auditSearch(f'{id:02}',log)
    return auditFunc[id-1](m)
def evalFunc0(pattern,context,desired):
#context format : "[fieldname] [value]"    
#use pattern to fetch [value] in content and compare it with desired
#return 1:match of pattern 2:value not equal to desired when matched
    m = re.search(pattern, context)
    if m:
        if m.group(0).strip() == desired:
            return [True, None]
        else:
            return [False, m.group(0).strip()]
    return [False,None]
def evalFunc1(patterns,context):
#compare context with all pattern in patterns
#return False if any of pattern not matched
    for p in patterns:
        if not re.search(p, context):
            return [False,None]
    return [True,None]
def getAudit01(match):
    if match:
        accounts = [s for s in match.group(0).split("\n") if not len(s)==0]
        if len(accounts)==1 and accounts[0]=='root':
            return [True,None]
    return [False,"|".join(accounts)]

def getAudit02(match):
    if match:
        accounts = [s for s in match.group(0).splitlines() if not len(s)==0]
        if len(accounts)==0:
            return [True,None]
        else:
            return [False,"|".join(accounts)]
    return True
 
def getAudit03(match):
    patterns = ['/var/log/cron',\
                '/var/log/maillog',\
                '/var/log/messages',\
                '/var/log/secure',\
                '/var/log/spooler']
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit04(match):
    if match:
        s = match.group(0).strip('\n')
        if ("0logwatch->/usr/share/logwatch/scripts/logwatch.pl" in s):
            return [True,None]
    return [False,None]
def getAudit05(match):
    if match:
        s = match.group(0).strip('\n')
        if len(s) == 0:
            return [True,None]
        invalidAccounts = [t.split(":")[0] for t in s.splitlines()]
    return [False,"|".join(invalidAccounts)]
def getAudit06(match):
    return getAudit05(match)
    
def getAudit07(match):
    return evalFunc0('(?<=^PASS_MIN_DAYS)[\b\s]*\d+',match.group(0).strip('\n'),PASS_MIN_DAYS)

def getAudit08(match):
    return evalFunc0('(?<=^PASS_WARN_AGE)[\b\s]*\d+',match.group(0).strip('\n'),PASS_WARN_AGE)

def getAudit09(match):
    return evalFunc0('(?<=^PASS_MAX_DAYS)[\b\s]*\d+',match.group(0).strip('\n'),PASS_MAX_DAYS)
        
def getAudit10(match):
    return evalFunc0('(?<=^PASS_MIN_LEN)[\b\s]*\d+',match.group(0).strip('\n'),PASS_MIN_LEN)

def getAudit11(match):
    return evalFunc0('(?<=retry=)\b?\d+(?=[\s\n]?)',match.group(0).strip('\n'),RETRY)
def getAudit12(match):
    return evalFunc0('(?<=dcredit=)\b?\d+(?=[\s\n]?)',match.group(0).strip('\n'),DCREDIT)
def getAudit13(match):
    return evalFunc0('(?<=ucredit=)\b?\d+(?=[\s\n]?)',match.group(0).strip('\n'),UCREDIT)
def getAudit14(match):
    return evalFunc0('(?<=lcredit=)\b?\d+(?=[\s\n]?)',match.group(0).strip('\n'),LCREDIT)
def getAudit15(match):
    return evalFunc0('(?<=ocredit=)\b?\d+(?=[\s\n]?)',match.group(0).strip('\n'),OCREDIT)
def getAudit16(match):
    return evalFunc0('(?<=difok=)\b?\d+(?=[\s\n]?)',match.group(0).strip('\n'),DIFOK)
def getAudit17(match):
    return evalFunc0('(?<=remember=)\b?\d+(?=[\s\n]?)',match.group(0).strip('\n'),REMEMBER)
def getAudit18(match):
    return evalFunc0('(?<=is\s).+(?=\s?)',match.group(0).strip('\n'),SHA512)
def getAudit19(match):
    return evalFunc0('(?<=deny=)\b?\d+(?=[\s\n]?)',match.group(0).strip('\n'),DENY)
def getAudit20(match):
    patterns = ["enabled"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit21(match):
    patterns = ["-a always,exit -F arch=b(32|64) -S adjtimex -S settimeofday -S stime -k time-change", \
                "-a always,exit -F arch=b(32|64) -S clock_settime -k time-change", \
                "-w /etc/localtime -p wa -k time-change"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit22(match):
    patterns = ["-w /etc/group -p wa -k identity", \
                "-w /etc/passwd -p wa -k identity", \
                "-w /etc/gshadow -p wa -k identity", \
                "-w /etc/shadow -p wa -k identity", \
                "-w /etc/security/opasswd -p wa -k identity"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit23(match):
    patterns = ["-a exit,always -F arch=b(32|64) -S sethostname -S setdomainname -k system-locale", \
                "-w /etc/issue -p wa -k system-locale", \
                "-w /etc/issue.net -p wa -k system-locale", \
                "-w /etc/hosts -p wa -k system-locale", \
                "-w /etc/sysconfig/network -p wa -k system-locale"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit24(match):
    patterns = ["-w /etc/selinux/ -p wa -k MAC-policy"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit25(match):
    patterns = ["-a always,exit -F arch=b(32|64) -S chmod -S fchmod -S fchmodat -F auid>=\d+ -F auid!=4294967295 -k perm_mod", \
                "-a always,exit -F arch=b(32|64) -S chown -S fchown -S fchownat -S lchown -F auid>=\d+ -F auid!=4294967295 -k perm_mod", \
                "-a always,exit -F arch=b(32|64) -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=\d+ -F auid!=4294967295 -k perm_mod"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit26(match):
    patterns = ["-a always,exit -F arch=b(32|64) -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=\d+ -F auid!=4294967295 -k access", \
                "-a always,exit -F arch=b(32|64) -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=\d+ -F auid!=4294967295 -k access"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit27(match):
    patterns = ["-a always,exit -F path=.+ -F perm=x -F auid>=\d+ -F auid!=4294967295 -k privileged"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit28(match):
    patterns = ["-a always,exit -F arch=b(32|64) -S mount -F auid>=\d+ -F auid!=4294967295 -k export"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit29(match):
    patterns = ["-a always,exit -F arch=b(32|64) -S unlink -S unlinkat -S rename -S renameat -F auid>=\d+ -F auid!=4294967295 -k delete"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit30(match):
    patterns = ["-w /etc/sudoers -p wa -k actions"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit31(match):
    patterns = ["-w /sbin/insmod -p x -k modules", \
                "-w /sbin/rmmod -p x -k modules", \
                "-w /sbin/modprobe -p x -k modules", \
                "-a always,exit -F arch=b(32|64) -S init_module -S delete_module -k modules"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit32(match):
    patterns = ["^-e 2"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit33(match):
    patterns = ["-w /var/log/faillog -p wa -k logins", \
                "-w /var/log/lastlog -p wa -k logins"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit34(match):
    patterns = ["-w /var/run/utmp -p wa -k session", \
                "-w /var/log/btmp -p wa -k session", \
                "-w /var/log/wtmp -p wa -k session"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit35(match):
    patterns = ["15"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit36(match):
    patterns = ["enabled"]
    return evalFunc1(patterns, match.group(0).strip('\n'))
def getAudit37(match):
    patterns = ["\*filter", \
                ":INPUT DROP \[0:0\]", \
                ":FORWARD DROP \[0:0\]"]
    return evalFunc1(patterns, match.group(0).strip('\n'))

def getAudit38(match):
    return evalFunc0('(?<=net\.ipv4\.ip_forward\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_IP_FORWARD)
def getAudit39(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.all\.send_redirects\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_ALL_SEND_REDIRECTS)    
def getAudit40(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.default\.send_redirects\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_DEFAULT_SEND_REDIRECTS)    
def getAudit41(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.all\.secure_redirects\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_ALL_SECURE_REDIRECTS)    
def getAudit42(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.default\.secure_redirects\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_DEFAULT_SECURE_REDIRECTS)    
def getAudit43(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.all\.accept_redirects\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_ALL_ACCEPT_REDIRECTS)    
def getAudit44(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.default\.accept_redirects\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_DEFAULT_ACCEPT_REDIRECTS)
def getAudit45(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.all\.accept_source_route\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_ALL_ACCEPT_SOURCE_ROUTE)
def getAudit46(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.default\.accept_source_route\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_DEFAULT_ACCEPT_SOURCE_ROUTE)
def getAudit47(match):
    return evalFunc0('(?<=net\.ipv4\.icmp_ignore_bogus_error_responses\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_ICMP_IGNORE_BOGUS_ERROR_RESPONSES)
def getAudit48(match):
    return evalFunc0('(?<=net\.ipv4\.icmp_echo_ignore_broadcasts\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_ICMP_ECHO_IGNORE_BROADCASTS)
def getAudit49(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.all\.log_martians\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_ALL_LOG_MARTIANS)
def getAudit50(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.all\.rp_filter\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_ALL_RP_FILTER)
def getAudit51(match):
    return evalFunc0('(?<=net\.ipv4\.conf\.default\.rp_filter\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_CONF_DEFAULT_RP_FILTER)
def getAudit52(match):
    return evalFunc0('(?<=net\.ipv4\.tcp_syncookies\s=\s)\d+',match.group(0).strip('\n'),NET_IPV4_TCP_SYNCOOKIES)
def getAudit53(match):
    wireless = [s for s in match.group(0).splitlines() if not len(s)==0]
    if len(wireless)==0:
        return [True,None]
    return [False,"|".join(wireless)]
def getAudit54(match):
    s = match.group(0).strip('\n')
    pattern = '^server\s+.+'
    m = re.search(pattern, s,re.MULTILINE)
    if m:
        return [True,None]
    return [False,None]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--read", help = "來源Excel檔案路徑")
    parser.add_argument("-o", "--output", help = "輸出TVMS檔案路徑")
    parser.add_argument("-a", "--all", help = "輸出所有稽核結果",action="store_true",default=False)
    args = parser.parse_args()
    INPUT_FILE = args.read
    if args.output:
        OUTPUT_DIR = args.output
        OUTPUT_FILE     = os.path.join(OUTPUT_DIR,"TVMS_Linux_" + os.path.splitext(os.path.basename(INPUT_FILE))[0]+".csv")
    else: #if output dir not set, set it to input file's dir 
        OUTPUT_FILE     = os.path.join(os.path.dirname(INPUT_FILE),"TVMS_Linux_" + os.path.splitext(os.path.basename(INPUT_FILE))[0]+".csv")
    SHOW_ALL = args.all
    
    
    try:
        input_file = open(INPUT_FILE,encoding='utf-8',mode='r')
    except :
        print(f'Unable to open {INPUT_FILE}--', sys.exc_info()[0])
        raise
    log = "".join(input_file.readlines())
    input_file.close()
    log_time = getLogtime(log)
    [OS,IP] = getOS(log)
    try:
        output_file = open(OUTPUT_FILE,encoding='utf-8-sig',mode='w')
    except :
        print(f'Unable to open {OUTPUT_FILE}--', sys.exc_info()[0])
        raise
    
    fields_name = list(TVMS_HEADERS.values())
    output_file.write(",".join(fields_name)+"\n")
    N = len(INFO_TABLES) - 1
    global auditFunc
    for i in range(1,N+1):
        eval('auditFunc.append(' + f'getAudit{i:02}' + ')')
    
    for row in INFO_TABLES[1:]:
        audit_id = int(row[0])
        r = getAuditResult(audit_id,log)
        if r[0]:
            result = '符合'
            setting = ''
        else:
            result = '不符合'
            if r[1]:
                setting = r[1]
            else:
                setting = '設定值有誤或未設定'
        if r[0]==False or SHOW_ALL: # write to file if audit not passed
            result_list = {'A':log_time,
                           'B':IP,                       
                           'C':'',
                           'D':'',
                           'E':'',
                           'F':'GCB合規檢測',
                           'G':result,
                           'H':row[2],         # mapping to 弱點類別
                           'I':'',
                           'J':row[1], # mapping to 評估工具原廠之弱點編號
                           'K':row[3], # mapping to 弱點說明
                           'L':'',
                           'M':row[4], # mapping to 弱點修補建議
                           'N':setting,
                           'O':'合規'}
            result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
            output_file.write(",".join(list(result_list.values()))+"\n")
    output_file.close()
if __name__ == '__main__':
    try:
        main()
    except:
        print(f'Unable to run this program--', sys.exc_info()[0])
        raise
