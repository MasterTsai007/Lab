import json
import re

# ==========================================
# 1. 系統設定參數
# ==========================================
INPUT_FILE = "sample.json"      # 您的原始日誌檔名
OUTPUT_FILE = "modern_apt_from_raw.jsonl" # 產出的超級考卷檔名
SOURCE_NAME = "generic_threat_dataset"    # 來源標籤 (供 Excel 反查使用)

# ==========================================
# 2. 核心大腦：威脅特徵簽名庫 (Threat Signatures)
# ==========================================
# 論文亮點：這是一個可擴充的「規則式標註引擎」。
# 只要日誌的內容同時滿足 'keywords' 裡的所有字眼，就會被貼上對應的 'ttps' 標籤。
THREAT_SIGNATURES = [
    # 1. 持久化 (Persistence)
    {
        "name": "Registry Run Keys / Logon Script",
        "keywords": ["userinitmprlogonscript", "reg.exe"],
        "ttps": ["T1037.001", "T1547.001"]
    },
    # 2. 憑證存取 (Credential Access)
    {
        "name": "LSASS Memory Dumping",
        "keywords": ["lsass.exe", "grantedaccess", "0x1010"], # 記憶體讀取特徵
        "ttps": ["T1003.001"]
    },
    {
        "name": "Mimikatz Execution",
        "keywords": ["mimikatz", "sekurlsa"],
        "ttps": ["T1003.001"]
    },
    # 3. 防禦規避 (Defense Evasion)
    {
        "name": "Clear Windows Event Logs",
        "keywords": ["wevtutil.exe", "cl", "system"],
        "ttps": ["T1070.001"]
    },
    {
        "name": "Disable Windows Defender",
        "keywords": ["disableantispyware", "reg", "add"],
        "ttps": ["T1562.001"]
    },
    # 4. 執行 (Execution)
    {
        "name": "Malicious PowerShell (Hidden/Encoded)",
        "keywords": ["powershell", "-w", "hidden", "-enc"],
        "ttps": ["T1059.001"]
    },
    # 5. 衝擊 (Impact)
    {
        "name": "Delete Volume Shadow Copies (Ransomware)",
        "keywords": ["vssadmin.exe", "delete", "shadows"],
        "ttps": ["T1490"]
    }
    # 💡 您可以在這裡無限擴充您想測試的攻擊手法...
]

# ==========================================
# 3. 泛用型標註邏輯
# ==========================================
def determine_ground_truth(log_str):
    """
    動態比對簽名庫。如果完全吻合某個規則，就回傳該規則的 TTPs。
    """
    log_lower = log_str.lower()
    
    for rule in THREAT_SIGNATURES:
        # 檢查該規則的所有關鍵字是否都存在於日誌中 (AND 邏輯)
        if all(keyword in log_lower for keyword in rule["keywords"]):
            return rule["ttps"]
            
    # 如果所有惡意規則都沒中，判定為背景雜訊
    return ["Unknown Threat"]

def extract_log_list(raw_data):
    """
    智慧型陣列提取：自動適應不同靶機/SIEM匯出的 JSON 結構
    """
    if isinstance(raw_data, list):
        return raw_data
    if isinstance(raw_data, dict):
        # 常見的包裝鍵名
        for key in ["logs", "events", "data", "records"]:
            if key in raw_data and isinstance(raw_data[key], list):
                return raw_data[key]
    return []

# ==========================================
# 4. 開始執行資料管線 (Data Pipeline)
# ==========================================
print(f"⏳ 啟動泛用型日誌轉換器: {INPUT_FILE}")

try:
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        raw_data = json.load(f)
except FileNotFoundError:
    print(f"❌ 找不到檔案 {INPUT_FILE}，請確認檔案存在。")
    exit()

logs_list = extract_log_list(raw_data)
if not logs_list:
    print("❌ 無法從 JSON 中提取日誌陣列，請確認結構。")
    exit()

converted_count = 0
malicious_count = 0
threat_stats = {}

with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_f:
    for log_entry in logs_list:
        # 將單筆日誌轉為純字串，方便正則或關鍵字搜尋
        log_str = json.dumps(log_entry, ensure_ascii=False)
        
        # 取得標準答案 (Ground Truth)
        valid_ttps = determine_ground_truth(log_str)
        
        if "Unknown Threat" not in valid_ttps:
            malicious_count += 1
            # 統計命中哪些戰術 (供最後顯示用)
            ttp_key = ", ".join(valid_ttps)
            threat_stats[ttp_key] = threat_stats.get(ttp_key, 0) + 1

        # 組裝成 LLM 指令微調 (Instruction-Tuning) 格式
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
        converted_count += 1

# ==========================================
# 5. 輸出轉檔報告
# ==========================================
print("\n" + "=" * 50)
print(f"✅ 轉換管線執行完畢！已產出: {OUTPUT_FILE}")
print("=" * 50)
print(f"➤ 總處理日誌數： {converted_count} 筆")
print(f"➤ 成功標記威脅： {malicious_count} 筆")
print(f"➤ 判定為背景雜訊： {converted_count - malicious_count} 筆")

if malicious_count > 0:
    print("\n🔍 [提取出的威脅分佈]")
    for ttp, count in threat_stats.items():
        print(f"   - {ttp}: {count} 筆")
print("=" * 50)