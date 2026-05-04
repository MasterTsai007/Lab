import os
import glob
import json
import re

# ========================================================
# 1. 路徑與系統設定
# ========================================================
OTRF_BASE_DIR = "./Security-Datasets/datasets/atomic/windows/"
OUTPUT_EXAM_JSONL = "massive_exam_dataset.jsonl"

TARGET_EVENT_IDS = ["1", "10", "11", "4688", "4624"]

# 🛡️ 升級版白名單：除了 LSASS，再加入 Event 1 常見的 Windows 背景雜訊
NOISY_IMAGES = [
    "searchui.exe", "searchapp.exe", "backgroundtaskhost.exe", 
    "mobsync.exe", "taskhostw.exe", "dashost.exe", "sihost.exe",
    "conhost.exe", "svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "msmpeng.exe"
]

TACTIC_MAPPING = {
    "credential_access": ["T1003", "T1055", "T1555", "Credential Access"],
    "lateral_movement": ["T1021", "T1090", "T1563", "Lateral Movement"],
    "defense_evasion": ["T1055", "T1070", "T1562", "Defense Evasion"],
    "execution": ["T1059", "T1047", "T1569", "Execution"],
    "persistence": ["T1053", "T1543", "T1547", "Persistence"],
    "privilege_escalation": ["T1134", "T1548", "T1055", "Privilege Escalation"]
}

# ========================================================
# 2. 自動化掃描與轉換邏輯
# ========================================================
print(f"🔍 正在掃描 OTRF 目錄: {OTRF_BASE_DIR}")
json_files = glob.glob(os.path.join(OTRF_BASE_DIR, "**", "*.json"), recursive=True)
print(f"📁 共找到 {len(json_files)} 個 JSON 日誌檔，準備進行批次轉換...\n")

extracted_count = 0
noise_filtered_count = 0

with open(OUTPUT_EXAM_JSONL, 'w', encoding='utf-8') as outfile:
    for file_path in json_files:
        valid_ttps = []
        
        match = re.search(r'(T\d{4}(?:\.\d{3})?)', file_path, re.IGNORECASE)
        if match: valid_ttps.append(match.group(1).upper())
            
        for tactic, ttps in TACTIC_MAPPING.items():
            if tactic in file_path.lower():
                valid_ttps.extend(ttps)
                break
                
        if not valid_ttps: valid_ttps = ["Unknown Threat"]

        try:
            file_extracted = 0 # 計算單一檔案抽了幾題
            with open(file_path, 'r', encoding='utf-8') as infile:
                for line in infile:
                    if not line.strip(): continue
                    try: log_entry = json.loads(line)
                    except: continue
                        
                    event_id = str(log_entry.get("EventID", ""))
                    if event_id not in TARGET_EVENT_IDS: continue
                        
                    slim_log = {"EventID": event_id}
                    for key in ["Image", "CommandLine", "SourceImage", "TargetImage", "GrantedAccess", "CallTrace", "TargetUserName", "LogonType", "ElevatedToken"]:
                        if log_entry.get(key): slim_log[key] = log_entry[key]

                    # 🛡️ 核心防護網 1：過濾 LSASS 存取雜訊 (Event 10)
                    if event_id == "10" and "lsass.exe" in slim_log.get("TargetImage", "").lower():
                        source_img = slim_log.get("SourceImage", "").lower()
                        if any(ws in source_img for ws in NOISY_IMAGES):
                            noise_filtered_count += 1
                            continue
                            
                    # 🛡️ 核心防護網 2：過濾 Cortana 與 Windows 背景服務雜訊 (Event 1 / 4688)
                    if event_id in ["1", "4688"]:
                        image = slim_log.get("Image", "").lower()
                        if any(ws in image for ws in NOISY_IMAGES):
                            # 如果沒有帶特殊的指令 (CommandLine 很短)，就當作純雜訊丟棄
                            cmd = slim_log.get("CommandLine", "")
                            if len(cmd) < 50 and not any(k in cmd.lower() for k in ["-enc", "bypass", "hidden", "http"]):
                                noise_filtered_count += 1
                                continue
                                
                    if len(slim_log) <= 1: continue

                    prompt_text = (
                        "Below is an instruction that describes a task, paired with an input that provides further context. "
                        "Write a response that appropriately completes the request.\n"
                        "### Instruction:\n"
                        "Analyze the endpoint log, extract malicious features, and map to MITRE ATT&CK. "
                        "You MUST output strictly in JSON containing 'TTP_ID' and 'Explanation'.\n"
                        "### Input:\n"
                        f"{json.dumps(slim_log)}\n"
                        "### Response:\n"
                        "{\"TTP_ID\": \"TXXXX\", \"Explanation\": \"Pending Human Labeling\"}"
                    )
                    
                    output_data = {
                        "text": prompt_text,
                        "valid_ttps": list(set(valid_ttps)),
                        "source_file": os.path.basename(file_path)
                    }
                    
                    outfile.write(json.dumps(output_data) + "\n")
                    extracted_count += 1
                    file_extracted += 1
                    
                    # 每個檔案往後多看一點，抓到 5 筆「非雜訊」的精華再換下一個檔案
                    if file_extracted >= 5:
                        break 

        except Exception as e:
            continue

print("=" * 60)
print(f"🎉 批次轉換大功告成！")
print(f"🛡️ 成功過濾 Cortana 等合法背景雜訊：{noise_filtered_count} 筆")
print(f"🎯 成功打造超級題庫：共 {extracted_count} 題，已寫入 {OUTPUT_EXAM_JSONL}")
print("=" * 60)