import json
import os

# ========================================================
# 1. 設定區：OTRF 真實 Log 與攻擊鏈設定
# ========================================================
INPUT_OTRF_FILE = "cmd_psexec_lsa_secrets_dump_2020-10-1903305471.json" 
OUTPUT_JSONL_FILE = "real_dataset.jsonl"    

GROUND_TRUTH_TTP = "T1003.001" 
GROUND_TRUTH_EXP = "Credential dumping via LSASS memory extraction."

# 🌟 【終極升級】：完整的 Empire 攻擊鏈戰術涵蓋範圍
VALID_ATTACK_CHAIN = [
    "T1003", # 憑證傾印 (核心意圖)
    "T1059", # PowerShell/CMD 執行
    "T1569", # 系統服務執行 (PsExec)
    "T1047", # WMI 執行
    "T1112", # 修改登錄檔 (reg save)
    "T1053", # 排程任務
    "T1078"  # 有效帳號
]

# ========================================================
# 2. 深度搜索演算法
# ========================================================
def find_value_in_dict(data, target_key):
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() == target_key.lower(): return v
            if isinstance(v, dict):
                result = find_value_in_dict(v, target_key)
                if result: return result
    return ""

# ========================================================
# 3. 轉換與過濾邏輯
# ========================================================
if not os.path.exists(INPUT_OTRF_FILE):
    print(f"❌ 找不到檔案 {INPUT_OTRF_FILE}")
    exit()

converted_count = 0
with open(INPUT_OTRF_FILE, 'r', encoding='utf-8') as infile, \
     open(OUTPUT_JSONL_FILE, 'w', encoding='utf-8') as outfile:
    
    for line in infile:
        line = line.strip()
        if not line: continue
            
        try:
            log_data = json.loads(line)
            event_id = find_value_in_dict(log_data, "EventID")
            if str(event_id) not in ["1", "10", "11"]: continue
            
            slim_log = {
                "EventID": event_id,
                "Image": find_value_in_dict(log_data, "Image"),
                "CommandLine": find_value_in_dict(log_data, "CommandLine")
            }
            if not slim_log["Image"] and not slim_log["CommandLine"]: continue
            slim_log = {k: v for k, v in slim_log.items() if v}
            
            prompt_text = (
                "Below is an instruction that describes a task, paired with an input that provides further context. "
                "Write a response that appropriately completes the request.\n"
                "### Instruction:\n"
                "Analyze the endpoint log, extract malicious features, and map to MITRE ATT&CK. "
                "You MUST output strictly in JSON containing 'TTP_ID' and 'Explanation'.\n"
                "### Input:\n"
                f"{json.dumps(slim_log)}\n"
                "### Response:\n"
                f"{json.dumps({'TTP_ID': GROUND_TRUTH_TTP, 'Explanation': GROUND_TRUTH_EXP})}"
            )
            
            output_data = {
                "text": prompt_text,
                "valid_ttps": VALID_ATTACK_CHAIN
            }
            
            outfile.write(json.dumps(output_data) + "\n")
            converted_count += 1
            if converted_count >= 10: break
                
        except json.JSONDecodeError:
            continue

print(f"🎉 轉換完成！已將「終極攻擊鏈陣列」寫入 {OUTPUT_JSONL_FILE}")