import requests
import json
import time
import csv
import re
import os

# ==========================================
# 1. 測評環境與參數設定
# ==========================================
OLLAMA_API = "http://localhost:11434/api/generate"
OUTPUT_CSV = "Architecture_RealWorld_Results.csv"
DATASET_FILE = "real_dataset.jsonl" 
MAX_TESTS = 10 

MODEL_SINGLE = "my-soc-agent-en" 
MODEL_L1 = "my-soc-agent-en"     
MODEL_L2 = "llama3.1"     

# ==========================================
# 2. 自動載入 JSONL 題庫與【攻擊鏈答案】
# ==========================================
def load_test_logs(filename, max_count):
    logs = []
    if not os.path.exists(filename): return logs

    with open(filename, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f, 1):
            if i > max_count: break
            data = json.loads(line.strip())
            
            # 抓出隱藏的有效 TTP 陣列，若無則預設空陣列
            valid_ttps = data.get("valid_ttps", [])
            
            match = re.search(r'### Input:\n(.*?)\n### Response:', data.get("text", ""), re.DOTALL)
            if match:
                logs.append({
                    "id": f"Task_{i:03d}",
                    "log": match.group(1).strip(),
                    "valid_ttps": valid_ttps
                })
    return logs

test_logs = load_test_logs(DATASET_FILE, MAX_TESTS)

# ==========================================
# 3. 核心功能函式
# ==========================================
def call_llm(prompt, target_model):
    payload = {
        "model": target_model, 
        "prompt": prompt, 
        "stream": False, 
        "format": "json", 
        "options": {"temperature": 0.0, "num_predict": 500, "stop": ["</s>", "### Instruction:", "### Input:"]}
    }
    try: return requests.post(OLLAMA_API, json=payload).json().get("response", "").strip()
    except: return ""

def extract_json(text):
    cleaned = re.sub(r'```json\s*', '', text, flags=re.IGNORECASE)
    cleaned = re.sub(r'```\s*', '', cleaned).strip()
    stack, start_idx = 0, -1
    for i, char in enumerate(cleaned):
        if char == '{':
            if stack == 0: start_idx = i
            stack += 1
        elif char == '}':
            stack -= 1
            if stack == 0 and start_idx != -1:
                try: return json.loads(cleaned[start_idx:i+1])
                except:
                    try: return json.loads(re.sub(r'[\x00-\x1F\x7F]', '', cleaned[start_idx:i+1]))
                    except: pass
    return {}

def validate_keys(data_dict, required_keys):
    if not isinstance(data_dict, dict): return False
    lower_keys = [str(k).lower() for k in data_dict.keys()]
    return all(req.lower() in lower_keys for req in required_keys)

# 【核心升級：攻擊鏈寬鬆比對邏輯】
def check_ttp_match(valid_list, predicted):
    if not predicted or not valid_list: return "❌ Miss"
    pred = str(predicted).strip().lower()

    for valid_ttp in valid_list:
        valid = str(valid_ttp).strip().lower()
        # 1. 命中攻擊鏈中任何一環
        if valid in pred or pred in valid:
            return "✅ Hit (命中攻擊鏈)"
        # 2. 命中父類別 (例如答案有 T1059，預測為 T1059.001)
        valid_parent = valid.split('.')[0]
        if valid_parent in pred:
            return "⚠️ Partial (命中父類別)"
            
    return "❌ Miss"

# ==========================================
# 4. 測評主程式
# ==========================================
if not test_logs: exit()

results = []
print(f"\n🚀 開始執行系統架構消融實驗 (攻擊鏈評測版)")
requests.post(OLLAMA_API, json={"model": MODEL_L1, "prompt": "hi", "stream": False})
req_keys = ["TTP_ID", "Explanation", "Severity", "Mitigation"]

for item in test_logs:
    valid_ttps = item['valid_ttps']
    
    # --- 單兵 ---
    t0 = time.time()
    single_out = call_llm(f"### Instruction:\nAnalyze the log. Output strictly a JSON dictionary with exactly 4 keys: 'TTP_ID', 'Explanation', 'Severity', 'Mitigation'.\n### Input:\n{item['log']}\n### Response:", MODEL_SINGLE)
    single_time = round(time.time() - t0, 2)
    single_json = extract_json(single_out)
    single_is_valid = validate_keys(single_json, req_keys)
    
    s_ttp = single_json.get("TTP_ID", single_json.get("ttp_id", ""))
    s_acc_str = check_ttp_match(valid_ttps, s_ttp)
    
    # --- 聯防 ---
    t0 = time.time()
    l1_out = call_llm(f"### Instruction:\nAnalyze the log and map to MITRE ATT&CK. Output strictly a JSON dictionary with exactly 2 keys: 'TTP_ID', 'Explanation'.\n### Input:\n{item['log']}\n### Response:", MODEL_L1)
    l1_json = extract_json(l1_out)
    l1_ttp = l1_json.get("TTP_ID", l1_json.get("ttp_id", "Unknown"))
    l1_exp = l1_json.get("Explanation", l1_json.get("explanation", "Unknown"))
    
    l2_out = call_llm(f"### Instruction:\nBased on the log and identified threat ({l1_ttp}), assess the severity. Output strictly a JSON dictionary with exactly 2 keys: 'Severity' (High/Medium/Low) and 'Mitigation'.\n### Original Log:\n{item['log']}\n### Identified Threat:\n{l1_exp}\n### Response:", MODEL_L2)
    l2_json = extract_json(l2_out)
    multi_time = round(time.time() - t0, 2)
    
    final_multi_json = {**l1_json, **l2_json}
    multi_is_valid = validate_keys(final_multi_json, req_keys)
    
    m_acc_str = check_ttp_match(valid_ttps, l1_ttp)
    
    print(f"➤ {item['id']} | 預期攻擊鏈: {', '.join(valid_ttps[:4])}...")
    print(f"   [單兵] 格式: {'✅' if single_is_valid else '❌'} | 準確度: {s_acc_str} ({s_ttp})")
    print(f"   [聯防] 格式: {'✅' if multi_is_valid else '❌'} | 準確度: {m_acc_str} ({l1_ttp})")
    print("-" * 50)
    
    # 判斷是否算過關 (只要是 Hit 或是 Partial 都算答對)
    results.append({
        "Single_Valid": single_is_valid,
        "Single_Acc": "Hit" in s_acc_str or "Partial" in s_acc_str,
        "Multi_Valid": multi_is_valid,
        "Multi_Acc": "Hit" in m_acc_str or "Partial" in m_acc_str
    })

# 統計報表
total = len(results)
print("\n" + "="*50)
print("📊 論文實驗數據：真實攻擊鏈綜合命中率")
print("="*50)

s_acc = sum(1 for r in results if r["Single_Acc"])
m_acc = sum(1 for r in results if r["Multi_Acc"])

print(f"【單一代理人架構 (Single Agent)】")
print(f"  ➤ 攻擊鏈綜合命中率: {s_acc/total*100:.1f}% ({s_acc}/{total})")

print(f"\n【異質聯防管線 (Multi-Agent Pipeline)】")
print(f"  ➤ 攻擊鏈綜合命中率: {m_acc/total*100:.1f}% ({m_acc}/{total})")
print("="*50)