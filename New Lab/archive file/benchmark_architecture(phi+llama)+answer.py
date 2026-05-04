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
OUTPUT_CSV = "Architecture_Ablation_Results_Accuracy.csv"
#DATASET_FILE = "dataset_en.jsonl" 
DATASET_FILE = "real_dataset.jsonl"

# 【測試數量控制】
MAX_TESTS = 10

MODEL_SINGLE = "my-soc-agent-en" 
MODEL_L1 = "my-soc-agent-en"     
MODEL_L2 = "llama3.1"     

# ==========================================
# 2. 自動載入 JSONL 題庫與【標準答案 (Ground Truth)】
# ==========================================
def load_test_logs(filename, max_count):
    logs = []
    if not os.path.exists(filename):
        print(f"❌ 找不到檔案: {filename}")
        return [{"id": "Error", "log": "{}", "expected_ttp": "Unknown"}]

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                if i > max_count:
                    break
                
                data = json.loads(line.strip())
                full_text = data.get("text", "")
                
                # 同時抓取題目 (Input) 與標準答案 (Response)
                match = re.search(r'### Input:\n(.*?)\n### Response:\n(.*)', full_text, re.DOTALL)
                if match:
                    log_content = match.group(1).strip()
                    response_content = match.group(2).strip()
                    
                    # 從標準答案中解析出正確的 TTP_ID
                    expected_ttp = "Unknown"
                    try:
                        resp_json = json.loads(response_content)
                        expected_ttp = resp_json.get("TTP_ID", "Unknown")
                    except:
                        pass
                        
                    logs.append({
                        "id": f"Task_{i:03d}",
                        "log": log_content,
                        "expected_ttp": expected_ttp # 偷偷把答案存起來
                    })
        print(f"✅ 成功載入 {len(logs)} 筆測試題目與標準答案！")
    except Exception as e:
        print(f"❌ 解析 JSONL 失敗: {e}")
        return [{"id": "Error", "log": "{}", "expected_ttp": "Unknown"}]
    
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
        "options": {
            "temperature": 0.0,
            "num_predict": 500, 
            "stop": ["</s>", "<|end|>", "### Instruction:", "### Input:"] 
        }
    }
    try:
        res = requests.post(OLLAMA_API, json=payload).json()
        return res.get("response", "").strip()
    except Exception as e:
        return ""

def extract_json(text):
    cleaned = re.sub(r'```json\s*', '', text, flags=re.IGNORECASE)
    cleaned = re.sub(r'```\s*', '', cleaned)
    cleaned = cleaned.strip()
    stack = 0
    start_idx = -1
    for i, char in enumerate(cleaned):
        if char == '{':
            if stack == 0: start_idx = i
            stack += 1
        elif char == '}':
            stack -= 1
            if stack == 0 and start_idx != -1:
                json_str = cleaned[start_idx:i+1]
                try: return json.loads(json_str)
                except:
                    clean_str = re.sub(r'[\x00-\x1F\x7F]', '', json_str)
                    try: return json.loads(clean_str)
                    except: pass
    return {}

def validate_keys(data_dict, required_keys):
    if not isinstance(data_dict, dict): return False, required_keys
    lower_keys = [str(k).lower() for k in data_dict.keys()]
    missing_keys = [req for req in required_keys if req.lower() not in lower_keys]
    return (len(missing_keys) == 0), missing_keys

# 【新增：寬鬆的 TTP 比對邏輯】
def check_ttp_match(expected, predicted):
    if expected == "Unknown" or not predicted:
        return False
    # 只要模型吐出的字串「包含」標準答案就算對 (例如答案是 T1059，模型吐 "T1059 - PowerShell" 算對)
    return str(expected).strip().lower() in str(predicted).strip().lower()

# ==========================================
# 4. 提示詞工程 (Prompts)
# ==========================================
def prompt_single_agent(log):
    return f"""### Instruction:
Analyze the log. Output strictly a JSON dictionary with exactly 4 keys: 'TTP_ID', 'Explanation', 'Severity', 'Mitigation'. Do not add any markdown formatting.
### Input:
{log}
### Response:"""

def prompt_multi_L1(log):
    return f"""### Instruction:
Analyze the log and map to MITRE ATT&CK. Output strictly a JSON dictionary with exactly 2 keys: 'TTP_ID', 'Explanation'. Do not add any markdown.
### Input:
{log}
### Response:"""

def prompt_multi_L2(log, l1_ttp, l1_exp):
    return f"""### Instruction:
Based on the log and identified threat ({l1_ttp}), assess the severity. Output strictly a JSON dictionary with exactly 2 keys: 'Severity' (High/Medium/Low) and 'Mitigation'. Do not add any markdown.
### Original Log:
{log}
### Identified Threat:
{l1_exp}
### Response:"""

# ==========================================
# 5. 測評主程式
# ==========================================
if test_logs[0]['id'] == "Error": exit()

results = []
print(f"\n🚀 開始執行系統架構消融實驗 (包含準確率評測)")
requests.post(OLLAMA_API, json={"model": MODEL_L1, "prompt": "hi", "stream": False})
req_keys = ["TTP_ID", "Explanation", "Severity", "Mitigation"]

for item in test_logs:
    expected_ttp = item['expected_ttp']
    
    # --- 單兵 ---
    t0 = time.time()
    single_out = call_llm(prompt_single_agent(item['log']), MODEL_SINGLE)
    single_time = round(time.time() - t0, 2)
    single_json = extract_json(single_out)
    single_is_valid, _ = validate_keys(single_json, req_keys)
    
    # 比對單兵準確率
    single_pred_ttp = single_json.get("TTP_ID", single_json.get("ttp_id", ""))
    single_is_acc = check_ttp_match(expected_ttp, single_pred_ttp)
    
    # --- 聯防 ---
    t0 = time.time()
    l1_out = call_llm(prompt_multi_L1(item['log']), MODEL_L1)
    l1_json = extract_json(l1_out)
    l1_ttp = l1_json.get("TTP_ID", l1_json.get("ttp_id", "Unknown"))
    l1_exp = l1_json.get("Explanation", l1_json.get("explanation", "Unknown"))
    
    l2_out = call_llm(prompt_multi_L2(item['log'], l1_ttp, l1_exp), MODEL_L2)
    l2_json = extract_json(l2_out)
    multi_time = round(time.time() - t0, 2)
    
    final_multi_json = {**l1_json, **l2_json}
    multi_is_valid, _ = validate_keys(final_multi_json, req_keys)
    
    # 比對聯防準確率 (由 L1 決定)
    multi_is_acc = check_ttp_match(expected_ttp, l1_ttp)
    
    # 終端機顯示進度
    print(f"➤ {item['id']} | 標準答案: {expected_ttp}")
    print(f"   [單兵] 格式: {'✅' if single_is_valid else '❌'} | TTP命中: {'✅' if single_is_acc else '❌'} ({single_pred_ttp})")
    print(f"   [聯防] 格式: {'✅' if multi_is_valid else '❌'} | TTP命中: {'✅' if multi_is_acc else '❌'} ({l1_ttp})")
    print("-" * 50)
    
    results.append({
        "Test_ID": item['id'],
        "Expected_TTP": expected_ttp,
        "Single_Valid_Keys": single_is_valid,
        "Single_TTP_Match": single_is_acc,
        "Single_Latency": single_time,
        "Multi_Valid_Keys": multi_is_valid,
        "Multi_TTP_Match": multi_is_acc,
        "Multi_Latency": multi_time,
        "Single_Raw": single_out.replace("\n", " "),
        "Multi_L1_Raw": l1_out.replace("\n", " "),
        "Multi_L2_Raw": l2_out.replace("\n", " ")
    })

# ==========================================
# 6. 輸出報表與自動統計
# ==========================================
csv_columns = ["Test_ID", "Expected_TTP", "Single_Valid_Keys", "Single_TTP_Match", "Single_Latency", 
               "Multi_Valid_Keys", "Multi_TTP_Match", "Multi_Latency", "Single_Raw", "Multi_L1_Raw", "Multi_L2_Raw"]
with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8-sig') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    writer.writeheader()
    for data in results:
        writer.writerow(data)

print("\n" + "="*50)
print("📊 論文實驗數據自動統計報告 (精準度版)")
print("="*50)

total = len(results)

s_fmt = sum(1 for r in results if r["Single_Valid_Keys"])
s_acc = sum(1 for r in results if r["Single_TTP_Match"])
s_time = sum(r["Single_Latency"] for r in results) / total

m_fmt = sum(1 for r in results if r["Multi_Valid_Keys"])
m_acc = sum(1 for r in results if r["Multi_TTP_Match"])
m_time = sum(r["Multi_Latency"] for r in results) / total

print(f"【單一代理人架構 (Single Agent)】")
print(f"  ➤ 格式完整率: {s_fmt/total*100:.1f}%")
print(f"  ➤ ＴＴＰ準確率: {s_acc/total*100:.1f}% ({s_acc}/{total})")
print(f"  ➤ 平均推論耗時: {s_time:.2f} 秒")

print(f"\n【同質聯防管線 (Multi-Agent Pipeline)】")
print(f"  ➤ 格式完整率: {m_fmt/total*100:.1f}%")
print(f"  ➤ ＴＴＰ準確率: {m_acc/total*100:.1f}% ({m_acc}/{total})")
print(f"  ➤ 平均推論耗時: {m_time:.2f} 秒")
print("="*50)