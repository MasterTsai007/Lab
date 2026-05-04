import requests
import json
import time
import csv
import re
import os

# ==========================================
# 1. 測評環境與參數設定 (同質模型極速版)
# ==========================================
OLLAMA_API = "http://localhost:11434/api/generate"
OUTPUT_CSV = "Architecture_Ablation_Results_Homogeneous(phi+phi).csv"
DATASET_FILE = "dataset_en.jsonl" # 您的 110 題庫檔案名稱

# 【測試數量控制】
# 預設跑全部 110 題。如果您想先測幾題，可以改成 5。
MAX_TESTS = 110 

# 【同質管線測試設定】全部使用您微調的專屬模型
MODEL_SINGLE = "my-soc-agent-en" # 單兵對照組
MODEL_L1 = "my-soc-agent-en"     # 聯防 L1：特徵萃取
MODEL_L2 = "my-soc-agent-en"     # 聯防 L2：建議擴充

# ==========================================
# 2. 自動載入 JSONL 題庫
# ==========================================
def load_test_logs(filename, max_count):
    logs = []
    if not os.path.exists(filename):
        print(f"❌ 找不到檔案: {filename}。請確認它與此腳本放在同一個資料夾。")
        return [{"id": "Error", "log": "{}"}]

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                if i > max_count:
                    break
                
                data = json.loads(line.strip())
                full_text = data.get("text", "")
                
                # 從完整的 Prompt 中精準萃取出 ### Input: 裡面的 Log 內容
                match = re.search(r'### Input:\n(.*?)\n### Response:', full_text, re.DOTALL)
                if match:
                    log_content = match.group(1).strip()
                    logs.append({
                        "id": f"Task_{i:03d}", # 自動產生 Task_001, Task_002...
                        "log": log_content
                    })
        print(f"✅ 成功從 {filename} 載入 {len(logs)} 筆測試題目！")
    except Exception as e:
        print(f"❌ 解析 JSONL 失敗: {e}")
        return [{"id": "Error", "log": "{}"}]
    
    return logs

test_logs = load_test_logs(DATASET_FILE, MAX_TESTS)

# ==========================================
# 3. 核心功能函式 (容錯設計)
# ==========================================
def call_llm(prompt, target_model):
    """呼叫 Ollama API，具備強制 JSON 模式與防暴走斷路器"""
    payload = {
        "model": target_model, 
        "prompt": prompt, 
        "stream": False, 
        "format": "json", # 強制底層只能吐 JSON
        "options": {
            "temperature": 0.0,
            "num_predict": 500, # 給足字數空間
            "stop": ["</s>", "<|end|>", "### Instruction:", "### Input:"] # 強制煞車皮
        }
    }
    try:
        res = requests.post(OLLAMA_API, json=payload).json()
        return res.get("response", "").strip()
    except Exception as e:
        print(f"   [API 錯誤] {e}")
        return ""

def extract_json(text):
    """終極強健的堆疊式 JSON 萃取器：專治模型碎碎念與連發"""
    cleaned = re.sub(r'```json\s*', '', text, flags=re.IGNORECASE)
    cleaned = re.sub(r'```\s*', '', cleaned)
    cleaned = cleaned.strip()

    stack = 0
    start_idx = -1
    
    for i, char in enumerate(cleaned):
        if char == '{':
            if stack == 0:
                start_idx = i
            stack += 1
        elif char == '}':
            stack -= 1
            if stack == 0 and start_idx != -1:
                # 抓到第一個完整 JSON 就回傳，無視後面的幻覺
                json_str = cleaned[start_idx:i+1]
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    clean_str = re.sub(r'[\x00-\x1F\x7F]', '', json_str)
                    try:
                        return json.loads(clean_str)
                    except:
                        pass
    return {}

def validate_keys(data_dict, required_keys):
    """大小寫免疫的欄位驗證器"""
    if not isinstance(data_dict, dict):
        return False, required_keys
    lower_keys = [str(k).lower() for k in data_dict.keys()]
    missing_keys = []
    for req in required_keys:
        if req.lower() not in lower_keys:
            missing_keys.append(req)
    return (len(missing_keys) == 0), missing_keys

# ==========================================
# 4. 提示詞工程 (Prompts) - 配合 Phi-3 微調格式
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
if test_logs[0]['id'] == "Error":
    print("程式終止：請先解決題庫載入問題。")
    exit()

results = []
print(f"\n🚀 開始執行系統架構消融實驗")
print(f"   ➤ 單兵模型: {MODEL_SINGLE}")
print(f"   ➤ 聯防 L1 模型: {MODEL_L1}")
print(f"   ➤ 聯防 L2 模型: {MODEL_L2}\n")

# 暖機
requests.post(OLLAMA_API, json={"model": MODEL_L1, "prompt": "hi", "stream": False})

req_keys = ["TTP_ID", "Explanation", "Severity", "Mitigation"]

for item in test_logs:
    print(f"➤ 正在測試: {item['id']}")
    
    # --- 單兵 ---
    t0 = time.time()
    single_out = call_llm(prompt_single_agent(item['log']), MODEL_SINGLE)
    single_time = round(time.time() - t0, 2)
    single_json = extract_json(single_out)
    single_is_valid, s_missing = validate_keys(single_json, req_keys)
    s_debug = "完美" if single_is_valid else f"漏掉 {s_missing}"
    print(f"   [單兵] 耗時: {single_time:05.2f}s | 完整度: {single_is_valid} ({s_debug})")
    
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
    multi_is_valid, m_missing = validate_keys(final_multi_json, req_keys)
    m_debug = "完美" if multi_is_valid else f"漏掉 {m_missing}"
    print(f"   [聯防] 耗時: {multi_time:05.2f}s | 完整度: {multi_is_valid} ({m_debug})")
    print("-" * 50)
    
    results.append({
        "Test_ID": item['id'],
        "Single_Valid_All_Keys": single_is_valid,
        "Single_Latency": single_time,
        "Multi_Valid_All_Keys": multi_is_valid,
        "Multi_Latency": multi_time,
        "Single_Raw": single_out.replace("\n", " "),
        "Multi_L1_Raw": l1_out.replace("\n", " "),
        "Multi_L2_Raw": l2_out.replace("\n", " ")
    })

# ==========================================
# 6. 輸出報表與自動統計
# ==========================================
csv_columns = ["Test_ID", "Single_Valid_All_Keys", "Single_Latency", "Multi_Valid_All_Keys", "Multi_Latency", "Single_Raw", "Multi_L1_Raw", "Multi_L2_Raw"]
with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8-sig') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    writer.writeheader()
    for data in results:
        writer.writerow(data)

print(f"🎉 測評完畢！數據已匯出至: {OUTPUT_CSV}")
print("\n" + "="*50)
print("📊 論文實驗數據自動統計報告")
print("="*50)

total_tests = len(results)
single_valid_count = sum(1 for r in results if r["Single_Valid_All_Keys"])
single_avg_latency = sum(r["Single_Latency"] for r in results) / total_tests
single_success_rate = (single_valid_count / total_tests) * 100

multi_valid_count = sum(1 for r in results if r["Multi_Valid_All_Keys"])
multi_avg_latency = sum(r["Multi_Latency"] for r in results) / total_tests
multi_success_rate = (multi_valid_count / total_tests) * 100

print(f"【單一代理人架構 (Single Agent)】")
print(f"  ➤ 格式與欄位完整率: {single_success_rate:.1f}% ({single_valid_count}/{total_tests})")
print(f"  ➤ 平均推論耗時:     {single_avg_latency:.2f} 秒")

print(f"\n【同質聯防管線 (Multi-Agent Pipeline)】")
print(f"  ➤ 格式與欄位完整率: {multi_success_rate:.1f}% ({multi_valid_count}/{total_tests})")
print(f"  ➤ 平均推論耗時:     {multi_avg_latency:.2f} 秒")
print("="*50)