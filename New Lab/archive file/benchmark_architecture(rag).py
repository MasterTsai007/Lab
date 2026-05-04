import requests
import json
import time
import csv
import re
import os
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

# ==========================================
# 1. 環境與模型設定
# ==========================================
OLLAMA_API = "http://localhost:11434/api/generate"
DATASET_FILE = "real_dataset.jsonl" 
MAX_TESTS = 20 

MODEL_L1 = "my-soc-agent-en"     
MODEL_L2 = "llama3.1"           

# ==========================================
# 2. 啟動 RAG 向量引擎
# ==========================================
print("\n⏳ 正在啟動 RAG 向量引擎與載入 MITRE 知識庫...")
embedder = SentenceTransformer('all-MiniLM-L6-v2')

try:
    with open("mitre_knowledge_base.json", "r", encoding="utf-8") as f:
        mitre_kb = json.load(f)
    mitre_ids = list(mitre_kb.keys())
    mitre_descriptions = list(mitre_kb.values())
    kb_embeddings = embedder.encode(mitre_descriptions)
    print(f"✅ RAG 系統就緒：已載入 {len(mitre_ids)} 筆 MITRE 戰術情資。")
except Exception as e:
    print(f"❌ 錯誤：找不到 mitre_knowledge_base.json。請先執行 build_mitre_kb.py！")
    exit()

# ==========================================
# 3. 核心功能函式
# ==========================================
def rag_retrieve_ttp(query_text):
    """使用語意向量比對，將意圖轉為最接近的 TTP ID"""
    if not query_text or query_text == "Unknown":
        return "Unknown"
    
    query_embedding = embedder.encode([query_text])
    similarities = cosine_similarity(query_embedding, kb_embeddings)[0]
    
    best_idx = np.argmax(similarities)
    best_score = similarities[best_idx]
    
    if best_score > 0.35:
        return mitre_ids[best_idx]
    return f"Unknown (Score: {best_score:.2f})"

def call_llm(prompt, model):
    payload = {
        "model": model, 
        "prompt": prompt, 
        "stream": False, 
        "format": "json",
        "options": {"temperature": 0.0, "stop": ["### Instruction:", "### Input:"]}
    }
    try:
        res = requests.post(OLLAMA_API, json=payload).json()
        return res.get("response", "").strip()
    except: return ""

def extract_json(text):
    try:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match: return json.loads(match.group())
    except: pass
    return {}

def check_ttp_match(valid_list, predicted_ttp):
    """攻擊鏈命中邏輯：檢查預測是否在有效陣列內"""
    if not predicted_ttp or not valid_list: return False
    pred = str(predicted_ttp).split('.')[0].upper() 
    for valid in valid_list:
        if pred in str(valid).upper(): return True
    return False

# ==========================================
# 4. 測評主迴圈 (雙軌語意解耦版)
# ==========================================
test_data = []
with open(DATASET_FILE, 'r', encoding='utf-8') as f:
    for i, line in enumerate(f):
        if i >= MAX_TESTS: break
        d = json.loads(line)
        log_match = re.search(r'### Input:\n(.*?)\n### Response:', d['text'], re.DOTALL)
        test_data.append({
            "log": log_match.group(1).strip() if log_match else "",
            "valid_ttps": d.get("valid_ttps", [])
        })

print(f"\n🚀 開始執行【意圖辨識 x 攻擊鏈擴充】最終消融實驗 (共 {len(test_data)} 題)")
results = []

for idx, item in enumerate(test_data, 1):
    # 🌟 升級版 L1 Prompt：強制解耦 Action 與 Intent
    prompt_l1 = f"### Instruction:\nAnalyze the log. You must decouple the surface action from the ultimate strategic intent. Output JSON with exactly 2 keys: 'Action' and 'Intent'.\n### Input:\n{item['log']}\n### Response:"
    l1_raw = call_llm(prompt_l1, MODEL_L1)
    l1_json = extract_json(l1_raw)
    
    l1_action = l1_json.get("Action", "Unknown")
    l1_intent = l1_json.get("Intent", "Unknown")
    
    # ⚡ 意圖權重機制：優先使用 Intent 進行 RAG 檢索，避免 Action 關鍵字干擾
    rag_query = l1_intent if len(str(l1_intent)) > 10 else f"{l1_action} intended to {l1_intent}"
    rag_ttp = rag_retrieve_ttp(rag_query)
    
    # --- [L2] 結合所有資訊產出緩解策略 ---
    full_threat_desc = f"Action: {l1_action}. Intent: {l1_intent}."
    prompt_l2 = f"### Instruction:\nBased on threat {rag_ttp} ({full_threat_desc}), assess severity. Output JSON: 'Severity', 'Mitigation'.\n### Input:\n{item['log']}\n### Response:"
    l2_raw = call_llm(prompt_l2, MODEL_L2)
    l2_json = extract_json(l2_raw)
    
    is_hit = check_ttp_match(item['valid_ttps'], rag_ttp)
    
    print(f"➤ Task_{idx:03d} | RAG 映射結果: {rag_ttp}")
    print(f"   [判定] {'✅ Hit' if is_hit else '❌ Miss'}")
    print(f"   [動作] {l1_action[:50]}...")
    print(f"   [意圖] {l1_intent[:50]}...")
    print("-" * 50)
    
    results.append(is_hit)

hit_rate = (sum(results) / len(results)) * 100
print(f"\n📊 論文實驗數據：【意圖驅動 RAG 系統】最終測評結果")
print(f"==================================================")
print(f"➤ 測試樣本數: {len(results)}")
print(f"➤ 終極綜合命中率 (RAG + Intent): {hit_rate:.1f}%")
print(f"==================================================")