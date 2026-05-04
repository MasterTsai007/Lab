import requests
import json
import re
import numpy as np
import time
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

# ==========================================
# 1. 環境與設定
# ==========================================
OLLAMA_API = "http://localhost:11434/api/generate"
MODEL_L1 = "my-soc-agent-en"
MODEL_L2 = "llama3.1"
DATASET_FILE = "empire_mimikatz_logonpasswords_2020-08-07103224.json"  # 🌟 動態讀取您轉好的題庫

print("⏳ 正在啟動 RAG 向量引擎與載入知識庫...")
embedder = SentenceTransformer('all-MiniLM-L6-v2')
with open("mitre_knowledge_base.json", "r", encoding="utf-8") as f:
    mitre_kb = json.load(f)
mitre_ids, mitre_descriptions = list(mitre_kb.keys()), list(mitre_kb.values())
kb_embeddings = embedder.encode(mitre_descriptions)

def call_llm(prompt, model):
    payload = {"model": model, "prompt": prompt, "stream": False, "format": "json"}
    try: return requests.post(OLLAMA_API, json=payload).json().get("response", "").strip()
    except: return ""

def extract_json(text):
    try:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match: return json.loads(match.group())
    except: pass
    return {}

# ==========================================
# 2. 動態讀取資料並進行自動化獵捕
# ==========================================
test_data = []
# 🌟 這裡就是動態讀取您剛剛轉好的 EVTX JSONL 檔案
try:
    with open(DATASET_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            d = json.loads(line)
            # 把 Input 區塊抓出來
            log_match = re.search(r'### Input:\n(.*?)\n### Response:', d['text'], re.DOTALL)
            if log_match: test_data.append(log_match.group(1).strip())
except Exception as e:
    print(f"❌ 找不到 {DATASET_FILE}，請先執行 convert_evtx_to_jsonl.py！")
    exit()

print(f"\n🚀 啟動自動化 SOC 營運管線 (共發現 {len(test_data)} 筆待處理日誌)\n")
print("="*60)

for idx, target_log in enumerate(test_data, 1):
    print(f"📡 正在處理第 {idx} 筆日誌...")
    
    # [L1] 意圖解耦
    l1_prompt = f"### Instruction:\nAnalyze the log. Decouple surface action from ultimate strategic intent. Output strictly in JSON with 'Action', 'Intent'.\n### Input:\n{target_log}\n### Response:"
    l1_json = extract_json(call_llm(l1_prompt, MODEL_L1))
    action, intent = l1_json.get("Action", "Unknown"), l1_json.get("Intent", "Unknown")
    
    # [RAG] 意圖檢索
    query_embedding = embedder.encode([intent])
    sims = cosine_similarity(query_embedding, kb_embeddings)[0]
    best_idx = np.argmax(sims)
    rag_ttp = mitre_ids[best_idx] if sims[best_idx] > 0.35 else "Unknown"
    
    # [L2] 產出策略
    l2_prompt = f"### Instruction:\nBased on the identified threat {rag_ttp} (Intent: {intent}) originating from this action: {action}. Assess severity and provide mitigation strategy. Output strictly in JSON with 'Severity', 'Mitigation'.\n### Input:\n{target_log}\n### Response:"
    l2_json = extract_json(call_llm(l2_prompt, MODEL_L2))
    
    # 🌟 輸出可介接 SIEM 的結果
    final_alert = {
        "Log_ID": f"Event_{idx:03d}",
        "Threat_ID": rag_ttp,
        "Identified_Action": action,
        "Strategic_Intent": intent,
        "Severity": l2_json.get("Severity", "Unknown"),
        "Mitigation_Strategy": l2_json.get("Mitigation", "Manual investigation required.")
    }
    
    print(json.dumps(final_alert, indent=4, ensure_ascii=False))
    print("-" * 60)
    time.sleep(1) # 稍作暫停讓輸出更好看

print("✅ 所有日誌分析完畢！")