import json
import requests
import pandas as pd
import re
import chromadb
from sentence_transformers import SentenceTransformer

# =====================================================================
# 1. 系統組態設定 (System Configuration)
# =====================================================================
OLLAMA_API = "http://localhost:11434/api/generate"
L1_MODEL = "phi3"         # 輕量級意圖萃取代理人
L3_MODEL = "llama3.1"     # 旗艦級語意裁判代理人

DATASET_FILE = "complex_apt_dataset_50.jsonl"
EXPORT_EXCEL = "benchmark_results_50.xlsx"

# =====================================================================
# 2. 連線至真實 RAG 向量資料庫 (ChromaDB)
# =====================================================================
print("⏳ 載入嵌入模型 (SentenceTransformer)...")
# 如果您已經下載了模型，可以把這裡換成本地路徑，例如 './local_embedder_model'
embedder = SentenceTransformer('all-MiniLM-L6-v2') 

print("⏳ 連線至本地 RAG 向量資料庫 (ChromaDB)...")
try:
    client = chromadb.PersistentClient(path="./my_soc_vectordb")
    collection = client.get_collection(name="mitre_rules")
    print(f"✔️ 成功連線！知識庫內含 {collection.count()} 條戰術規則。")
except Exception as e:
    print("❌ 找不到知識庫！請先確認您已執行過 build_kb.py 來建置資料庫。")
    exit()

# =====================================================================
# 3. 核心呼叫函數 (強制關閉隨機性)
# =====================================================================
def call_ollama(model, prompt, json_mode=False):
    payload = {
        "model": model, 
        "prompt": prompt, 
        "stream": False, 
        "options": {"temperature": 0.0}
    }
    if json_mode: payload["format"] = "json"
    try:
        res = requests.post(OLLAMA_API, json=payload).json()
        return res.get("response", "").strip()
    except Exception as e:
        print(f"API Error: {e}")
        return ""

# =====================================================================
# 4. 主測試迴圈
# =====================================================================
def run_benchmark():
    results = []
    
    try:
        with open(DATASET_FILE, 'r', encoding='utf-8') as f:
            tasks = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ 找不到測試檔 {DATASET_FILE}。")
        return

    total_available = len(tasks)
    if total_available == 0: return

    print("\n" + "="*60)
    print(f"📂 成功載入測試集，共發現 {total_available} 筆資料。")
    user_input = input(f"👉 請輸入您想測試的筆數 (直接按 Enter 則執行全部): ").strip()
    
    if user_input.isdigit():
        limit = int(user_input)
        tasks = tasks[:limit]
    
    print("="*60 + "\n")

    for idx, task in enumerate(tasks):
        task_id = f"Task_{idx+1:03d}"
        source_log = task.get("text", "")
        ground_truth = task.get("valid_ttps", ["Unknown Threat"])
        
        # -------------------------------------------------------------
        # [Phase 1: L1 意圖萃取 (防幻覺版)] 
        # -------------------------------------------------------------
        l1_prompt = f"""### Instruction:
You are an elite threat hunter analyzing endpoint logs. 
Because you do not have environmental context, you must evaluate the log strictly based on the explicit command executed. DO NOT hallucinate motives that are not in the text.

CRITICAL RULES FOR TACTICAL LABELING:
1. READ THE EXACT COMMAND: Do not overreact. If the command is a standard application (e.g., Chrome, git, backgroundTaskHost) without malicious parameters, you MUST output "Normal System Behavior / Unknown Threat".
2. PREVENT HALLUCINATIONS: 
   - NEVER output "Credential Dumping" UNLESS you explicitly see lsass, SAM, NTDS, MiniDump, or known password tools (e.g., LaZagne, Mimikatz).
   - NEVER output "Command Injection" UNLESS you explicitly see arbitrary code execution, encoded payloads, or malicious scripts.
   - NEVER output "Privilege Escalation" UNLESS you explicitly see permission modification, runas, or token manipulation.
3. If the command is a standard built-in administrative or network tool (e.g., ipconfig, whoami, net, ping) used without clear malicious intent, label it as "Suspected Discovery" or "Normal System Behavior / Unknown Threat".

CRITICAL FORMAT RULE:
- You MUST evaluate the ENTIRE sequence and formulate ONE final conclusion.
- The "Intent" field MUST be a SINGLE string containing the exact tactical goal AND a brief 1-sentence technical explanation.

Now analyze the following log sequence. Output ONLY valid JSON: {{"Action": "overall summary", "Intent": "the single highest severity tactical goal and explanation, OR 'Normal System Behavior / Unknown Threat'"}}.

### Input:
{source_log}
### Response:"""
        
        l1_response = call_ollama(L1_MODEL, l1_prompt, json_mode=True)
        
        try:
            l1_json = json.loads(l1_response)
            intent = l1_json.get("Intent", "Unknown Threat")
            
            if isinstance(intent, list):
                intent = " ".join([str(item) for item in intent])
            elif isinstance(intent, dict):
                intent = intent.get("Tactical Goal", str(intent))
                
            if not isinstance(intent, str):
                intent = str(intent)
                
            intent = re.sub(r'[{}\[\]\'"]', '', intent)
                
        except Exception:
            intent = "Unknown Threat"

        # -------------------------------------------------------------
        # [Phase 2: 真實 RAG 戰術映射 (向 ChromaDB 檢索)] 
        # -------------------------------------------------------------
        is_normal = any(k in intent.lower() for k in ["normal", "benign", "standard", "legitimate", "unknown threat"])
        
        if is_normal:
            rag_ttp = "Unknown Threat"
            rag_distance = 99.9 # 標記為極大距離
        else:
            query_embedding = embedder.encode([intent]).tolist()
            db_results = collection.query(
                query_embeddings=query_embedding,
                n_results=1
            )
            
            rag_distance = db_results['distances'][0][0]
            best_mitre_id = db_results['ids'][0][0]
            
            # 設定距離閾值 (1.2 是一個良好的基準值，代表一定的語意相似度)
            threshold = 1.2
            if rag_distance < threshold:
                rag_ttp = best_mitre_id
            else:
                rag_ttp = "Unknown Threat"

        # -------------------------------------------------------------
        # [Phase 3: 傳統字串嚴格比對 (Exact Match)]
        # -------------------------------------------------------------
        exact_match = (rag_ttp in ground_truth) or (rag_ttp == "Unknown Threat" and "Unknown Threat" in ground_truth)

        # -------------------------------------------------------------
        # [Phase 4: L3 LLM-as-a-Judge 語意等效裁判 (無敵 JSON 解析版)]
        # -------------------------------------------------------------
        l3_score = 0
        judge_reason = ""
        
        if exact_match:
            l3_score = 2
            judge_reason = "Exact Match. (Auto-approved by system without LLM Judge)"
        else:
            l3_prompt = f"""You are an absolute, deterministic logic gate evaluating cybersecurity predictions. 
Evaluate the prediction against the Ground Truth by strictly following this Pseudo-code logic block. Do not invent context.

[Inputs]
- Ground Truth (Valid Tactics): {ground_truth}
- Analyst Prediction: {rag_ttp}

[Pseudo-code Logic Gate]
IF Prediction exists in Ground Truth list OR (Prediction is "Unknown Threat" AND Ground Truth is "['Unknown Threat']"):
    Return Score 2, Reason: "Exact Match"
    
ELSE IF Ground Truth is "['Unknown Threat']" AND Prediction is a specific MITRE ID (e.g., T1087):
    Return Score 0, Reason: "False Positive. Predicted a threat where none exists."
    
ELSE IF Ground Truth has specific MITRE IDs AND Prediction is "Unknown Threat":
    Return Score 0, Reason: "False Negative. Failed to detect the threat."
    
ELSE IF Ground Truth has specific MITRE IDs AND Prediction is a DIFFERENT specific MITRE ID:
    Analyze the sub-technique relationship. Are they fundamentally addressing the exact same tactical goal (e.g., T1059.001 and T1059)?
    IF YES: Return Score 1, Reason: "Partial Match. Tactically related."
    IF NO: Return Score 0, Reason: "Mismatched Tactics."

Based ONLY on the logic above, output your final decision in valid JSON format ONLY, without any conversational text or markdown blocks:
{{"Score": 0, "Reason": "string"}}"""
            
            l3_res = call_ollama(L3_MODEL, l3_prompt, json_mode=True)
            
            try:
                # 🛡️ 無敵 JSON 提取器：用正則表達式硬把 {} 中間的內容挖出來
                json_match = re.search(r'\{.*\}', l3_res, re.DOTALL)
                if json_match:
                    clean_json_str = json_match.group(0)
                    # 處理內部可能的引號打架問題
                    clean_json_str = clean_json_str.replace("'", "\"") 
                    l3_json = json.loads(clean_json_str)
                    
                    l3_score = int(l3_json.get("Score", 0))
                    judge_reason = str(l3_json.get("Reason", "No reason provided by LLM."))
                else:
                    raise ValueError("No JSON block found in response.")
                    
            except Exception as e:
                l3_score = 0
                judge_reason = f"Parse Error: {e} | Raw Output: {l3_res[:50]}..."

        print(f"➤ {task_id} | L3 Score: {l3_score} | EM: {exact_match} | 預測: {rag_ttp}")
        
        results.append({
            "Task_ID": task_id,
            "Ground_Truth": str(ground_truth),
            "L1_Intent": intent,
            "System_Prediction": rag_ttp,
            "RAG_Distance": rag_distance,
            "Exact_Match": exact_match,
            "L3_Score": l3_score,
            "Judge_Reason": judge_reason
        })

    # =====================================================================
    # 5. 數據匯出
    # =====================================================================
    df = pd.DataFrame(results)
    total_cases = len(df)
    em_rate = df['Exact_Match'].mean() * 100 if total_cases > 0 else 0
    l3_pass_rate = len(df[df['L3_Score'] > 0]) / total_cases * 100 if total_cases > 0 else 0
    
    df.to_excel(EXPORT_EXCEL, index=False)
    
    print("\n" + "="*60)
    print(f"📊 實驗數據總結已儲存至：{EXPORT_EXCEL}")
    print("="*60)
    print(f"➤ 實際測試樣本數：{total_cases} 筆")
    print(f"➤ 成功筆數 (Score 1-2)：{len(df[df['L3_Score'] > 0])} 筆")
    print(f"➤ 失敗筆數 (Score 0)  ：{len(df[df['L3_Score'] == 0])} 筆")
    print(f"➤ 傳統字串嚴格命中率 (Exact Match): {em_rate:.1f}%")
    print(f"➤ L3 裁判實務有效命中率 (L3 Pass Rate): {l3_pass_rate:.1f}%")
    print("="*60)

if __name__ == "__main__":
    run_benchmark()