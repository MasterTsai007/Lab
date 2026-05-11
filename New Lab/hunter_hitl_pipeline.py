import json
import requests
import pandas as pd
import re
import chromadb
from sentence_transformers import SentenceTransformer

# =====================================================================
# 1. 系統組態設定 
# =====================================================================
OLLAMA_API = "http://localhost:11434/api/generate"

# 【架構核心】Mixture of Experts (專家混合)
L1_MODEL = "phi3"         # 輕量級 (負責第一線海量意圖萃取)
L2_EXPERT = "llama3.1"    # 旗艦級 (負責黃燈區的深度覆核)

REAL_WORLD_LOGS = "complex_apt_dataset_50.jsonl"
EXPORT_EXCEL = "hunting_hitl_report.xlsx"

# =====================================================================
# 2. 連線至 RAG 向量資料庫
# =====================================================================
print("⏳ 載入嵌入模型...")
embedder = SentenceTransformer('all-MiniLM-L6-v2') 

print("⏳ 連線至本地 ChromaDB 知識庫...")
try:
    client = chromadb.PersistentClient(path="./my_soc_vectordb")
    collection = client.get_collection(name="mitre_rules")
except Exception as e:
    print("❌ 找不到知識庫！請先執行 build_kb.py")
    exit()

# =====================================================================
# 3. 核心呼叫函數
# =====================================================================
def call_ollama(model, prompt, json_mode=False):
    payload = {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.0}}
    if json_mode: payload["format"] = "json"
    try:
        res = requests.post(OLLAMA_API, json=payload).json()
        return res.get("response", "").strip()
    except Exception as e:
        return f"Error: {e}"

# =====================================================================
# 4. 實戰狩獵與人機協同迴圈
# =====================================================================
def run_hunter():
    results = []
    try:
        with open(REAL_WORLD_LOGS, 'r', encoding='utf-8') as f:
            tasks = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ 找不到日誌檔 {REAL_WORLD_LOGS}。")
        return

    print(f"\n🕵️‍♂️ 啟動 Next-Gen SOC (人機協同模式)，共 {len(tasks)} 筆日誌。")
    print("="*60)

    for idx, task in enumerate(tasks):
        log_id = task.get("id", f"Log_{idx+1:05d}")
        source_log = task.get("text", "")
        
        # -------------------------------------------------------------
        # [Phase 1: L1 探員快速掃描]
        # -------------------------------------------------------------
        l1_prompt = f"""### Instruction:
You are an elite threat hunter. Analyze the log strictly based on the explicit command executed. DO NOT hallucinate.
CRITICAL RULES:
1. If standard application/built-in tool without malicious intent, output "Normal System Behavior / Unknown Threat".
2. NEVER output Credential Dumping, Command Injection, or Privilege Escalation UNLESS explicit evidence exists.
Output valid JSON: {{"Intent": "tactical goal and 1-sentence explanation OR 'Normal System Behavior / Unknown Threat'"}}
### Input:
{source_log}
### Response:"""
        
        l1_res = call_ollama(L1_MODEL, l1_prompt, json_mode=True)
        try:
            intent = json.loads(re.search(r'\{.*\}', l1_res, re.DOTALL).group(0).replace("'", "\"")).get("Intent", "Unknown Threat")
        except:
            intent = "Unknown Threat"

        is_normal = any(k in intent.lower() for k in ["normal", "benign", "unknown threat"])
        
        # -------------------------------------------------------------
        # [Phase 2: RAG 距離計算與紅綠燈分流] 
        # -------------------------------------------------------------
        rag_ttp = "Unknown Threat"
        distance = 99.9
        action_taken = "Auto-Dismissed (Green)"
        l2_analysis = "N/A"
        
        if not is_normal:
            query_emb = embedder.encode([intent]).tolist()
            db_res = collection.query(query_embeddings=query_emb, n_results=1)
            distance = db_res['distances'][0][0]
            rag_ttp = db_res['ids'][0][0]
            
            if distance < 1.0:
                # 🔴 紅燈：極度確信是攻擊
                action_taken = "Auto-Confirmed (Red)"
                print(f"🔴 [自動攔截] {log_id} | 戰術: {rag_ttp} | 距離: {distance:.2f} (確信)")
                
            elif 1.0 <= distance <= 1.5:
                # 🟡 黃燈：進入 L2 專家覆核與人工審查階段
                print("\n" + "⚠️"*30)
                print(f"🟡 [灰區警報 - 需要人類長官裁決] Log ID: {log_id}")
                print(f"➤ 原始日誌: {source_log[:150]}...")
                print(f"➤ L1 (Phi-3) 判斷: {intent}")
                print(f"➤ RAG 映射結果: {rag_ttp} (距離: {distance:.2f} - 信心不足)")
                
                print("⏳ 正在呼叫 L2 專家 (Llama 3.1) 進行深度覆核...")
                l2_prompt = f"""You are a Tier-2 Senior Cybersecurity Analyst. 
A junior analyst flagged the following log as suspicious and mapped it to MITRE Tactic {rag_ttp}.
Log: {source_log}
Junior Analyst's Intent: {intent}

Provide a 2-sentence deep analysis. Does this log genuinely represent the mapped tactic, or is it a False Positive (normal administrative behavior)? Start your response with "VERDICT: CONFIRM" or "VERDICT: REJECT", followed by your reasoning."""
                
                l2_analysis = call_ollama(L2_EXPERT, l2_prompt)
                print(f"👨‍⚖️ L2 專家意見:\n{l2_analysis}\n")
                
                # 【人機協同介入點】暫停程式，等待人類輸入
                while True:
                    user_decision = input("👉 長官，請問要確認此告警嗎？(Y=確認威脅 / N=標記誤報): ").strip().upper()
                    if user_decision == 'Y':
                        action_taken = "Human-Confirmed (Yellow)"
                        print("✔️ 已手動確認威脅，記錄至報表。")
                        break
                    elif user_decision == 'N':
                        action_taken = "Human-Rejected (Yellow -> False Positive)"
                        rag_ttp = "False Positive (Cleared)"
                        print("❌ 已標記為誤報，忽略此紀錄。")
                        break
                    else:
                        print("⚠️ 請輸入 Y 或 N。")
                print("⚠️"*30 + "\n")

            else:
                # 🟢 綠燈：距離太遠，L1 判斷錯誤，實為正常
                rag_ttp = "Unknown Threat"
                action_taken = "Auto-Dismissed (Distance > 1.5)"

        results.append({
            "Log_ID": log_id,
            "L1_Intent": intent,
            "Predicted_MITRE_ID": rag_ttp,
            "Distance": distance,
            "Action_Taken": action_taken,
            "L2_Expert_Analysis": l2_analysis
        })

    # =====================================================================
    # 5. 匯出狩獵報告
    # =====================================================================
    df = pd.DataFrame(results)
    df.to_excel(EXPORT_EXCEL, index=False)
    print(f"\n📊 狩獵結束！人機協同報告已儲存至：{EXPORT_EXCEL}")

if __name__ == "__main__":
    run_hunter()