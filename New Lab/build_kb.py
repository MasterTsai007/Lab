import json
import os
import chromadb
from sentence_transformers import SentenceTransformer

# =====================================================================
# 1. 系統環境與路徑設定
# =====================================================================
JSON_FILE = "full_mitre_data.json"
DB_PATH = "./my_soc_vectordb"
COLLECTION_NAME = "mitre_rules"

def build_knowledge_base():
    print("🚀 [Next-Gen SOC] 啟動 MITRE ATT&CK 知識庫建置程序...\n")

    # 檢查檔案是否存在
    if not os.path.exists(JSON_FILE):
        print(f"❌ 找不到 {JSON_FILE}！請確認您已下載 MITRE 官方資料檔。")
        return

    # =====================================================================
    # 2. 解析 STIX 2.1 JSON 格式
    # =====================================================================
    print(f"📂 正在解析 MITRE 官方 STIX JSON ({JSON_FILE})...")
    with open(JSON_FILE, 'r', encoding='utf-8') as f:
        stix_data = json.load(f)

    mitre_kb = {}
    
    # 遍歷 STIX 格式，把「攻擊模式 (attack-pattern)」抓出來
    for obj in stix_data.get("objects", []):
        
        # 過濾掉被撤銷 (revoked) 或已棄用 (deprecated) 的戰術
        if obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            
            # 取得 MITRE ID (例如 T1059)
            external_id = None
            for ext in obj.get("external_references", []):
                if ext.get("source_name") == "mitre-attack":
                    external_id = ext.get("external_id")
                    break
            
            if external_id:
                name = obj.get("name", "")
                desc_full = obj.get("description", "")
                
                # 💡 RAG 最佳實踐：擷取第一段簡介 (以換行符號切割)
                # 避免整篇萬字說明塞進去導致向量濃度被稀釋
                desc_short = desc_full.split('\n')[0] 
                
                # 組合出給 L1 探員和 RAG 引擎比對的標準格式
                mitre_kb[external_id] = f"{name}: {desc_short}"

    print(f"✔️ 成功從 40MB 檔案中，精粹出 {len(mitre_kb)} 條有效 MITRE 戰術與技術！\n")

    # =====================================================================
    # 3. 啟動向量轉換引擎
    # =====================================================================
    print("⏳ 載入嵌入模型 (SentenceTransformer: all-MiniLM-L6-v2)...")
    embedder = SentenceTransformer('all-MiniLM-L6-v2')

    print(f"🗄️ 初始化本地向量資料庫 (ChromaDB) 於 {DB_PATH} ...")
    client = chromadb.PersistentClient(path=DB_PATH)

    # 為了確保資料是最新的，如果已經存在舊的集合，就先刪除重建
    try:
        client.delete_collection(name=COLLECTION_NAME)
        print("  🧹 已清除舊版知識庫，準備寫入新版資料。")
    except Exception:
        pass # 如果是第一次跑，找不到集合是正常的，直接忽略

    collection = client.create_collection(name=COLLECTION_NAME)

    # =====================================================================
    # 4. 寫入 ChromaDB 資料庫
    # =====================================================================
    mitre_ids = list(mitre_kb.keys())
    mitre_texts = list(mitre_kb.values())

    print("🧠 正在將數百條文字轉換為高維度向量 (約需 10~30 秒)...")
    embeddings = embedder.encode(mitre_texts).tolist() # ChromaDB 需要 list 格式

    print("💾 正在將資料寫入硬碟...")
    collection.add(
        ids=mitre_ids,
        embeddings=embeddings,
        documents=mitre_texts
    )

    print("\n" + "="*60)
    print(f"🎉 知識庫建置大功告成！共 {len(mitre_ids)} 筆實戰戰術已封裝完畢！")
    print(f"👉 您的資料庫實體檔案已安全儲存於：{DB_PATH} 資料夾內。")
    print("="*60)

if __name__ == "__main__":
    build_knowledge_base()