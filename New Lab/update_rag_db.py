import requests
import chromadb
import time

# =====================================================================
# 系統設定參數 (已升級至 STIX 2.1)
# =====================================================================
DB_PATH = "./my_soc_vectordb"      # 🌟 改成您主程式用的路徑
COLLECTION_NAME = "mitre_rules"    # 🌟 改成您主程式用的集合名稱

# 🌟 變更 1：全新來源 MITRE 官方 STIX 2.1 (attack-stix-data 儲存庫)
MITRE_STIX_2_1_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

def fetch_and_build_db():
    print("🌐 [1/4] 正在從 MITRE 官方 (STIX 2.1) 下載最新版 ATT&CK 資料...")
    start_time = time.time()
    
    try:
        response = requests.get(MITRE_STIX_2_1_URL)
        response.raise_for_status()
        stix_data = response.json()
    except Exception as e:
        print(f"❌ 下載失敗，請檢查網路連線: {e}")
        return

    print(f"✅ 下載完成！(耗時: {time.time() - start_time:.2f} 秒)")
    print("🧠 [2/4] 正在解析 STIX 2.1 格式並萃取戰術/技術 (T-Codes)...")

    documents = []
    metadatas = []
    ids = []

    # 🌟 變更 2：尋找 Collection 的版本號 (STIX 2.1 特有功能)
    collection_version = "Unknown"
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            collection_version = obj.get("x_mitre_version", "Unknown")
            print(f"📚 偵測到 MITRE ATT&CK 集合版本: v{collection_version}")
            break

    # 解析 STIX 2.1 JSON 萃取技術
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            
            mitre_id = None
            url = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    url = ref.get("url")
                    break
            
            # 🌟 變更 3：智慧過濾髒資料
            # STIX 2.1 中，技術可能會被撤銷 (revoked) 或廢棄 (deprecated)
            is_revoked = obj.get("revoked", False)
            is_deprecated = obj.get("x_mitre_deprecated", False)
            
            # 只有當技術存在、有描述，且「沒有」被撤銷/廢棄時，才加入資料庫
            if mitre_id and obj.get("description") and not is_revoked and not is_deprecated:
                name = obj.get("name", "Unknown")
                description = obj.get("description")
                
                documents.append(f"{name}: {description}")
                ids.append(mitre_id)
                metadatas.append({
                    "name": name,
                    "tactic_id": mitre_id,
                    "url": url if url else "N/A",
                    "source": f"mitre_stix_2.1_v{collection_version}"
                })

    print(f"🎯 成功萃取出 {len(ids)} 筆有效攻擊技術資料！(已過濾廢棄/撤銷項目)")

    print(f"📂 [3/4] 正在連接並初始化本地 ChromaDB ({DB_PATH})...")
    client = chromadb.PersistentClient(path=DB_PATH)
    
    # 安全地刪除舊資料庫 (使用寬鬆的 Exception 避免初次執行報錯)
    try:
        client.delete_collection(name=COLLECTION_NAME)
        print("🗑️ 已清除舊版資料庫。")
    except Exception:
        pass 

    collection = client.create_collection(name=COLLECTION_NAME)

    print("🤖 [4/4] 正在將文本轉化為向量 (Embedding) 並寫入資料庫...")
    
    # 批次寫入資料庫
    batch_size = 100
    for i in range(0, len(ids), batch_size):
        end_idx = min(i + batch_size, len(ids))
        collection.add(
            documents=documents[i:end_idx],
            metadatas=metadatas[i:end_idx],
            ids=ids[i:end_idx]
        )
        print(f"   ▶ 進度: {end_idx} / {len(ids)} 筆寫入完成...")

    print("=" * 50)
    print(f"🎉 恭喜！RAG 向量資料庫已成功更新至 MITRE ATT&CK v{collection_version}！")
    print(f"總計寫入: {collection.count()} 筆最新威脅技術。")
    print("=" * 50)

if __name__ == "__main__":
    fetch_and_build_db()