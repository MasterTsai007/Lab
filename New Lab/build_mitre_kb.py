import requests
import json
import os

# MITRE ATT&CK 官方 CTI (Cyber Threat Intelligence) JSON 網址
MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTPUT_KB_FILE = "mitre_knowledge_base.json"

print("⏳ 正在連線至 MITRE ATT&CK 官方資料庫下載最新威脅情資...")
try:
    response = requests.get(MITRE_STIX_URL)
    response.raise_for_status()
    stix_data = response.json()
except Exception as e:
    print(f"❌ 下載失敗: {e}")
    exit()

mitre_kb = {}
print("🔍 正在解析資料並萃取 TTP 標籤與解釋...")

# 遍歷 STIX 資料格式，尋找所有的攻擊模式 (attack-pattern)
for obj in stix_data.get("objects", []):
    if obj.get("type") == "attack-pattern":
        # 抓取 TTP ID (例如 T1059.001)
        ext_refs = obj.get("external_references", [])
        ttp_id = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                ttp_id = ref.get("external_id")
                break
        
        # 抓取官方的詳細描述
        description = obj.get("description", "")
        name = obj.get("name", "")
        
        if ttp_id and description:
            # 將名稱與描述結合，讓 RAG 的向量比對更精準
            mitre_kb[ttp_id] = f"{name}: {description}"

# 儲存成我們專屬的知識庫
with open(OUTPUT_KB_FILE, "w", encoding="utf-8") as f:
    json.dump(mitre_kb, f, indent=4, ensure_ascii=False)

print(f"🎉 武器庫建置完成！共成功載入 {len(mitre_kb)} 筆 MITRE 攻擊技術！")
print(f"💾 檔案已儲存為: {OUTPUT_KB_FILE}")