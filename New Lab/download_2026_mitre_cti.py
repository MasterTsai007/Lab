# -*- coding: utf-8 -*-
from taxii2client.v20 import Collection
import pandas as pd
from tqdm import tqdm

def fetch_latest_mitre_data():
    print("? 正在連線至 MITRE ATT&CK 官方 TAXII 伺服器 (2026 年最新節點)...")
    # MITRE ATT&CK Enterprise 的官方 TAXII Collection URL
    collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")
    
    print("?? 正在下載最新 STIX 情資包裹，請稍候 (這可能需要幾分鐘)...")
    stix_data = collection.get_objects()
    
    records = []
    print("?? 正在解析並過濾威脅戰術與技術...")
    
    for obj in tqdm(stix_data['objects']):
        # 我們只提取「攻擊模式 (attack-pattern)」，也就是 Technique
        if obj['type'] == 'attack-pattern':
            # 提取 MITRE T-ID (例如 T1059.001)
            mitre_id = None
            if 'external_references' in obj:
                for ref in obj['external_references']:
                    if ref['source_name'] == 'mitre-attack':
                        mitre_id = ref['external_id']
                        break
            
            if mitre_id:
                records.append({
                    "MITRE_ID": mitre_id,
                    "Name": obj.get('name', 'Unknown'),
                    "Description": obj.get('description', 'No description available.'),
                    "Created": obj.get('created', ''),
                    "Modified": obj.get('modified', '')
                })

    # 轉換成 DataFrame 並匯出成最新的 CSV
    df = pd.DataFrame(records)
    
    # 按照 ID 排序，讓資料更整齊
    df = df.sort_values(by="MITRE_ID")
    
    output_filename = "mitre_attack_latest_2026.csv"
    
    # 輸出時加上 encoding='utf-8-sig' 確保 Excel 打開不會亂碼
    df.to_csv(output_filename, index=False, encoding='utf-8-sig')
    print(f"\n?? 成功下載 {len(df)} 筆最新威脅技術！已儲存至 {output_filename}")

if __name__ == "__main__":
    fetch_latest_mitre_data()