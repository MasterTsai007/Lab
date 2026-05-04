import requests
import yaml
import json
import re

# ==========================================
# 1. 設定 SigmaHQ GitHub API (以 Windows Process Creation 為例)
# ==========================================
# 這是 SigmaHQ 官方持續更新的最新規則資料夾
GITHUB_API_URL = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows/process_creation"
OUTPUT_FILE = "dynamic_sigma_dataset.jsonl"

print("⏳ 正在從 SigmaHQ 抓取全球最新、持續更新的威脅規則...")

try:
    # 取得資料夾內的檔案列表
    response = requests.get(GITHUB_API_URL)
    files = response.json()
    
    # 我們只抓前 20 個最新規則作為 Demo (您可以改大)
    test_cases = []
    
    for file_info in files[:20]:
        if file_info['name'].endswith('.yml'):
            # 下載 YAML 原始檔
            raw_url = file_info['download_url']
            rule_text = requests.get(raw_url).text
            rule_yaml = yaml.safe_load(rule_text)
            
            # --- [萃取 Ground Truth (MITRE ID)] ---
            tags = rule_yaml.get('tags', [])
            mitre_ids = []
            for tag in tags:
                # 把 'attack.t1003.001' 轉成 'T1003.001'
                match = re.search(r'attack\.t(\d{4}(\.\d{3})?)', tag.lower())
                if match:
                    mitre_ids.append(f"T{match.group(1).upper()}")
            
            if not mitre_ids: continue # 如果沒有標註 MITRE ID 就跳過
                
            # --- [萃取 Log 特徵 (把 Sigma 搜尋條件轉成假 Log)] ---
            # 實務上可以把 selection 字典轉成一段指令文字
            detection = rule_yaml.get('detection', {})
            log_features = str(detection).replace('\n', ' ')
            
            # 建立符合 benchmark 的格式
            thesis_format = {
                "source_file": f"SigmaHQ_{file_info['name']}",
                "valid_ttps": list(set(mitre_ids)),
                "text": f"### Instruction:\nYou are an elite threat hunter. Analyze this process creation log feature and extract the tactical intent.\n### Input:\n{log_features[:300]}\n### Response:"
            }
            test_cases.append(thesis_format)
            print(f"✔️ 成功轉換規則: {file_info['name']} -> {mitre_ids}")

    # 寫入 JSONL 考卷檔案
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for case in test_cases:
            f.write(json.dumps(case, ensure_ascii=False) + '\n')

    print(f"\n🎉 太棒了！已成功生成持續更新的動態測試集：{OUTPUT_FILE}")
    print("👉 現在您可以把 benchmark_with_judge.py 的 DATASET_FILE 換成這個檔案了！")

except Exception as e:
    print(f"❌ 發生錯誤: {e}")