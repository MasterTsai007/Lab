import json
import os
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx
import re

# ========================================================
# 1. 系統與過濾器設定
# ========================================================
INPUT_EVTX = "Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx"  # 替換為您要轉換的 EVTX 檔案名稱
OUTPUT_JSONL = "real_dataset.jsonl"

# 監聽的目標 Event ID (包含程序建立、憑證存取、檔案建立、登入)
TARGET_EVENT_IDS = ["1", "10", "11", "4688", "4624"] 

# 🛡️ 白名單過濾器：已知會合法存取 lsass.exe 的系統核心程序
LSASS_WHITELIST = [
    "svchost.exe", 
    "csrss.exe", 
    "lsass.exe", 
    "services.exe", 
    "msmpeng.exe"  # Windows Defender
]

# ========================================================
# 2. XML 清理工具
# ========================================================
def remove_xml_namespaces(xml_string):
    """移除 XML 的命名空間，讓 ElementTree 更容易尋找標籤"""
    return re.sub(' xmlns="[^"]+"', '', xml_string)

# ========================================================
# 3. 雙軌特徵萃取與前置過濾邏輯 (論文亮點)
# ========================================================
def parse_evtx_to_jsonl(evtx_path, output_path):
    if not os.path.exists(evtx_path):
        print(f"❌ 找不到檔案：{evtx_path}。請確認檔名是否正確！")
        return

    print(f"⏳ 正在解析日誌 {evtx_path} (已啟用前置雜訊過濾機制)...")
    extracted_count = 0
    filtered_noise_count = 0

    with Evtx(evtx_path) as evtx:
        with open(output_path, 'a', encoding='utf-8') as outfile:
            for record in evtx.records():
                try:
                    xml_str = remove_xml_namespaces(record.xml())
                    root = ET.fromstring(xml_str)
                    
                    event_id_elem = root.find('.//EventID')
                    if event_id_elem is None or event_id_elem.text not in TARGET_EVENT_IDS:
                        continue
                    event_id = event_id_elem.text
                    
                    slim_log = {"EventID": event_id}
                    
                    # 萃取各種類型日誌的關鍵欄位
                    for data in root.findall('.//Data'):
                        name = data.get('Name')
                        # [策略 A] 程序與指令
                        if name in ['Image', 'NewProcessName', 'ProcessName', 'SourceImage', 'TargetImage']:
                            slim_log[name] = data.text if data.text else ""
                        elif name in ['CommandLine', 'ProcessCommandLine']:
                            slim_log[name] = data.text if data.text else ""
                        # [策略 B] 登入與提權 (4624)
                        elif event_id == "4624" and name in ['TargetUserName', 'LogonType', 'ElevatedToken']:
                            slim_log[name] = data.text if data.text else ""
                        # [策略 C] API 呼叫追蹤 (10)
                        elif event_id == "10" and name in ['GrantedAccess', 'CallTrace']:
                            slim_log[name] = data.text if data.text else ""

                    # 🛡️ 核心防護網：執行前置雜訊過濾 (Pre-inference Filtering)
                    if event_id == "10" and "lsass.exe" in slim_log.get("TargetImage", "").lower():
                        source_img = slim_log.get("SourceImage", "").lower()
                        # 如果來源程序在白名單中，判定為合法系統雜訊，直接拋棄
                        if any(whitelist in source_img for whitelist in LSASS_WHITELIST):
                            filtered_noise_count += 1
                            continue 
                            
                    # 剔除沒有實質內容的空殼日誌
                    if len(slim_log) <= 1:
                        continue
                        
                    # ========================================================
                    # 4. 封裝為標準化考卷格式
                    # ========================================================
                    prompt_text = (
                        "Below is an instruction that describes a task, paired with an input that provides further context. "
                        "Write a response that appropriately completes the request.\n"
                        "### Instruction:\n"
                        "Analyze the endpoint log, extract malicious features, and map to MITRE ATT&CK. "
                        "You MUST output strictly in JSON containing 'TTP_ID' and 'Explanation'.\n"
                        "### Input:\n"
                        f"{json.dumps(slim_log)}\n"
                        "### Response:\n"
                        "{\"TTP_ID\": \"TXXXX\", \"Explanation\": \"Pending Human Labeling\"}"
                    )
                    
                    output_data = {
                        "text": prompt_text,
                        "valid_ttps": ["TXXXX"] 
                    }
                    
                    outfile.write(json.dumps(output_data) + "\n")
                    extracted_count += 1
                    
                except Exception as e:
                    continue

    print("-" * 60)
    print(f"🎉 資料預處理完成！")
    print(f"🛡️ 成功過濾系統合法雜訊：{filtered_noise_count} 筆")
    print(f"🎯 成功提煉高威脅價值考題：{extracted_count} 筆，已寫入 {output_path}")
    print("-" * 60)

if __name__ == "__main__":
    parse_evtx_to_jsonl(INPUT_EVTX, OUTPUT_JSONL)