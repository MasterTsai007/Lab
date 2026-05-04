import json

# 設定輸入與輸出
INPUT_RAW_JSON = "empire_mimikatz_logonpasswords_2020-08-07103224.json"
OUTPUT_EXAM_JSONL = "real_dataset.jsonl" # 🌟 這就是 L3 裁判要讀的考卷

LSASS_WHITELIST = ["svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "msmpeng.exe"]

print(f"⏳ 正在將原始日誌 {INPUT_RAW_JSON} 轉換為 L3 裁判標準考卷...")
extracted_count = 0

try:
    with open(INPUT_RAW_JSON, 'r', encoding='utf-8') as infile, open(OUTPUT_EXAM_JSONL, 'w', encoding='utf-8') as outfile:
        for line in infile:
            if not line.strip(): continue
            log_entry = json.loads(line)
            
            event_id = str(log_entry.get("EventID", ""))
            
            # 鎖定 Event ID 10 並執行白名單過濾
            if event_id == "10":
                target_img = log_entry.get("TargetImage", "").lower()
                source_img = log_entry.get("SourceImage", "").lower()
                
                if "lsass.exe" in target_img:
                    if not any(ws in source_img for ws in LSASS_WHITELIST):
                        
                        # 提煉精華欄位
                        slim_log = {
                            "EventID": "10",
                            "SourceImage": log_entry.get("SourceImage", ""),
                            "TargetImage": log_entry.get("TargetImage", ""),
                            "GrantedAccess": log_entry.get("GrantedAccess", ""),
                            "CallTrace": log_entry.get("CallTrace", "")
                        }
                        
                        # 🎯 包裝成標準考卷格式
                        prompt_text = (
                            "Below is an instruction that describes a task, paired with an input that provides further context. "
                            "Write a response that appropriately completes the request.\n"
                            "### Instruction:\n"
                            "Analyze the endpoint log, extract malicious features, and map to MITRE ATT&CK. "
                            "You MUST output strictly in JSON containing 'TTP_ID' and 'Explanation'.\n"
                            "### Input:\n"
                            f"{json.dumps(slim_log)}\n"
                            "### Response:\n"
                            "{\"TTP_ID\": \"TXXXX\", \"Explanation\": \"Pending...\"}"
                        )
                        
                        # 🌟 給 L3 裁判的「標準答案 (Ground Truth)」
                        # 因為這是 Mimikatz，我們把 T1055(程序注入) 和 T1003(憑證存取) 都列為正確答案
                        output_data = {
                            "text": prompt_text,
                            "valid_ttps": ["T1055", "T1003"] 
                        }
                        
                        outfile.write(json.dumps(output_data) + "\n")
                        extracted_count += 1
                        break # 抓一題最具代表性的就夠了

    print(f"🎉 成功製作考卷！提煉了 {extracted_count} 題高難度題目至 {OUTPUT_EXAM_JSONL}")

except Exception as e:
    print(f"❌ 發生錯誤: {e}")