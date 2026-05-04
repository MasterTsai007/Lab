import json

filename = "real_dataset.jsonl" # 您的真實題庫檔案

print("🔍 讓我們來看看模型到底看到了什麼 Log：\n" + "="*50)
with open(filename, 'r', encoding='utf-8') as f:
    for i, line in enumerate(f, 1):
        data = json.loads(line)
        text = data.get("text", "")
        # 切出 Input 區塊
        log_start = text.find("### Input:\n") + 11
        log_end = text.find("### Response:\n")
        log_content = text[log_start:log_end].strip()
        
        # 轉回 JSON 方便讀取
        try:
            log_json = json.loads(log_content)
            image = log_json.get("Image", "Unknown")
            cmd = log_json.get("CommandLine", "Unknown")
            print(f"➤ Task_{i:03d} | 執行程式: {image}")
            print(f"   指令內容: {cmd[:100]}...") # 只印前100字
            print("-" * 50)
        except:
            pass