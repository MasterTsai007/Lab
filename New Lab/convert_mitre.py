import json

INPUT_FILE = 'mitre_eval_data.json' # 請確認檔名與您存檔的名稱一致 (如 er7_cohort_results.json)
OUTPUT_FILE = 'mitre_cti_hunting.jsonl'

def convert_mitre_data():
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ 找不到 {INPUT_FILE}，請確認檔案位置。")
        return

    seen_descriptions = set()
    output_records = []

    # 🛠️ 智慧解析結構：判斷 JSON 的外層，自動把裡面的 List 全部挖出來
    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                items.extend(value)

    for item in items:
        # 防呆機制：確保 item 是字典結構
        if not isinstance(item, dict):
            continue
            
        # 萃取攻擊步驟的描述文字
        desc = item.get("Step_Description", "").strip()
        
        # 過濾掉空白或是已經處理過的描述 (避免不同廠商的重複資料)
        if not desc or desc in seen_descriptions:
            continue
            
        seen_descriptions.add(desc)
        
        # 建立一個有意義的 ID (例如: Scattered_Spider_Step1_1.1)
        scenario = item.get("Scenario_Name", "Unknown_Scenario").replace(" ", "_")
        step_name = item.get("Step_Name", "Step").split(" - ")[0].replace(" ", "")
        substep = str(item.get("Substep", "0"))
        
        record_id = f"{scenario}_{step_name}_{substep}"
        
        # 轉換成 Universal Pipeline 看得懂的格式
        record = {
            "id": record_id,
            "text": desc
        }
        output_records.append(record)

    # 寫入 jsonl 檔案
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_f:
        for record in output_records:
            out_f.write(json.dumps(record, ensure_ascii=False) + '\n')

    print(f"✔️ 成功轉換！共萃取出 {len(output_records)} 筆獨立的攻擊情境描述。")
    print(f"✔️ 檔案已儲存為：{OUTPUT_FILE}")

if __name__ == "__main__":
    # 若您的檔案名稱是 er7_cohort_results.json，請在上方 INPUT_FILE 修改檔名
    convert_mitre_data()