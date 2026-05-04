import json

filename = "dataset_en.jsonl"
error_count = 0

print(f"🔍 開始掃描 {filename} ...\n")

try:
    with open(filename, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                # 測試是否能完美解析
                parsed = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"❌ [第 {line_num} 行] 發現格式錯誤: {e}")
                print(f"   有問題的內容: {line[:100]}...\n")
                error_count += 1
                
    if error_count == 0:
        print("🎉 恭喜！這 110 筆資料的 JSONL 格式完美無瑕，可以放心丟上 Colab 煉丹了！")
    else:
        print(f"⚠️ 掃描完畢，總共發現 {error_count} 個格式錯誤，請依照上面的行號回去修正。")

except FileNotFoundError:
    print(f"找不到檔案 {filename}，請確認檔名是否正確！")