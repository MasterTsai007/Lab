import json
records = []
for fname in ['otrf_hunting.jsonl', 'uwf_hunting.jsonl']:
    with open(fname, encoding='utf-8') as f:
        for line in f:
            records.append(line)
with open('all_hunting.jsonl', 'w', encoding='utf-8') as f:
    f.writelines(records)
print('合併完成：' + str(len(records)) + ' 筆')