import json
with open('evtx_labeled.jsonl', encoding='utf-8') as f:
    r = json.loads(f.readline())
print(r['text'][:300])
print('host欄位:', r.get('host','無'))
print('user欄位:', r.get('user','無'))
print('timestamp:', r.get('timestamp','無'))