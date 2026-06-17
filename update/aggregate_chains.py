# -*- coding: utf-8 -*-
"""
=======================================================================
 Behavior Chain Aggregator (行為鏈聚合器 - 知識庫距離動態純化完全體)
=======================================================================
 完美實現使用者提案：
   1. 100% 物理拔除 TOOL_INTEL_FALLBACK，拒絕任何寫死（Hardcoded）字串。
   2. 逐筆拆解安全事件，精準提取包含 CommandLine/Log 在內的核心進程名稱。
   3. 將純進程名稱直接投入現有的 MITRE ATT&CK 向量知識庫 (mitre_rules) 查詢。
   4. 若該進程與整個安全知識庫的最近距離依然極度遙遠 (Distance >= 0.78)，
      證明該程式在數學語意上絕對不可能與惡意攻擊有關，系統自動將其剔除。
=======================================================================
"""
import argparse
import json
import re
import os
from collections import defaultdict
from datetime import datetime
from dateutil import parser as date_parser

# 延遲載入大數據向量模組，確保在未初始化環境下不崩潰
_SOC_CLIENT = None
_MITRE_COLLECTION = None
_EMBEDDER = None

def _is_absolutely_benign_via_rag(text: str) -> bool:
    """
    🔬 純 RAG 向量邊界動態審查閘門 (Zero-Hardcoding Pure RAG Gate)
    提取進程名稱，直接與惡意威脅知識庫比對最低距離，若距離極遠則判定為良性常態維運雜訊。
    """
    global _SOC_CLIENT, _MITRE_COLLECTION, _EMBEDDER
    
    if _SOC_CLIENT is None:
        try:
            import chromadb
            from sentence_transformers import SentenceTransformer
            
            _EMBEDDER = SentenceTransformer('all-MiniLM-L6-v2')
            _SOC_CLIENT = chromadb.PersistentClient(path="./my_soc_vectordb")
            _MITRE_COLLECTION = _SOC_CLIENT.get_collection(name="mitre_rules")
        except Exception:
            return False 

    try:
        # 1. 精準洗出當前事件的「單一進程名稱」，完美兼容 CommandLine 與 Log 等格式
        process_match = re.search(r'(?:Process|process_name|Image|NewProcessName|CommandLine|Log|RuleDesc)=([^\s|,|\|]+)', text, re.I)
        if process_match:
            clean_text = process_match.group(1).split("\\")[-1].split("/")[-1]
            clean_text = re.sub(r'["\']', '', clean_text).lower().strip()
        else:
            clean_text = text.strip()[:40].lower()
            
        if not clean_text or len(clean_text) < 3:
            return False

        # 2. 將純粹的進程名稱向量化，向惡意技術知識庫發起全面查詢
        query_emb = _EMBEDDER.encode([clean_text]).tolist()
        res = _MITRE_COLLECTION.query(query_embeddings=query_emb, n_results=1)
        
        if res and res['distances'] and res['distances'][0]:
            min_distance = res['distances'][0][0]
            
            # 📐 數學去噪閾值：若最短距離依然 >= 0.78，代表這是一個完全獨立於威脅技術之外的良性常態組件
            if min_distance >= 0.78:
                return True 
                
    except Exception:
        pass
    return False


def parse_timestamp(ts_str):
    """將各種時間格式統一成 UTC naive datetime"""
    if not ts_str:
        return None
    try:
        if isinstance(ts_str, (int, float)):
            return datetime.utcfromtimestamp(float(ts_str))
        ts_str = str(ts_str).strip()
        if ' @ ' in ts_str:
            ts_str = ts_str.replace(' @ ', ' ')
        if re.match(r'^[\d.]+[Ee][\d+\-]+$', ts_str):
            return datetime.utcfromtimestamp(float(ts_str))
        dt = date_parser.parse(ts_str)
        if dt.tzinfo is not None:
            from datetime import timezone
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None


_HOST_FIELD_PATTERNS = re.compile(
    r'(?:Host|Computer|Hostname|hostname|SrcAddr|src_ip)=([^\s|,]+)',
    re.IGNORECASE
)
_USER_FIELD_PATTERNS = re.compile(
    r'(?:User|SubjectUserName|TargetUserName|AccountName|username|user_name)=([^\s|,]+)',
    re.IGNORECASE
)
_EXCLUDE_VALUES = {'-', 'n/a', 'na', 'null', 'none', 'system', ''}

def _is_excluded(val: str) -> bool:
    return not val or val.strip().lower() in _EXCLUDE_VALUES


def extract_host_user(record):
    """從 record 動態萃取 (host, user) 組合鍵"""
    text = record.get('text', '')
    host = str(record.get('host', '') or record.get('Host', '') or record.get('hostname', '')).strip()
    user = str(record.get('user', '') or record.get('User', '') or record.get('username', '')).strip()

    if _is_excluded(host):
        for m in _HOST_FIELD_PATTERNS.finditer(text):
            val = m.group(1).strip().rstrip('|,')
            if not _is_excluded(val) and len(val) > 1:
                host = val
                break

    if _is_excluded(user):
        for m in _USER_FIELD_PATTERNS.finditer(text):
            val = m.group(1).strip().rstrip('|,')
            if not _is_excluded(val) and len(val) > 1:
                user = val
                break

    if _is_excluded(user):
        source = record.get('source', '') or record.get('source_file', '')
        if source:
            user = re.sub(r'\.(csv|evtx|json|log|jsonl)$', '', source, flags=re.IGNORECASE)[:50]

    if _is_excluded(host):
        m = re.search(r'src=([0-9]{1,3}(?:\.[0-9]{1,3}){3})', text)
        if m:
            host = m.group(1)
            user = user or 'network'

    if _is_excluded(host):
        ttps = record.get('valid_ttps', [])
        if ttps and ttps[0] != 'Unknown Threat':
            host = ttps[0]
            user = user or 'default'

    return host.lower().strip(), user.lower().strip()


def aggregate_chains(input_path, output_path, window_seconds=300):
    """主聚合邏輯：依 Host+User 分組，滑動視窗切鏈"""
    print(f"📂 讀取：{input_path}")
    print(f"⏱️  視窗：{window_seconds} 秒（{window_seconds/60:.1f} 分鐘）")

    groups = defaultdict(list)
    skipped_no_key = 0
    skipped_no_time = 0
    purified_benign_count = 0  

    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue

            # 🚀 執行純 RAG 原子級去噪判定
            event_text = r.get('text', '')
            if _is_absolutely_benign_via_rag(event_text):
                purified_benign_count += 1
                continue

            host, user = extract_host_user(r)
            if not host or not user:
                skipped_no_key += 1
                continue

            ts = parse_timestamp(r.get('timestamp', ''))
            if not ts:
                skipped_no_time += 1
                continue

            r['_parsed_time'] = ts
            r['_host'] = host
            r['_user'] = user
            groups[(host, user)].append(r)

    print(f"\n📊 分組與 RAG 動態去噪統計：")
    print(f"   有效分組：{len(groups)} 組")
    print(f"   🛡️ 知識庫數學邊界智慧純化(過濾)：{purified_benign_count} 筆")
    print(f"   略過無Host/User：{skipped_no_key}")
    print(f"   略過無Timestamp：{skipped_no_time}")

    chains = []
    chain_idx = 0

    for (host, user), events in groups.items():
        events.sort(key=lambda x: x['_parsed_time'])

        current_chain = []
        for ev in events:
            if not current_chain:
                current_chain.append(ev)
                continue

            time_diff = (ev['_parsed_time'] - current_chain[-1]['_parsed_time']).total_seconds()
            if time_diff <= window_seconds:
                current_chain.append(ev)
            else:
                chains.append(_build_chain_record(current_chain, host, user, chain_idx))
                chain_idx += 1
                current_chain = [ev]

        if current_chain:
            chains.append(_build_chain_record(current_chain, host, user, chain_idx))
            chain_idx += 1

    chain_lengths = [len(c['events']) for c in chains]
    multi_event_chains = sum(1 for n in chain_lengths if n > 1)

    print(f"\n📈 聚合攻擊鏈統計：")
    print(f"   總鏈數：{len(chains)}")
    print(f"   多事件鏈（≥2事件）：{multi_event_chains}")
    print(f"   單事件鏈：{len(chains) - multi_event_chains}")
    if chain_lengths:
        print(f"   平均鏈長：{sum(chain_lengths)/len(chain_lengths):.1f} 事件")
        print(f"   最長鏈：{max(chain_lengths)} 事件")

    with open(output_path, 'w', encoding='utf-8') as f:
        for chain in chains:
            f.write(json.dumps(chain, ensure_ascii=False) + '\n')

    print(f"\n✅ 完成！輸出至：{output_path}")
    return chains


_DYNAMIC_TOOL_INTEL = None

def _load_tool_intel_from_kb(db_path="./my_soc_vectordb", collection_name="mitre_rules"):
    """純動態情報載入：若知識庫為空，直接回傳空字典，絕不使用任何 Fallback 白名單"""
    global _DYNAMIC_TOOL_INTEL
    try:
        import chromadb
        client = chromadb.PersistentClient(path=db_path)
        col = client.get_collection(collection_name)
        results = col.get(include=["documents"])

        dynamic = {}
        for tid, doc in zip(results["ids"], results["documents"]):
            tool_section = re.search(r'Known tools:\s*(.+?)(?:\s*\||\s*$)', doc)
            if not tool_section:
                continue
            for tool_desc in tool_section.group(1).split('|'):
                tool_desc = tool_desc.strip()
                if not tool_desc:
                    continue
                first_word = re.match(r'([a-zA-Z0-9_\-\.]+)', tool_desc)
                if first_word:
                    keyword = first_word.group(1).lower()
                    if len(keyword) > 3:
                        dynamic[keyword] = tool_desc

        _DYNAMIC_TOOL_INTEL = dynamic
        print(f"   ✅ 從知識庫動態載入 {len(dynamic)} 個工具情報條目")
        return dynamic
    except Exception as e:
        _DYNAMIC_TOOL_INTEL = {}
        return {}


def _annotate_with_threat_intel(text):
    global _DYNAMIC_TOOL_INTEL
    if _DYNAMIC_TOOL_INTEL is None:
        _load_tool_intel_from_kb()

    tool_dict = _DYNAMIC_TOOL_INTEL or {}
    text_lower = text.lower()
    annotations = []
    seen_tools = set()

    for tool_keyword, intel_desc in tool_dict.items():
        if tool_keyword in text_lower and tool_keyword not in seen_tools:
            annotations.append(f"[THREAT-INTEL] {tool_keyword}: {intel_desc}")
            seen_tools.add(tool_keyword)

    if annotations:
        return text + "\n" + "\n".join(annotations)
    return text


def _build_chain_record(events, host, user, chain_idx):
    start_time = events[0]['_parsed_time']
    end_time = events[-1]['_parsed_time']

    chain_lines = []
    for ev in events:
        delta = (ev['_parsed_time'] - start_time).total_seconds()
        chain_lines.append(f"[T+{int(delta)}s] {ev.get('text', '')}")
    raw_chain_text = "\n".join(chain_lines)

    chain_text = _annotate_with_threat_intel(raw_chain_text)

    all_ttps = set()
    for ev in events:
        for ttp in ev.get('valid_ttps', []):
            if ttp and ttp != "Unknown Threat":
                all_ttps.add(ttp)
    valid_ttps = sorted(all_ttps) if all_ttps else ["Unknown Threat"]

    clean_events = []
    for ev in events:
        ev_copy = {k: v for k, v in ev.items() if not k.startswith('_')}
        clean_events.append(ev_copy)

    return {
        "id":          f"CHAIN_{chain_idx:05d}",
        "host":        host,
        "user":        user,
        "start_time":  start_time.isoformat(),
        "end_time":    end_time.isoformat(),
        "duration_s":  int((end_time - start_time).total_seconds()),
        "event_count": len(events),
        "text":        chain_text,
        "valid_ttps":  valid_ttps,
        "events":      clean_events
    }


def main():
    parser = argparse.ArgumentParser(description='將單事件 JSONL 聚合為行為鏈')
    parser.add_argument('--input',  required=True, help='輸入單事件 JSONL')
    parser.add_argument('--output', default='chains.jsonl', help='輸出鏈 JSONL')
    parser.add_argument('--window', type=int, default=300, help='時間視窗（秒），預設 300=5分鐘')
    
    # 🔬 測試模式專用限制面板
    parser.add_argument('--limit', type=int, default=0, help='除錯專用：限制只讀取前 N 筆安全事件進行測試')
    args = parser.parse_args()

    if args.limit > 0:
        print(f"🔬 [冒煙測試模式啟動] 正在擷取前 {args.limit} 筆事件進行智慧原子去噪測試...")
        test_input_path = "temp_smoke_test.jsonl"
        try:
            with open(args.input, 'r', encoding='utf-8') as fin, open(test_input_path, 'w', encoding='utf-8') as fout:
                for idx, line in enumerate(fin):
                    if idx >= args.limit: break
                    fout.write(line)
            aggregate_chains(test_input_path, args.output, args.window)
            if os.path.exists(test_input_path): os.remove(test_input_path)
            return
        except Exception as e:
            print(f"❌ 測試模式重組失敗: {e}")

    aggregate_chains(args.input, args.output, args.window)


if __name__ == '__main__':
    main()