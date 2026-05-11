# -*- coding: utf-8 -*-
"""
=======================================================================
 Behavior Chain Aggregator (行為鏈聚合器)
=======================================================================
 把單事件 JSONL 聚合成「攻擊鏈」，模擬真實 SOC 分析師的工作流程：
   1. 依 (Host, User) 組合分組
   2. 5 分鐘滑動視窗內的事件視為同一條行為鏈
   3. 輸出新格式 JSONL，每筆代表一條鏈

 設計依據：
   - 真實 APT 攻擊跨多個事件，單事件偵測會錯失關聯
   - Host+User 組合可區分「同主機不同帳號」的橫向移動場景
   - 5 分鐘視窗是業界 SIEM (Splunk, QRadar) 的常用預設值

 使用方式：
   python aggregate_chains.py --input otrf_hunting.jsonl --output chains.jsonl
   python aggregate_chains.py --input otrf_hunting.jsonl --window 300

=======================================================================
"""
import argparse
import json
import re
from collections import defaultdict
from datetime import datetime
from dateutil import parser as date_parser


def parse_timestamp(ts_str):
    """將各種時間格式統一成 UTC naive datetime（無時區資訊）
    
    問題根源：OTRF 的時間戳含時區（offset-aware），
              UWF 的時間戳不含時區（offset-naive），
              兩者混用時 Python 無法排序比較。
    解法：全部統一轉成 UTC naive（去掉 tzinfo）。
    """
    if not ts_str:
        return None
    try:
        if isinstance(ts_str, (int, float)):
            return datetime.utcfromtimestamp(float(ts_str))
        ts_str = str(ts_str).strip()
        # 處理科學記號（如 1.709288997389379E9）
        if 'E' in ts_str.upper() and '.' in ts_str:
            return datetime.utcfromtimestamp(float(ts_str))
        dt = date_parser.parse(ts_str)
        # 若有時區資訊，轉換至 UTC 後移除 tzinfo → naive
        if dt.tzinfo is not None:
            from datetime import timezone
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None


def extract_host_user(record):
    """從 record 萃取 (host, user) 組合鍵
    支援格式：
      OTRF/Wazuh：record['host'] + record['user'] 欄位
      EVTX Sysmon：text 裡的 Computer= + User= 或 SubjectUserName=
      UWF Zeek：text 裡的 src= IP
      EVTX（無 User）：Computer= + source_file 作為替代 user 鍵
    """
    text = record.get('text', '')

    # 優先從專屬欄位取
    host = record.get('host', '') or record.get('Host', '')
    user = record.get('user', '') or record.get('User', '')

    # 從 text 萃取 host（支援 Host= 和 Computer= 兩種格式）
    if not host:
        m = re.search(r'Host=([^\s|]+)', text)
        host = m.group(1) if m else ''
    if not host:
        m = re.search(r'Computer=([^\s]+)', text)
        host = m.group(1) if m else ''

    # 從 text 萃取 user（支援多種 Sysmon 欄位名稱）
    if not user:
        for field in ['User=', 'SubjectUserName=', 'TargetUserName=']:
            m = re.search(field + r'([^\s|]+)', text)
            if m and m.group(1) not in ('-', 'N/A', ''):
                user = m.group(1)
                break

    # EVTX 資料常常沒有 User 欄位 → 用 source_file 當替代 user 鍵
    # 這樣同一個 EVTX 檔的事件會被正確聚合在一起
    if not user:
        source_file = record.get('source_file', '')
        if source_file:
            # 去掉副檔名，用檔名作為 user 替代鍵
            user = re.sub(r'\.(evtx|json|log)$', '', source_file, flags=re.IGNORECASE)
            user = user[:50]  # 截斷過長的檔名

    # Zeek 網路流量（無 host/user）→ 用 src_ip 當分組鍵
    if not host and not user:
        m = re.search(r'src=([0-9.]+):', text)
        if m:
            host = m.group(1)
            user = 'network'

    # 最後防線：若仍然沒有 host，用 TTP ID 當 host 鍵（讓同類攻擊聚合）
    if not host:
        ttps = record.get('valid_ttps', [])
        if ttps and ttps[0] != 'Unknown Threat':
            host = ttps[0]
            if not user:
                user = 'evtx_default'

    return host.lower().strip(), user.lower().strip()


def aggregate_chains(input_path, output_path, window_seconds=300):
    """
    主聚合邏輯：依 Host+User 分組，5 分鐘滑動視窗切鏈

    Args:
        window_seconds: 視窗大小（秒），預設 300=5分鐘
    """
    print(f"📂 讀取：{input_path}")
    print(f"⏱️  視窗：{window_seconds} 秒（{window_seconds/60:.1f} 分鐘）")

    # ── Step 1: 按 (host, user) 分組 ──────────────────────────────
    groups = defaultdict(list)
    skipped_no_key = 0
    skipped_no_time = 0

    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
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

    print(f"\n📊 分組統計：")
    print(f"   有效分組：{len(groups)} 組")
    print(f"   略過無Host/User：{skipped_no_key}")
    print(f"   略過無Timestamp：{skipped_no_time}")

    # ── Step 2: 每組內按時間排序 + 滑動視窗切鏈 ─────────────────────
    chains = []
    chain_idx = 0

    for (host, user), events in groups.items():
        # 按時間排序
        events.sort(key=lambda x: x['_parsed_time'])

        # 滑動視窗切鏈：第一個事件開新鏈，後續事件若與鏈內最後事件
        # 時間差 <= window_seconds 就加入同鏈，否則開新鏈
        current_chain = []
        for ev in events:
            if not current_chain:
                current_chain.append(ev)
                continue

            time_diff = (ev['_parsed_time'] - current_chain[-1]['_parsed_time']).total_seconds()
            if time_diff <= window_seconds:
                current_chain.append(ev)
            else:
                # 時間差超過視窗 → 結束當前鏈，開新鏈
                chains.append(_build_chain_record(current_chain, host, user, chain_idx))
                chain_idx += 1
                current_chain = [ev]

        # 處理最後一條鏈
        if current_chain:
            chains.append(_build_chain_record(current_chain, host, user, chain_idx))
            chain_idx += 1

    # ── Step 3: 統計與輸出 ────────────────────────────────────────
    chain_lengths = [len(c['events']) for c in chains]
    multi_event_chains = sum(1 for n in chain_lengths if n > 1)

    print(f"\n📈 鏈統計：")
    print(f"   總鏈數：{len(chains)}")
    print(f"   多事件鏈（≥2事件）：{multi_event_chains}")
    print(f"   單事件鏈：{len(chains) - multi_event_chains}")
    if chain_lengths:
        print(f"   平均鏈長：{sum(chain_lengths)/len(chain_lengths):.1f} 事件")
        print(f"   最長鏈：{max(chain_lengths)} 事件")

    # 寫入輸出檔
    with open(output_path, 'w', encoding='utf-8') as f:
        for chain in chains:
            f.write(json.dumps(chain, ensure_ascii=False) + '\n')

    print(f"\n✅ 完成！輸出至：{output_path}")
    return chains


# =======================================================================
# 工具情報字典（Threat Intelligence Annotations）
# 解決 LLM 小模型不認識特定攻擊工具的問題
# 當行為鏈文字裡出現這些工具名稱時，自動補充一行 [THREAT-INTEL] 說明
# 讓 L1 不需要靠自己的訓練知識，直接從注釋獲得足夠資訊做出正確判斷
# =======================================================================
TOOL_INTEL = {
    # T1003.001 - LSASS Memory
    "outflank-dumpert":  "LSASS memory dumper using direct syscalls to bypass EDR/AV detection",
    "dumpert":           "LSASS memory dumper using direct syscalls to bypass EDR/AV detection",
    "nanodump":          "LSASS memory dump tool using syscall-based technique to evade AV",
    "handlekatz":        "LSASS credential dump tool duplicating process handles to bypass restrictions",
    "pypykatz":          "Python-based mimikatz reimplementation for LSASS credential extraction",
    "sharpdump":         "C# LSASS memory dump tool for credential extraction",
    "lsassy":            "Remote LSASS memory dump tool for credential extraction",
    # T1558.003 - Kerberoasting
    "rubeus":            "Kerberos attack toolkit for ticket harvesting, kerberoasting, and pass-the-ticket attacks",
    "getuserspns":       "Kerberoasting tool requesting Kerberos service tickets for offline hash cracking",
    "invoke-kerberoast": "PowerShell Kerberoasting script extracting service account ticket hashes",
    # T1197 - BITS Jobs
    "bitsadmin":         "Windows BITS job manager abused for stealthy background file download and persistence",
    # T1218.013 - Mavinject
    "mavinject":         "Windows signed binary abused for DLL injection into running processes",
    # T1055 - Process Injection
    "processhollowing":  "Process injection technique replacing legitimate process memory with malicious code",
    # T1021.002 - SMB/Windows Admin Shares
    "psexec":            "Remote execution tool using SMB for lateral movement and remote command execution",
    # T1059.001 - PowerShell
    "powersploit":       "PowerShell post-exploitation framework for privilege escalation and persistence",
    "empire":            "Post-exploitation framework using PowerShell agents for lateral movement",
    # T1547.001 - Registry Run Keys
    "userinitmlplogonscript": "Windows registry logon script persistence mechanism triggered at user login",
    # SAM / LSA registry paths (讓路徑關鍵字也能觸發注釋)
    "security\\policy\\secrets": "LSA Secrets registry path — contains service account credentials and cached passwords (T1003.004)",
    "hklm\\security":   "LSA Secrets registry hive — dumping this extracts service account credentials (T1003.004)",
    "hklm\\sam":        "SAM registry hive — contains local account password hashes (T1003.002)",
    "esentutl":          "Windows database utility abused to copy locked files (SAM/NTDS) via VSS for credential dumping",
    # General credential tools
    "mimikatz":          "Credential extraction tool dumping passwords, hashes, Kerberos tickets from memory",
    "wce":               "Windows Credential Editor for extracting and modifying authentication credentials",
    "secretsdump":       "Impacket tool remotely dumping SAM, LSA secrets, and NTDS credentials",
    "crackmapexec":      "Post-exploitation framework for network-wide credential dumping and lateral movement",
}


def _annotate_with_threat_intel(text):
    """
    掃描行為鏈文字，遇到已知攻擊工具就補充一行 [THREAT-INTEL] 注釋
    讓小型 LLM 不需要靠自己的知識庫就能識別工具用途
    """
    text_lower = text.lower()
    annotations = []
    seen_tools = set()

    for tool_keyword, intel_desc in TOOL_INTEL.items():
        if tool_keyword in text_lower and tool_keyword not in seen_tools:
            annotations.append(f"[THREAT-INTEL] {tool_keyword}: {intel_desc}")
            seen_tools.add(tool_keyword)

    if annotations:
        return text + "\n" + "\n".join(annotations)
    return text


def _build_chain_record(events, host, user, chain_idx):
    """
    把 N 個事件包成一條鏈的標準格式

    輸出格式：
    {
        "id": "CHAIN_00042",
        "host": "...", "user": "...",
        "start_time": "...", "end_time": "...",
        "event_count": 3,
        "text": "[T+0s] EventID=4688 ... CommandLine=...\n[THREAT-INTEL] ...",
        "valid_ttps": ["T1003.001", "T1547.001"],
        "events": [...]
    }
    """
    start_time = events[0]['_parsed_time']
    end_time = events[-1]['_parsed_time']

    # 組合行為鏈文字（時間相對標記，方便 LLM 理解先後順序）
    chain_lines = []
    for ev in events:
        delta = (ev['_parsed_time'] - start_time).total_seconds()
        chain_lines.append(f"[T+{int(delta)}s] {ev.get('text', '')}")
    raw_chain_text = "\n".join(chain_lines)

    # 🔍 工具情報注釋：自動補充已知攻擊工具的說明
    chain_text = _annotate_with_threat_intel(raw_chain_text)

    # 收集所有 valid_ttps 的聯集（去重，移除 Unknown Threat）
    all_ttps = set()
    for ev in events:
        for ttp in ev.get('valid_ttps', []):
            if ttp and ttp != "Unknown Threat":
                all_ttps.add(ttp)
    valid_ttps = sorted(all_ttps) if all_ttps else ["Unknown Threat"]

    # 移除聚合時用的內部欄位
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
    parser.add_argument('--window', type=int, default=300,
                        help='時間視窗（秒），預設 300=5分鐘')
    args = parser.parse_args()

    aggregate_chains(args.input, args.output, args.window)


if __name__ == '__main__':
    main()