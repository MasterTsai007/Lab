"""
=======================================================================
 Dataset → JSONL 格式轉換腳本
 支援：EVTX-to-MITRE-Attack | COMISET | Splunk BOTSv2/v3
=======================================================================
 使用方式：
   python convert_datasets_to_jsonl.py --source evtx    --input ./EVTX-to-MITRE-Attack
   python convert_datasets_to_jsonl.py --source comiset --input ./COMISET_Lab  (資料夾)
   python convert_datasets_to_jsonl.py --source comiset --input ./events.json  (單一檔案)
   python convert_datasets_to_jsonl.py --source bots    --input ./botsv2_attack_only.json

 COMISET 實際格式：Elasticsearch NDJSON（每行一個 JSON 物件，含 _source 包層）
   - 攻擊標籤欄位：PossibleCause（"Unknown" = 正常事件）
   - 核心內容：Operation, event_original_message, event_id, host_name, user_name
=======================================================================
"""

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# -----------------------------------------------------------------------
# 共用輸出函數
# -----------------------------------------------------------------------
def write_jsonl(records: list, output_path: str):
    with open(output_path, 'w', encoding='utf-8', errors='replace') as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    print(f"\n✅ 轉換完成！共 {len(records)} 筆")
    print(f"📄 輸出路徑：{output_path}")


# =======================================================================
# 1. EVTX-to-MITRE-Attack 轉換器
#    資料夾結構：TA0002-Execution/T1059-Command/.../attack.evtx
#    → 從路徑解析 Tactic (TA編號) 和 Technique (T編號)
# =======================================================================
def convert_evtx(input_dir: str, output_path: str):
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
    except ImportError:
        print("❌ 需要安裝 python-evtx：pip install python-evtx")
        sys.exit(1)

    records = []
    input_path = Path(input_dir)
    evtx_files = list(input_path.rglob("*.evtx"))

    if not evtx_files:
        print(f"❌ 在 {input_dir} 找不到任何 .evtx 檔案")
        sys.exit(1)

    print(f"🔍 找到 {len(evtx_files)} 個 .evtx 檔案，開始解析...")

    for evtx_file in evtx_files:
        # 從資料夾路徑萃取 ATT&CK 標籤
        # 例：TA0002-Execution/T1059-Command-and-Scripting-Interpreter/...
        parts = evtx_file.parts
        tactic = "Unknown"
        technique_id = "Unknown"

        for part in parts:
            ta_match = re.match(r'(TA\d{4})', part)
            t_match  = re.match(r'(T\d{4}(?:\.\d{3})?)', part)
            if ta_match:
                tactic = part          # e.g. "TA0002-Execution"
            if t_match:
                technique_id = t_match.group(1)  # e.g. "T1059"

        # 解析 EVTX 內容
        try:
            with evtx.Evtx(str(evtx_file)) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

                        # 提取關鍵欄位
                        event_id_el = root.find('.//e:EventID', ns)
                        computer_el = root.find('.//e:Computer', ns)
                        time_el     = root.find('.//e:TimeCreated', ns)
                        event_data  = root.find('.//e:EventData', ns)

                        event_id  = event_id_el.text if event_id_el is not None else ""
                        computer  = computer_el.text  if computer_el is not None else ""
                        timestamp = time_el.get('SystemTime', '') if time_el is not None else ""

                        # 把所有 EventData 欄位組成可讀文字
                        data_parts = []
                        if event_data is not None:
                            for data in event_data:
                                name  = data.get('Name', '')
                                value = (data.text or '').strip()
                                if value:
                                    data_parts.append(f"{name}={value}")

                        text_repr = f"EventID={event_id} Computer={computer} " + " ".join(data_parts)

                        records.append({
                            "id":         f"EVTX_{technique_id}_{len(records):05d}",
                            "text":       text_repr.strip(),
                            "valid_ttps": [technique_id],
                            "tactic":     tactic,
                            "source_file": evtx_file.name,
                            "timestamp":  timestamp
                        })
                    except Exception:
                        continue
        except Exception as e:
            print(f"  ⚠️ 略過 {evtx_file.name}（解析失敗：{e}）")
            continue

    write_jsonl(records, output_path)


# =======================================================================
# 2. COMISET 轉換器
#    實際格式：Elasticsearch NDJSON（每行一個 JSON 物件）
#
#    關鍵欄位（位於 _source 層）：
#      PossibleCause       → 攻擊標籤，"Unknown" 代表正常事件
#      event_id            → Windows Event ID
#      event_original_message → 完整原始訊息
#      Operation           → WMI/具體操作內容
#      host_name           → 主機名稱
#      user_name           → 使用者
#      @timestamp          → 時間戳
#      log_name            → 日誌來源
#      ResultCode          → 執行結果代碼
#
#    支援輸入：單一 .json/.ndjson 檔，或整個資料夾（遞迴掃描）
# =======================================================================
def _parse_comiset_line(line: str, idx: int) -> dict | None:
    """解析單行 COMISET JSON，回傳轉換後的 record 或 None"""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    # 支援兩種格式：有 _source 包層（Elasticsearch dump）或裸 _source
    src = obj.get("_source", obj)

    # ── 萃取攻擊標籤 ──────────────────────────────────────────────
    possible_cause = str(src.get("PossibleCause", "Unknown")).strip()

    # PossibleCause 範例值：
    #   "Unknown"                   → 正常/未知事件
    #   "T1047"                     → 直接 Technique ID
    #   "WMI Execution (T1047)"     → 帶描述的 Technique
    #   "TA0002"                    → Tactic ID
    # 規則：只接受標準 ATT&CK ID（T\d{4} 或 TA\d{4}）
    # Temporary / Permanent / Binding EventFilter 等雜訊值一律歸 Unknown Threat
    technique_id = "Unknown Threat"
    if possible_cause and possible_cause.lower() != "unknown":
        match = re.search(r'(TA?\d{4}(?:\.\d{3})?)', possible_cause)
        if match:
            technique_id = match.group(1)
        # else: 無法萃取標準 ID → 保持 Unknown Threat

    valid_ttps = ["Unknown Threat"] if technique_id == "Unknown Threat" else [technique_id]

    # ── 組成可讀的 LOG 文字 ───────────────────────────────────────
    # 優先使用 Operation（WMI 操作）或 event_original_message
    operation   = src.get("Operation", "")
    orig_msg    = src.get("event_original_message", "")
    event_id    = str(src.get("event_id", ""))
    host_name   = src.get("host_name", src.get("beat_name", ""))
    user_name   = src.get("user_name", src.get("User", ""))
    log_name    = src.get("log_name", "")
    result_code = src.get("ResultCode", "")
    timestamp   = src.get("@timestamp", src.get("event_original_time", ""))

    # 建構文字表示（模擬 SOC 分析師看到的格式）
    parts = []
    if event_id:    parts.append(f"EventID={event_id}")
    if host_name:   parts.append(f"Host={host_name}")
    if user_name:   parts.append(f"User={user_name}")
    if log_name:    parts.append(f"Log={log_name}")
    if result_code: parts.append(f"ResultCode={result_code}")

    # 主要內容：優先 Operation，否則用原始訊息
    main_content = operation or orig_msg
    if main_content:
        parts.append(main_content)

    text = " | ".join(parts)
    if not text:
        return None

    return {
        "id":         f"COMISET_{idx:06d}",
        "text":       text[:3000],   # 截斷超長訊息
        "valid_ttps": valid_ttps,
        "PossibleCause": possible_cause,
        "timestamp":  timestamp,
        "event_id":   event_id,
        "host":       host_name
    }


def convert_comiset(input_path_str: str, output_path: str):
    input_path = Path(input_path_str)
    records = []
    idx = 0

    # 自動判斷輸入是單檔還是資料夾
    if input_path.is_dir():
        # 遞迴掃描所有 .json / .ndjson / .jsonl 檔
        json_files = list(input_path.rglob("*.json")) + \
                     list(input_path.rglob("*.ndjson")) + \
                     list(input_path.rglob("*.jsonl"))
        if not json_files:
            print(f"❌ 在 {input_path_str} 找不到任何 JSON 檔案")
            sys.exit(1)
        print(f"📂 找到 {len(json_files)} 個 JSON 檔案，開始解析...")
    elif input_path.is_file():
        json_files = [input_path]
        print(f"📂 讀取單一檔案：{input_path_str}")
    else:
        print(f"❌ 找不到路徑：{input_path_str}")
        sys.exit(1)

    for json_file in json_files:
        print(f"   → 處理：{json_file.name}")
        try:
            with open(json_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    record = _parse_comiset_line(line, idx)
                    if record:
                        records.append(record)
                        idx += 1
        except Exception as e:
            print(f"   ⚠️  略過 {json_file.name}（{e}）")
            continue

    # 統計標籤分布
    label_counts = {}
    for r in records:
        cause = r.get("PossibleCause", "Unknown")
        label_counts[cause] = label_counts.get(cause, 0) + 1

    print(f"\n📊 標籤分布（前 10）：")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"   {label:30s} → {count} 筆")

    write_jsonl(records, output_path)


# =======================================================================
# 3. Splunk BOTSv2 / v3 轉換器
#    從 GitHub 匯出的 JSON 格式（raw events）
# =======================================================================
def convert_bots(input_json: str, output_path: str):
    print(f"📂 讀取 BOTS JSON：{input_json}")

    records = []
    with open(input_json, 'r', encoding='utf-8', errors='replace') as f:
        # 支援 JSON Lines 或 JSON Array 兩種格式
        content = f.read().strip()

    if content.startswith('['):
        events = json.loads(content)
    else:
        events = [json.loads(line) for line in content.splitlines() if line.strip()]

    print(f"   → 原始事件數：{len(events)}")

    for idx, event in enumerate(events):
        # BOTS 事件常見欄位
        source      = event.get('source', event.get('sourcetype', ''))
        raw         = event.get('_raw', event.get('raw', ''))
        host        = event.get('host', '')
        timestamp   = event.get('_time', event.get('time', ''))
        attack_data = event.get('attack_data', {})

        # 組成文字表示
        text = raw or str(event)
        if host:
            text = f"host={host} " + text

        # BOTS 沒有直接的 TTP 標籤 → 進入 Hunting Mode (不加 valid_ttps)
        record = {
            "id":        f"BOTS_{idx:06d}",
            "text":      text[:2000],   # 截斷超長 raw event
            "source":    source,
            "timestamp": str(timestamp)
        }

        # 若 attack_data 欄位有 MITRE 標籤（Attack-Only 版本可能有）
        if attack_data:
            ttp = attack_data.get('technique_id', '')
            if ttp:
                record['valid_ttps'] = [ttp]

        records.append(record)

    write_jsonl(records, output_path)

# =======================================================================
# 4. UWF-ZeekData24 轉換器
#    欄位：src_ip_zeek, dest_ip_zeek, proto, service, conn_state,
#          history, duration, orig_bytes, resp_bytes,
#          label_tactic, label_technique, label_binary, datetime
#    支援：單一 CSV 或整個資料夾（遞迴掃描）
# =======================================================================
def convert_uwf(input_path_str, output_path):
    import csv

    input_path = Path(input_path_str)
    if input_path.is_dir():
        csv_files = sorted(input_path.rglob("*.csv"))
        if not csv_files:
            print("No CSV files found in " + input_path_str)
            sys.exit(1)
        print("Found " + str(len(csv_files)) + " CSV files...")
    elif input_path.is_file():
        csv_files = [input_path]
        print("Reading: " + input_path_str)
    else:
        print("Path not found: " + input_path_str)
        sys.exit(1)

    records = []
    idx = 0
    label_counts = {}

    for csv_file in csv_files:
        print("  -> " + csv_file.name)
        try:
            with open(csv_file, "r", encoding="utf-8", newline="", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    label_binary = row.get("label_binary", "False").strip()
                    label_tech   = row.get("label_technique", "").strip()
                    label_tactic = row.get("label_tactic", "").strip()

                    is_attack = label_binary.lower() == "true"

                    if is_attack and re.match(r"T\d{4}", label_tech):
                        valid_ttps = [label_tech]
                    else:
                        valid_ttps = ["Unknown Threat"]

                    key = label_tech if is_attack else "Normal"
                    label_counts[key] = label_counts.get(key, 0) + 1

                    src_ip   = row.get("src_ip_zeek", "")
                    src_port = row.get("src_port_zeek", "")
                    dst_ip   = row.get("dest_ip_zeek", "")
                    dst_port = row.get("dest_port_zeek", "")
                    proto    = row.get("proto", "")
                    service  = row.get("service", "")
                    conn_st  = row.get("conn_state", "")
                    history  = row.get("history", "")
                    orig_b   = row.get("orig_bytes", "")
                    resp_b   = row.get("resp_bytes", "")
                    orig_p   = row.get("orig_pkts", "")
                    resp_p   = row.get("resp_pkts", "")
                    dur      = row.get("duration", "")
                    ts       = row.get("datetime", row.get("ts", ""))

                    parts = []
                    if proto:    parts.append("proto=" + proto)
                    if src_ip:   parts.append("src=" + src_ip + ":" + src_port)
                    if dst_ip:   parts.append("dst=" + dst_ip + ":" + dst_port)
                    if service:  parts.append("service=" + service)
                    if conn_st:  parts.append("conn_state=" + conn_st)
                    if history:  parts.append("history=" + history)
                    if dur:
                        try: parts.append("duration=" + str(round(float(dur), 4)) + "s")
                        except: parts.append("duration=" + dur)
                    if orig_b:   parts.append("orig_bytes=" + orig_b)
                    if resp_b:   parts.append("resp_bytes=" + resp_b)
                    if orig_p:   parts.append("orig_pkts=" + orig_p)
                    if resp_p:   parts.append("resp_pkts=" + resp_p)
                    if label_tactic and is_attack:
                        parts.append("tactic=" + label_tactic)

                    text = " | ".join(parts)
                    if not text:
                        continue

                    records.append({
                        "id":           "UWF_" + str(idx).zfill(7),
                        "text":         text,
                        "valid_ttps":   valid_ttps,
                        "label_tactic": label_tactic,
                        "label_binary": label_binary,
                        "timestamp":    ts,
                        "src":          src_ip + ":" + src_port,
                        "dst":          dst_ip + ":" + dst_port
                    })
                    idx += 1
        except Exception as e:
            print("  WARNING: skip " + csv_file.name + " (" + str(e) + ")")
            continue

    print("")
    print("Label distribution (top 15):")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1])[:15]:
        print("  " + label.ljust(25) + str(count).rjust(8))

    write_jsonl(records, output_path)

# =======================================================================
# Main
# =======================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Convert security datasets to SOC Pipeline JSONL format"
    )
    parser.add_argument("--source",  required=True,
                        choices=["evtx", "comiset", "bots", "uwf"],
                        help="Dataset type (uwf = UWF-ZeekData24)")
    parser.add_argument("--input",   required=True,
                        help="Input path (file or folder)")
    parser.add_argument("--output",  default="",
                        help="Output JSONL path (auto-named if omitted)")
    parser.add_argument("--limit",   type=int, default=0,
                        help="Max records (0 = no limit)")
    args = parser.parse_args()

    output = args.output or "mitre_cti_hunting_" + args.source + ".jsonl"

    if args.source == "evtx":
        convert_evtx(args.input, output)
    elif args.source == "comiset":
        convert_comiset(args.input, output)
    elif args.source == "bots":
        convert_bots(args.input, output)
    elif args.source == "uwf":
        convert_uwf(args.input, output)

    if args.limit > 0:
        with open(output, "r", encoding="utf-8") as f:
            lines = f.readlines()
        with open(output, "w", encoding="utf-8") as f:
            f.writelines(lines[:args.limit])
        print("Truncated to " + str(args.limit) + " records")


if __name__ == "__main__":
    main()
