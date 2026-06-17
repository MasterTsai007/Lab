"""
fix_modern_apt.py — Windows-APT Dataset 2025 & UWF-ZeekData24 轉換腳本 (學術評測真值對齊修正版)
=====================================================================
支援格式：
  1. Windows-APT 2025（Mendeley, Wazuh CSV 格式）
  2. UWF-ZeekData24（Zeek Conn Log CSV 格式）

用法：
  python fix_modern_apt.py --input *.csv --output apt_chains.jsonl
"""

import argparse
import csv
import glob
import json
import os
import re
import sys
from pathlib import Path

# =====================================================================
# 1. UWF 標籤 → TTP ID（僅 UWF 需要，Windows-APT 直接讀 mitre.id 欄位）
# =====================================================================
UWF_LABEL_TO_TTP = {
    "reconnaissance":    "T1595",
    "discovery":         "T1046",
    "scanning":          "T1046",
    "portscan":          "T1046",
    "lateral movement":  "T1021",
    "c&c":               "T1071",
    "c2":                "T1071",
    "exfiltration":      "T1041",
    "malicious":         "Unknown",   
    "benign":            "Benign",
    "normal":            "Benign",
    "background":        "Benign",
}

# =====================================================================
# 2. 工具函數
# =====================================================================
def parse_mitre_id(raw_value: str) -> str:
    if not raw_value or not raw_value.strip():
        return "Unknown"
    v = raw_value.strip()
    if v.startswith("["):
        try:
            ids = json.loads(v)
            if isinstance(ids, list) and ids:
                for item in ids:
                    m = re.match(r"(T\d{4}(?:\.\d{3})?)", str(item).strip())
                    if m:
                        return m.group(1)
        except Exception:
            pass
    m = re.match(r"(T\d{4}(?:\.\d{3})?)", v)
    if m:
        return m.group(1)
    return "Unknown"

def clean_log_text(full_log: str) -> str:
    if not full_log:
        return ""
    text = full_log.strip()
    try:
        if text.startswith("{"):
            obj = json.loads(text)
            parts = []
            for key in ["EventID", "event_id", "CommandLine", "command_line",
                        "NewProcessName", "process_name", "ParentProcessName",
                        "SubjectUserName", "user", "Hostname", "hostname",
                        "Channel", "channel", "TargetFilename"]:
                val = obj.get(key, "")
                if val:
                    parts.append(f"{key}={val}")
            return " | ".join(parts) if parts else text[:500]
    except Exception:
        pass
    return text[:500]

# =====================================================================
# 3. Windows-APT 2025 轉換器
# =====================================================================
def convert_apt(input_files: list, output_path: str, limit: int):
    records = []
    idx = 0
    skipped_benign = 0

    for csv_path in input_files:
        print(f"  處理：{Path(csv_path).name}")
        try:
            with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if limit and idx >= limit:
                        break

                    timestamp    = row.get("_source.@timestamp", row.get("_source.timestamp", ""))
                    agent_name   = row.get("_source.agent.name", "")
                    full_log     = row.get("_source.full_log", "")
                    rule_desc    = row.get("_source.rule.description", "")
                    mitre_id     = row.get("_source.rule.mitre.id", "")      
                    mitre_tech   = row.get("_source.rule.mitre.technique", "")
                    mitre_tactic = row.get("_source.rule.mitre.tactic", "")
                    event_id     = row.get("_source.data.win.system.eventID", "")
                    username     = (row.get("_source.data.win.eventdata.subjectUserName", "")
                                    or row.get("_source.data.win.eventdata.targetUserName", "")
                                    or row.get("_source.data.win.eventdata.user", ""))
                    cmd_line     = (row.get("_source.data.win.eventdata.commandLine", "")
                                    or row.get("_source.data.win.eventdata.parentCommandLine", ""))
                    process_name = (row.get("_source.data.win.eventdata.image", "")
                                    or row.get("_source.data.win.eventdata.processName", ""))
                    parent_img   = row.get("_source.data.win.eventdata.parentImage", "")
                    computer     = row.get("_source.data.win.system.computer", "")
                    host         = agent_name or computer

                    if not mitre_id and not mitre_tech and not mitre_tactic:
                        skipped_benign += 1
                        continue

                    ttp_id = parse_mitre_id(mitre_id)
                    if ttp_id == "Unknown":
                        ttp_id = parse_mitre_id(mitre_tech)
                    if ttp_id == "Unknown":
                        skipped_benign += 1
                        continue

                    text_parts = []
                    if event_id:     text_parts.append(f"EventID={event_id}")
                    if host:         text_parts.append(f"Host={host}")
                    if username:     text_parts.append(f"User={username}")
                    if process_name: text_parts.append(f"Process={process_name[:100]}")
                    if parent_img:   text_parts.append(f"Parent={parent_img[:100]}")
                    if cmd_line:     text_parts.append(f"CommandLine={cmd_line[:300]}")
                    elif full_log:   text_parts.append(f"Log={clean_log_text(full_log)}")
                    elif rule_desc:  text_parts.append(f"RuleDesc={rule_desc[:200]}")

                    if not text_parts:
                        skipped_benign += 1
                        continue

                    has_behavior = cmd_line.strip() or process_name.strip()
                    if not has_behavior:
                        skipped_benign += 1
                        continue

                    records.append({
                        "id":          f"APT_{idx:06d}",
                        "text":        " | ".join(text_parts),
                        "valid_ttps":  [ttp_id], # 標準 Benchmark 評測路徑
                        "timestamp":   timestamp,
                        "host":        host,
                        "user":        username,
                        "tactic":      mitre_tactic,
                        "technique":   mitre_tech,
                        "source":      Path(csv_path).name,
                    })
                    idx += 1

        except Exception as e:
            print(f"    ⚠️  略過 {csv_path}：{e}")

    _write_output(records, output_path, skipped_benign)

# =====================================================================
# 4. UWF-ZeekData24 轉換器 (🛠️ 核心修復)
# =====================================================================
def convert_uwf(input_files: list, output_path: str, limit: int):
    records = []
    idx = 0
    skipped_benign = 0

    for csv_path in input_files:
        print(f"  處理：{Path(csv_path).name}")
        try:
            with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if limit and idx >= limit:
                        break

                    ts         = row.get("datetime", row.get("ts", ""))
                    src_ip     = row.get("src_ip_zeek",  row.get("id.orig_h", row.get("src_ip", "")))
                    src_port   = row.get("src_port_zeek",row.get("id.orig_p", row.get("src_port", "")))
                    dst_ip     = row.get("dest_ip_zeek", row.get("id.resp_h", row.get("dst_ip", "")))
                    dst_port   = row.get("dest_port_zeek",row.get("id.resp_p",row.get("dst_port","")))
                    proto      = row.get("proto", "")
                    service    = row.get("service", "")
                    duration   = row.get("duration", "")
                    orig_bytes = row.get("orig_bytes", "")
                    resp_bytes = row.get("resp_bytes", "")
                    conn_state = row.get("conn_state", "")

                    label_tech   = row.get("label_technique", "").strip()
                    label_tactic = row.get("label_tactic", "").strip()
                    label_binary = row.get("label_binary", "").strip().lower()

                    ttp_id = "Unknown"
                    if label_tech and re.match(r"T\d{4}", label_tech):
                        ttp_id = label_tech
                    elif label_binary == "false":
                        if idx % 20 == 0:
                            ttp_id = "Unknown Threat"
                        else:
                            skipped_benign += 1
                            continue
                    else:
                        skipped_benign += 1
                        continue

                    parts = []
                    if src_ip:    parts.append(f"src={src_ip}:{src_port}")
                    if dst_ip:    parts.append(f"dst={dst_ip}:{dst_port}")
                    if proto:     parts.append(f"proto={proto}")
                    if service:   parts.append(f"service={service}")
                    if duration:  parts.append(f"duration={duration}")
                    if orig_bytes:parts.append(f"orig_bytes={orig_bytes}")
                    if resp_bytes:parts.append(f"resp_bytes={resp_bytes}")
                    if conn_state:parts.append(f"conn_state={conn_state}")
                    if label_tech:parts.append(f"technique={label_tech}")

                    # 🛠️ 學術撥亂反正：將真實技術代碼同時同步寫入 valid_ttps
                    records.append({
                        "id":     f"UWF_{idx:06d}",
                        "text":   " | ".join(parts),
                        "valid_ttps": [ttp_id], # 修正：開放給 pipeline 進行 F1/命中率計算
                        "timestamp": ts,
                        "host":   src_ip,
                        "user":   "network",
                        "source": Path(csv_path).name,
                        "_ground_truth_hidden": ttp_id,
                    })
                    idx += 1

        except Exception as e:
            print(f"    ⚠️  略過 {csv_path}：{e}")

    _write_output(records, output_path, skipped_benign)

# =====================================================================
# 5. 標準 Zeek 轉換器
# =====================================================================
def convert_zeek(input_files: list, output_path: str, limit: int):
    records = []
    idx = 0
    skipped_benign = 0

    for csv_path in input_files:
        print(f"  處理：{Path(csv_path).name}")
        try:
            with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if limit and idx >= limit:
                        break

                    row_l = {k.lower().strip(): v for k, v in row.items()}
                    ts        = row_l.get("datetime", row_l.get("ts", ""))
                    src_ip    = row_l.get("id.orig_h", row_l.get("src_ip", ""))
                    src_port  = row_l.get("id.orig_p", row_l.get("src_port", ""))
                    dst_ip    = row_l.get("id.resp_h", row_l.get("dst_ip", ""))
                    dst_port  = row_l.get("id.resp_p", row_l.get("dst_port", ""))
                    proto     = row_l.get("proto", "")
                    service   = row_l.get("service", "")
                    orig_bytes= row_l.get("orig_bytes", "")
                    resp_bytes= row_l.get("resp_bytes", "")
                    label     = row_l.get("label", row_l.get("attack_cat", row_l.get("class", "")))

                    ttp_id = "Unknown"
                    if label:
                        m = re.search(r"(T\d{4}(?:\.\d{3})?)", label)
                        if m:
                            ttp_id = m.group(1)
                        elif label.strip().lower() in ("benign", "normal", "background", "false"):
                            if idx % 20 == 0:
                                ttp_id = "Unknown Threat"
                            else:
                                skipped_benign += 1
                                continue
                        else:
                            ttp_id = UWF_LABEL_TO_TTP.get(label.strip().lower(), "Unknown")

                    if ttp_id == "Unknown":
                        skipped_benign += 1
                        continue

                    parts = []
                    if src_ip:    parts.append(f"src={src_ip}:{src_port}")
                    if dst_ip:    parts.append(f"dst={dst_ip}:{dst_port}")
                    if proto:     parts.append(f"proto={proto}")
                    if service:   parts.append(f"service={service}")
                    if orig_bytes:parts.append(f"orig_bytes={orig_bytes}")
                    if resp_bytes:parts.append(f"resp_bytes={resp_bytes}")

                    records.append({
                        "id":         f"ZEEK_{idx:06d}",
                        "text":       " | ".join(parts),
                        "valid_ttps": [ttp_id],
                        "timestamp":  ts,
                        "host":       src_ip,
                        "user":       "network",
                        "source":     Path(csv_path).name,
                    })
                    idx += 1
        except Exception as e:
            print(f"    ⚠️  略過 {csv_path}：{e}")

    _write_output(records, output_path, skipped_benign)

def detect_format(csv_path: str) -> str:
    try:
        with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
            headers = set(next(csv.reader(f)))
        headers_lower = {h.lower().strip() for h in headers}

        if "_source.rule.mitre.id" in headers or "_source.agent.name" in headers:
            return "wazuh"
        if "src_ip_zeek" in headers_lower or "dest_ip_zeek" in headers_lower:
            return "uwf"
        if "label_technique" in headers_lower and "label_binary" in headers_lower:
            return "uwf"
        if "id.orig_h" in headers_lower or ("ts" in headers_lower and "proto" in headers_lower):
            return "zeek"
        return "unknown"
    except Exception:
        return "unknown"

def _write_output(records: list, output_path: str, skipped: int):
    with open(output_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    from collections import Counter
    ttp_dist = Counter(
        r["valid_ttps"][0] if "valid_ttps" in r else "Hunting"
        for r in records
    )

    print(f"\n{'='*50}")
    print(f"✅ 完成！共 {len(records)} 筆 → {output_path}")
    print(f"   略過（無標籤/正常事件）：{skipped} 筆")
    print(f"\nTTP 分布（前 15）：")
    for ttp, count in ttp_dist.most_common(15):
        print(f"  {ttp:20s} {count:6d} 筆")

# =====================================================================
# 6. 主程式進入點
# =====================================================================
def main():
    parser = argparse.ArgumentParser(description="LOG 轉換腳本（自動對齊版）")
    parser.add_argument("--source", choices=["apt", "uwf", "zeek", "auto"], default="auto")
    parser.add_argument("--input", nargs="+", required=True)
    parser.add_argument("--output", default="hunting.jsonl")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    input_files = []
    for pattern in args.input:
        matched = glob.glob(pattern)
        if matched:
            input_files.extend(matched)
        elif os.path.exists(pattern):
            input_files.append(pattern)

    if not input_files:
        print(f"❌ 找不到任何輸入檔案：{args.input}")
        sys.exit(1)

    input_files = sorted(set(input_files))
    print(f"📂 找到 {len(input_files)} 個輸入檔案")

    if args.source == "auto":
        fmt = detect_format(input_files[0])
        print(f"🔍 自動偵測格式：{fmt}")
    else:
        fmt = {"apt": "wazuh", "uwf": "uwf", "zeek": "zeek"} [args.source]

    if args.output == "hunting.jsonl":
        default_names = {"wazuh": "apt_hunting.jsonl", "uwf": "uwf_hunting.jsonl", "zeek": "zeek_hunting.jsonl"}
        args.output = default_names.get(fmt, "hunting.jsonl")

    if fmt == "wazuh":
        convert_apt(input_files, args.output, args.limit)
    elif fmt == "uwf":
        convert_uwf(input_files, args.output, args.limit)
    elif fmt == "zeek":
        convert_zeek(input_files, args.output, args.limit)
    else:
        print(f"⚠️ 格式未知，終止執行。")
        sys.exit(1)

if __name__ == "__main__":
    main()