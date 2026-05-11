import argparse
import csv
import json
import re
import sys
from pathlib import Path

def write_jsonl(records, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    print("Done! Total records: " + str(len(records)))
    print("Output: " + output_path)

def convert_uwf(input_path_str, output_path):
    input_path = Path(input_path_str)
    if input_path.is_dir():
        csv_files = sorted(input_path.rglob("*.csv"))
        print("Found " + str(len(csv_files)) + " CSV files")
    elif input_path.is_file():
        csv_files = [input_path]
        print("Reading: " + input_path_str)
    else:
        print("ERROR: path not found: " + input_path_str)
        sys.exit(1)

    records = []
    idx = 0
    label_counts = {}

    for csv_file in csv_files:
        print("  -> " + csv_file.name)
        try:
            with open(csv_file, 'r', encoding='utf-8', newline='', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    label_binary = row.get('label_binary', 'False').strip()
                    label_tech   = row.get('label_technique', '').strip()
                    label_tactic = row.get('label_tactic', '').strip()
                    is_attack = label_binary.lower() == 'true'

                    if is_attack and re.match(r'T\d{4}', label_tech):
                        valid_ttps = [label_tech]
                    else:
                        valid_ttps = ['Unknown Threat']

                    key = label_tech if is_attack else 'Normal'
                    label_counts[key] = label_counts.get(key, 0) + 1

                    src_ip   = row.get('src_ip_zeek', '')
                    src_port = row.get('src_port_zeek', '')
                    dst_ip   = row.get('dest_ip_zeek', '')
                    dst_port = row.get('dest_port_zeek', '')
                    proto    = row.get('proto', '')
                    service  = row.get('service', '')
                    conn_st  = row.get('conn_state', '')
                    history  = row.get('history', '')
                    orig_b   = row.get('orig_bytes', '')
                    resp_b   = row.get('resp_bytes', '')
                    orig_p   = row.get('orig_pkts', '')
                    resp_p   = row.get('resp_pkts', '')
                    dur      = row.get('duration', '')
                    ts       = row.get('datetime', row.get('ts', ''))

                    parts = []
                    if proto:    parts.append('proto=' + proto)
                    if src_ip:   parts.append('src=' + src_ip + ':' + src_port)
                    if dst_ip:   parts.append('dst=' + dst_ip + ':' + dst_port)
                    if service:  parts.append('service=' + service)
                    if conn_st:  parts.append('conn_state=' + conn_st)
                    if history:  parts.append('history=' + history)
                    if dur:
                        try:    parts.append('duration=' + str(round(float(dur), 4)) + 's')
                        except: parts.append('duration=' + dur)
                    if orig_b:   parts.append('orig_bytes=' + orig_b)
                    if resp_b:   parts.append('resp_bytes=' + resp_b)
                    if orig_p:   parts.append('orig_pkts=' + orig_p)
                    if resp_p:   parts.append('resp_pkts=' + resp_p)
                    if label_tactic and is_attack:
                        parts.append('tactic=' + label_tactic)

                    text = ' | '.join(parts)
                    if not text:
                        continue

                    records.append({
                        'id':           'UWF_' + str(idx).zfill(7),
                        'text':         text,
                        'valid_ttps':   valid_ttps,
                        'label_tactic': label_tactic,
                        'label_binary': label_binary,
                        'timestamp':    ts,
                        'src':          src_ip + ':' + src_port,
                        'dst':          dst_ip + ':' + dst_port
                    })
                    idx += 1
        except Exception as e:
            print("  WARNING: skip " + str(csv_file.name) + ' (' + str(e) + ')')

    print("\nLabel distribution:")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1])[:15]:
        print('  ' + label.ljust(25) + str(count).rjust(8))

    write_jsonl(records, output_path)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input',  required=True)
    parser.add_argument('--output', default='mitre_cti_hunting_uwf.jsonl')
    parser.add_argument('--limit',  type=int, default=0)
    args = parser.parse_args()

    convert_uwf(args.input, args.output)

    if args.limit > 0:
        with open(args.output, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        with open(args.output, 'w', encoding='utf-8') as f:
            f.writelines(lines[:args.limit])
        print('Truncated to ' + str(args.limit) + ' records')

if __name__ == '__main__':
    main()