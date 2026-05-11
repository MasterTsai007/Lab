import requests, json, re
from zipfile import ZipFile
from io import BytesIO

# 各資料集路徑與對應 TTP ID
DATASETS = [
    ("credential_access/host/psh_lsass_memory_dump_comsvcs",                    "T1003.001"),
    ("credential_access/host/cmd_lsass_memory_dumpert_syscalls",                 "T1003.001"),
    ("credential_access/host/cmd_sam_copy_esentutl",                            "T1003.002"),
    ("credential_access/host/cmd_psexec_lsa_secrets_dump",                      "T1003.004"),
    ("credential_access/host/empire_mimikatz_extract_keys",                     "T1558.003"),
    ("defense_evasion/host/psh_mavinject_dll_notepad",                          "T1218.013"),
    ("defense_evasion/host/cmd_bitsadmin_download_psh_script",                  "T1197"),
    ("lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl",                   "T1021.002"),
]

# 每個 TTP 對應的關鍵字清單：LOG 裡必須至少有一個才保留
# 這解決了「whoami + wmiprvse 被標記為 T1558.003」的 GT 標記問題
TTP_KEYWORDS = {
    "T1003.001": ["lsass", "comsvcs", "minidump", "procdump", "dumpert", "nanodump"],
    "T1003.002": ["sam",   "esentutl", "hklm\\sam", "hklm/sam"],
    "T1003.004": ["secret", "hklm\\security", "hklm/security", "lsa"],
    "T1558.003": ["kerberos", "rubeus", "getuserspns", "kerberoast", "tgt", "tgs", "spn",
                  "asktgt", "asktgs", "kirbi", "mimikatz", "sekurlsa"],
    "T1197":     ["bitsadmin", "bits", "bitstransfer"],
    "T1218.013": ["mavinject"],
    "T1021.002": ["psexec", "\\\\", "svcctl"],
    "T1055":     ["inject", "mavinject", "virtualalloc", "writeprocessmemory"],
}

BASE    = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"
OUTPUT  = "otrf_hunting.jsonl"

records = []
idx     = 0
skipped = 0

for path, ttp_id in DATASETS:
    url = BASE + path + ".zip"
    print("Downloading: " + path.split("/")[-1] + " (" + ttp_id + ")")
    try:
        r = requests.get(url, timeout=60)
        zf = ZipFile(BytesIO(r.content))
        with zf.open(zf.namelist()[0]) as f:
            for line in f:
                try:
                    obj = json.loads(line.decode("utf-8", errors="replace"))
                except:
                    continue

                cmd  = obj.get("CommandLine",      obj.get("command_line",   ""))
                proc = obj.get("NewProcessName",   obj.get("process_name",   ""))
                par  = obj.get("ParentProcessName","")
                eid  = str(obj.get("EventID",      obj.get("event_id",       "")))
                host = obj.get("Hostname",         obj.get("host_name",      "WORKSTATION"))
                user = obj.get("SubjectUserName",  obj.get("user_name",      "wardog"))
                ts   = obj.get("@timestamp",       obj.get("TimeCreated",    ""))

                # 過濾沒有 CommandLine 的附帶事件
                if not cmd:
                    skipped += 1
                    continue

                # 過濾沒有該 TTP 關鍵字的事件（解決 GT 標記問題）
                keywords = TTP_KEYWORDS.get(ttp_id, [])
                combined = (cmd + " " + proc).lower()
                if keywords and not any(kw.lower() in combined for kw in keywords):
                    skipped += 1
                    continue

                parts = []
                if eid:  parts.append("EventID=" + eid)
                if host: parts.append("Host=" + host)
                if user: parts.append("User=" + user)
                if proc: parts.append("Process=" + proc)
                if par:  parts.append("Parent=" + par)
                if cmd:  parts.append("CommandLine=" + str(cmd)[:300])

                records.append({
                    "id":         "OTRF_" + str(idx).zfill(6),
                    "text":       " | ".join(parts),
                    "valid_ttps": [ttp_id],
                    "timestamp":  str(ts),
                    "host":       host,
                    "user":       user
                })
                idx += 1

        print("  -> OK (total: " + str(idx) + ", skipped: " + str(skipped) + ")")

    except Exception as e:
        print("  WARNING: " + str(e))

with open(OUTPUT, "w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print("\nDone! Total: " + str(len(records)) + " records -> " + OUTPUT)
print("Skipped (no keywords or no CommandLine): " + str(skipped))