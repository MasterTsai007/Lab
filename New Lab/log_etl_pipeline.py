import json
import os
import glob
from datetime import datetime, timedelta

# ========================================================
# 🔧 工具函數：智慧擷取與解析
# ========================================================
def get_field(data, possible_keys, default="Unknown"):
    """
    智慧探測欄位：支援巢狀字典解析 (例如 'winlog.event_data.CommandLine')
    會依序嘗試 possible_keys 裡面的欄位名稱，找到第一個有值的就回傳。
    """
    for key in possible_keys:
        parts = key.split('.')
        val = data
        try:
            for part in parts:
                val = val[part]
            if val is not None and val != "": 
                return str(val)
        except (KeyError, TypeError):
            continue
    return default

def parse_time(time_str):
    """
    動態時間解析器：包容各種 SIEM 匯出時常見的奇葩時間格式
    """
    if not time_str or time_str == "Unknown":
        return None
        
    # 移除微軟常見的過多小數位數 (例如 .1234567Z -> .123Z)
    if '.' in time_str and time_str.endswith('Z'):
        base, fraction = time_str.split('.')
        time_str = f"{base}.{fraction[:3]}Z"

    formats = [
        "%Y-%m-%dT%H:%M:%SZ",       # 2026-05-04T12:00:55Z
        "%Y-%m-%dT%H:%M:%S.%fZ",    # 2026-05-04T12:00:55.123Z
        "%Y-%m-%dT%H:%M:%S",        # 2026-05-04T12:00:55
        "%Y-%m-%d %H:%M:%S",        # 2026-05-04 12:00:55
        "%Y/%m/%d %H:%M:%S"         # 2026/05/04 12:00:55
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(time_str, fmt)
        except ValueError:
            continue
            
    # 如果傳統格式都失敗，嘗試使用 Python 內建的 ISO 解析 (支援 Python 3.7+)
    try:
        return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
    except Exception:
        return None

# ========================================================
# 1. 動態檔案讀取模組 (File Ingestion)
# ========================================================
def load_raw_logs_from_directory(directory_path):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        print(f"⚠️ 找不到目錄 {directory_path}，已自動建立。請放入您的日誌檔。")
        return []

    all_raw_logs = []
    print(f"📂 正在掃描目錄: {directory_path} ...")
    
    # --- 處理標準 .json 格式 (整包陣列或字典) ---
    for filepath in glob.glob(os.path.join(directory_path, '*.json')):
        print(f"  📄 讀取標準 JSON: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # 智慧解包：如果是陣列直接用，如果是字典則尋找裡面的陣列
                log_list = data if isinstance(data, list) else next((v for v in data.values() if isinstance(v, list)), [])
                
                for log_entry in log_list:
                    if isinstance(log_entry, dict):
                        log_entry['_source_type'] = 'json_parsed'
                        all_raw_logs.append(log_entry)
        except Exception as e:
            print(f"    ❌ JSON 讀取失敗: {e}")

    # --- 處理 .jsonl 格式 (單行獨立 JSON) ---
    for filepath in glob.glob(os.path.join(directory_path, '*.jsonl')):
        print(f"  📄 讀取 JSONL: {filepath}")
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        log_entry = json.loads(line)
                        log_entry['_source_type'] = 'json_parsed'
                        all_raw_logs.append(log_entry)
                    except json.JSONDecodeError:
                        continue

    # --- 處理純文字 .log 格式 (Syslog) ---
    for filepath in glob.glob(os.path.join(directory_path, '*.log')):
        print(f"  📄 讀取 Text Log: {filepath}")
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    all_raw_logs.append({'_source_type': 'text_linux', 'raw_text': line.strip()})

    print(f"✔️ 共成功載入 {len(all_raw_logs)} 筆原始日誌。\n")
    return all_raw_logs

# ========================================================
# 2. 正規化模組 (Normalization)
# ========================================================
def normalize_log(raw_log):
    """將各異質日誌清洗為標準的 {time, host, action} 格式"""
    normalized = {}
    
    # --- 處理 JSON 格式日誌 ---
    if raw_log.get('_source_type') == 'json_parsed':
        # 🎯 這裡定義了常見的欄位名稱備案 (優先順序：由左至右)
        time_keys = ['TimeCreated', '@timestamp', 'timestamp', 'event_time', 'date', 'Event.System.TimeCreated.@SystemTime']
        host_keys = ['Computer', 'hostname', 'host.name', 'agent.hostname', 'device_name', 'Event.System.Computer']
        action_keys = ['CommandLine', 'NewProcessName', 'process.command_line', 'message', 'event.original', 'Event.EventData.CommandLine']
        
        # 擷取原始字串
        raw_time = get_field(raw_log, time_keys)
        normalized['host'] = get_field(raw_log, host_keys, "UnknownHost")
        normalized['action'] = get_field(raw_log, action_keys, "UnknownAction")
        
        # 解析時間物件
        parsed_time = parse_time(raw_time)
        if not parsed_time:
            return None # 時間解析失敗就丟棄該筆資料
        normalized['time'] = parsed_time

    # --- 處理 Linux Syslog 純文字 ---
    elif raw_log.get('_source_type') == 'text_linux':
        try:
            parts = raw_log['raw_text'].split(' ', 2)
            if len(parts) >= 3:
                parsed_time = parse_time(parts[0])
                if not parsed_time: return None
                normalized['time'] = parsed_time
                normalized['host'] = parts[1]
                normalized['action'] = parts[2].replace("COMMAND=", "")
            else:
                return None
        except Exception:
            return None

    else:
        return None

    # 過濾掉沒有實際動作的無效 Log
    if normalized.get('action') == "UnknownAction":
        return None

    return normalized

# ========================================================
# 3. 分群與時間窗切割 (Grouping & Time-Windowing)
# ========================================================
def build_time_windows(normalized_logs, window_minutes=5):
    """將正規化後的日誌，依照 Host 與時間窗打包成序列"""
    host_groups = {}
    for log in normalized_logs:
        if not log: continue
        host = log["host"]
        if host not in host_groups:
            host_groups[host] = []
        host_groups[host].append(log)
        
    final_sequences = []
    
    for host, logs in host_groups.items():
        logs.sort(key=lambda x: x["time"])
        current_window, window_start_time = [], None
        
        for log in logs:
            if not current_window:
                window_start_time = log["time"]
                current_window.append(log)
            else:
                if log["time"] - window_start_time <= timedelta(minutes=window_minutes):
                    current_window.append(log)
                else:
                    final_sequences.append({"host": host, "sequence": current_window})
                    current_window = [log]
                    window_start_time = log["time"]
        
        if current_window:
            final_sequences.append({"host": host, "sequence": current_window})
            
    return final_sequences

# ========================================================
# 🚀 主程式執行區塊
# ========================================================
if __name__ == "__main__":
    RAW_LOGS_DIR = "./raw_logs"
    OUTPUT_FILE = "etl_processed_sequences.jsonl"
    
    print("⏳ [Next-Gen SOC] 啟動日誌前置處理 (ETL) 管線...\n")
    
    # 1. 讀取
    raw_logs_stream = load_raw_logs_from_directory(RAW_LOGS_DIR)
    if not raw_logs_stream:
        print("🛑 管線停止。")
        exit()

    # 🔍 抓漏專用：印出第一筆原始日誌幫助除錯
    print("\n🔍 偷看第一筆原始 Log 結構 (作為對照參考)：")
    print(json.dumps(raw_logs_stream[0], indent=4, ensure_ascii=False)[:500] + " ...[省略]")
    print("="*40 + "\n")

    # 2. 正規化
    norm_logs = [normalize_log(log) for log in raw_logs_stream]
    
    # 統計流失率
    valid_logs = [log for log in norm_logs if log is not None]
    lost_logs = len(raw_logs_stream) - len(valid_logs)
    print(f"🧹 正規化完成。有效日誌: {len(valid_logs)} 筆 | 丟棄格式不符之雜訊: {lost_logs} 筆\n")

    if not valid_logs:
        print("🛑 所有日誌在正規化過程中皆被判定為無效。請檢查原始 JSON 欄位是否包含在 `time_keys`, `host_keys`, `action_keys` 中！")
        exit()

    # 3. 切割時間窗
    time_windows = build_time_windows(valid_logs, window_minutes=5)

    # 4. 輸出 JSONL
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for idx, tw in enumerate(time_windows):
            host = tw['host']
            seq_text = "\n".join([f"- {log['time'].strftime('%H:%M:%S')}: {log['action']}" for log in tw['sequence']])
            f.write(json.dumps({"source_host": host, "text": seq_text}, ensure_ascii=False) + '\n')
            
    print(f"🎉 處理大功告成！已將 {len(valid_logs)} 筆行為，成功聚合為 {len(time_windows)} 組時間窗序列！")
    print(f"👉 您的測試考卷已產生於：{OUTPUT_FILE}")