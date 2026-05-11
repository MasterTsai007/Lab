import json
import requests

# =====================================================================
# 1. 系統組態設定
# =====================================================================
OLLAMA_API = "http://localhost:11434/api/generate"
L2_MODEL = "llama3.1"  # 使用較大參數的模型來撰寫專業的防禦腳本

def generate_playbook(log_id, original_log, mitre_id, l1_intent):
    print("\n" + "🚨"*20)
    print(f"啟動自動化應變程序 (SOAR) - 案件編號: {log_id}")
    print(f"威脅指標: {mitre_id} ({l1_intent.split(':')[0]})")
    print("🚨"*20 + "\n")
    print("⏳ L2 應變代理人正在自動撰寫防禦與調查工單 (Playbook)...\n")

    prompt = f"""You are an elite Incident Response (IR) Commander in a SOC. 
A highly confident threat has been detected on an endpoint.

[Incident Context]
- Target MITRE Tactic: {mitre_id}
- Tactic Name/Intent: {l1_intent}
- Raw Endpoint Log: {original_log}

Your task is to generate a concise, actionable Incident Response Playbook for the Level 1 SOC analysts to execute immediately.

Structure the playbook strictly using the following Markdown format:

### 🔴 Threat Summary
(1 sentence explaining how the raw log maps to the MITRE tactic)

### 🛡️ Immediate Containment Actions
(2-3 bullet points on how to isolate the endpoint or block the process)

### 🔍 Threat Hunting & Investigation Queries
(Provide 1-2 practical commands, such as PowerShell or Splunk SPL, to investigate the scope of the breach)

### 🩹 Remediation Strategy
(1 sentence on long-term fixing, like patching or credential resetting)

Output ONLY the Markdown playbook. Do not add conversational filler. Translate the headings and content into Traditional Chinese (zh-TW) for the local SOC team."""

    payload = {
        "model": L2_MODEL,
        "prompt": prompt,
        "stream": True, # 開啟串流模式，讓文字像打字機一樣酷炫地印出來
        "options": {"temperature": 0.2} # 保持低溫度，確保指令的準確性
    }

    try:
        response = requests.post(OLLAMA_API, json=payload, stream=True)
        response.raise_for_status()
        
        for line in response.iter_lines():
            if line:
                chunk = json.loads(line)
                print(chunk.get("response", ""), end="", flush=True)
        print("\n\n" + "="*60)
        print("✔️ 工單生成完畢，已自動派發至 IT 維運團隊。")
        
    except Exception as e:
        print(f"❌ 呼叫 L2 代理人失敗: {e}")

if __name__ == "__main__":
    # 模擬我們剛才跑出滿分的 Task_001
    mock_log_id = "Task_001"
    mock_log = r'"CommandLine": "procdump.exe -accepteula -ma lsass.exe lsass.dmp"'
    mock_mitre_id = "T1003.001"
    mock_intent = "Credential Dumping: The command line includes 'procdump.exe -ma', which is used to dump memory and potentially capture credentials."
    
    generate_playbook(mock_log_id, mock_log, mock_mitre_id, mock_intent)