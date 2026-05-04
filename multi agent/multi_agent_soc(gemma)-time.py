import os
import time
import psutil
import pyautogui
from datetime import datetime
from crewai import Agent, Task, Crew, Process, LLM

# 破解 CrewAI 的 OpenAI KEY 檢查
os.environ["OPENAI_API_KEY"] = "NA" 

# ==========================================
# 0. 實驗數據記錄器設定
# ==========================================
output_dir = "Thesis_MultiAgent_Logs"
os.makedirs(output_dir, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
process = psutil.Process(os.getpid())

task_times = []

def record_task_time(task_output):
    """回呼函式：精準紀錄每個 Task 完成的瞬間"""
    current_time = time.time()
    task_times.append(current_time)
    print(f"\n⏱️ 階段任務交接，標記時間點...")

print(f"[{timestamp}] 🔬 多代理人實驗紀錄系統已啟動...")

# ==========================================
# 1. 配置模型大腦
# ==========================================
expert_llm = LLM(model="ollama/gemma4:e4b", base_url="http://localhost:11434", temperature=0.0)
writer_llm = LLM(model="ollama/gemma4:e4b", base_url="http://localhost:11434", temperature=0.6)

# ==========================================
# 2. 建立 Agent 團隊 (L1 & L2 用英文，L3 用中文)
# ==========================================
l1_hunter = Agent(
    role='L1 Threat Hunting Analyst',
    goal='Analyze logs and map to MITRE ATT&CK in ENGLISH.',
    backstory='SOC Tier 1 specialist. You are cold, logical, and rely only on evidence.',
    verbose=True, allow_delegation=False, llm=expert_llm
)

l2_cti = Agent(
    role='L2 Threat Intelligence Expert',
    goal='Provide Severity and Mitigation in ENGLISH.',
    backstory='Senior security architect. Your responses must be concise.',
    verbose=True, allow_delegation=False, llm=expert_llm
)

l3_reporter = Agent(
    role='資安事件通報撰寫員',
    goal='將英文 JSON 轉換為專業的海巡繁體中文通報。',
    backstory='精通中英翻譯的海巡署專業幕僚。',
    verbose=True, allow_delegation=False, llm=writer_llm
)

# ==========================================
# 3. 定義 Tasks (綁定計時回呼)
# ==========================================
raw_log = '{"EventID": 1, "CommandLine": "powershell.exe -nop -w hidden -EncodedCommand JABzAD0ATgBl...", "User": "admin"}'

task_extract = Task(
    description=f"Analyze log: {raw_log}",
    expected_output='Strict JSON string with TTP_ID and Explanation (English).',
    agent=l1_hunter,
    callback=record_task_time
)

task_enrich = Task(
    description="Enrich the previous JSON with Severity and Mitigation.",
    expected_output='Merged JSON string with 4 keys (English).',
    agent=l2_cti,
    callback=record_task_time
)

task_report = Task(
    description="撰寫繁體中文資安通報單，包含發生時間、事件類型、嚴重等級、事件說明與處置建議。",
    expected_output='Markdown 格式的中文通報單。',
    agent=l3_reporter,
    callback=record_task_time
)

soc_crew = Crew(
    agents=[l1_hunter, l2_cti, l3_reporter],
    tasks=[task_extract, task_enrich, task_report],
    process=Process.sequential
)

# ==========================================
# 4. 🏁 開始執行並「擷取時間與記憶體」
# ==========================================
print("\n🚨 啟動 SOC 三層次自動化分析流水線...\n")

# 紀錄起點 (時間與記憶體)
start_wall_time = time.time()
start_mem = process.memory_info().rss / (1024 * 1024) 
task_times.append(start_wall_time) 

# 讓 AI 執行任務
final_result = soc_crew.kickoff()

# 紀錄終點 (記憶體)
end_mem = process.memory_info().rss / (1024 * 1024)
mem_used = round(end_mem - start_mem, 2)

# 計算各階段時間
t1 = round(task_times[1] - task_times[0], 2)
t2 = round(task_times[2] - task_times[1], 2)
t3 = round(task_times[3] - task_times[2], 2)
total_t = round(task_times[3] - task_times[0], 2)

print("\n" + "="*60)
print("🎯 最終防禦決策結果：")
print(final_result)
print("="*60)
print("📊 實驗數據總結報告")
print("-" * 60)
print(f"⏱️ 階段 1 (L1 推論耗時): {t1} s")
print(f"⏱️ 階段 2 (L2 推論耗時): {t2} s")
print(f"⏱️ 階段 3 (L3 生成與切換): {t3} s")
print(f"📡 總體端到端反應時間: {total_t} s")
print(f"💾 Python 程序記憶體增量: {mem_used} MB")
print("="*60)

# ==========================================
# 5. 📸 自動截圖與存檔
# ==========================================
print("\n📸 正在自動進行螢幕截圖與數據存檔...")


# 【關鍵修正】：強制程式暫停 3 秒，讓終端機有時間把文字印完並捲到底
time.sleep(5)



screenshot_path = os.path.join(output_dir, f"MultiAgent(gemma)_{timestamp}.png")
pyautogui.screenshot(screenshot_path)

log_path = os.path.join(output_dir, "Metrics_Summary.txt")
with open(log_path, "a", encoding="utf-8") as f:
    f.write(f"時間: {timestamp} | 總耗時: {total_t}s | 記憶體增量: {mem_used}MB\n")
    f.write(f"細項耗時 -> L1: {t1}s | L2: {t2}s | L3: {t3}s\n")
    f.write("-" * 50 + "\n")

print(f"✅ 實驗完成！截圖已存至資料夾: {output_dir}")