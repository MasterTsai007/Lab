import os
# 【關鍵破解】：塞入假的 API Key，騙過 CrewAI 的底層檢查機制
os.environ["OPENAI_API_KEY"] = "NA"

import time
import os
import psutil
import pyautogui
from datetime import datetime
from crewai import Agent, Task, Crew, Process, LLM

# ==========================================
# 0. 自動化記錄器設定區
# ==========================================
# 建立一個專屬資料夾來放實驗截圖與數據
output_dir = "Thesis_Experiments"
os.makedirs(output_dir, exist_ok=True)

# 取得現在時間作為檔名標籤
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
process = psutil.Process(os.getpid())

print(f"[{timestamp}] 🔬 實驗紀錄系統已啟動...")

# ==========================================
# 1. 核心大腦切換區 (您可以在這裡切換 Llama 或 Gemma)
# ==========================================


current_model = "ollama/phi3" 
#current_model = "ollama/my-soc-agent"

print(f"🧠 目前載入模型：{current_model}")

local_llm = LLM(
    model=current_model,
    base_url="http://localhost:11434",
    temperature=0.0 
)

# ==========================================
# 2. 建立 Agent 與 Task
# ==========================================
soc_analyst = Agent(
    role='資深 SOC 威脅狩獵分析師',
    goal='精準分析端點日誌，提取惡意特徵並對應至 MITRE ATT&CK 框架',
    backstory='你是一名在海巡署資安營運中心工作的專家。',
    verbose=True, 
    allow_delegation=False,
    llm=local_llm
)

test_log = """
{"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -EncodedCommand JABzAD0ATgBl...", "User": "CGA_DOMAIN\\admin"}
"""

alpaca_prompt = f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.
### Instruction:
判斷是否具備惡意攻擊特徵，並精準輸出對應的 MITRE ATT&CK 標籤(TTP ID)與解釋(Explanation)。請嚴格使用 JSON 格式輸出。
### Input:
{test_log}
### Response:
"""

analyze_task = Task(description=alpaca_prompt, expected_output='嚴格的 JSON 格式字串', agent=soc_analyst)
soc_crew = Crew(agents=[soc_analyst], tasks=[analyze_task], process=Process.sequential)

# ==========================================
# 3. 🏁 開始執行並「自動擷取各項花費」
# ==========================================
print("🚀 開始執行自動化分析任務...\n")

# 記錄起點數值
start_time = time.time()
start_mem = process.memory_info().rss / (1024 * 1024) # 轉換為 MB

# 讓 AI 執行任務
result = soc_crew.kickoff()

# 記錄終點數值
end_time = time.time()
end_mem = process.memory_info().rss / (1024 * 1024) # 轉換為 MB

# 計算各項花費
execution_time = round(end_time - start_time, 2)
mem_used = round(end_mem - start_mem, 2)

print("\n==========================================")
print("🎯 最終防禦決策結果：")
print(result)
print("==========================================")
print(f"⏱️ 推論耗時花費：{execution_time} 秒")
print(f"💾 記憶體增加花費：{mem_used} MB")

# ==========================================
# 4. 📸 自動截圖與存檔 (完全不需人工)
# ==========================================
print("\n📸 正在自動進行螢幕截圖與數據存檔...")

time.sleep(5)


# 自動截取整個螢幕畫面
screenshot_path = os.path.join(output_dir, f"Experiment_{current_model.replace('ollama/', '')}_{timestamp}.png")
pyautogui.screenshot(screenshot_path)

# 將數據自動寫入報表 txt 檔
log_path = os.path.join(output_dir, "Experiment_Results.txt")
with open(log_path, "a", encoding="utf-8") as f:
    f.write(f"時間: {timestamp} | 模型: {current_model} | 耗時: {execution_time}s | 記憶體增量: {mem_used}MB\n")
    f.write(f"結果: {result}\n")
    f.write("-" * 50 + "\n")

print(f"✅ 實驗完成！截圖已存至: {screenshot_path}")