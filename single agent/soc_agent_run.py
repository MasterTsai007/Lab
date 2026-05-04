import time
from crewai import Agent, Task, Crew, Process, LLM

print("🔗 正在連線至 Windows 本地端 Ollama 服務...")

# ==========================================
# 1. 核心大腦切換區 (論文比較關鍵)
# ==========================================
# 💡 論文測試切換指南：
# 測試 Llama 3.1 請用: model="ollama/llama3.1"
# 測試 Gemma 模型請用: model="ollama/gemma4:e4b" (或您下載的 gemma4 標籤)

current_model = "ollama/gemma4:e4b" 
print(f"🧠 目前載入模型：{current_model}")

local_llm = LLM(
    model=current_model,
    base_url="http://localhost:11434",
    temperature=0.0  # 強制關閉創造力，確保 JSON 格式穩定
)

# ==========================================
# 2. 建立 Agent (特務角色設定)
# ==========================================
soc_analyst = Agent(
    role='資深 SOC 威脅狩獵分析師',
    goal='精準分析端點日誌，提取惡意特徵並對應至 MITRE ATT&CK 框架',
    backstory='你是一名在海巡署資安營運中心工作的專家。你擅長從充滿雜訊的 Windows 事件日誌中找出駭客的蛛絲馬跡，並嚴格依賴事實進行推論。',
    verbose=True, 
    allow_delegation=False,
    llm=local_llm
)

# ==========================================
# 3. 定義 Task (指派任務)
# ==========================================
# 這裡放入我們用 PowerShell 抓出來的真實日誌 (這是一筆 PowerShell 惡意混淆日誌範例)
test_log = """
{"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -EncodedCommand JABzAD0ATgBl...", "User": "CGA_DOMAIN\\admin"}
"""

# 強迫使用 Alpaca 格式，穩定小模型的中文語意與 JSON 輸出
alpaca_prompt = f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.

### Instruction:
你是一名專業的資安營運中心(SOC) AI 分析師。請分析以下端點日誌(Log)，判斷是否具備惡意攻擊特徵，並精準輸出對應的 MITRE ATT&CK 標籤(TTP ID)與解釋(Explanation)。若判定為正常系統管理行為，請標記為 'None (Benign)'。請嚴格使用 JSON 格式輸出，不要輸出任何其他多餘的文字或解釋。

### Input:
{test_log}

### Response:
"""

analyze_task = Task(
    description=alpaca_prompt,
    expected_output='嚴格的 JSON 格式字串，必須包含 "TTP_ID" 與 "Explanation"。',
    agent=soc_analyst
)

# ==========================================
# 4. 組成 Crew 並執行與計時
# ==========================================
soc_crew = Crew(
    agents=[soc_analyst],
    tasks=[analyze_task],
    process=Process.sequential
)

print("🚀 開始執行自動化分析任務...\n")
start_time = time.time() # 開始計時

result = soc_crew.kickoff()

end_time = time.time()   # 結束計時
execution_time = round(end_time - start_time, 2)

print("\n==========================================")
print("🎯 最終防禦決策結果：")
print("==========================================")
print(result)
print("==========================================")
print(f"⏱️ 推論耗時：{execution_time} 秒")