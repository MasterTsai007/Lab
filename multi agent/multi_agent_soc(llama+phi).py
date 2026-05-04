import os
import time
# 【關鍵破解】：塞入假的 API Key，騙過 CrewAI 的底層檢查機制
os.environ["OPENAI_API_KEY"] = "NA" 

from crewai import Agent, Task, Crew, Process, LLM

print("🔗 啟動海巡 SOC 聯合防禦指揮中心...")

# --- 1. 配置模型大腦 ---
# 專家大腦：負責精準判定與 JSON 輸出 (鎖死溫度 0.0)
expert_llm = LLM(
    model="ollama/llama3.1", # 您微調好的特戰專家
    base_url="http://localhost:11434",
    temperature=0.0 
)

# 文書大腦：負責撰寫流暢的海巡公文 (稍微開啟溫度 0.6 增加語意流暢度)
writer_llm = LLM(
    model="ollama/my-soc-agent",    # 原廠 Llama 3.1 或 Gemma 4
    base_url="http://localhost:11434",
    temperature=0.6 
)



# ============--- 2. 建立 Agent 團隊 ---===============================

# 第一棒：L1 威脅狩獵分析師 (尋找惡意特徵，限定英文)
l1_hunter = Agent(
    role='L1 Threat Hunting Analyst',
    goal='Analyze endpoint logs, extract malicious features, and map to MITRE ATT&CK. You MUST output all explanations strictly in ENGLISH.',
    backstory='You are a Tier 1 SOC analyst. You are cold, logical, and rely only on evidence. You think and write exclusively in English.',
    verbose=True, 
    allow_delegation=False,
    llm=expert_llm 
)

# 第二棒：L2 威脅情資專家 (提出緩解建議，限定英文)
l2_cti = Agent(
    role='L2 Threat Intelligence Expert',
    goal='Evaluate the Severity and propose Mitigation based on the provided TTP. You MUST output your results strictly in ENGLISH.',
    backstory='You are a senior security architect. Your responses must be concise, accurate, and written entirely in English.',
    verbose=True, 
    allow_delegation=False,
    llm=expert_llm 
)

# 第三棒維持不變 (它是負責寫中文報告的)
l3_reporter = Agent(
    role='資安事件通報撰寫員',
    goal='將生硬的英文 JSON 威脅情資，翻譯並轉寫成符合台灣政府機關（海巡署）語氣的【繁體中文】資安事件通報單。',
    backstory='你是文筆極佳的海巡署幕僚，精通中英翻譯，擅長將技術語言轉化為長官能快速理解的公文。',
    verbose=True, 
    allow_delegation=False,
    llm=writer_llm 
)


# ============--- 3. 定義連續任務 (Tasks) ---===============================




# 模擬一筆真實被攔截的 PowerShell 惡意日誌
raw_log = """
{"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -EncodedCommand JABzAD0ATgBl...", "User": "CGA_DOMAIN\\admin"}
"""

# 任務 1：擷取特徵 (全面改用英文 Prompt)
task_extract = Task(
    description=f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.
### Instruction:
Analyze the following endpoint log, determine if it exhibits malicious attack characteristics, and output the corresponding MITRE ATT&CK label (TTP_ID) and Explanation. The Explanation MUST be written in ENGLISH.
### Input:
{raw_log}
### Response:""",
    expected_output='A strict JSON string containing ONLY "TTP_ID" and "Explanation" (in English).',
    agent=l1_hunter
)

# 任務 2：擴充情資 (全面改用英文 Prompt)
task_enrich = Task(
    description="""Review the JSON threat intelligence provided by the previous analyst. 
Based on the TTP, determine the Severity (High/Medium/Low) and provide one specific technical Mitigation recommendation in ENGLISH.
Merge your results with the previous JSON to output a single JSON with four keys.""",
    expected_output='A strict JSON string containing: "TTP_ID", "Explanation", "Severity", and "Mitigation". ALL values MUST be in English.',
    agent=l2_cti
)

# 任務 3：撰寫通報單 (強調翻譯功能)
task_report = Task(
    description="""請閱讀上一位專家傳遞給你的【英文 JSON 威脅情資】。
請將這些英文資訊「翻譯」並「擴寫」，以繁體中文撰寫一份【海巡署資安營運中心 異常事件通報】。
內容須包含：
1. 發生時間 (自行帶入今日) 
2. 事件類型 (對應 TTP，請翻成中文) 
3. 嚴重等級 (請翻成 高/中/低) 
4. 事件說明 (將英文 Explanation 翻譯成流暢的中文) 
5. 處置建議 (將英文 Mitigation 翻譯成專業的中文)。
語氣必須專業、嚴謹，排版要清晰易讀。""",
    expected_output='一份排版精美的繁體中文通報單 (Markdown 格式)。',
    agent=l3_reporter
)



# ============--- 4. 組成 Crew 並執行 ---===============================


soc_crew = Crew(
    agents=[l1_hunter, l2_cti, l3_reporter],
    tasks=[task_extract, task_enrich, task_report],
    process=Process.sequential # 核心：保證任務 1 -> 2 -> 3 循序漸進
)

print("\n🚨 偵測到異常日誌，啟動 SOC 三層次自動化分析流程...\n")
start_time = time.time()

# 開始執行！
final_report = soc_crew.kickoff()

end_time = time.time()

print("\n=======================================================")
print("✅ 最終交付成果：【高階資安通報單】")
print("=======================================================")
print(final_report)
print("=======================================================")
print(f"⏱️ 聯合作戰總耗時：{round(end_time - start_time, 2)} 秒")