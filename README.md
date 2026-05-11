# 🎓 碩士論文研究實驗庫 (Thesis Research Lab)

本專案 (Lab) 為本人論文研究的程式碼與實驗數據存放庫。主要研究方向聚焦於 **AI Agent (人工智慧代理)** 的應用與架構探討，透過實作單一代理與多代理系統，驗證論文提出之假設與演算法效能。

> **研究主題**：基於 LLM 的多代理協作機制研究

## 📂 資料夾結構 (Repository Structure)

本專案主要以 Python 開發，依照實驗階段與架構分為以下目錄：

* **`single agent/`** 
  * 單一 AI 代理系統的基礎實驗與模組。
  * 負責測試代理的基本認知、決策能力以及與外部環境/API 的基礎互動。
  * 主程式區塊在auto_soc_agent_run開頭的py檔案中，後面括號中代表使用的模型。
* **`multi agent/`** 
  * 多 AI 代理 (Multi-Agent System, MAS) 的協作環境。
  * 重點在於實作多個 Agent 之間的通訊協議、任務分配、衝突解決機制與共同決策能力。
  * 主程式區塊在multi_agent_soc開頭的py檔案中，後面括號中代表使用的模型。
* **`New Lab/`** 
  * 最新實驗模組與暫存區 (Sandbox)。
  * 用於快速概念驗證 (PoC)、測試新的開源套件或演算法草稿。
  * 主程式區塊分成
    * 改版前：benchmark_with_judge.py
    * 改版後：universal_soc_pipeline.py 

## 🛠️ 開發環境與技術棧 (Tech Stack)

* **主要語言**: Python 3.10
* **核心套件**: Ollama、Phi-3、Llama3.1、Gemma2、MITRE STIX 2.1
* **其他工具**: Miniconda
