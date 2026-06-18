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
  * 實驗過程產生模組與暫存區 (Sandbox)。
  * 用於快速概念驗證 (PoC)、測試新的開源套件或演算法草稿。
  * 主程式區塊分成
    * 改版前：benchmark_with_judge.py
    * 改版後：universal_soc_pipeline.py 
* **`update/`** 
  * 最新實驗模組 (Sandbox)。
  * 產生論文最終腳本。
  * 主程式在universal_soc_pipeline.py 


## 🛠️ 開發環境與技術棧 (Tech Stack)

* **主要語言**: Python 3.10
* **核心套件**: Ollama、Phi-3、Llama3.1、Gemma2、MITRE STIX 2.1
* **其他工具**: Miniconda

### 🚀 環境建置 (Environment Setup)

本專案使用 **Miniconda** 來進行環境隔離，以確保套件版本乾淨且不會與其他專案衝突。請依照以下步驟建立專屬的論文研究環境：

* **建立專屬環境**
打開終端機 (Windows 請開啟 `Anaconda Prompt (Miniconda3)`，macOS/Linux 請開啟 `Terminal`)，輸入以下指令建立名為 `soc_thesis` 的環境，並指定使用 Python 3.10：
```bash
conda create --name soc_thesis python=3.10
```

* **啟動環境**
```bash
conda activate soc_thesis
```

* **安裝所需套件**
```bash
pip install requests pandas openpyxl chromadb sentence-transformers python-dateutil
```
