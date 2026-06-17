# 自動化 SOC 威脅狩獵系統 (Automated SOC Threat Hunting System)

本專案提出一種基於**多專家語言模型 (Multi-Agent MoE)** 與**多粒度向量檢索 (Multi-Granularity RAG)** 的自動化資安營運中心 (SOC) 威脅狩獵系統。本系統打破傳統單一資安設備的特徵比對限制，透過法庭辯論機制實現高精準度的自動化去噪與威脅標記。

## ✨ 核心創新功能

* **多粒度 RAG 檢索 (`build_kb.py`)：** 將 MITRE ATT&CK 知識庫平行拆解為 L1(描述)、L2(程序)、L3(工具)、L4(指令) 四個入口，解決傳統 RAG 長文語意稀釋的問題。
* **物理隔離的 MoE 法庭辯論 (`universal_soc_pipeline.py`)：** 由不同陣營的大模型分別擔任控方(挖掘威脅)與辯方(解釋常態維運)，並交由第三方獨立法官進行最終裁決。
* **原子級意圖初審去噪 (`aggregate_chains.py`)：** 利用正規表示式提煉核心進程，並與威脅知識庫進行幾何距離審查，將絕對安全的常態雜訊於前端直接剔除。
* **學術反思與三態嚴格矩陣：** 內建「情境脈絡對齊」與「標籤污染反思審計」救贖機制，並採用嚴格的 3-State Cohen's $\kappa$ 統計，防止傳統評估機制中的盛行率悖論作弊。

## ⚙️ 環境安裝

建議使用 **Python 3.10.x** 以確保 ChromaDB 與 PyTorch 的底層 C++ 依賴完美相容。

1. **Clone 專案：**
   ```bash
   git clone [https://github.com/MasterTsai007/Lab.git](https://github.com/MasterTsai007/Lab.git)
   cd Lab```
   
2. **安裝依賴套件：**
(Windows 用戶若安裝 ChromaDB 報錯，請先安裝 Visual Studio C++ Build Tools)
   ```bash
   pip install -r requirements.txt```
3. **環境變數與 API 設定：**
本專案依賴多個雲端 LLM API。請將 config.example.py 複製並重新命名為 config.py，填入您的真實 API Keys：
   ```bash
   cp config.example.py config.py```
   
## 🚀 執行流程 (Quick Start)

請嚴格依照以下順序執行，即可重現完整實驗流水線：

**Step 1: 建立多粒度向量知識庫**
將 MITRE 原始資料轉換為 ChromaDB 向量檢索庫。
   ```bash
   python build_kb.py```
   
**Step 2: 啟動原子初審去噪與日誌聚合**
將單筆日誌純化，並依據時間視窗聚合為攻擊鏈。
   ```bash
   python aggregate_chains.py --input apt_hunting.jsonl --output apt_chains.jsonl --window 300```
   
**Step 3: 執行消融實驗大表與多模型法庭辯論**
啟動主系統，依據提示選擇模式 (Mode 1 ~ Mode 4) 進行測試。
   ```bash
   python universal_soc_pipeline.py```

**執行完畢後，系統會自動產出包含完整法庭辯論紀錄與三態統計矩陣的 ablation_mode_X_report.xlsx。**

## 📊 實驗模式說明

    Mode 1: 純單發 LLM Baseline (對抗型強迫推理組)

    Mode 2: 傳統 RAG Baseline

    Mode 3: 本文變體架構 (多粒度 RAG + MoE)

    Mode 4: 本文完全體提案 (多粒度 RAG + MoE + 審計反思)
