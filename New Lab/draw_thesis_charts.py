import matplotlib.pyplot as plt
import numpy as np
import os

# 設定中文字型與大小
plt.rcParams['font.sans-serif'] = ['Microsoft JhengHei']
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams.update({'font.size': 12})
output_dir = "thesis_charts"
if not os.path.exists(output_dir): os.makedirs(output_dir)

def draw_final_ablation_chart():
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # 四個實驗階段的進化
    stages = [
        'Baseline\n(原廠模型+死板比對)', 
        'V1: Domain Fine-Tuning\n(微調單兵+攻擊鏈擴充)', 
        'V2: Intent-RAG\n(意圖驅動檢索+死板比對)',
        'V3: The Ultimate\n(意圖 RAG + LLM裁判)'
    ]
    
    # 對應的命中率數據 (0% -> 30% -> 20% -> 95%)
    scores = [0, 30, 20, 95]
    
    # 顏色漸層：從淺藍到深藍，最後一根用亮眼的金色或橘色突顯突破
    colors = ['#BDC3C7', '#5DADE2', '#2874A6', '#E67E22']
    
    x = np.arange(len(stages))
    bars = ax.bar(x, scores, width=0.5, color=colors)

    # 加上數據標籤
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height}%',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 5),
                    textcoords="offset points",
                    ha='center', va='bottom', fontweight='bold', fontsize=14)

    ax.set_ylabel('系統綜合命中率 / 實務有效告警率 (%)', fontweight='bold')
    ax.set_title('意圖驅動異質多代理人架構之效能演進 (Ablation Study)', pad=20, fontweight='bold', fontsize=16)
    ax.set_xticks(x)
    ax.set_xticklabels(stages, fontsize=11)
    ax.set_ylim(0, 110) # 拉高天花板
    
    # 加上網格線與趨勢線
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.plot(x, scores, color='#C0392B', marker='o', linestyle='-', linewidth=2, markersize=8, alpha=0.8, label='效能成長趨勢')
    ax.legend(loc='upper left')

    plt.tight_layout()
    file_path = os.path.join(output_dir, 'fig2_final_evolution.png')
    plt.savefig(file_path, dpi=300)
    print(f"✅ 成功產出終極演進圖表：{file_path}")

if __name__ == '__main__':
    draw_final_ablation_chart()