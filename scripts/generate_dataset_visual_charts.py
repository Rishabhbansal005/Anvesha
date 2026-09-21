import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUTPUT_DIR = r"C:\Users\Ongkar\Desktop\Avnesh\Anvesha-main\Anvesha-main\docs\screenshots"
os.makedirs(OUTPUT_DIR, exist_ok=True)
CHART_PATH = os.path.join(OUTPUT_DIR, "dataset_breakdown_visuals.png")

# Set global styles
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
fig, axs = plt.subplots(2, 2, figsize=(14, 10), dpi=300)
fig.patch.set_facecolor('#0f172a')

# Palette
DARK_NAVY = '#0f172a'
CARD_BG = '#1e293b'
ACCENT_BLUE = '#38bdf8'
ACCENT_GREEN = '#4ade80'
ACCENT_PURPLE = '#c084fc'
ACCENT_ORANGE = '#fb923c'
ACCENT_RED = '#f87171'
TEXT_WHITE = '#f8fafc'
TEXT_MUTED = '#94a3b8'

for ax in axs.flat:
    ax.set_facecolor(CARD_BG)
    ax.tick_params(colors=TEXT_MUTED, labelsize=9)
    for spine in ax.spines.values():
        spine.set_color('#334155')

# -------------------------------------------------------------
# CHART 1: Total Sample Volume per Model Engine (Donut / Horizontal Bar)
# -------------------------------------------------------------
ax1 = axs[0, 0]
models = [
    'M4: Network Telemetry\n(NSL-KDD 41 Feats)',
    'M1: Phishing NLP\n(Enron/Nazario/IWSPA)',
    'M2: BEC Urgency\n(Synthetic/Dube-2)',
    'M3A: RFC-822 Transport\n(Multi-Route Headers)',
    'M3B: Lookalike Domains\n(50 Brand Entities)'
]
sample_counts = [34394, 10714, 3579, 2376, 840]
colors_list = [ACCENT_BLUE, ACCENT_GREEN, ACCENT_PURPLE, ACCENT_ORANGE, '#e879f9']

bars = ax1.barh(models, sample_counts, color=colors_list, height=0.55, edgecolor='#475569')
ax1.set_title('1. Clean Dataset Scale by Model (Total: 51,903 Samples)', color=TEXT_WHITE, fontsize=11, fontweight='bold', pad=12)
ax1.set_xlabel('Number of Clean Forensic Samples', color=TEXT_MUTED, fontsize=9)
ax1.invert_yaxis()
for bar, count in zip(bars, sample_counts):
    ax1.text(count + 400, bar.get_y() + bar.get_height()/2, f'{count:,}',
             va='center', color=TEXT_WHITE, fontweight='bold', fontsize=8.5)
ax1.set_xlim(0, 39000)

# -------------------------------------------------------------
# CHART 2: Train / Validation / Test Splits (Count Breakdown)
# -------------------------------------------------------------
ax2 = axs[0, 1]
models_short = ['M4 Net', 'M1 Phish', 'M2 BEC', 'M3A Hdr', 'M3B Dom']
train_counts = [18035, 6171, 2400, 1425, 466]
val_counts   = [4509, 1543, 600, 475, 117]
test_counts  = [11850, 3000, 579, 476, 257]

x = np.arange(len(models_short))
width = 0.55

p1 = ax2.bar(x, train_counts, width, label='Training Set', color='#38bdf8', edgecolor='#0284c7')
p2 = ax2.bar(x, val_counts, width, bottom=train_counts, label='Validation Set (Stratified)', color='#818cf8', edgecolor='#4f46e5')
bottom_p3 = np.array(train_counts) + np.array(val_counts)
p3 = ax2.bar(x, test_counts, width, bottom=bottom_p3, label='Independent Holdout Test', color='#34d399', edgecolor='#059669')

ax2.set_title('2. Split Composition: Train vs Val vs Holdout Test', color=TEXT_WHITE, fontsize=11, fontweight='bold', pad=12)
ax2.set_ylabel('Sample Volume', color=TEXT_MUTED, fontsize=9)
ax2.set_xticks(x)
ax2.set_xticklabels(models_short, color=TEXT_WHITE, fontsize=9)
ax2.legend(loc='upper right', facecolor=CARD_BG, edgecolor='#334155', labelcolor=TEXT_WHITE, fontsize=8)

for idx, (t, v, te) in enumerate(zip(train_counts, val_counts, test_counts)):
    tot = t + v + te
    ax2.text(idx, tot + 600, f'{tot:,}', ha='center', color=TEXT_WHITE, fontsize=8, fontweight='bold')

# -------------------------------------------------------------
# CHART 3: Exact Deduplication & Leakage Prevention Audit
# -------------------------------------------------------------
ax3 = axs[1, 0]
dedup_categories = [
    'M1: Phishing NLP\n(SHA-256 Text Dedup)',
    'M2: BEC Urgency\n(Lure Clustering)',
    'M3B: Lookalike\n(Domain Redundancy)',
    'M4: Network Exposure\n(Pre-filtered Benchmark)'
]
raw_cands = [16050, 3200, 850, 34394]
purged    = [3217, 221, 127, 0]
clean     = [12833, 2979, 723, 34394]
pcts      = [20.04, 6.91, 14.94, 0.0]

y = np.arange(len(dedup_categories))
h = 0.35

rects1 = ax3.barh(y - h/2, raw_cands, h, label='Raw Ingested Candidate', color='#64748b', edgecolor='#475569')
rects2 = ax3.barh(y + h/2, purged, h, label='Duplicates / Redundancy Purged', color='#f87171', edgecolor='#dc2626')

ax3.set_title('3. Deduplication Audit & Data Sanitization', color=TEXT_WHITE, fontsize=11, fontweight='bold', pad=12)
ax3.set_yticks(y)
ax3.set_yticklabels(dedup_categories, color=TEXT_WHITE, fontsize=8.5)
ax3.invert_yaxis()
ax3.set_xlabel('Sample Count', color=TEXT_MUTED, fontsize=9)
ax3.legend(loc='lower right', facecolor=CARD_BG, edgecolor='#334155', labelcolor=TEXT_WHITE, fontsize=8)

for idx, p in enumerate(purged):
    if p > 0:
        ax3.text(p + 300, y[idx] + h/2, f'-{p:,} ({pcts[idx]}%)', va='center', color='#fca5a5', fontweight='bold', fontsize=8)

# -------------------------------------------------------------
# CHART 4: Empirical Validation vs Held-Out Test F1 Scores
# -------------------------------------------------------------
ax4 = axs[1, 1]
models_eval = ['M1: Phishing', 'M2: BEC', 'M3A: Impersonation', 'M3B: Lookalike', 'M4: Net (KDD-21)']
val_f1 = [96.80, 97.10, 94.20, 96.28, 95.86]
test_f1 = [95.45, 95.45, 93.75, 94.59, 95.39]

x_eval = np.arange(len(models_eval))
w_eval = 0.35

rects_v = ax4.bar(x_eval - w_eval/2, val_f1, w_eval, label='Validation F1-Score', color='#38bdf8', edgecolor='#0284c7')
rects_t = ax4.bar(x_eval + w_eval/2, test_f1, w_eval, label='Holdout Benchmark Test F1', color='#4ade80', edgecolor='#16a34a')

ax4.set_title('4. Generalization: Validation vs Adversarial Holdout Test F1', color=TEXT_WHITE, fontsize=11, fontweight='bold', pad=12)
ax4.set_ylabel('F1 Score (%)', color=TEXT_MUTED, fontsize=9)
ax4.set_ylim(88, 100)
ax4.set_xticks(x_eval)
ax4.set_xticklabels(models_eval, color=TEXT_WHITE, fontsize=8, rotation=12)
ax4.legend(loc='lower right', facecolor=CARD_BG, edgecolor='#334155', labelcolor=TEXT_WHITE, fontsize=8)

for r_v, r_t in zip(rects_v, rects_t):
    ax4.text(r_v.get_x() + r_v.get_width()/2, r_v.get_height() + 0.3, f"{r_v.get_height():.1f}%", ha='center', color=TEXT_WHITE, fontsize=7.5, fontweight='bold')
    ax4.text(r_t.get_x() + r_t.get_width()/2, r_t.get_height() + 0.3, f"{r_t.get_height():.1f}%", ha='center', color='#86efac', fontsize=7.5, fontweight='bold')

plt.tight_layout(pad=2.5)
plt.savefig(CHART_PATH, facecolor=fig.get_facecolor(), edgecolor='none', dpi=300)
plt.close()
print(f"[+] Dataset visual chart generated successfully at: {CHART_PATH}")
