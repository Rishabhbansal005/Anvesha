# ANVESH — ML Datasets & Corpus Governance

## Dataset Architecture Summary (SIH26106)

In accordance with ANVESH Phase 4 Dataset Governance:
- **Zero data fabrication**: Metrics and counts are computed from actual processed data files.
- **Model 1 Binary Scope**: Strictly binary classification (`BENIGN` vs `THREAT_PHISHING`).
- **Advance-Fee Fraud (`THREAT_ADVANCE_FEE`)**: 967 advance-fee fraud emails are preserved separately and excluded from Model 1 binary training.
- **Strict Partition Isolation**: IWSPA-AP (3,000) and ANVESH Challenge Set (50) are 100% isolated and held out.
- **Label Preservation**: Both `original_label` and `anvesh_label` are stored in every record.
- **No Early Calibration Claims**: Probability estimates are documented as model estimates (`phishing_probability`, `benign_probability`).

---

### Exact Dataset Sample Counts

| Corpus Tier | Split / Source | Total Samples | `THREAT_PHISHING` | `BENIGN` | `THREAT_ADVANCE_FEE` | `THREAT_BEC` | Model 1 Role |
|---|---|---|---|---|---|---|---|
| **Tier A: Development Train** | 70% Development | **6,847** | 3,500 | 2,671 | 676 | 0 | Binary Training: **6,171** samples |
| **Tier B: Development Val** | 30% Development | **2,936** | 1,500 | 1,145 | 291 | 0 | Binary Validation: **2,645** samples |
| **Tier C: Independent Test** | IWSPA-AP (Held-out) | **3,000** | 1,500 | 1,500 | 0 | 0 | Held-Out Independent Benchmark |
| **Tier D: Challenge Set** | ANVESH 50-Benchmark | **50** | 0 | 20 | 0 | 30 | Held-Out Adversarial Forensic Benchmark |

- **Model 1 Binary Development Corpus**: **8,816** (6,171 Train [70.00%] / 2,645 Val [30.00%])
- **Advance-Fee Fraud Archive (`THREAT_ADVANCE_FEE`)**: **967** (Preserved downstream fraud corpus)
- **Grand Total Unique Samples Across All Tiers**: **12,833**
- **Cross-Partition Duplicate Overlap**: **0**

See [PRETRAINING_AUDIT.md](file:///c:/Users/Rishabh%20Bansal/OneDrive/Desktop/Razorpay%20Buildathon/SIH2026/ml/datasets/PRETRAINING_AUDIT.md) for full audit details and leakage analysis.
