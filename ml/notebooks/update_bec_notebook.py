import json

cells = [
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "# ANVESH — Model 2: Business Email Compromise (BEC) Baseline Colab Training & Cross-Source Evaluation\n",
            "\n",
            "> **Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  \n",
            "> **Target Model:** Model 2 (BEC vs NON_BEC Text Classifier)  \n",
            "> **Input:** Subject + Body text only (No headers, No SPF/DKIM/DMARC, No IP/DNS/TI)  \n",
            "> **Governance Status:** MULTI-SOURCE GOVERNED BASELINE EVALUATED  \n",
            "> **Governance Invariant:** Model 1 and Phase 4/5 Artifacts REMAIN COMPLETELY FROZEN."
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 1. Environment Setup & Dependencies\n",
            "Install and import core libraries (scikit-learn, pandas, numpy, joblib, hashlib)."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "!pip install --quiet scikit-learn joblib pandas numpy\n",
            "import sys, os, json, hashlib, re, random\n",
            "import numpy as np\n",
            "import pandas as pd\n",
            "from sklearn.feature_extraction.text import TfidfVectorizer\n",
            "from sklearn.linear_model import LogisticRegression\n",
            "from sklearn.pipeline import Pipeline\n",
            "from sklearn.metrics import (\n",
            "    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report\n",
            ")\n",
            "import joblib\n",
            "\n",
            "print(f\"Python Version: {sys.version}\")\n",
            "print(\"Environment initialized successfully.\")"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 2. Dataset Loading & Multi-Partition Ingestion\n",
            "Load the 4 governed partitions: TRAIN, VALIDATION, INDEPENDENT_TEST (Dube BEC-2), and ADVERSARIAL_TEST."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "def load_partition(filename):\n",
            "    records = []\n",
            "    if not os.path.exists(filename):\n",
            "        print(f\"Uploading {filename}...\")\n",
            "        from google.colab import files\n",
            "        uploaded = files.upload()\n",
            "        filename = list(uploaded.keys())[0]\n",
            "    with open(filename, \"r\", encoding=\"utf-8\") as f:\n",
            "        for line in f:\n",
            "            if line.strip():\n",
            "                records.append(json.loads(line))\n",
            "    df = pd.DataFrame(records)\n",
            "    df[\"text\"] = df[\"subject\"].fillna(\"\") + \" \" + df[\"body\"].fillna(\"\")\n",
            "    df[\"target\"] = df[\"label\"].map(lambda x: 1 if x == \"BEC\" else 0)\n",
            "    return df\n",
            "\n",
            "train_df = load_partition(\"train.jsonl\")\n",
            "val_df = load_partition(\"val.jsonl\")\n",
            "indep_df = load_partition(\"independent_test_dube_bec2.jsonl\")\n",
            "adv_df = load_partition(\"adversarial_test.jsonl\")\n",
            "\n",
            "print(f\"TRAIN: {len(train_df)}, VAL: {len(val_df)}, INDEP: {len(indep_df)}, ADV: {len(adv_df)}\")"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 3. Provenance Verification & Data Statistics\n",
            "Inspect sources, sample counts, and label distributions across all 4 partitions."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "for name, df in [(\"TRAIN\", train_df), (\"VAL\", val_df), (\"INDEP\", indep_df), (\"ADV\", adv_df)]:\n",
            "    print(f\"=== {name} Statistics ===\")\n",
            "    print(f\"Total: {len(df)} | BEC: {sum(df['target']==1)} | NON_BEC: {sum(df['target']==0)}\")\n",
            "    if \"source\" in df.columns:\n",
            "        print(df[\"source\"].value_counts())\n",
            "    print()"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 4. Deduplication & Cross-Source Overlap Detection\n",
            "Verify that zero SHA-256 hashes or normalized strings leak between TRAIN and INDEPENDENT_TEST."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "def get_hashes(df):\n",
            "    return set(hashlib.sha256(t.strip().lower().encode('utf-8')).hexdigest() for t in df['text'])\n",
            "\n",
            "train_hashes = get_hashes(train_df)\n",
            "val_hashes = get_hashes(val_df)\n",
            "indep_hashes = get_hashes(indep_df)\n",
            "adv_hashes = get_hashes(adv_df)\n",
            "\n",
            "print(f\"Train vs Val Overlap:   {len(train_hashes.intersection(val_hashes))} (Expected: 0)\")\n",
            "print(f\"Train vs Indep Overlap: {len(train_hashes.intersection(indep_hashes))} (Expected: 0)\")\n",
            "print(f\"Train vs Adv Overlap:   {len(train_hashes.intersection(adv_hashes))} (Expected: 0)\")"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 5. Model 2 Architecture & Training\n",
            "Fit `TfidfVectorizer(ngram_range=(1,2), sublinear_tf=True, max_features=5000)` + `LogisticRegression(C=1.0, class_weight='balanced', random_state=42)` on TRAIN partition ONLY."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "pipeline = Pipeline([\n",
            "    (\"tfidf\", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words=\"english\", max_features=5000)),\n",
            "    (\"clf\", LogisticRegression(C=1.0, class_weight=\"balanced\", random_state=42, max_iter=1000))\n",
            "])\n",
            "\n",
            "pipeline.fit(train_df[\"text\"], train_df[\"target\"])\n",
            "print(\"Model 2 fitted successfully on TRAIN partition.\")"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 6. In-Source Validation Evaluation\n",
            "Calculate in-source metrics (Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix)."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "val_preds = pipeline.predict(val_df[\"text\"])\n",
            "val_probs = pipeline.predict_proba(val_df[\"text\"])[:, 1]\n",
            "\n",
            "print(\"=== VALIDATION EVALUATION ===\")\n",
            "print(f\"Accuracy:  {accuracy_score(val_df['target'], val_preds):.4f}\")\n",
            "print(f\"Precision: {precision_score(val_df['target'], val_preds):.4f}\")\n",
            "print(f\"Recall:    {recall_score(val_df['target'], val_preds):.4f}\")\n",
            "print(f\"F1 Score:  {f1_score(val_df['target'], val_preds):.4f}\")\n",
            "print(f\"ROC-AUC:   {roc_auc_score(val_df['target'], val_probs):.4f}\")\n",
            "print(\"\\nConfusion Matrix:\")\n",
            "print(confusion_matrix(val_df['target'], val_preds))"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 7. Out-of-Source Independent Generalization Test (Rohit Dube BEC-2)\n",
            "Evaluate Model 2 on the held-out Dube BEC-2 benchmark paired with held-out Enron business communications."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "indep_preds = pipeline.predict(indep_df[\"text\"])\n",
            "indep_probs = pipeline.predict_proba(indep_df[\"text\"])[:, 1]\n",
            "\n",
            "print(\"=== INDEPENDENT TEST (Dube BEC-2) EVALUATION ===\")\n",
            "print(f\"Accuracy:  {accuracy_score(indep_df['target'], indep_preds):.4f}\")\n",
            "print(f\"Precision: {precision_score(indep_df['target'], indep_preds):.4f}\")\n",
            "print(f\"Recall:    {recall_score(indep_df['target'], indep_preds):.4f}\")\n",
            "print(f\"F1 Score:  {f1_score(indep_df['target'], indep_preds):.4f}\")\n",
            "print(f\"ROC-AUC:   {roc_auc_score(indep_df['target'], indep_probs):.4f}\")\n",
            "print(\"\\nConfusion Matrix:\")\n",
            "print(confusion_matrix(indep_df['target'], indep_preds))"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 8. Adversarial Evasion Robustness Benchmark\n",
            "Evaluate Model 2 against obfuscated BEC emails containing Cyrillic homoglyphs and zero-width spaces."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "adv_preds = pipeline.predict(adv_df[\"text\"])\n",
            "adv_recall = recall_score(adv_df['target'], adv_preds, pos_label=1)\n",
            "\n",
            "print(\"=== ADVERSARIAL EVASION TEST ===\")\n",
            "print(f\"Total Adversarial Samples: {len(adv_df)}\")\n",
            "print(f\"Adversarial BEC Detected:  {sum(adv_preds == 1)}\")\n",
            "print(f\"Adversarial BEC Recall:    {adv_recall * 100:.2f}%\")"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 9. Top Predictive N-Gram Features\n",
            "Extract top tokens driving BEC prediction vs. NON_BEC legitimate business classification."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "vectorizer = pipeline.named_steps[\"tfidf\"]\n",
            "classifier = pipeline.named_steps[\"clf\"]\n",
            "feat_names = np.array(vectorizer.get_feature_names_out())\n",
            "coefs = classifier.coef_[0]\n",
            "\n",
            "top_pos = np.argsort(coefs)[-15:][::-1]\n",
            "top_neg = np.argsort(coefs)[:15]\n",
            "\n",
            "print(\"Top 10 BEC Predictive Indicators:\")\n",
            "for i in top_pos[:10]:\n",
            "    print(f\"  + {feat_names[i]:<25} ({coefs[i]:+.4f})\")\n",
            "\n",
            "print(\"\\nTop 10 NON_BEC Predictive Indicators:\")\n",
            "for i in top_neg[:10]:\n",
            "    print(f\"  - {feat_names[i]:<25} ({coefs[i]:+.4f})\")"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 10. Error Analysis & False Positive Inspection\n",
            "Inspect false alarms on legitimate business emails to understand language boundary limitations."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "indep_df[\"pred\"] = indep_preds\n",
            "indep_df[\"prob\"] = np.round(indep_probs, 4)\n",
            "\n",
            "fps = indep_df[(indep_df[\"target\"] == 0) & (indep_df[\"pred\"] == 1)]\n",
            "fns = indep_df[(indep_df[\"target\"] == 1) & (indep_df[\"pred\"] == 0)]\n",
            "\n",
            "print(f\"False Positives (Legitimate flagged as BEC): {len(fps)}\")\n",
            "print(f\"False Negatives (BEC missed):                  {len(fns)}\")\n",
            "\n",
            "if len(fps) > 0:\n",
            "    print(\"\\nSample False Positives (Financial Vocabulary Overlap):\")\n",
            "    print(fps[[\"id\", \"subject\", \"prob\"]].head(5).to_string())"
        ]
    },
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## 11. Artifact Export & Governance Packaging\n",
            "Serialize `model.joblib`, `metadata.json`, and `top_features.json` under `ml/models/bec_baseline_v1/`."
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "os.makedirs(\"bec_baseline_v1\", exist_ok=True)\n",
            "joblib.dump(pipeline, \"bec_baseline_v1/model.joblib\")\n",
            "\n",
            "with open(\"bec_baseline_v1/model.joblib\", \"rb\") as f:\n",
            "    model_hash = hashlib.sha256(f.read()).hexdigest()\n",
            "\n",
            "print(f\"Model 2 Joblib Hash: {model_hash}\")\n",
            "!zip -r bec_baseline_v1_colab.zip bec_baseline_v1/"
        ]
    }
]

notebook = {
    "cells": cells,
    "metadata": {
        "language_info": {
            "name": "python"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 2
}

with open("ml/notebooks/02_bec_baseline_colab.ipynb", "w", encoding="utf-8") as f:
    json.dump(notebook, f, indent=2)

print("Notebook 02_bec_baseline_colab.ipynb successfully updated!")
