import json

notebook = {
    "cells": [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# ANVESH — Model 2: Business Email Compromise (BEC) Baseline Training\n",
                "\n",
                "> **Platform:** ANVESH — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  \n",
                "> **Target Model:** Model 2 (BEC vs NON_BEC Text Classifier)  \n",
                "> **Input:** Subject + Body text only (No headers, No SPF/DKIM/DMARC, No IP/DNS/TI)  \n",
                "> **Governance Status:** DEVELOPMENT / PIPELINE VALIDATION NOTEBOOK  \n",
                "> **Notice:** In accordance with ANVESH Scientific Integrity standards, this notebook demonstrates the reproducible training pipeline for Model 2. Model 1 and Phase 4 artifacts remain frozen."
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 1. Environment Setup\n",
                "Install required dependencies and verify execution environment."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "!pip install --quiet scikit-learn joblib pandas numpy\n",
                "import sys, os, json, hashlib\n",
                "import numpy as np\n",
                "import pandas as pd\n",
                "from sklearn.feature_extraction.text import TfidfVectorizer\n",
                "from sklearn.linear_model import LogisticRegression\n",
                "from sklearn.pipeline import Pipeline\n",
                "from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score, precision_score, recall_score, f1_score\n",
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
                "## 2. Dataset Ingestion & Governance Checks\n",
                "Load the BEC development dataset. Verify SHA-256 integrity and label taxonomy (`BEC` vs `NON_BEC`)."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# Upload or load bec_development_synthetic.jsonl\n",
                "DATASET_PATH = \"bec_development_synthetic.jsonl\"\n",
                "\n",
                "if not os.path.exists(DATASET_PATH):\n",
                "    print(\"Uploading dataset...\")\n",
                "    from google.colab import files\n",
                "    uploaded = files.upload()\n",
                "    DATASET_PATH = list(uploaded.keys())[0]\n",
                "\n",
                "records = []\n",
                "with open(DATASET_PATH, \"r\", encoding=\"utf-8\") as f:\n",
                "    for line in f:\n",
                "        if line.strip():\n",
                "            records.append(json.loads(line))\n",
                "\n",
                "df = pd.DataFrame(records)\n",
                "print(f\"Loaded {len(df)} records.\")\n",
                "print(df[[\"id\", \"label\", \"subtype\", \"subject\"]].to_string())"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 3. Label Encoding & Feature Engineering\n",
                "Extract text feature (Subject + Body) and encode target binary labels (`BEC` -> 1, `NON_BEC` -> 0)."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "df[\"text\"] = df[\"subject\"].fillna(\"\") + \" \" + df[\"body\"].fillna(\"\")\n",
                "df[\"target\"] = df[\"label\"].map(lambda x: 1 if x == \"BEC\" else 0)\n",
                "\n",
                "print(\"Label Distribution:\")\n",
                "print(df[\"label\"].value_counts())\n",
                "print(\"\\nSubtype Distribution:\")\n",
                "print(df[\"subtype\"].value_counts())"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 4. Model Architecture & Pipeline Construction\n",
                "We use a linear TF-IDF + LogisticRegression baseline:\n",
                "- **TF-IDF:** n-gram range (1, 2), sublinear term frequency, English stop words removal.\n",
                "- **LogisticRegression:** C=1.0, class_weight=\"balanced\", random_state=42, max_iter=1000."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "pipeline = Pipeline([\n",
                "    (\"tfidf\", TfidfVectorizer(\n",
                "        ngram_range=(1, 2),\n",
                "        sublinear_tf=True,\n",
                "        stop_words=\"english\",\n",
                "        max_features=5000\n",
                "    )),\n",
                "    (\"clf\", LogisticRegression(\n",
                "        C=1.0,\n",
                "        class_weight=\"balanced\",\n",
                "        random_state=42,\n",
                "        max_iter=1000\n",
                "    ))\n",
                "])\n",
                "\n",
                "# Fit pipeline on development set\n",
                "X = df[\"text\"]\n",
                "y = df[\"target\"]\n",
                "pipeline.fit(X, y)\n",
                "print(\"Model 2 baseline pipeline fitted successfully.\")"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 5. Development Set Evaluation & Diagnostics\n",
                "Inspect training accuracy, decision scores, and probability outputs."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "preds = pipeline.predict(X)\n",
                "probs = pipeline.predict_proba(X)[:, 1]\n",
                "\n",
                "df[\"predicted_label\"] = [\"BEC\" if p == 1 else \"NON_BEC\" for p in preds]\n",
                "df[\"bec_probability\"] = np.round(probs, 4)\n",
                "\n",
                "print(\"=== Evaluation Summary ===\")\n",
                "print(f\"Accuracy:  {accuracy_score(y, preds):.4f}\")\n",
                "print(f\"Precision: {precision_score(y, preds):.4f}\")\n",
                "print(f\"Recall:    {recall_score(y, preds):.4f}\")\n",
                "print(f\"F1 Score:  {f1_score(y, preds):.4f}\")\n",
                "print(\"\\nConfusion Matrix:\")\n",
                "print(confusion_matrix(y, preds))\n",
                "\n",
                "print(\"\\nDetailed Results per Scenario:\")\n",
                "print(df[[\"id\", \"subtype\", \"label\", \"predicted_label\", \"bec_probability\"]].to_string())"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 6. Feature Weight Analysis & N-Gram Attribution\n",
                "Examine the top positive features (driving BEC prediction) and top negative features (driving NON_BEC prediction)."
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
                "feature_names = np.array(vectorizer.get_feature_names_out())\n",
                "coefs = classifier.coef_[0]\n",
                "\n",
                "top_pos_idx = np.argsort(coefs)[-15:][::-1]\n",
                "top_neg_idx = np.argsort(coefs)[:15]\n",
                "\n",
                "top_features = {\n",
                "    \"top_bec_features\": [\n",
                "        {\"feature\": feature_names[i], \"weight\": float(coefs[i])} for i in top_pos_idx\n",
                "    ],\n",
                "    \"top_non_bec_features\": [\n",
                "        {\"feature\": feature_names[i], \"weight\": float(coefs[i])} for i in top_neg_idx\n",
                "    ]\n",
                "}\n",
                "\n",
                "print(\"Top BEC Features (Indicators):\")\n",
                "for f in top_features[\"top_bec_features\"][:10]:\n",
                "    print(f\"  + {f['feature']:<25} ({f['weight']:+.4f})\")\n",
                "\n",
                "print(\"\\nTop NON_BEC Features (Indicators):\")\n",
                "for f in top_features[\"top_non_bec_features\"][:10]:\n",
                "    print(f\"  - {f['feature']:<25} ({f['weight']:+.4f})\")"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 7. Export Model Artifacts & Metadata\n",
                "Serialize `model.joblib`, `metadata.json`, and `top_features.json` under `ml/models/bec_baseline_v1/` format."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "os.makedirs(\"bec_baseline_v1\", exist_ok=True)\n",
                "\n",
                "# 1. Save model.joblib\n",
                "model_path = \"bec_baseline_v1/model.joblib\"\n",
                "joblib.dump(pipeline, model_path)\n",
                "\n",
                "with open(model_path, \"rb\") as f:\n",
                "    model_hash = hashlib.sha256(f.read()).hexdigest()\n",
                "\n",
                "# 2. Save top_features.json\n",
                "with open(\"bec_baseline_v1/top_features.json\", \"w\", encoding=\"utf-8\") as f:\n",
                "    json.dump(top_features, f, indent=2)\n",
                "\n",
                "# 3. Save metadata.json\n",
                "metadata = {\n",
                "    \"model_name\": \"bec_baseline_v1\",\n",
                "    \"version\": \"1.0.0\",\n",
                "    \"architecture\": \"TfidfVectorizer + LogisticRegression\",\n",
                "    \"target\": \"BEC (1) vs NON_BEC (0)\",\n",
                "    \"governance_status\": \"DEVELOPMENT_BASELINE_ONLY\",\n",
                "    \"calibration_status\": \"UNCALIBRATED_RAW_SIGMOID\",\n",
                "    \"model_sha256\": model_hash,\n",
                "    \"hyperparameters\": {\n",
                "        \"ngram_range\": [1, 2],\n",
                "        \"sublinear_tf\": True,\n",
                "        \"C\": 1.0,\n",
                "        \"class_weight\": \"balanced\",\n",
                "        \"random_state\": 42,\n",
                "        \"max_iter\": 1000\n",
                "    }\n",
                "}\n",
                "\n",
                "with open(\"bec_baseline_v1/metadata.json\", \"w\", encoding=\"utf-8\") as f:\n",
                "    json.dump(metadata, f, indent=2)\n",
                "\n",
                "print(\"Artifacts exported:\")\n",
                "print(f\"- {model_path} (SHA-256: {model_hash})\")\n",
                "print(\"- bec_baseline_v1/metadata.json\")\n",
                "print(\"- bec_baseline_v1/top_features.json\")"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 8. Download Artifacts\n",
                "Compress and download generated artifacts for local verification."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "!zip -r bec_baseline_v1_artifacts.zip bec_baseline_v1/\n",
                "try:\n",
                "    from google.colab import files\n",
                "    files.download(\"bec_baseline_v1_artifacts.zip\")\n",
                "except Exception as e:\n",
                "    print(f\"Local environment: {e}\")"
            ]
        }
    ],
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

print("Notebook successfully written to ml/notebooks/02_bec_baseline_colab.ipynb")
