# PROJECT_NAME — Machine Learning Architecture (SIH26106)

This directory houses the ML pipeline:
- **Baseline**: TF-IDF Vectorizer + Logistic Regression (Lightweight, locally inferenced in milliseconds).
- **Google Colab Training**: For heavier transformer fine-tuning (e.g., DistilBERT for phishing/BEC text classification).
- **Output Artifacts**: Serialized `.joblib` or ONNX model files placed in `ml/models/` for local runtime inference.
