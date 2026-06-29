"""
ML-based phishing classifier using Gradient Boosting.
Loads a model pre-trained on a real, balanced, 11,430-URL dataset
(Hannousse & Yahiouche, 2021) instead of the previous 50 hand-written
synthetic examples, which caused the model to rely almost entirely on
"has_https" and not generalize to real-world URLs.

To retrain from scratch (e.g. on your own/updated data), see retrain.py.
"""

import os
import pickle
import numpy as np
from utils.url_utils import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../models/phishing_model_v2.pkl")

# Feature columns (order must match extract_features output keys)
FEATURE_KEYS = [
    "url_length", "domain_length", "path_length",
    "num_dots", "num_subdomains",
    "num_hyphens", "num_underscores", "num_slashes",
    "num_question_marks", "num_at_signs", "num_ampersands",
    "num_equals", "num_percent", "num_digits_in_domain",
    "has_https", "has_ip_address", "has_port",
    "has_login_keyword", "has_secure_keyword",
    "has_paypal", "has_amazon", "has_google", "has_apple", "has_microsoft",
    "has_hex_encoding", "has_double_slash", "is_shortened",
    "is_risky_tld", "query_length", "num_params",
    # v2 additions
    "digit_ratio_url", "digit_ratio_domain", "domain_entropy",
    "longest_word_len", "count_www", "tld_length", "has_multiple_https_tokens",
]


class MLModel:
    def __init__(self):
        self.model = self._load()

    def _load(self):
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. Run retrain.py first to "
                f"generate phishing_model_v2.pkl from raw_dataset.csv."
            )
        with open(MODEL_PATH, "rb") as f:
            print("[MLModel] Loaded retrained model (v2).")
            return pickle.load(f)

    def _url_to_vector(self, url: str) -> list:
        features = extract_features(url)
        return [features.get(k, 0) for k in FEATURE_KEYS]

    def predict(self, url: str) -> dict:
        try:
            vec = np.array([self._url_to_vector(url)])
            proba = self.model.predict_proba(vec)[0]
            phishing_prob = float(proba[1])
            return {
                "score": round(phishing_prob, 4),
                "prediction": "phishing" if phishing_prob >= 0.5 else "safe",
            }
        except Exception as e:
            return {"score": 0.5, "prediction": "unknown", "error": str(e)}
