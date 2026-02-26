import os
from pathlib import Path

import tensorflow as tf
import joblib
import numpy as np

from feature_extractor import extract_features_from_url

BASE_DIR = Path(__file__).resolve().parent

# Prefer your final v2 artifacts when present, then fall back to generic names
MODEL_CANDIDATES = [
    BASE_DIR / "snn_trained_on_real_v2.keras",
    BASE_DIR / "model" / "snn_trained_on_real_v2.keras",
    BASE_DIR / "model" / "phishguard_model.keras",
    BASE_DIR / "phishguard_model.keras",
]

SCALER_CANDIDATES = [
    BASE_DIR / "scaler_trained_on_real_v2.save",
    BASE_DIR / "model" / "scaler_trained_on_real_v2.save",
    BASE_DIR / "model" / "scaler.save",
    BASE_DIR / "scaler.save",
]


def _pick_existing(candidates, kind: str) -> Path:
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(
        f"{kind} not found. Looked for: " + ", ".join(str(p) for p in candidates)
    )


print("🔄 Loading PhishGuard trained model...")

MODEL_PATH = _pick_existing(MODEL_CANDIDATES, "Model")
SCALER_PATH = _pick_existing(SCALER_CANDIDATES, "Scaler")

model = tf.keras.models.load_model(str(MODEL_PATH))
scaler = joblib.load(str(SCALER_PATH))

print(f"✅ Model loaded: {MODEL_PATH.name}")
print(f"✅ Scaler loaded: {SCALER_PATH.name}")


def _predict_from_features(features: np.ndarray) -> float:
    """
    Internal helper: takes a raw 14‑dim feature vector and returns phishing probability.
    """
    scaled = scaler.transform(features.reshape(1, -1))
    pred = model.predict(scaled, verbose=0)
    return float(pred[0][1])


def predict_url(url: str) -> float:
    """
    Takes URL string and returns phishing probability score in [0,1].
    """
    features = extract_features_from_url(url)
    return _predict_from_features(features)
