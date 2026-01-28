# app.py
import os, json, re, math, traceback
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import joblib
import tensorflow as tf
from urllib.parse import urlparse

# ---------- Config ----------
APP_DIR = os.path.dirname(__file__)
MODEL_DIR = os.path.join(APP_DIR, "model")
LISTS_PATH = os.path.join(APP_DIR, "lists.json")

# Candidate filenames (from your notebook). We'll try in order.
MODEL_CANDIDATES = [
    os.path.join(MODEL_DIR, "snn_trained_on_real_v2.keras"),
    os.path.join(MODEL_DIR, "snn_trained_on_real.keras"),
    os.path.join(MODEL_DIR, "snn_trained_on_real.keras"),  # duplicate safe
    os.path.join(MODEL_DIR, "snn_trained_model.keras"),
    os.path.join(MODEL_DIR, "snn_baseline.h5")
]
SCALER_CANDIDATES = [
    os.path.join(MODEL_DIR, "scaler_trained_on_real_v2.save"),
    os.path.join(MODEL_DIR, "scaler_trained_on_real_v2.save"),
    os.path.join(MODEL_DIR, "scaler.pkl"),
    os.path.join(MODEL_DIR, "scaler.save"),
]

app = Flask(__name__)
CORS(app)

# ---------- persist lists ----------
def load_lists():
    if not os.path.exists(LISTS_PATH):
        data = {"whitelist": [], "blacklist": []}
        with open(LISTS_PATH, "w") as f:
            json.dump(data, f)
        return data
    with open(LISTS_PATH, "r") as f:
        return json.load(f)

def save_lists(data):
    with open(LISTS_PATH, "w") as f:
        json.dump(data, f, indent=2)

# ---------- feature extraction (matches notebook) ----------
# uses same tokens & order as your notebook's extract_features_from_url
suspicious_tokens = [
    "login","secure","account","update","verify","signin","bank","confirm",
    "ebay","paypal","reset","auth","security","verify","verification"
]
common_tlds = {'.com', '.net', '.org', '.info', '.biz', '.co', '.uk', '.ru', '.io'}
cyrillic_re = re.compile(r'[\u0400-\u04FF]')
invisible_chars = ['\u200b','\u200c','\u200d','\ufeff']

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p + 1e-12, 2) for p in probs)

def extract_features_from_url(url: str):
    # normalize (ensure scheme present)
    orig = url
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url = 'http://' + url
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    full = (host + path + ('?' + query if query else '')).strip()

    url_length = len(orig)
    num_dots = orig.count('.')
    num_hyphens = orig.count('-')
    num_slashes = max(0, orig.count('/') - (2 if scheme else 0))
    num_digits = sum(c.isdigit() for c in orig)
    if host:
        parts = host.split('.')
        num_subdomains = max(0, len(parts) - 2)
    else:
        num_subdomains = 0
    contains_suspicious_words = int(any(tok in orig.lower() for tok in suspicious_tokens))
    entropy = shannon_entropy(full)
    contains_cyrillic = int(bool(cyrillic_re.search(orig)))
    contains_hidden_chars = int(any(ch in orig for ch in invisible_chars))
    is_punycode = int(host.startswith('xn--') if host else 0)
    contains_ip = int(bool(re.search(r'(?:\d{1,3}\.){3}\d{1,3}', host)))
    contains_common_tld = int(any(host.endswith(tld) for tld in common_tlds))
    uses_https = int(scheme == 'https')

    feat_vector = [
        url_length, num_dots, num_hyphens, num_slashes, num_digits,
        num_subdomains, contains_suspicious_words, entropy, contains_cyrillic,
        contains_hidden_chars, is_punycode, contains_ip, contains_common_tld, uses_https
    ]
    # Also return a dict of features (for debug/interpretability)
    feat_dict = {
        'url_length': url_length, 'num_dots': num_dots, 'num_hyphens': num_hyphens,
        'num_slashes': num_slashes, 'num_digits': num_digits, 'num_subdomains': num_subdomains,
        'contains_suspicious_words': contains_suspicious_words, 'entropy': entropy,
        'contains_cyrillic': contains_cyrillic, 'contains_hidden_chars': contains_hidden_chars,
        'is_punycode': is_punycode, 'contains_ip': contains_ip, 'contains_common_tld': contains_common_tld,
        'uses_https': uses_https, 'host': host
    }
    return np.array(feat_vector, dtype=float).reshape(1, -1), feat_dict

# ---------- load model & scaler ----------
MODEL = None
SCALER = None

def try_load_model_and_scaler():
    global MODEL, SCALER
    # model
    for m in MODEL_CANDIDATES:
        if os.path.exists(m):
            try:
                MODEL = tf.keras.models.load_model(m)
                print("Loaded model:", m)
                break
            except Exception as e:
                print("Found model file but failed to load:", m, "->", e)
    # scaler
    for s in SCALER_CANDIDATES:
        if os.path.exists(s):
            try:
                SCALER = joblib.load(s)
                print("Loaded scaler:", s)
                break
            except Exception as e:
                print("Found scaler file but failed to load:", s, "->", e)

try_load_model_and_scaler()

# ---------- scoring ----------
def compute_uncertainty(prob):
    # crude entropy-based uncertainty (0..1). Lower uncertainty = more confident.
    p = float(max(min(prob, 1.0-1e-9), 1e-9))
    ent = - (p*math.log(p,2) + (1-p)*math.log(1-p,2))  # in bits
    # max entropy for binary is 1 bit (at p=0.5)
    uncertainty = min(1.0, ent / 1.0)
    return uncertainty

# ------ Replace the old fallback scoring with this milder heuristic ------
def predict_from_features(X):
    """
    Conservative fallback heuristic.
    X is (1,14) feature vector in the order used by your extractor.
    """
    if MODEL is not None:
        pred = MODEL.predict(X, verbose=0)
        pred = np.asarray(pred)
        if pred.ndim == 2 and pred.shape[1] == 2:
            return float(pred[0,1])
        else:
            return float(pred.ravel()[0])

    # Defensive extraction with defaults
    try:
        url_length = float(X[0,0])
        suspicious_flag = float(X[0,6])
        entropy_val = float(X[0,7])
        contains_ip = float(X[0,11])
        uses_https = float(X[0,13])
    except Exception:
        url_length = 50.0
        suspicious_flag = 0.0
        entropy_val = 3.0
        contains_ip = 0.0
        uses_https = 1.0

    # Normalize
    norm_entropy = min(1.0, entropy_val / 6.0)
    norm_length = min(1.0, url_length / 200.0)

    # Conservative weights -> lower false positives
    score = 0.30 * suspicious_flag + \
            0.20 * norm_entropy + \
            0.05 * contains_ip + \
            0.05 * norm_length - \
            0.25 * uses_https

    score = float(max(0.0, min(1.0, score)))
    return score
# ------------------------------------------------------------------------
    pred = MODEL.predict(X_scaled, verbose=0)
    pred = np.asarray(pred)
    if pred.ndim == 2 and pred.shape[1] == 2:
        proba = float(pred[0,1])
    else:
        proba = float(pred.ravel()[0])
    # Ensure 0..1
    proba = float(max(0.0, min(1.0, proba)))
    return proba

# ---------- endpoints ----------
@app.route("/check", methods=["GET"])
def check():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    try:
        lists = load_lists()
        # simple normalization: if host matches whitelisted or blacklisted domain entries
        _, fd = extract_features_from_url(url)
        host = fd.get("host", "").lower()

        if host and any(host == d or host.endswith("." + d) for d in lists.get("whitelist", [])):
            return jsonify({"url":url, "phishing_score": 0.0, "uncertainty": 0.0, "label":"whitelist", "confidence":1.0})

        if host and any(host == d or host.endswith("." + d) for d in lists.get("blacklist", [])):
            return jsonify({"url":url, "phishing_score": 1.0, "uncertainty": 0.0, "label":"blacklist", "confidence":1.0})

        feats, feat_dict = extract_features_from_url(url)
        if SCALER is not None:
            try:
                Xs = SCALER.transform(feats)
            except Exception:
                # fallback: if scaler incompatible, try to reshape/fit minimal transform
                Xs = feats
        else:
            Xs = feats

        score = predict_from_features(Xs)
        uncertainty = compute_uncertainty(score)
        label = "Phishing" if score >= 0.5 else "Legitimate"
        return jsonify({
            "url": url,
            "phishing_score": round(float(score),4),
            "uncertainty": round(float(uncertainty),4),
            "label": label,
            "confidence": round(1-float(uncertainty),4),
            "features": feat_dict
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/list", methods=["POST"])
def add_to_list():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    target = (data.get("list") or "").strip().lower()
    if not url or target not in ("whitelist", "blacklist"):
        return jsonify({"error":"provide 'url' and 'list' ('whitelist'|'blacklist')"}), 400
    lists = load_lists()
    # store domain (normalized)
    _, fd = extract_features_from_url(url)
    domain = fd.get("host", "").lower()
    if not domain:
        domain = url.lower()
    if domain in lists.get(target, []):
        return jsonify({"status":"already_present","list":target,"url":domain}), 200
    lists[target].append(domain)
    other = "whitelist" if target=="blacklist" else "blacklist"
    if domain in lists.get(other, []):
        lists[other].remove(domain)
    save_lists(lists)
    return jsonify({"status":"ok","list":target,"url":domain}), 201

# Add this block to provide /predict POST endpoint expected by the frontend
@app.route("/predict", methods=["POST"])
def predict_endpoint():
    """
    Accepts JSON: { "url": "..." }
    Returns: { score, parameter_scores, model_uncertainty, features, url }
    """
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        feats, feat_dict = extract_features_from_url(url)
        if SCALER is not None:
            try:
                Xs = SCALER.transform(feats)
            except Exception:
                Xs = feats
        else:
            Xs = feats

        score = predict_from_features(Xs)
        uncertainty = compute_uncertainty(score)

        # Build parameter_scores mapping (simple mapping from features).
        parameter_scores = {
            "lexical_entropy": round(min(1.0, feat_dict.get("entropy",0)/6.0), 4),
            "ssl_cert_presence": round(float(feat_dict.get("uses_https",0)), 4),
            "ip_as_host": round(float(feat_dict.get("contains_ip",0)), 4),
            "obfuscation_tokens": round(float(feat_dict.get("contains_suspicious_words",0) or feat_dict.get("contains_hidden_chars",0)), 4),
            "url_length": round(min(1.0, feat_dict.get("url_length",0)/200.0), 4),
            # other fields filler so frontend doesn't break:
            "domain_age": 0.0,
            "whois_abnormality": 0.0,
            "redirect_count": 0.0,
            "suspicious_tld": round(0.0 if feat_dict.get("contains_common_tld",0) else 1.0, 4),
            "brand_similarity_score": 0.0,
            "uncommon_ports": 0.0,
            "presence_of_encoded_characters": round(float(feat_dict.get("contains_hidden_chars",0)), 4)
        }

        response = {
            "url": url,
            "score": round(float(score), 4),
            "parameter_scores": parameter_scores,
            "model_uncertainty": round(float(uncertainty), 4),
            "features": feat_dict
        }
        return jsonify(response)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/lists", methods=["GET"])
def get_lists():
    return jsonify(load_lists())

if __name__ == "__main__":
    # ensure model dir exists
    os.makedirs(MODEL_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
