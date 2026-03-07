from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
import re
from urllib.parse import urlparse
import os
import csv

from predictor import predict_url
from feature_extractor import extract_features_from_url

app = FastAPI(title="PhishGuard AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home() -> Dict[str, Any]:
    return {"status": "PhishGuard backend running"}


TOP_DOMAINS = set()
csv_path = os.path.join(os.path.dirname(__file__), "top_domains.csv")
if os.path.exists(csv_path):
    print(f"Loading top domains from {csv_path}...")
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    TOP_DOMAINS.add(row[1].strip().lower())
        print(f"Loaded {len(TOP_DOMAINS)} top domains into memory.")
    except Exception as e:
        print(f"Error loading top domains: {e}")
else:
    print(f"Warning: {csv_path} not found. Using default trusted domains.")
    # Fallback to defaults if CSV is missing
    TOP_DOMAINS = {
        "google.com", "github.com", "microsoft.com", "amazon.com", "facebook.com",
        "apple.com", "linkedin.com", "youtube.com", "wikipedia.org", "stackoverflow.com",
        "amazon.in", "flipkart.com", "flipkart.in", "udemy.com"
    }


def _normalize_host(url: str) -> str:
    if not url:
        return ""
    try:
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url = "http://" + url
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _is_trusted_domain(host: str) -> bool:
    host = (host or "").lower()
    if not host:
        return False
        
    # Check the exact host
    if host in TOP_DOMAINS:
        return True
        
    # Check all valid domain suffixes (e.g., for mail.google.com, we check mail.google.com and google.com)
    parts = host.split('.')
    # We only check up to parts-1 because a TLD (like .com) alone shouldn't trigger a whitelist match
    for i in range(len(parts) - 1):
        suffix = ".".join(parts[i:])
        if suffix in TOP_DOMAINS:
            return True
            
    return False


def _build_parameter_scores(raw_features):
    """
    Convert the 14‑dim feature vector into simple 0‑1 risk scores
    (purely heuristic, just for UI breakdown – model still drives final score).
    Order must match feature_extractor.extract_features_from_url().
    """
    (
        url_length,
        num_dots,
        num_hyphens,
        num_slashes,
        num_digits,
        num_subdomains,
        contains_suspicious_words,
        entropy,
        contains_cyrillic,
        contains_hidden_chars,
        is_punycode,
        contains_ip,
        contains_common_tld,
        uses_https,
    ) = raw_features.tolist()

    def clamp(x, lo=0.0, hi=1.0):
        return max(lo, min(hi, float(x)))

    scores = {
        "url_length": clamp(url_length / 200.0),
        "num_dots": clamp((num_dots - 1.0) / 5.0),
        "num_hyphens": clamp(num_hyphens / 10.0),
        "num_slashes": clamp((num_slashes - 3.0) / 5.0),
        "num_digits": clamp(num_digits / 15.0),
        "num_subdomains": clamp(num_subdomains / 3.0),
        "contains_suspicious_words": clamp(contains_suspicious_words),
        "entropy": clamp((entropy - 2.5) / 2.5),
        "contains_cyrillic": clamp(contains_cyrillic),
        "contains_hidden_chars": clamp(contains_hidden_chars),
        "is_punycode": clamp(is_punycode),
        "contains_ip": clamp(contains_ip),
        # common TLD & HTTPS are usually *good*, so risk is inverted
        "contains_common_tld": clamp(1.0 - contains_common_tld),
        "uses_https": clamp(1.0 - uses_https),
    }
    return scores


def _lexical_risk(raw_features) -> float:
    (
        url_length,
        num_dots,
        num_hyphens,
        num_slashes,
        num_digits,
        num_subdomains,
        contains_suspicious_words,
        entropy,
        contains_cyrillic,
        contains_hidden_chars,
        is_punycode,
        contains_ip,
        contains_common_tld,
        uses_https,
    ) = raw_features.tolist()

    def clamp(x, lo=0.0, hi=1.0):
        return max(lo, min(hi, float(x)))

    # Strong signals
    r_susp = float(contains_suspicious_words)
    r_sub = clamp((num_subdomains - 1.0) / 3.0)  # grows after 1–2 subdomains
    r_len = clamp((url_length - 120.0) / 180.0)
    r_digits = clamp(num_digits / 30.0)
    r_entropy = clamp((entropy - 3.5) / 1.5)

    # Weak but important signals
    r_rare_charset = float(
        max(contains_cyrillic, contains_hidden_chars, is_punycode, contains_ip)
    )

    base = max(r_susp, r_sub, r_len, r_digits, r_entropy, r_rare_charset)

    # If no explicit phishing tokens, let strong HTTPS + common TLD soften risk
    if not contains_suspicious_words:
        good_signals = int(bool(uses_https)) + int(bool(contains_common_tld))
        if good_signals == 2:
            base *= 0.5
        elif good_signals == 1:
            base *= 0.7

    return clamp(base)


def _estimate_uncertainty(score: float) -> float:
    """
    Lightweight pseudo‑uncertainty: highest near 0.5, lowest near 0 or 1.
    Returns value in [0,1].
    """
    score = max(0.0, min(1.0, float(score)))
    dist = abs(score - 0.5) * 2.0  # 0 at 0.5, 1 at 0 or 1
    return 1.0 - dist


@app.post("/predict")
async def predict(request: Request) -> Dict[str, Any]:
    try:
        data = await request.json()

        if isinstance(data, dict):
            url = data.get("url")
        elif isinstance(data, str):
            url = data
        else:
            url = None

        if not url or not isinstance(url, str):
            return {"error": "No URL provided"}

        host = _normalize_host(url)

        # Built‑in trusted domains (same idea as notebook)
        if _is_trusted_domain(host):
            return {
                "score": 0.0,
                "model_score": 0.0,
                "heuristic_risk": 0.0,
                "parameter_scores": {},
                "model_uncertainty": 0.0,
                "trusted_domain": True,
                "host": host,
            }

        # model probability from trained SNN
        model_score = float(predict_url(url))

        # raw features for explanation + lexical risk
        raw_features = extract_features_from_url(url)
        parameter_scores = _build_parameter_scores(raw_features)
        heuristic_risk = _lexical_risk(raw_features)

        # combine: keep model as baseline, but never below strong lexical warning
        score = max(model_score, heuristic_risk)
        model_uncertainty = _estimate_uncertainty(score)

        return {
            "score": score,
            "model_score": model_score,
            "heuristic_risk": heuristic_risk,
            "parameter_scores": parameter_scores,
            "model_uncertainty": model_uncertainty,
        }

    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=5000, reload=True)
