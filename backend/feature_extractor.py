import re
import math
import numpy as np
from urllib.parse import urlparse

def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p + 1e-12, 2) for p in probs)

cyrillic_re = re.compile(r'[\u0400-\u04FF]')
invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']

suspicious_tokens = [
    "login","secure","account","update","verify","signin","bank",
    "confirm","paypal","reset","auth","security","verification"
]

common_tlds = ['.com','.net','.org','.info','.biz','.co','.uk','.ru','.io','.gov']

def extract_features_from_url(url):

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    full = (host + path + ("?" + query if query else "")).strip()

    url_length = len(url)
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_slashes = url.count('/')
    num_digits = sum(c.isdigit() for c in url)

    if host:
        parts = host.split('.')
        num_subdomains = max(0, len(parts) - 2)
    else:
        num_subdomains = 0

    contains_suspicious_words = int(any(tok in url.lower() for tok in suspicious_tokens))
    entropy = shannon_entropy(full)
    contains_cyrillic = int(bool(cyrillic_re.search(url)))
    contains_hidden_chars = int(any(ch in url for ch in invisible_chars))
    is_punycode = int(host.startswith("xn--")) if host else 0
    contains_ip = int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', host)))
    contains_common_tld = int(any(host.endswith(tld) for tld in common_tlds))
    uses_https = int(parsed.scheme == "https")

    feat_vector = [
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
        uses_https
    ]

    return np.array(feat_vector, dtype=float)
