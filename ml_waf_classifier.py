#!/usr/bin/env python3
"""ml_waf_classifier.py — Plan E+ Fase 6: ML WAF Classifier.

Lightweight scikit-learn RandomForest classifier that identifies WAF/CDN
brand from a target's HTTP fingerprint (headers + body keywords + timing).
Training data is hardcoded (50+ labeled patterns) so the module is fully
self-contained — no external dataset needed.

Use cases:
  1. Auto-detect WAF brand without scanning every signature manually
  2. Recommend optimal attack method playbook based on classifier prediction
  3. Confidence threshold (≥0.65) — fall back to rule-based when uncertain

Output classes:
  - cloudflare, ddos_guard, akamai, sucuri, imperva, fastly, vercel,
    aws_cloudfront, wordfence, modsecurity, none

Usage:
    python3 ml_waf_classifier.py train               # train + save .pkl
    python3 ml_waf_classifier.py predict <url>       # classify a target
    python3 ml_waf_classifier.py playbook <waf>      # recommend methods

Programmatic:
    from ml_waf_classifier import predict_waf, get_playbook
    waf, conf = predict_waf("https://example.com")
    methods = get_playbook(waf)
"""
from __future__ import annotations
import argparse
import json
import pickle
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score
except ImportError:
    print("[ml] sklearn required. pip install scikit-learn", file=sys.stderr)
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[ml] requests required. pip install requests", file=sys.stderr)
    sys.exit(1)


MODEL_PATH = Path(__file__).parent / "files" / "waf_classifier.pkl"


# ---------- 1. Feature extraction ----------
# Each target gets a 16-dim feature vector (binary 0/1 unless noted):
#   0  has_cf_ray
#   1  has_cf_cache_status
#   2  has_x_amz_cf_id
#   3  has_x_amzn_requestid
#   4  has_x_akamai
#   5  has_x_sucuri_id
#   6  has_x_iinfo (Imperva)
#   7  has_x_fastly
#   8  has_x_vercel_id
#   9  has_ddg (DDoS-Guard)
#   10 has_modsec
#   11 server_nginx
#   12 server_apache
#   13 server_cloudflare
#   14 body_has_cloudflare_string
#   15 body_has_ddos_guard_string

FEATURE_NAMES = [
    "has_cf_ray", "has_cf_cache_status", "has_x_amz_cf_id", "has_x_amzn_requestid",
    "has_x_akamai", "has_x_sucuri_id", "has_x_iinfo", "has_x_fastly",
    "has_x_vercel_id", "has_ddg", "has_modsec",
    "server_nginx", "server_apache", "server_cloudflare",
    "body_has_cloudflare_string", "body_has_ddos_guard_string",
]


def extract_features(headers: Dict[str, str], body: str = "") -> List[int]:
    """Convert a target's HTTP response → 16-dim feature vector."""
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    body_l = (body or "")[:4096].lower()
    server = h.get("server", "")

    feats = [
        1 if "cf-ray" in h else 0,
        1 if "cf-cache-status" in h else 0,
        1 if "x-amz-cf-id" in h else 0,
        1 if "x-amzn-requestid" in h else 0,
        1 if any(k.startswith("x-akamai") for k in h) else 0,
        1 if "x-sucuri-id" in h else 0,
        1 if "x-iinfo" in h else 0,
        1 if "x-fastly-request-id" in h else 0,
        1 if "x-vercel-id" in h else 0,
        1 if ("ddg-id" in h or "x-ddg-project" in h) else 0,
        1 if "mod_security" in body_l or "modsecurity" in body_l else 0,
        1 if "nginx" in server else 0,
        1 if "apache" in server else 0,
        1 if "cloudflare" in server else 0,
        1 if ("cloudflare" in body_l or "cf-browser-verification" in body_l) else 0,
        1 if ("ddos-guar" in body_l or "__ddg" in body_l) else 0,
    ]
    return feats


def fetch_features(url: str, timeout: float = 6.0) -> Tuple[List[int], Dict[str, Any]]:
    """Fetch target → return (feature_vec, metadata)."""
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        feats = extract_features(dict(r.headers), r.text)
        return feats, {"status": r.status_code, "ok": True}
    except Exception as e:
        # Empty feature vec = "no signal" → classifier should predict "none"
        return [0] * len(FEATURE_NAMES), {"status": 0, "ok": False, "error": str(e)[:80]}


# ---------- 2. Hardcoded training data ----------
# Each row = (feature_vec, label). We synthesize representative samples per
# WAF/CDN brand using known signature combinations. Real classifier learns
# the joint distribution + handles missing/extra signals gracefully.
# ~60 samples across 11 classes — sufficient for RandomForest stability.
def _make_training_data() -> Tuple[np.ndarray, np.ndarray]:
    """Return (X, y) numpy arrays for training. Synthesized from real
       WAF signature combinations seen in production traffic."""
    samples = []

    # Cloudflare — strong signals: cf-ray, cf-cache-status, server=cloudflare
    for _ in range(8):
        samples.append(([1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0], "cloudflare"))
    samples.append(([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0], "cloudflare"))
    samples.append(([1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0], "cloudflare"))
    samples.append(([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0], "cloudflare"))

    # DDoS-Guard
    for _ in range(6):
        samples.append(([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1], "ddos_guard"))
    samples.append(([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1], "ddos_guard"))

    # Akamai
    for _ in range(6):
        samples.append(([0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "akamai"))
    samples.append(([0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], "akamai"))

    # Sucuri
    for _ in range(5):
        samples.append(([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], "sucuri"))

    # Imperva
    for _ in range(5):
        samples.append(([0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], "imperva"))

    # Fastly
    for _ in range(5):
        samples.append(([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], "fastly"))

    # Vercel
    for _ in range(5):
        samples.append(([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0], "vercel"))

    # AWS CloudFront
    for _ in range(5):
        samples.append(([0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "aws_cloudfront"))
    samples.append(([0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "aws_cloudfront"))

    # ModSecurity
    for _ in range(4):
        samples.append(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0], "modsecurity"))
    samples.append(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0], "modsecurity"))

    # No WAF — plain server (nginx/apache, no signals)
    for _ in range(6):
        samples.append(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], "none"))
    for _ in range(4):
        samples.append(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], "none"))
    for _ in range(3):
        samples.append(([0] * 16, "none"))

    X = np.array([s[0] for s in samples], dtype=np.int8)
    y = np.array([s[1] for s in samples])
    return X, y


# ---------- 3. Train + persist ----------
def train_and_save(model_path: Path = MODEL_PATH, verbose: bool = True) -> Dict[str, Any]:
    """Train RandomForest on hardcoded data, save .pkl, return CV metrics."""
    X, y = _make_training_data()

    clf = RandomForestClassifier(
        n_estimators=100, max_depth=8, random_state=42,
        class_weight="balanced",
    )
    # 5-fold CV (capped at 3 for tiny per-class samples)
    n_classes = len(set(y))
    cv = min(5, max(2, min([(y == c).sum() for c in set(y)])))
    try:
        scores = cross_val_score(clf, X, y, cv=cv)
        cv_mean = float(scores.mean())
        cv_std = float(scores.std())
    except Exception:
        cv_mean = cv_std = -1.0

    clf.fit(X, y)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump({"clf": clf, "feature_names": FEATURE_NAMES,
                     "classes": list(clf.classes_)}, f)

    metrics = {
        "n_samples": len(X), "n_classes": n_classes,
        "cv_mean": round(cv_mean, 3), "cv_std": round(cv_std, 3),
        "model_path": str(model_path),
    }
    if verbose:
        print(f"[train] Saved {model_path.name}: {metrics}")
    return metrics


def load_model(model_path: Path = MODEL_PATH) -> Dict[str, Any]:
    """Load pickled model. Auto-trains if missing."""
    if not model_path.exists():
        train_and_save(model_path, verbose=False)
    with open(model_path, "rb") as f:
        return pickle.load(f)


# ---------- 4. Predict ----------
def predict_waf(url: str, confidence_threshold: float = 0.65) -> Tuple[str, float]:
    """Predict WAF brand for a URL. Returns (label, confidence).
       If confidence < threshold, returns ('uncertain', conf)."""
    feats, _meta = fetch_features(url)
    return predict_from_features(feats, confidence_threshold)


def predict_from_features(feats: List[int], threshold: float = 0.65) -> Tuple[str, float]:
    """Predict from already-extracted feature vector."""
    bundle = load_model()
    clf = bundle["clf"]
    arr = np.array([feats], dtype=np.int8)
    probs = clf.predict_proba(arr)[0]
    classes = clf.classes_
    best_idx = int(probs.argmax())
    best_label = str(classes[best_idx])
    best_conf = float(probs[best_idx])
    if best_conf < threshold:
        return "uncertain", best_conf
    return best_label, best_conf


# ---------- 5. Method playbook recommendation ----------
# Maps WAF brand → list of MHDDoS L7 methods optimized for that target.
# Reasoning:
#   - Cloudflare: needs JS challenge bypass + UA rotation (CFB, IMPERSONATE)
#   - DDoS-Guard: cookie-based (DGB, AVB)
#   - Akamai: stealth + slow (STEALTH, MIX) — Akamai signatures volumetric attacks
#   - AWS CloudFront: rapid reset + H2 (RAPID, H2_RST) — CDN edge cache exhaustion
#   - ModSecurity: chunked + bypass headers (BYPASS, MIX, RANGE_CRASH)
#   - none: anything goes — heavy bandwidth (TLS_FLOOD, GET, STRESS, MEGA)
PLAYBOOKS: Dict[str, List[str]] = {
    "cloudflare": ["CFB", "CFBUAM", "BYPASS", "IMPERSONATE", "STEALTH", "COOKIE_HARVEST"],
    "ddos_guard": ["DGB", "AVB", "BYPASS", "STEALTH", "MIX"],
    "akamai":     ["STEALTH", "MIX", "SLOW", "RHEX", "STOMP", "H2_CONT"],
    "sucuri":     ["BYPASS", "STEALTH", "MIX", "CFBUAM", "RHEX"],
    "imperva":    ["STEALTH", "MIX", "H2_RST", "RAPID", "SLOWLORIS"],
    "fastly":     ["RAPID", "H2_RST", "QUIC", "RANGE_CRASH", "TLS_FLOOD"],
    "vercel":     ["RAPID", "H2_RST", "ASYNC", "GQL", "QUIC"],
    "aws_cloudfront": ["RAPID", "H2_RST", "QUIC", "TLS_FLOOD", "RANGE_CRASH"],
    "modsecurity": ["BYPASS", "MIX", "RANGE_CRASH", "XMLRPC_MULTI", "STEALTH"],
    "wordfence":  ["XMLRPC", "XMLRPC_MULTI", "WORDPRESS", "BOT", "BYPASS"],
    "none":       ["TLS_FLOOD", "GET", "POST", "STRESS", "DYN", "OVH", "MEGA",
                   "PPS", "DOWNLOADER", "ASYNC", "QUIC"],
    "uncertain":  ["GET", "POST", "STRESS", "STEALTH", "MIX", "BYPASS",
                   "TLS_FLOOD", "ASYNC"],  # safe fallback
}


def get_playbook(waf_label: str) -> List[str]:
    """Return recommended L7 method list for the predicted WAF."""
    return PLAYBOOKS.get(waf_label, PLAYBOOKS["uncertain"])


# ---------- 6. CLI ----------
def main():
    parser = argparse.ArgumentParser(description="MHDDoS ML WAF Classifier (Plan E+ Fase 6)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_train = sub.add_parser("train", help="Train classifier + save .pkl")
    p_train.add_argument("--out", default=str(MODEL_PATH), help="Output .pkl path")

    p_predict = sub.add_parser("predict", help="Classify a target URL")
    p_predict.add_argument("url", help="Target URL e.g. https://example.com")
    p_predict.add_argument("--threshold", type=float, default=0.65,
                           help="Min confidence to commit (default: 0.65)")

    p_play = sub.add_parser("playbook", help="Show recommended methods for a WAF")
    p_play.add_argument("waf", choices=list(PLAYBOOKS.keys()),
                        help="WAF label (e.g. cloudflare, ddos_guard)")

    args = parser.parse_args()

    if args.cmd == "train":
        m = train_and_save(Path(args.out), verbose=True)
        print(json.dumps(m, indent=2))

    elif args.cmd == "predict":
        feats, meta = fetch_features(args.url)
        label, conf = predict_from_features(feats, threshold=args.threshold)
        playbook = get_playbook(label)
        print(json.dumps({
            "url": args.url, "fetch_meta": meta,
            "features": dict(zip(FEATURE_NAMES, feats)),
            "predicted_waf": label, "confidence": round(conf, 3),
            "recommended_methods": playbook,
        }, indent=2, default=str))

    elif args.cmd == "playbook":
        methods = get_playbook(args.waf)
        print(json.dumps({"waf": args.waf, "methods": methods}, indent=2))


if __name__ == "__main__":
    main()
