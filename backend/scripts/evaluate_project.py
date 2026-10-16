"""
Project evaluation helper.

Generates:
  - Confusion matrices + precision/recall for:
      * Spam classifier (joblib pipeline)
      * SQL validation classifier (joblib pipeline)
  - Ablation comparisons:
      * Spam: heuristics-only vs ML-only vs hybrid (max score)
      * SQL: heuristics-only vs ML-only vs hybrid (combine logic)
  - Latency percentiles (P50/P95) for analyzer endpoints using FastAPI TestClient.

This script is designed to be reproducible and grounded in the repo artifacts:
  - Datasets under backend/data/raw/
  - Models under backend/data/models_store/
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import statistics
import warnings
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
RAW = BACKEND / "data" / "raw"
MODELS = BACKEND / "data" / "models_store"

# Ensure repo root is on sys.path so `import backend...` works when executed from other CWDs.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@contextlib.contextmanager
def _silence_stdio(enabled: bool):
    if not enabled:
        yield
        return
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        yield



def _percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return float("nan")
    if p <= 0:
        return float(min(values))
    if p >= 100:
        return float(max(values))
    s = sorted(values)
    idx = (len(s) - 1) * (p / 100.0)
    lo = int(np.floor(idx))
    hi = int(np.ceil(idx))
    if lo == hi:
        return float(s[lo])
    w = idx - lo
    return float((1.0 - w) * s[lo] + w * s[hi])


@dataclass(frozen=True)
class BinaryMetrics:
    tn: int
    fp: int
    fn: int
    tp: int
    precision_pos: float
    recall_pos: float
    f1_pos: float
    support_pos: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "confusion_matrix": {"tn": self.tn, "fp": self.fp, "fn": self.fn, "tp": self.tp},
            "precision_pos": self.precision_pos,
            "recall_pos": self.recall_pos,
            "f1_pos": self.f1_pos,
            "support_pos": self.support_pos,
        }


def _binary_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> BinaryMetrics:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))
    pr, rc, f1, sup = precision_recall_fscore_support(y_true, y_pred, labels=[1], average=None, zero_division=0)
    return BinaryMetrics(
        tn=tn,
        fp=fp,
        fn=fn,
        tp=tp,
        precision_pos=float(pr[0]),
        recall_pos=float(rc[0]),
        f1_pos=float(f1[0]),
        support_pos=int(sup[0]),
    )


def _load_csv_queries(path: Path) -> List[str]:
    """
    Robust loader for query CSVs where rows may contain commas and other characters.

    The training notebook intentionally reads these files line-by-line (rather than strict CSV parsing)
    to avoid tokenization errors caused by embedded commas/quotes in SQL text.
    """
    if not path.exists():
        raise FileNotFoundError(str(path))
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not lines:
        return []
    # Skip header line
    out: List[str] = []
    for raw in lines[1:]:
        s = (raw or "").strip()
        if not s:
            continue
        # Strip a single pair of surrounding quotes when present.
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            s = s[1:-1]
        out.append(s)
    return out


def load_sql_dataset(normal_path: Path, malicious_path: Path) -> Tuple[List[str], List[int]]:
    normal = _load_csv_queries(normal_path)
    malicious = _load_csv_queries(malicious_path)
    X = normal + malicious
    y = [0] * len(normal) + [1] * len(malicious)
    return X, y


def load_spam_dataset_emails_csv(path: Path) -> Tuple[List[str], List[int]]:
    df = pd.read_csv(path)
    if "text" not in df.columns or "spam" not in df.columns:
        raise ValueError(f"{path} must contain 'text' and 'spam' columns")
    df = df.dropna(subset=["text"]).copy()
    X = [str(x) for x in df["text"].tolist()]
    y = [int(x) for x in df["spam"].astype(int).tolist()]
    return X, y


def _preprocess_text_simple(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "").lower()).strip()


def _safe_predict_proba(model: Any, texts: Sequence[str]) -> Optional[np.ndarray]:
    if not hasattr(model, "predict_proba"):
        return None
    try:
        return np.asarray(model.predict_proba(list(texts)))
    except Exception:
        return None


# --- Spam heuristics (mirrors backend/services/spam_detection_service.py) ---
_URL_RE = re.compile(r"https?://[\\w\\-\\.:@%\\+~#=/?&]+", re.IGNORECASE)


def _extract_urls(text: str) -> List[str]:
    return _URL_RE.findall(text or "")


def _domain_of(url: str) -> str:
    from urllib.parse import urlparse

    try:
        host = urlparse(url).hostname or ""
        return host.lower()
    except Exception:
        return ""


def _is_ip_literal(host: str) -> bool:
    return bool(re.match(r"^(\\d{1,3}\\.){3}\\d{1,3}$", host))


def _base_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _url_indicators(text: str, suspicious_tlds: Sequence[str], blocklist: Optional[set] = None) -> Dict[str, Any]:
    urls = _extract_urls(text)
    hosts = [_domain_of(u) for u in urls if u]
    indicators: Dict[str, Any] = {
        "total_urls": len(urls),
        "ip_urls": 0,
        "suspicious_tlds": 0,
        "punycode": 0,
        "blocklisted": [],
        "hosts": hosts[:10],
    }
    suspicious_tlds_set = set([t.strip().lower() for t in suspicious_tlds if t.strip()])
    for h in hosts:
        if not h:
            continue
        if h.startswith("xn--"):
            indicators["punycode"] += 1
        base = _base_domain(h)
        tld = base.split(".")[-1] if "." in base else base
        if tld in suspicious_tlds_set:
            indicators["suspicious_tlds"] += 1
        if _is_ip_literal(h):
            indicators["ip_urls"] += 1
        if blocklist and (base in blocklist or h in blocklist):
            indicators["blocklisted"].append(h)
    return indicators


def _heuristic_phishing_score(indicators: Dict[str, Any]) -> float:
    score = 0.0
    score += min(0.3, 0.05 * max(0, int(indicators.get("total_urls", 0)) - 1))
    score += 0.15 if int(indicators.get("ip_urls", 0)) > 0 else 0.0
    score += 0.2 if int(indicators.get("suspicious_tlds", 0)) > 0 else 0.0
    score += 0.2 if int(indicators.get("punycode", 0)) > 0 else 0.0
    score += 0.3 if indicators.get("blocklisted") else 0.0
    return float(min(score, 0.95))


def eval_spam(
    X: Sequence[str],
    y: Sequence[int],
    spam_model_path: Path,
    threshold: float,
    test_size: float,
    random_state: int,
) -> Dict[str, Any]:
    model = joblib.load(spam_model_path)

    X_raw = [str(t) for t in X]
    X_ml = [_preprocess_text_simple(t) for t in X_raw]
    idx = list(range(len(X_raw)))
    idx_train, idx_test, y_train, y_test = train_test_split(
        idx, list(y), test_size=test_size, random_state=random_state, stratify=list(y)
    )
    X_test_ml = [X_ml[i] for i in idx_test]
    X_test_raw = [X_raw[i] for i in idx_test]

    proba = _safe_predict_proba(model, X_test_ml)
    if proba is None:
        y_pred_ml = [int(x) for x in model.predict(X_test_ml)]
        ml_scores = [float("nan")] * len(y_pred_ml)
    else:
        ml_scores = [float(p[1]) for p in proba]
        y_pred_ml = [1 if s >= threshold else 0 for s in ml_scores]

    suspicious_tlds = (os.getenv("SUSPICIOUS_TLDS", "zip,top,work,xyz,country,click,link").lower()).split(",")
    blocklist_path = os.getenv("REPUTATION_BLOCKLIST_PATH", str(BACKEND / "data" / "reputation" / "blocklist.txt"))
    blocklist: Optional[set] = None
    try:
        p = Path(blocklist_path)
        if p.exists():
            blocklist = set(line.strip().lower() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.startswith("#"))
    except Exception:
        blocklist = None

    heur_scores: List[float] = []
    for t in X_test_raw:
        ind = _url_indicators(t, suspicious_tlds=suspicious_tlds, blocklist=blocklist)
        heur_scores.append(_heuristic_phishing_score(ind))
    y_pred_heur = [1 if s >= threshold else 0 for s in heur_scores]

    hybrid_scores = [max(ms if not np.isnan(ms) else 0.0, hs) for ms, hs in zip(ml_scores, heur_scores)]
    y_pred_hybrid = [1 if s >= threshold else 0 for s in hybrid_scores]

    return {
        "dataset": {
            "source": str(spam_model_path),
            "test_size": test_size,
            "random_state": random_state,
            "threshold": threshold,
            "n_total": len(X),
            "n_test": len(idx_test),
        },
        "ml_only": _binary_metrics(y_test, y_pred_ml).as_dict(),
        "heuristics_only": _binary_metrics(y_test, y_pred_heur).as_dict(),
        "hybrid": _binary_metrics(y_test, y_pred_hybrid).as_dict(),
    }


# --- SQL evaluation ---
def _init_query_analysis_models(quiet: bool) -> Tuple[Any, Any]:
    from backend.core.ai_models.anomaly_detection.model import AnomalyDetectionModel

    with _silence_stdio(quiet):
        anomaly_model = AnomalyDetectionModel(
            model_path=str(MODELS / "anomaly_detection_model.joblib"),
            processor_scaler_path=str(MODELS / "anomaly_query_scaler.joblib"),
        )
        qv_model = joblib.load(MODELS / "query_validation_model.joblib")
    return anomaly_model, qv_model


def _sql_heuristics_scan(sql: str) -> Tuple[bool, float, List[str]]:
    from backend.services.query_analysis_service import QueryAnalysisService

    # Reuse service implementation (regex scan + weights).
    # We do not need full service initialization to run _heuristics_scan.
    # Instantiate a minimal object without running __init__ (avoids model loading overhead here).
    svc = object.__new__(QueryAnalysisService)  # type: ignore[call-arg]
    hr = QueryAnalysisService._heuristics_scan(svc, sql)  # type: ignore[arg-type]
    suspected = bool(getattr(hr, "suspected", False))
    score = float(getattr(hr, "heuristic_score", 0.0) or 0.0)
    hits = list(getattr(hr, "hits", []) or [])
    # Merge AST cues when possible (best-effort)
    try:
        ast_hits = QueryAnalysisService._ast_semantics(svc, sql)  # type: ignore[arg-type]
        for h in ast_hits:
            if h not in hits:
                hits.append(h)
    except Exception:
        pass
    return suspected, score, hits


def eval_sql(
    X: Sequence[str],
    y: Sequence[int],
    test_size: float,
    random_state: int,
    quiet: bool,
) -> Dict[str, Any]:
    anomaly_model, qv_model = _init_query_analysis_models(quiet)

    X_raw = [str(t) for t in X]
    X_ml = [_preprocess_text_simple(t) for t in X_raw]
    idx = list(range(len(X_raw)))
    idx_train, idx_test, y_train, y_test = train_test_split(
        idx, list(y), test_size=test_size, random_state=random_state, stratify=list(y)
    )
    X_test_raw = [X_raw[i] for i in idx_test]
    X_test_ml = [X_ml[i] for i in idx_test]

    # ML-only: query validation model prediction
    y_pred_ml = [int(x) for x in qv_model.predict(X_test_ml)]

    # Heuristics-only: high confidence hits OR score threshold
    try:
        from backend.services.query_analysis_service import CRITICAL_CODES, HEURISTICS_HIGH_THRESHOLD
        critical = set(CRITICAL_CODES)
        thr = float(HEURISTICS_HIGH_THRESHOLD)
    except Exception:
        critical = {"stacked_query_dml", "xp_cmdshell", "union_select"}
        thr = 0.75

    y_pred_heur: List[int] = []
    y_pred_hybrid: List[int] = []
    for q_raw, q_ml in zip(X_test_raw, X_test_ml):
        # Heuristics/anomaly run on raw SQL, ML runs on preprocessed text (mirrors service behavior)
        suspected, score, hits = _sql_heuristics_scan(q_raw)
        heur_high_conf = any(h in critical for h in hits)
        heur_high = bool(suspected and score >= thr)

        # Heuristics-only binary decision
        y_pred_heur.append(1 if (heur_high_conf or heur_high) else 0)

        # Hybrid: mirrors QueryAnalysisService._combine_assessments mapping to High/Critical
        pred, _score = anomaly_model.predict_and_score([q_raw])[0]
        anomaly_anomalous = (int(pred) == -1)
        nlp_malicious = bool(int(qv_model.predict([q_ml])[0]) == 1)

        is_mal = False
        if heur_high_conf:
            is_mal = True
        elif anomaly_anomalous and nlp_malicious:
            is_mal = True
        elif nlp_malicious or heur_high:
            is_mal = True
        else:
            # Medium (anomaly only) is treated as non-malicious for block/alert decisions
            is_mal = False
        y_pred_hybrid.append(1 if is_mal else 0)

    return {
        "dataset": {
            "source": "normal_queries.csv + malicious_queries.csv",
            "test_size": test_size,
            "random_state": random_state,
            "n_total": len(X),
            "n_test": len(idx_test),
        },
        "sql_validation_ml_only": _binary_metrics(y_test, y_pred_ml).as_dict(),
        "heuristics_only": _binary_metrics(y_test, y_pred_heur).as_dict(),
        "hybrid": _binary_metrics(y_test, y_pred_hybrid).as_dict(),
    }


def eval_enforcement_false_positive_rates(normal_queries: Sequence[str], quiet: bool) -> Dict[str, Any]:
    """
    Evaluate approximate false positive *block* rates on benign queries.

    Notes:
      - We set a service context so service-context gating does not dominate results.
      - We initialize QueryAnalysisService so the enforcer can reuse the same heuristics engine.
    """
    with _silence_stdio(quiet):
        from backend.security.request_context import set_current_service
        from backend.services.alerts_service import AlertsService
        from backend.services.query_analysis_service import QueryAnalysisService

    # Ensure service context is available (prevents "unknown_service" inflation)
    set_current_service("/evaluation")

    # Initialize SQL analysis service once so sql_enforcer can call the shared heuristics scan.
    try:
        QueryAnalysisService.get_instance()
    except Exception:
        with _silence_stdio(quiet):
            QueryAnalysisService(
                anomaly_model_path=str(MODELS / "anomaly_detection_model.joblib"),
                anomaly_scaler_path=str(MODELS / "anomaly_query_scaler.joblib"),
                query_validation_model_path=str(MODELS / "query_validation_model.joblib"),
                alerts_service=AlertsService(),
            )

    with _silence_stdio(quiet):
        import backend.security.sql_enforcer as enf

    would_block_critical = 0
    would_block_high = 0
    would_flag = 0
    total = 0

    for q in normal_queries:
        total += 1
        res = enf.decide(q, parameters={})
        decision = str(res.get("decision") or "")
        if decision != "ALLOW":
            would_flag += 1
        if decision == "BLOCK_IMMEDIATE":
            would_block_critical += 1
        if decision in ("BLOCK_IMMEDIATE", "FLAG_FOR_REVIEW_BLOCK"):
            would_block_high += 1

    def rate(n: int) -> float:
        return float(n) / float(total) if total else 0.0

    return {
        "n_benign": total,
        "flag_rate": rate(would_flag),
        "block_rate_block_critical": rate(would_block_critical),
        "block_rate_block_high": rate(would_block_high),
    }


def bench_latencies(iterations: int, quiet: bool) -> Dict[str, Any]:
    with _silence_stdio(quiet):
        from fastapi.testclient import TestClient
        from backend.server.main import app

    def ms(dt: float) -> float:
        return dt * 1000.0

    sql_payloads = [
        {"query": "SELECT id, name FROM users WHERE id = 42"},
        {"query": "SELECT * FROM users WHERE name = 'admin' OR '1'='1'; DROP TABLE users; --"},
    ]
    spam_payloads = [
        {"subject": "Meeting reminder", "body_text": "Hi team, reminder about tomorrow's agenda."},
        {"subject": "URGENT", "body_text": "Your account will be closed. Visit http://example.top/verify now."},
    ]

    # Small file payloads
    benign_file = ("hello.txt", b"hello world", "text/plain")
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("payloads/sh.txt", "bash -i")
    zip_file = ("rev.zip", mem.getvalue(), "application/zip")

    with _silence_stdio(quiet), TestClient(app) as client:
        # Warm up (models, caches, DB connection)
        client.post("/api/v1/analyze-sql/query", json=sql_payloads[0])
        client.post("/api/v1/analyze-spam/email", json=spam_payloads[0])
        client.post("/api/v1/analyze-file/file", files={"file": benign_file})

        sql_times: List[float] = []
        spam_times: List[float] = []
        file_times: List[float] = []

        for i in range(iterations):
            # SQL
            t0 = time.perf_counter()
            r = client.post("/api/v1/analyze-sql/query", json=sql_payloads[i % len(sql_payloads)])
            r.raise_for_status()
            sql_times.append(ms(time.perf_counter() - t0))

            # Spam
            t0 = time.perf_counter()
            r = client.post("/api/v1/analyze-spam/email", json=spam_payloads[i % len(spam_payloads)])
            r.raise_for_status()
            spam_times.append(ms(time.perf_counter() - t0))

            # File
            t0 = time.perf_counter()
            payload = benign_file if (i % 2 == 0) else zip_file
            r = client.post("/api/v1/analyze-file/file", files={"file": payload})
            r.raise_for_status()
            file_times.append(ms(time.perf_counter() - t0))

    def summarize(vals: List[float]) -> Dict[str, Any]:
        return {
            "n": len(vals),
            "p50_ms": _percentile(vals, 50),
            "p95_ms": _percentile(vals, 95),
            "mean_ms": float(statistics.mean(vals)) if vals else float("nan"),
        }

    return {
        "sql_analyze": summarize(sql_times),
        "spam_analyze": summarize(spam_times),
        "file_analyze": summarize(file_times),
        "notes": "Measured with FastAPI TestClient (in-process). Results depend on machine and configuration.",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sql-test-size", type=float, default=0.2)
    ap.add_argument("--spam-test-size", type=float, default=0.2)
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--spam-threshold", type=float, default=float(os.getenv("SPAM_FINAL_THRESHOLD", "0.8")))
    ap.add_argument("--latency-iters", type=int, default=60)
    ap.add_argument("--json", action="store_true", help="Print results as JSON only")
    args = ap.parse_args()
    quiet = bool(args.json)
    if quiet:
        warnings.filterwarnings("ignore")
        try:
            import logging

            logging.getLogger().setLevel(logging.CRITICAL)
        except Exception:
            pass

    # --- Spam evaluation ---
    spam_X, spam_y = load_spam_dataset_emails_csv(RAW / "emails" / "emails.csv")
    spam_res = eval_spam(
        spam_X,
        spam_y,
        spam_model_path=MODELS / "spam_detector_v1.joblib",
        threshold=float(args.spam_threshold),
        test_size=float(args.spam_test_size),
        random_state=int(args.random_state),
    )

    # --- SQL evaluation ---
    sql_X, sql_y = load_sql_dataset(RAW / "normal_queries.csv", RAW / "malicious_queries.csv")
    sql_res = eval_sql(sql_X, sql_y, test_size=float(args.sql_test_size), random_state=int(args.random_state), quiet=quiet)

    # --- Enforcement false-positive rate approximation ---
    enforcement_res = eval_enforcement_false_positive_rates(
        [_preprocess_text_simple(q) for q in _load_csv_queries(RAW / "normal_queries.csv")],
        quiet=quiet,
    )

    # --- Latency ---
    latency_res = bench_latencies(iterations=int(args.latency_iters), quiet=quiet)

    out = {
        "spam": spam_res,
        "sql": sql_res,
        "enforcement_false_positive_rates": enforcement_res,
        "latency": latency_res,
    }

    if args.json:
        print(json.dumps(out, indent=2))
        return

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
