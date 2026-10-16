"""
Build a larger weak-labeled spam/phishing corpus from online threat content + analyst false negatives.

Outputs:
- backend/data/corpus/phishing/raw/phishing_online_weaklabels.csv
- backend/data/corpus/phishing/raw/phishing_online_weaklabels_report.json

Usage:
  python -m backend.scripts.update_spam_threat_corpus
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from backend.core.database import SessionLocal, create_db_tables, ensure_runtime_schema_compatibility
from backend.core.models import DefenderFeedback


DOMAIN_FEEDS: List[str] = [
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "https://openphish.com/feed.txt",
]

REQUIRED_SCENARIOS: List[str] = [
    "modern_phishing",
    "legitimate_transactional",
    "sender_domain_metadata",
    "url_feature_rich",
    "attachment_feature_rich",
    "multilingual_style_shift",
]

SAFE_SENDER_LOCALPARTS = ["alerts", "notifications", "support", "helpdesk", "billing", "security"]
BENIGN_LOCALPARTS = ["noreply", "billing", "orders", "updates", "service", "support"]


def _backend_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _to_base_domain(host: str) -> str:
    h = (host or "").strip().lower().strip(".")
    if not h:
        return ""
    parts = [p for p in h.split(".") if p]
    if len(parts) < 2:
        return h
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _extract_host(raw: str) -> Optional[str]:
    line = (raw or "").strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
        parts = line.split()
        if len(parts) >= 2:
            line = parts[1].strip()
    if line.startswith("http://") or line.startswith("https://"):
        try:
            host = urlparse(line).hostname
            if host:
                return host.lower()
        except Exception:
            return None
    if "/" in line:
        line = line.split("/", 1)[0]
    if ":" in line:
        line = line.split(":", 1)[0]
    if "." not in line:
        return None
    if not re.match(r"^[a-zA-Z0-9._-]+$", line):
        return None
    return line.lower()


def _download_lines(url: str) -> Iterable[str]:
    req = Request(url, headers={"User-Agent": "DefenderAI-WeakLabelBuilder/1.0"})
    with urlopen(req, timeout=20) as resp:
        text = resp.read().decode("utf-8", errors="ignore")
    for line in text.splitlines():
        yield line


def _load_domains_from_reputation_scores(path: Path, min_score: float = 0.80, max_domains: int = 2000) -> List[str]:
    out: List[str] = []
    if not path.exists():
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as fp:
            reader = csv.DictReader(fp)
            for row in reader:
                domain = _to_base_domain(str(row.get("domain") or "").strip())
                if not domain:
                    continue
                try:
                    score = float(row.get("score") or 0.0)
                except Exception:
                    continue
                if score < min_score:
                    continue
                out.append(domain)
                if len(out) >= max_domains:
                    break
    except Exception:
        return []
    return out


def _load_domain_list(path: Path) -> Set[str]:
    out: Set[str] = set()
    if not path.exists():
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            host = _extract_host(line)
            if not host:
                continue
            out.add(_to_base_domain(host))
    return out


def _is_positive_spam_label(value: Optional[str]) -> bool:
    token = str(value or "").strip().lower()
    return token in {"spam", "phishing", "malicious", "suspicious", "blocked", "junk"}


def _is_negative_spam_label(value: Optional[str]) -> bool:
    token = str(value or "").strip().lower()
    return token in {"ham", "safe", "benign", "allow", "not spam", "legitimate", "clean"}


def _load_false_negative_feedback(limit: int = 500) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    try:
        create_db_tables()
        ensure_runtime_schema_compatibility()
        with SessionLocal() as db:
            feedback_rows = (
                db.query(DefenderFeedback)
                .filter(DefenderFeedback.domain == "spam", DefenderFeedback.source == "human")
                .order_by(DefenderFeedback.timestamp.desc())
                .limit(max(1, int(limit) * 4))
                .all()
            )
            for row in feedback_rows:
                if not _is_positive_spam_label(row.true_label):
                    continue
                if not _is_negative_spam_label(row.predicted_label):
                    continue
                payload = row.sample_payload or {}
                subject = str(payload.get("subject") or "").strip()
                body = str(payload.get("body_text") or "").strip()
                sender = str(payload.get("sender_email") or "").strip()
                if not (subject or body):
                    continue
                rows.append({"subject": subject, "body_text": body, "sender_email": sender})
                if len(rows) >= max(1, int(limit)):
                    break
    except Exception:
        return []
    return rows


def _collect_online_domains(max_domains: int = 1800) -> List[str]:
    domains: Set[str] = set()
    for feed_url in DOMAIN_FEEDS:
        try:
            for raw in _download_lines(feed_url):
                host = _extract_host(raw)
                if not host:
                    continue
                domains.add(_to_base_domain(host))
                if len(domains) >= max_domains:
                    return sorted(domains)
        except Exception:
            continue
    return sorted(domains)


def _generate_phishing_templates() -> List[Dict[str, str]]:
    return [
        {
            "scenario": "modern_phishing",
            "subject": "Suspicious Transfer Detected",
            "body": "A transfer was initiated from your account. If unauthorized, cancel now: {url} If no action is taken within 15 minutes, transfer will be processed.",
            "url_features": "urgent_cta;payment_lure",
            "style_shift": "urgent_imperative",
            "language": "en",
        },
        {
            "scenario": "modern_phishing",
            "subject": "You were mentioned in Project {project}",
            "body": "{name} tagged you in an urgent comment: 'Review the updated credentials sheet now.' View comment: {url}",
            "url_features": "collab_lure;credential_harvest",
            "style_shift": "urgent_imperative",
            "language": "en",
        },
        {
            "scenario": "sender_domain_metadata",
            "subject": "Microsoft 365 Security Alert",
            "body": "We detected unusual sign-in activity. Re-authenticate immediately here: {url}",
            "url_features": "brand_impersonation;lookalike_domain",
            "style_shift": "brand_impersonation",
            "language": "en",
        },
        {
            "scenario": "url_feature_rich",
            "subject": "Delivery Attempt Failed",
            "body": "We missed your package. Confirm your address and re-delivery fee now: {url}",
            "url_features": "suspicious_tld;urgent_cta;tracking_query",
            "style_shift": "urgent_imperative",
            "language": "en",
        },
        {
            "scenario": "attachment_feature_rich",
            "subject": "Invoice Attached - Action Required",
            "body": "Please review the attached invoice and enable content to view details. Portal mirror: {url}",
            "url_features": "attachment_lure;cta",
            "style_shift": "attachment_lure",
            "language": "en",
            "attachment_features": "invoice.xlsm;macro_prompt",
        },
        {
            "scenario": "multilingual_style_shift",
            "subject": "Actualizacion urgente de seguridad",
            "body": "Hemos detectado actividad inusual. Confirme su cuenta aqui: {url}",
            "url_features": "lookalike_domain;urgent_cta",
            "style_shift": "urgent_imperative",
            "language": "es",
        },
    ]


def _generate_benign_templates() -> List[Dict[str, str]]:
    return [
        {
            "scenario": "legitimate_transactional",
            "subject": "Your Order Receipt #{order_id}",
            "body": "Thanks for your purchase. View your order details in your account: {url}",
            "url_features": "known_good_domain",
            "style_shift": "neutral_transactional",
            "language": "en",
        },
        {
            "scenario": "legitimate_transactional",
            "subject": "Monthly Statement Available",
            "body": "Your statement is ready in the secure portal: {url}",
            "url_features": "known_good_domain",
            "style_shift": "formal_transactional",
            "language": "en",
        },
        {
            "scenario": "multilingual_style_shift",
            "subject": "Aggiornamento spedizione",
            "body": "Il tuo ordine e stato spedito. Traccia la spedizione qui: {url}",
            "url_features": "known_good_domain",
            "style_shift": "neutral_transactional",
            "language": "it",
        },
    ]


def _safe_sender_localpart(rng: random.Random, malicious: bool) -> str:
    pool = SAFE_SENDER_LOCALPARTS if malicious else BENIGN_LOCALPARTS
    return pool[rng.randrange(0, len(pool))]


def refresh_spam_threat_corpus(
    *,
    output_path: Optional[Path] = None,
    report_path: Optional[Path] = None,
    max_phish_rows: int = 800,
    max_ham_rows: int = 300,
    feedback_limit: int = 500,
    seed: int = 42,
) -> Dict[str, Any]:
    rng = random.Random(int(seed))
    backend_root = _backend_root()

    if output_path is None:
        output_path = backend_root / "data" / "corpus" / "phishing" / "raw" / "phishing_online_weaklabels.csv"
    if report_path is None:
        report_path = backend_root / "data" / "corpus" / "phishing" / "raw" / "phishing_online_weaklabels_report.json"

    rep_scores_path = Path(os.getenv("REPUTATION_SCORES_PATH", str(backend_root / "data" / "reputation" / "domain_scores.csv"))).resolve()
    allowlist_path = Path(os.getenv("REPUTATION_ALLOWLIST_PATH", str(backend_root / "data" / "reputation" / "allowlist.txt"))).resolve()

    online_domains = _collect_online_domains(max_domains=max(800, max_phish_rows * 2))
    rep_domains = _load_domains_from_reputation_scores(rep_scores_path, min_score=0.80, max_domains=max(1200, max_phish_rows * 2))
    allow_domains = sorted(_load_domain_list(allowlist_path))
    malicious_domains = sorted({d for d in (online_domains + rep_domains) if d and d not in set(allow_domains)})
    if not malicious_domains:
        malicious_domains = [
            "secure-bank-alerts.co",
            "teams-files-share.work",
            "parcel-redelivery-notice.top",
            "vendor-payments-update.com",
        ]
    if not allow_domains:
        allow_domains = ["microsoft.com", "google.com", "amazon.com", "github.com", "office.com"]

    phish_templates = _generate_phishing_templates()
    ham_templates = _generate_benign_templates()
    projects = ["Delta", "Falcon", "Atlas", "Q2 Migration", "Payroll Refresh", "Vendor Access"]
    names = ["Alex", "Jordan", "Sam", "Taylor", "Chris", "Morgan"]

    rows: List[Dict[str, str]] = []
    dedup: Set[str] = set()

    fn_feedback = _load_false_negative_feedback(limit=feedback_limit)
    for item in fn_feedback:
        subject = str(item.get("subject") or "").strip()
        body = str(item.get("body_text") or "").strip()
        sender = str(item.get("sender_email") or "").strip()
        if not (subject or body):
            continue
        key = f"fn|{subject}|{body}"
        if key in dedup:
            continue
        dedup.add(key)
        rows.append(
            {
                "label": "phishing",
                "scenario": "modern_phishing",
                "subject": subject or "Security Update Required",
                "body_text": body,
                "sender_email": sender or "alerts@security-notice.invalid",
                "sender_domain": _to_base_domain(_extract_host(sender.split("@")[-1]) or ""),
                "urls": "embedded",
                "url_features": "analyst_false_negative",
                "attachment_features": "none",
                "language": "en",
                "style_shift": "urgent_imperative",
                "notes": "analyst false-negative feedback weak label",
            }
        )
        if len(rows) >= max(1, int(max_phish_rows)):
            break

    phish_target = max(0, int(max_phish_rows) - len(rows))
    for idx in range(phish_target):
        tpl = phish_templates[idx % len(phish_templates)]
        domain = malicious_domains[idx % len(malicious_domains)]
        url = f"https://{domain}/auth/{1000 + (idx % 9000)}"
        subject = str(tpl["subject"]).format(project=projects[rng.randrange(0, len(projects))], order_id=10000 + idx)
        body = str(tpl["body"]).format(
            url=url,
            project=projects[rng.randrange(0, len(projects))],
            name=names[rng.randrange(0, len(names))],
            order_id=10000 + idx,
        )
        sender_local = _safe_sender_localpart(rng, malicious=True)
        sender_email = f"{sender_local}@{domain}"
        key = f"p|{subject}|{body}|{sender_email}"
        if key in dedup:
            continue
        dedup.add(key)
        rows.append(
            {
                "label": "phishing",
                "scenario": str(tpl["scenario"]),
                "subject": subject,
                "body_text": body,
                "sender_email": sender_email,
                "sender_domain": domain,
                "urls": url,
                "url_features": str(tpl.get("url_features") or "suspicious"),
                "attachment_features": str(tpl.get("attachment_features") or "none"),
                "language": str(tpl.get("language") or "en"),
                "style_shift": str(tpl.get("style_shift") or "urgent_imperative"),
                "notes": "online weak label from high-risk domains",
            }
        )

    ham_target = max(1, int(max_ham_rows))
    for idx in range(ham_target):
        tpl = ham_templates[idx % len(ham_templates)]
        domain = allow_domains[idx % len(allow_domains)]
        url = f"https://{domain}/account/{2000 + (idx % 8000)}"
        subject = str(tpl["subject"]).format(order_id=20000 + idx, project=projects[idx % len(projects)])
        body = str(tpl["body"]).format(url=url, order_id=20000 + idx)
        sender_local = _safe_sender_localpart(rng, malicious=False)
        sender_email = f"{sender_local}@{domain}"
        key = f"h|{subject}|{body}|{sender_email}"
        if key in dedup:
            continue
        dedup.add(key)
        rows.append(
            {
                "label": "ham",
                "scenario": str(tpl["scenario"]),
                "subject": subject,
                "body_text": body,
                "sender_email": sender_email,
                "sender_domain": domain,
                "urls": url,
                "url_features": str(tpl.get("url_features") or "known_good_domain"),
                "attachment_features": str(tpl.get("attachment_features") or "none"),
                "language": str(tpl.get("language") or "en"),
                "style_shift": str(tpl.get("style_shift") or "neutral_transactional"),
                "notes": "benign transactional weak label",
            }
        )

    scenario_set = {str(r.get("scenario") or "") for r in rows}
    for scenario in REQUIRED_SCENARIOS:
        if scenario in scenario_set:
            continue
        fallback_domain = malicious_domains[0] if scenario != "legitimate_transactional" else allow_domains[0]
        label = "ham" if scenario == "legitimate_transactional" else "phishing"
        rows.append(
            {
                "label": label,
                "scenario": scenario,
                "subject": f"Coverage sample for {scenario}",
                "body_text": f"Automatic coverage row for scenario '{scenario}'.",
                "sender_email": f"coverage@{fallback_domain}",
                "sender_domain": fallback_domain,
                "urls": f"https://{fallback_domain}/sample",
                "url_features": "coverage_seed",
                "attachment_features": "none",
                "language": "en",
                "style_shift": "neutral_transactional" if label == "ham" else "urgent_imperative",
                "notes": "required scenario coverage safeguard",
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "label",
                "scenario",
                "subject",
                "body_text",
                "sender_email",
                "sender_domain",
                "urls",
                "url_features",
                "attachment_features",
                "language",
                "style_shift",
                "notes",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    label_counts: Dict[str, int] = {}
    scenario_counts: Dict[str, int] = {}
    for row in rows:
        label = str(row.get("label") or "unknown")
        label_counts[label] = label_counts.get(label, 0) + 1
        scenario = str(row.get("scenario") or "unknown")
        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1

    report = {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": {
            "output_csv": str(output_path),
            "report_json": str(report_path),
        },
        "stats": {
            "total_rows": len(rows),
            "label_distribution": label_counts,
            "scenario_distribution": scenario_counts,
            "required_scenarios": REQUIRED_SCENARIOS,
            "missing_required_scenarios": sorted(list(set(REQUIRED_SCENARIOS) - set(scenario_counts.keys()))),
        },
        "sources": {
            "online_domain_count": len(online_domains),
            "reputation_domain_count": len(rep_domains),
            "allowlist_domain_count": len(allow_domains),
            "analyst_false_negative_rows": len(fn_feedback),
        },
        "params": {
            "max_phish_rows": int(max_phish_rows),
            "max_ham_rows": int(max_ham_rows),
            "feedback_limit": int(feedback_limit),
            "seed": int(seed),
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Build weak-labeled online spam/phishing corpus.")
    parser.add_argument("--max-phish-rows", type=int, default=int(os.getenv("SPAM_WEAKLABEL_MAX_PHISH_ROWS", "800")))
    parser.add_argument("--max-ham-rows", type=int, default=int(os.getenv("SPAM_WEAKLABEL_MAX_HAM_ROWS", "300")))
    parser.add_argument("--feedback-limit", type=int, default=int(os.getenv("SPAM_WEAKLABEL_FEEDBACK_LIMIT", "500")))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    report = refresh_spam_threat_corpus(
        max_phish_rows=max(50, int(args.max_phish_rows)),
        max_ham_rows=max(20, int(args.max_ham_rows)),
        feedback_limit=max(0, int(args.feedback_limit)),
        seed=int(args.seed),
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
