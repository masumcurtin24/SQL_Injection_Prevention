"""
Build/refresh spam phishing domain reputation scores.

Outputs:
- backend/data/reputation/domain_scores.csv
- backend/data/reputation/allowlist.txt (ensures baseline trusted domains)

Usage:
  python -m backend.scripts.update_spam_reputation_feed
"""

from __future__ import annotations

import csv
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen


FEEDS: List[Tuple[str, str, float]] = [
    (
        "phishing_database_active",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        0.97,
    ),
    (
        "urlhaus_hostfile",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        0.95,
    ),
    (
        "openphish_feed",
        "https://openphish.com/feed.txt",
        0.94,
    ),
]

TRUSTED_ALLOWLIST = [
    "microsoft.com",
    "office.com",
    "office365.com",
    "google.com",
    "googleusercontent.com",
    "gmail.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "aws.amazon.com",
    "paypal.com",
    "stripe.com",
    "github.com",
    "gitlab.com",
    "atlassian.com",
    "slack.com",
    "zoom.us",
    "dropbox.com",
    "docusign.com",
    "adobe.com",
    "salesforce.com",
    "servicenow.com",
    "linkedin.com",
    "x.com",
    "facebook.com",
    "whatsapp.com",
    "youtube.com",
    "netflix.com",
    "reddit.com",
    "cloudflare.com",
]

LOCAL_HIGH_RISK_SEEDS = [
    "account-verify.click",
    "login-secure.xyz",
    "security-update.top",
    "giftcard-prize.work",
    "payroll-verify-secure.com",
    "microsoft-credential-check.com",
    "docusign-review-center.info",
    "expense-portal-refund.net",
    "tax-refund-fasttrack.online",
    "sso-certificate-sync.com",
    "drive-doc-viewer-secure.net",
    "security-extension-check.org",
    "utility-fastpay-billing.com",
]


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
        chunks = line.split()
        if len(chunks) >= 2:
            line = chunks[1].strip()
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
    if not re.match(r"^[a-zA-Z0-9._-]+$", line):
        return None
    if "." not in line:
        return None
    return line.lower()


def _download_lines(url: str) -> Iterable[str]:
    req = Request(url, headers={"User-Agent": "DefenderAI-ReputationUpdater/1.0"})
    with urlopen(req, timeout=20) as resp:
        data = resp.read().decode("utf-8", errors="ignore")
    for line in data.splitlines():
        yield line


def _merge_score(scores: Dict[str, Tuple[float, str]], domain: str, score: float, source: str) -> None:
    d = _to_base_domain(domain)
    if not d:
        return
    current = scores.get(d)
    if current is None or score > current[0]:
        scores[d] = (score, source)


def main() -> int:
    project_root = Path(__file__).resolve().parents[2]
    reputation_dir = project_root / "backend" / "data" / "reputation"
    reputation_dir.mkdir(parents=True, exist_ok=True)

    out_path = Path(os.getenv("REPUTATION_SCORES_PATH", str(reputation_dir / "domain_scores.csv"))).resolve()
    blocklist_path = Path(os.getenv("REPUTATION_BLOCKLIST_PATH", str(reputation_dir / "blocklist.txt"))).resolve()
    allowlist_path = Path(os.getenv("REPUTATION_ALLOWLIST_PATH", str(reputation_dir / "allowlist.txt"))).resolve()

    scores: Dict[str, Tuple[float, str]] = {}
    stats = {"remote_domains": 0, "local_blocklist": 0, "local_seed": 0, "allowlist_written": 0}

    for source_name, url, source_score in FEEDS:
        try:
            count = 0
            for raw in _download_lines(url):
                host = _extract_host(raw)
                if not host:
                    continue
                _merge_score(scores, host, source_score, source_name)
                count += 1
            stats["remote_domains"] += count
            print(f"[feed] {source_name}: {count} rows")
        except Exception as exc:
            print(f"[feed] {source_name}: skipped ({exc})")

    if blocklist_path.exists():
        with open(blocklist_path, "r", encoding="utf-8", errors="ignore") as fp:
            for line in fp:
                host = _extract_host(line)
                if not host:
                    continue
                _merge_score(scores, host, 0.99, "local_blocklist")
                stats["local_blocklist"] += 1

    for seed in LOCAL_HIGH_RISK_SEEDS:
        _merge_score(scores, seed, 0.98, "local_seed")
        stats["local_seed"] += 1

    allowlist_entries = set()
    if allowlist_path.exists():
        with open(allowlist_path, "r", encoding="utf-8", errors="ignore") as fp:
            for line in fp:
                host = _extract_host(line)
                if host:
                    allowlist_entries.add(_to_base_domain(host))
    allowlist_entries.update(_to_base_domain(d) for d in TRUSTED_ALLOWLIST if d)

    with open(allowlist_path, "w", encoding="utf-8", newline="") as fp:
        for domain in sorted(x for x in allowlist_entries if x):
            fp.write(f"{domain}\n")
            stats["allowlist_written"] += 1

    for domain in allowlist_entries:
        if domain:
            scores[domain] = (0.0, "allowlist")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(["domain", "score", "source", "updated_at"])
        now = datetime.now(timezone.utc).isoformat()
        for domain, (score, source) in sorted(scores.items()):
            writer.writerow([domain, f"{score:.4f}", source, now])

    print(f"[write] domain scores: {out_path} ({len(scores)} domains)")
    print(f"[write] allowlist: {allowlist_path} ({stats['allowlist_written']} domains)")
    print(f"[stats] {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
