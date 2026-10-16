#!/usr/bin/env python3
"""
MySQL general_log tail-and-forward script.

Reads a MySQL/MariaDB general log file, extracts SQL statements from 'Query' lines,
and posts them to the analyzer endpoint (default http://localhost:8000/api/v1/analyze-sql/query).

Usage:
  python mysql_general_log_forwarder.py --log /var/log/mysql/general.log \
      --endpoint http://backend:8000/api/v1/analyze-sql/query --batch-size 1

Notes:
  - Run with a user that can read the general log file.
  - Enable general log on the DB: --general-log=1 --general-log-file=/var/log/mysql/general.log
  - In docker-compose, mount /var/log/mysql into this container under /logs.
"""
import argparse
import os
import re
import sys
import time
import json
from typing import List

try:
    import requests
except Exception:
    print("ERROR: requests is required. pip install requests", file=sys.stderr)
    sys.exit(1)


def tail_f(path: str):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


QUERY_RE = re.compile(r"\bQuery\b\s+(.*)$", re.IGNORECASE)


def extract_query(line: str) -> str:
    m = QUERY_RE.search(line)
    if m:
        return m.group(1).strip()
    return ""


def post_queries(endpoint: str, queries: List[str], timeout: float = 2.0):
    for q in queries:
        try:
            resp = requests.post(endpoint, json={"query": q}, timeout=timeout)
            data = resp.json() if resp.headers.get('content-type','').startswith('application/json') else {}
            risk = (data.get('combined_assessment') or {}).get('overall_risk_level') or 'Unknown'
            print(f"[{resp.status_code}] risk={risk} q={(q[:120] + '...') if len(q)>120 else q}")
        except Exception as e:
            print(f"WARN: analyzer post failed: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', required=True, help='Path to MySQL general log')
    ap.add_argument('--endpoint', default='http://localhost:8000/api/v1/analyze-sql/query')
    ap.add_argument('--batch-size', type=int, default=1)
    args = ap.parse_args()

    buf: List[str] = []
    for line in tail_f(args.log):
        q = extract_query(line)
        if not q:
            continue
        buf.append(q)
        if len(buf) >= args.batch_size:
            post_queries(args.endpoint, buf)
            buf.clear()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

