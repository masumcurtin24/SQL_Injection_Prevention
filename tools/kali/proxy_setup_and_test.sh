#!/usr/bin/env bash
set -euo pipefail

# Ready-to-run DVWA + mitmproxy addon (Kali)
# - Starts DVWA in Docker on Kali (if not running)
# - Installs mitmproxy and starts a lightweight addon that calls the analyzer
# - Sends a quick SQLi request via the proxy to demonstrate blocking

# Config (override via env)
ANALYZER_HOST="${ANALYZER_HOST:-10.0.2.2}"   # Windows host as seen from Kali (VirtualBox NAT)
ANALYZER_PORT="${ANALYZER_PORT:-8000}"
DVWA_HOST="${DVWA_HOST:-127.0.0.1}"
DVWA_PORT="${DVWA_PORT:-8080}"
PROXY_PORT="${PROXY_PORT:-8081}"

ANALYZER_SQL_URL="http://${ANALYZER_HOST}:${ANALYZER_PORT}/api/v1/analyze-sql/query"
DVWA_URL="http://${DVWA_HOST}:${DVWA_PORT}"

echo "[1/6] Checking prerequisites (docker, curl, apt)..."
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required"; exit 1; }

echo "[2/6] Installing mitmproxy (sudo)..."
sudo apt-get update -y >/dev/null
sudo apt-get install -y mitmproxy >/dev/null

echo "[3/6] Starting DVWA on ${DVWA_URL} (if not running)..."
if ! docker ps --format '{{.Names}}' | grep -q '^dvwa$'; then
  docker rm -f dvwa >/dev/null 2>&1 || true
  docker run -d --name dvwa -p "${DVWA_PORT}:80" vulnerables/web-dvwa >/dev/null
else
  echo "DVWA already running."
fi

echo "[4/6] Writing lightweight AI proxy addon to /tmp/ai_proxy_addon.py ..."
ADDON_PATH="/tmp/ai_proxy_addon.py"
cat > "${ADDON_PATH}" <<PY
import json
import httpx
from mitmproxy import http, ctx

DVWA_TARGET_HOST = "${DVWA_HOST}"
AI_SQL_ANALYSIS_ENDPOINT = "${ANALYZER_SQL_URL}"
BLOCKING_ACTIONS_SQL = {"BLOCK_IMMEDIATE", "FLAG_FOR_REVIEW_BLOCK"}

class Addon:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0))
        ctx.log.info(f"Addon loaded. Target={DVWA_TARGET_HOST} Analyzer={AI_SQL_ANALYSIS_ENDPOINT}")

    async def done(self):
        await self.client.aclose()

    def _strings_from_request(self, flow: http.HTTPFlow):
        vals = []
        try:
            # Query params
            for k, v in flow.request.query.items(multi=True):
                if isinstance(v, str):
                    vals.append(v)
        except Exception:
            pass
        try:
            ct = (flow.request.headers.get("Content-Type") or "").lower()
            if flow.request.method in ("POST", "PUT", "PATCH"):
                if "application/json" in ct:
                    try:
                        data = json.loads(flow.request.get_text() or "{}")
                        def collect(x):
                            if isinstance(x, dict):
                                for vv in x.values(): collect(vv)
                            elif isinstance(x, list):
                                for vv in x: collect(vv)
                            elif isinstance(x, str):
                                vals.append(x)
                        collect(data)
                    except Exception:
                        pass
                elif "application/x-www-form-urlencoded" in ct:
                    for k, v in flow.request.urlencoded_form.items(multi=True):
                        if isinstance(v, str):
                            vals.append(v)
        except Exception:
            pass
        # Dedup & tidy
        out, seen = [], set()
        for s in vals:
            s2 = (s or "").strip()
            if not s2 or s2 in seen:
                continue
            seen.add(s2)
            out.append(s2)
        return out

    async def request(self, flow: http.HTTPFlow):
        if flow.request.host != DVWA_TARGET_HOST:
            return
        candidates = self._strings_from_request(flow)
        for s in candidates:
            try:
                r = await self.client.post(AI_SQL_ANALYSIS_ENDPOINT, json={"query": s})
                js = r.json() if r.headers.get('content-type','').startswith('application/json') else {}
                ca = js.get("combined_assessment") or {}
                action = ca.get("suggested_action", "ALLOW")
                risk = ca.get("overall_risk_level", "Unknown")
                if action in BLOCKING_ACTIONS_SQL:
                    msg = f"Request blocked by AI Security Proxy. Risk={risk}. Snippet: {s[:100]}"
                    ctx.log.warn(msg)
                    flow.response = http.Response.make(403, msg.encode(), {"Content-Type": "text/plain"})
                    return
            except Exception as e:
                ctx.log.warn(f"AI call failed: {e}")
        ctx.log.info(f"Allowing {flow.request.method} {flow.request.pretty_url}")

addons = [Addon()]
PY

echo "[5/6] Launching mitmproxy on :${PROXY_PORT} ..."
nohup mitmproxy -p "${PROXY_PORT}" -s "${ADDON_PATH}" > /tmp/mitmproxy.log 2>&1 &
sleep 2
echo "mitmproxy started (log: /tmp/mitmproxy.log)."

echo "[6/6] Quick smoke test through proxy (expected 403 if blocked) ..."
TEST_URL="${DVWA_URL}/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit"
code=$(curl -s -o /dev/null -w "%{http_code}" -x "http://127.0.0.1:${PROXY_PORT}" "${TEST_URL}" || true)
echo "HTTP status via proxy: ${code}"

cat <<EOF

Next steps:
- Configure your Kali browser to use HTTP proxy 127.0.0.1:${PROXY_PORT}
- Browse DVWA at ${DVWA_URL}, try SQLi pages (the proxy will block High/Critical queries)
- Tail logs: tail -f /tmp/mitmproxy.log

To stop mitmproxy: pkill -f mitmproxy
EOF

echo "Done."

