#!/usr/bin/env bash
set -euo pipefail

# Ready-to-run DVWA + PHP patch setup & quick tests (Kali)
# - Starts DVWA in Docker on Kali
# - Applies the DVWA SQL enforcement patch (calls analyzer; blocks High/Critical)
# - Verifies analyzer connectivity with a smoke query
# - Prints next steps to complete DVWA setup and test in browser

# Config (override via env)
ANALYZER_HOST="${ANALYZER_HOST:-10.0.2.2}"   # Windows host as seen from Kali (VirtualBox NAT)
ANALYZER_PORT="${ANALYZER_PORT:-8000}"
DVWA_HOST="${DVWA_HOST:-127.0.0.1}"
DVWA_PORT="${DVWA_PORT:-8080}"

ANALYZER_BASE_URL="http://${ANALYZER_HOST}:${ANALYZER_PORT}"
ANALYZER_SQL_URL="${ANALYZER_BASE_URL}/api/v1/analyze-sql/query"
DVWA_URL="http://${DVWA_HOST}:${DVWA_PORT}"

echo "[1/6] Checking prerequisites (docker, curl)..."
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required"; exit 1; }

echo "[2/6] Launching DVWA container on ${DVWA_URL} ..."
docker rm -f dvwa >/dev/null 2>&1 || true
docker run -d --name dvwa \
  -p "${DVWA_PORT}:80" \
  -e "DVWA_ANALYZER_URL=${ANALYZER_SQL_URL}" \
  vulnerables/web-dvwa >/dev/null

echo "[3/6] Preparing DVWA PHP enforcement patch..."
PATCH_TMP="/tmp/mysql_enforcement.patch"
cat > "${PATCH_TMP}" <<'PATCH'
--- a/dvwa/includes/DBMS/MySQL.php
+++ b/dvwa/includes/DBMS/MySQL.php
@@
 function dvwaDatabaseQuery( $link, $query ) {
 +    // --- DVWA SQL Enforcement Hook (added)
 +    // Calls external analyzer and blocks on High/Critical risk decisions
 +    // Configure analyzer URL via env DVWA_ANALYZER_URL (default: http://backend:8000/api/v1/analyze-sql/query)
 +    $dvwa_analyzer_url = getenv('DVWA_ANALYZER_URL');
 +    if (!$dvwa_analyzer_url) {
 +        $dvwa_analyzer_url = 'http://backend:8000/api/v1/analyze-sql/query';
 +    }
 +    $should_block = false;
 +    try {
 +        $payload = json_encode([ 'query' => $query ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
 +        if ($payload !== false) {
 +            $ch = curl_init($dvwa_analyzer_url);
 +            curl_setopt($ch, CURLOPT_POST, true);
 +            curl_setopt($ch, CURLOPT_HTTPHEADER, [ 'Content-Type: application/json' ]);
 +            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
 +            curl_setopt($ch, CURLOPT_TIMEOUT, 2);
 +            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
 +            $resp_raw = curl_exec($ch);
 +            if ($resp_raw !== false) {
 +                $resp = json_decode($resp_raw, true);
 +                if (is_array($resp) && isset($resp['combined_assessment']['overall_risk_level'])) {
 +                    $risk = $resp['combined_assessment']['overall_risk_level'];
 +                    if ($risk === 'High' || $risk === 'Critical') {
 +                        $should_block = true;
 +                    }
 +                }
 +            }
 +            curl_close($ch);
 +        }
 +    } catch (\Throwable $e) {
 +        // Fail-open on analyzer errors (optional): keep as-is for DVWA lab
 +    }
 +    if ($should_block) {
 +        http_response_code(403);
 +        die('Blocked by SQL policy (risk decision High/Critical).');
 +    }
     // ... original body continues below ...
 }
PATCH

echo "[4/6] Applying patch inside DVWA container..."
docker cp "${PATCH_TMP}" dvwa:/tmp/mysql_enforcement.patch
docker exec -i dvwa sh -c "cd /var/www/html && patch -p1 < /tmp/mysql_enforcement.patch"
docker exec -i dvwa sh -c "grep -n 'DVWA SQL Enforcement Hook' /var/www/html/dvwa/includes/DBMS/MySQL.php" >/dev/null \
  && echo "Patch verified in DVWA container." \
  || { echo "ERROR: Patch verification failed"; exit 1; }

echo "[5/6] Smoke test analyzer connectivity (direct API)..."
set +e
curl -s -X POST "${ANALYZER_SQL_URL}" -H 'Content-Type: application/json' \
  -d '{"query":"SELECT 1; DROP TABLE users; --"}' | sed -E 's/(\{|\}|\[|\])/\n&/g' | sed -n '1,20p'
rc=$?
set -e
if [ $rc -ne 0 ]; then
  echo "WARN: Analyzer connectivity check may have failed; ensure Windows firewall allows port ${ANALYZER_PORT}."
fi

echo
echo "[6/6] Manual DVWA init (one-time in browser)"
cat <<EOF
- Open: ${DVWA_URL}
- Login: admin / password
- Setup: go to "Setup" and click "Create/Reset Database"
- Security: go to "DVWA Security" and set to "Low"

Then test a few payloads on the SQL Injection page (expect 403 blocks from the patch):
- ${DVWA_URL}/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit
- ${DVWA_URL}/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201,%20@@version,%203%20--%20-&Submit=Submit
- ${DVWA_URL}/vulnerabilities/sqli/?id=1;%20DROP%20TABLE%20users;%20--&Submit=Submit

Tip: Watch analyzer logs on Windows to see decisions.
EOF

echo
echo "Done. If you need fully automated DVWA login/security setup, say the word and I’ll add it."

