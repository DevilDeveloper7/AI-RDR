#!/usr/bin/env bash
# One example request per service. Keys come from environment variables only:
#   export ABUSECH_AUTH_KEY=...   export OTX_API_KEY=...
# Usage: scripts/curl_examples.sh [sha256] [ip] [domain]
# Only hashes are sent: no files are downloaded or executed.
set -u
HASH="${1:-0000000000000000000000000000000000000000000000000000000000000000}"
IP="${2:-8.8.8.8}"
DOMAIN="${3:-example.com}"
: "${ABUSECH_AUTH_KEY:?set ABUSECH_AUTH_KEY first}"

echo "== MalwareBazaar get_info =="
curl -sS --max-time 15 -X POST https://mb-api.abuse.ch/api/v1/ \
  -H "Auth-Key: ${ABUSECH_AUTH_KEY}" -d "query=get_info&hash=${HASH}"; echo

echo "== ThreatFox search_hash =="
curl -sS --max-time 15 -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Auth-Key: ${ABUSECH_AUTH_KEY}" -H "Content-Type: application/json" \
  -d "{\"query\": \"search_hash\", \"hash\": \"${HASH}\"}"; echo

echo "== ThreatFox search_ioc (exact) =="
curl -sS --max-time 15 -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Auth-Key: ${ABUSECH_AUTH_KEY}" -H "Content-Type: application/json" \
  -d "{\"query\": \"search_ioc\", \"search_term\": \"${DOMAIN}\", \"exact_match\": true}"; echo

echo "== URLhaus host =="
curl -sS --max-time 15 -X POST https://urlhaus-api.abuse.ch/v1/host/ \
  -H "Auth-Key: ${ABUSECH_AUTH_KEY}" -d "host=${DOMAIN}"; echo

if [ -n "${OTX_API_KEY:-}" ]; then
  echo "== OTX IPv4 general =="
  curl -sS --max-time 15 -w '\nHTTP %{http_code}\n' \
    -H "X-OTX-API-KEY: ${OTX_API_KEY}" \
    "https://otx.alienvault.com/api/v1/indicators/IPv4/${IP}/general" | head -c 2000; echo
else
  echo "(OTX_API_KEY not set: skipping OTX)"
fi
