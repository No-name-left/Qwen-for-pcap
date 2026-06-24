#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK_API=0
BASE_URL="${LLM_BASE_URL:-${BASE_URL:-http://127.0.0.1:8000/v1}}"
MODEL="${LLM_MODEL_NAME:-${MODEL:-qwen3.5}}"
API_KEY="${LLM_API_KEY:-${API_KEY:-EMPTY}}"
PASS=0
WARN=0
FAIL=0

usage() {
  printf 'Usage: %s [--check-api] [--base-url URL] [--model NAME] [--api-key KEY]\n' "$0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-api) CHECK_API=1; shift ;;
    --base-url) BASE_URL="${2:?missing value for --base-url}"; shift 2 ;;
    --model) MODEL="${2:?missing value for --model}"; shift 2 ;;
    --api-key) API_KEY="${2:?missing value for --api-key}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '[FAIL] unknown argument: %s\n' "$1"; usage; exit 2 ;;
  esac
done

pass() { PASS=$((PASS + 1)); printf '[PASS] %s\n' "$*"; }
warn() { WARN=$((WARN + 1)); printf '[WARN] %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '[FAIL] %s\n' "$*"; }

printf 'Phase-1 VM readiness check\n'
printf 'Repository: %s\n' "$ROOT"
printf 'Current directory: %s\n' "$(pwd)"
printf 'Kernel: %s\n' "$(uname -a)"
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  printf 'OS: %s\n' "${PRETTY_NAME:-unknown}"
fi
if [[ -r /etc/openEuler-release ]]; then
  printf 'openEuler: %s\n' "$(cat /etc/openEuler-release)"
fi

if [[ -d /data ]]; then
  pass '/data exists'
  if command -v findmnt >/dev/null 2>&1 && findmnt -M /data >/dev/null 2>&1; then
    pass "/data mount: $(findmnt -M /data -no SOURCE,FSTYPE,TARGET 2>/dev/null | head -n 1)"
  else
    fail '/data exists but is not a distinct confirmed mount; inspect findmnt /data and lsblk -f'
  fi
  printf 'Filesystem: %s\n' "$(df -hT /data 2>/dev/null | tail -n 1)"
  [[ -r /data ]] && pass '/data is readable' || fail '/data is not readable'
  [[ -w /data ]] && pass '/data is writable' || warn '/data is not writable by the current user'
else
  fail '/data is missing; inspect lsblk -f, then mount manually if appropriate: mkdir -p /data && mount /dev/vdb1 /data'
fi

for directory in /data/competition_input /data/models /data/outputs; do
  if [[ -d "$directory" ]]; then
    pass "$directory exists"
  else
    warn "$directory is absent"
  fi
done

command -v python3 >/dev/null 2>&1 && pass "python3: $(python3 --version 2>&1)" || fail 'python3 is missing'
command -v tshark >/dev/null 2>&1 && pass "tshark: $(tshark --version 2>/dev/null | head -n 1)" || fail 'tshark is missing'
if command -v zeek >/dev/null 2>&1; then
  pass "zeek: $(zeek --version 2>&1 | head -n 1)"
elif command -v docker >/dev/null 2>&1; then
  if docker image inspect "${ZEEK_DOCKER_IMAGE:-zeek/zeek}" >/dev/null 2>&1; then
    warn "zeek binary is missing; local Docker image ${ZEEK_DOCKER_IMAGE:-zeek/zeek} is available as a manual fallback"
  else
    fail 'zeek is missing and no local Zeek Docker image is available (the checker will not pull one)'
  fi
else
  fail 'zeek is missing and Docker fallback is unavailable'
fi

for file in \
  .env.example \
  configs/phase1_vm.yaml \
  rag/metadata/rag_manifest.csv \
  rag/chunks/rag_chunks.jsonl \
  rag/index/keyword_index.json \
  scripts/run_phase1_pipeline.py \
  scripts/parse_public_pcaps.py \
  scripts/build_session_cards.py \
  scripts/build_classification_records.py \
  scripts/build_rag_query.py \
  scripts/retrieve_rag.py \
  scripts/evaluate_phase1_predictions.py; do
  [[ -f "$ROOT/$file" ]] && pass "$file" || fail "$file is missing"
done
if [[ ! -f "$ROOT/rag/chunks/rag_chunks.jsonl" || ! -f "$ROOT/rag/index/keyword_index.json" ]]; then
  warn 'rebuild RAG assets with: python3 scripts/build_rag_chunks.py && python3 scripts/build_keyword_index.py'
fi

if command -v python3 >/dev/null 2>&1; then
  if (cd "$ROOT" && python3 -m compileall -q scripts) && python3 - "$ROOT" <<'PY'
import importlib.util
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
required = ["yaml", "openai"]
missing = [name for name in required if importlib.util.find_spec(name) is None]
if missing:
    print("missing Python modules: " + ", ".join(missing))
    raise SystemExit(1)
PY
  then
    pass 'required Python modules and script syntax'
  else
    fail 'Python dependency or syntax check failed'
  fi
  if python3 - <<'PY'
try:
    import openpyxl  # noqa: F401
except ImportError:
    raise SystemExit(1)
PY
  then
    pass 'openpyxl is available for XLSX evaluation'
  else
    warn 'openpyxl is missing; CSV evaluation works, XLSX evaluation requires requirements.txt'
  fi
fi

if [[ "$CHECK_API" -eq 1 ]]; then
  HOST="$(python3 - "$BASE_URL" <<'PY' 2>/dev/null
import sys
from urllib.parse import urlparse
print(urlparse(sys.argv[1]).hostname or "")
PY
)"
  if [[ "$HOST" != '127.0.0.1' && "$HOST" != 'localhost' && "$HOST" != '::1' ]]; then
    fail "API readiness check only permits a loopback endpoint (received host: ${HOST:-invalid})"
  elif ! command -v curl >/dev/null 2>&1; then
    fail 'curl is missing; cannot perform optional API readiness check'
  else
    MODELS_JSON="$(mktemp)"
    if curl -fsS --max-time 8 -H "Authorization: Bearer $API_KEY" "${BASE_URL%/}/models" -o "$MODELS_JSON"; then
      if python3 - "$MODELS_JSON" "$MODEL" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
names = {str(item.get("id")) for item in data.get("data", []) if isinstance(item, dict)}
raise SystemExit(0 if not names or sys.argv[2] in names else 1)
PY
      then
        pass 'local OpenAI-compatible /models endpoint is reachable and model is present'
      else
        warn 'local API is reachable but the configured model name was not listed'
      fi
    else
      fail 'local OpenAI-compatible /models endpoint is not reachable'
    fi
    rm -f "$MODELS_JSON"
  fi
else
  warn 'API endpoint was not contacted; use --check-api for an explicit local /models probe'
fi

printf '\nSummary: PASS=%d WARN=%d FAIL=%d\n' "$PASS" "$WARN" "$FAIL"
[[ "$FAIL" -eq 0 ]]
