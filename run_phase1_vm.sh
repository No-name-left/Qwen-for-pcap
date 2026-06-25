#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR=""
CONFIG="$ROOT/configs/phase1_vm.yaml"
ARGS=("$@")

for arg in "${ARGS[@]}"; do
  if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
    exec python3 "$ROOT/scripts/run_phase1_pipeline.py" --help
  fi
done

index=0
while [[ "$index" -lt "${#ARGS[@]}" ]]; do
  case "${ARGS[$index]}" in
    --output-dir=*)
      OUTPUT_DIR="${ARGS[$index]#--output-dir=}"
      ;;
    --output-dir)
      index=$((index + 1))
      OUTPUT_DIR="${ARGS[$index]:?missing value for --output-dir}"
      ;;
    --config=*)
      CONFIG="${ARGS[$index]#--config=}"
      ;;
    --config)
      index=$((index + 1))
      CONFIG="${ARGS[$index]:?missing value for --config}"
      ;;
  esac
  index=$((index + 1))
done

if [[ -z "$OUTPUT_DIR" ]]; then
  if [[ -n "${PHASE1_OUTPUT_DIR:-}" ]]; then
    OUTPUT_DIR="$PHASE1_OUTPUT_DIR"
  else
    OUTPUT_BASE="$(python3 - "$CONFIG" <<'PY'
import pathlib
import sys
import yaml

config = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")) or {}
print(config.get("output_dir") or "/data/pcap/output")
PY
)"
    OUTPUT_DIR="${OUTPUT_BASE}_$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  ARGS+=(--output-dir "$OUTPUT_DIR")
fi

if [[ "$OUTPUT_DIR" == /data/* ]]; then
  if [[ ! -d /data ]]; then
    printf 'Refusing to create output under /data because /data does not exist. Run scripts/check_vm_ready.sh first.\n' >&2
    exit 1
  fi
  if command -v findmnt >/dev/null 2>&1 && ! findmnt -M /data >/dev/null 2>&1; then
    printf 'Refusing to write under /data because /data is not a confirmed mount. Check findmnt /data first.\n' >&2
    exit 1
  fi
fi

mkdir -p "$OUTPUT_DIR"
printf 'Phase-1 VM runner starting. Output: %s\n' "$OUTPUT_DIR"
printf 'Qwen thinking control: chat_template_kwargs.enable_thinking defaults to false; override with --enable-thinking or --disable-thinking.\n'
set +e
python3 "$ROOT/scripts/run_phase1_pipeline.py" "${ARGS[@]}" 2>&1 | tee -a "$OUTPUT_DIR/run.log"
STATUS=${PIPESTATUS[0]}
set -e
printf 'Phase-1 VM runner finished with status %d. Summary: %s/run_summary.md\n' "$STATUS" "$OUTPUT_DIR"
exit "$STATUS"
