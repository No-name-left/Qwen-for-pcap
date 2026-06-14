#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

RUN_API=false
for arg in "$@"; do
  case "$arg" in
    --run-api) RUN_API=true ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

python3 scripts/build_session_cards.py
python3 scripts/build_classification_records.py
python3 scripts/build_rag_query.py
python3 scripts/retrieve_rag.py --top-k 5
python3 scripts/build_qwen35_session_prompts.py
python3 scripts/export_competition_csv.py --dry-run

if [ "$RUN_API" = true ]; then
  echo "--run-api was requested, but this offline skeleton does not automatically call a model API." >&2
  echo "Use an explicit reviewed runner invocation with session-level prompts and official codes." >&2
  exit 3
fi

echo "stage1 offline skeleton complete"
