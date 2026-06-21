#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PARSED_DIR="$ROOT/outputs/parsed"
OUTPUT_ROOT="$ROOT/outputs"
MAX_CARDS=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --parsed-dir) PARSED_DIR="$2"; shift 2 ;;
    --output-root) OUTPUT_ROOT="$2"; shift 2 ;;
    --max-cards) MAX_CARDS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

SESSION_DIR="$OUTPUT_ROOT/session_cards"
QUERY_DIR="$OUTPUT_ROOT/rag_queries"
RETRIEVAL_DIR="$OUTPUT_ROOT/rag_retrieval"
SUBMISSION_DIR="$OUTPUT_ROOT/submissions"

python3 scripts/build_session_cards.py \
  --parsed-dir "$PARSED_DIR" \
  --output "$SESSION_DIR/session_cards_all.json" \
  --llm-output "$SESSION_DIR/llm_session_cards_all.json" \
  --report "$SESSION_DIR/session_cards_report.md" \
  --max-cards "$MAX_CARDS"
python3 scripts/build_classification_records.py \
  --session-cards "$SESSION_DIR/session_cards_all.json" \
  --scan-groups-output "$SESSION_DIR/scan_groups.json" \
  --records-output "$SESSION_DIR/classification_records_all.json" \
  --report "$SESSION_DIR/classification_records_report.md"
python3 scripts/build_rag_query.py \
  --input "$SESSION_DIR/classification_records_all.json" \
  --output "$QUERY_DIR/qwen35_session_records_rag_queries.jsonl" \
  --report "$QUERY_DIR/qwen35_session_records_rag_query_report.md"
python3 scripts/retrieve_rag.py \
  --queries "$QUERY_DIR/qwen35_session_records_rag_queries.jsonl" \
  --output "$RETRIEVAL_DIR/qwen35_session_records_retrieved_knowledge_top5.json" \
  --report "$RETRIEVAL_DIR/qwen35_session_records_retrieval_report_top5.md" \
  --top-k 5
python3 scripts/build_qwen35_session_prompts.py \
  --records "$SESSION_DIR/classification_records_all.json" \
  --retrieval "$RETRIEVAL_DIR/qwen35_session_records_retrieved_knowledge_top5.json" \
  --micro-output-dir "$OUTPUT_ROOT" \
  --report "$OUTPUT_ROOT/prompts_qwen35_technique_prompt_report.md"
python3 scripts/export_competition_csv.py \
  --records "$SESSION_DIR/classification_records_all.json" \
  --stage-output "$SUBMISSION_DIR/stage1_submission.csv" \
  --technique-output "$SUBMISSION_DIR/stage2_submission.csv" \
  --report "$SUBMISSION_DIR/submission_export_report.md" \
  --dry-run

echo "stage1 offline pipeline complete; no model API was called"
echo "run scripts/run_qwen_openai_compatible.py explicitly with a reviewed technique prompt directory to call an API"
