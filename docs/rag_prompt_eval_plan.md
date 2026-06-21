# RAG vs no-RAG paired evaluation plan

## Contract

- Use the same selected record IDs for both prompt types.
- The model predicts one official `technique_code`; it never predicts `stage_code`.
- Ground truth and label confidence remain outside `CLASSIFICATION_RECORD` and outside retrieved snippets.
- Default execution only creates prompts. API calls require the explicit `--run-api` switch.
- API runs use `temperature=0`, `max_tokens=512`, at most 20 records, and Qwen thinking disabled by default.

## Commands

```bash
# Prompt-only, no network/API call
python3 scripts/run_public_eval_api.py --max-records 20 --max-per-class 5

# Local vLLM OpenAI-compatible endpoint
BASE_URL=http://127.0.0.1:8000/v1 MODEL=qwen3.5 API_KEY=EMPTY \
  python3 scripts/run_public_eval_api.py --run-api --max-records 20 --max-per-class 5

# Provider that rejects Qwen-specific extra_body
python3 scripts/run_public_eval_api.py --run-api --disable-extra-body

# Re-evaluate already saved runner outputs without another API call
python3 scripts/evaluate_rag_vs_no_rag.py
```

`BASE_URL` / `MODEL` / `API_KEY` and `LLM_BASE_URL` / `LLM_MODEL_NAME` / `LLM_API_KEY` are equivalent. No key is printed or written to evaluation context.

## Outputs

- `results_long.jsonl`: paired record-level raw/parsed output, retrieval context and failure type.
- `summary.md`: overall/scoped metrics, improvements, regressions, disagreements and selected confusion pairs.
- `confusion_matrix.csv`: counts including `__ERROR__` predictions.
- `per_class_metrics.csv`: per-code accuracy split by confidence/source scope.
- `error_cases.jsonl`: incorrect, failed or disagreeing pairs.

The summary always separates high-confidence-only, all labels, `flow_only`, and PCAP/session-derived metrics. Medium/low mappings are exploratory and cannot be presented as high-confidence accuracy.
