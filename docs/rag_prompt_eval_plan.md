# RAG vs no-RAG paired evaluation plan

## Contract

- Use the same selected record IDs for both prompt types.
- The model predicts one official `technique_code`; it never predicts `stage_code`.
- Ground truth and label confidence remain outside `CLASSIFICATION_RECORD` and outside retrieved snippets.
- Default execution only creates prompts. API calls require the explicit `--run-api` switch.
- Prompt/mock preparation may use up to 64 records. Real API execution is safety-gated to at most two paired records (four calls), `RUN_REAL_API_TEST=1`, and a passing readiness report.
- `run_public_eval_api.py` retains that two-record ceiling. Guarded 8-12 record strict evaluation uses `run_small_api_eval.py`, which must pass its two-record smoke phase before starting the strict phase.
- Current prompt version is `observable_timing_boundary_rag_v4`; every prompt manifest and evaluation context records it. Historical v3 reports remain unchanged.
- Targeted RAG cards are selected from record features for the five named confusion pairs. They are ordered before ordinary top-k snippets but remain subordinate to record evidence.
- Runtime-profile budgets cap session context, snippet count/size and final prompt length.

## Commands

```bash
# Prompt-only, no network/API call
python3 scripts/run_public_eval_api.py --max-records 20 --max-per-class 5

# Local vLLM OpenAI-compatible endpoint
BASE_URL=http://127.0.0.1:8000/v1 MODEL=qwen3.5 API_KEY=EMPTY \
  python3 scripts/run_public_eval_api.py --run-api --max-records 20 --max-per-class 5

# Provider that rejects Qwen-specific extra_body
python3 scripts/run_public_eval_api.py --run-api --disable-extra-body

# Paired deterministic plumbing test, no network/model call
python3 scripts/run_public_eval_api.py --run-mock --max-records 20 --max-per-class 5

# 24-record tiered candidate plumbing test (still no real model call)
python3 scripts/run_public_eval_api.py \
  --eval-records datasets/public_eval/real_api_candidate_records.jsonl \
  --run-mock --max-records 24 --max-per-class 3

# Re-evaluate already saved runner outputs without another API call
python3 scripts/evaluate_rag_vs_no_rag.py
```

Guarded smoke plus strict online evaluation:

```bash
# Prompt/cost preparation only; no API call
python3 scripts/run_small_api_eval.py --dry-run --phase all --max-records 12

# Two-record smoke, then 8-12 strict external-high records only if smoke passes
RUN_REAL_API_TEST=1 python3 scripts/run_small_api_eval.py \
  --run-api --phase all --max-records 12 --resume
```

The staged runner records request IDs, latency, token usage, parse/label status, prompt evidence metadata, paired results, cost, and tiered reports. It forces Qwen thinking off and stops if the provider reports nonzero reasoning tokens.

`OPENAI_BASE_URL` / `OPENAI_MODEL` / `OPENAI_API_KEY`, `BASE_URL` / `MODEL` / `API_KEY`, and the corresponding `LLM_*` aliases are equivalent. No key is printed or written to evaluation context.

## Outputs

- `results_long.jsonl`: paired record-level raw/parsed output, retrieval context and failure type.
- `summary.md`: overall/scoped metrics, improvements, regressions, disagreements and selected confusion pairs.
- `confusion_matrix.csv`: counts including `__ERROR__` predictions.
- `per_class_metrics.csv`: per-code accuracy split by confidence/source scope.
- `error_cases.jsonl`: incorrect, failed or disagreeing pairs.

The summary always separates high-confidence-only, all labels, `flow_only`, and PCAP/session-derived metrics. Medium/low mappings are exploratory and cannot be presented as high-confidence accuracy.

Mock accuracy is never a model-quality result. For real comparisons, inspect per-record `targeted_boundary_doc_ids`, prompt character/token estimates, and whether a regression followed a boundary card that conflicted with stronger session behavior.
