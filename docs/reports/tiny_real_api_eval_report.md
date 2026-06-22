# Tiny real API paired-evaluation report

Date: 2026-06-22

- Status: `not_run_by_safety_gate`
- Remote readiness: passed (`/models` and one minimal chat both HTTP 200).
- Thinking off: supported.
- Usage tokens: returned by provider.
- `RUN_REAL_API_TEST=1`: not set.
- Paired calls made: 0.

The repository correctly stopped before model-quality testing. When explicitly enabled, select at most two records and run two no-RAG plus two RAG calls into `outputs/api_eval_tiny_real/`; then evaluate by confidence tier and inspect `error_cases.jsonl` before any larger run.

Recommended command after explicit approval:

```bash
RUN_REAL_API_TEST=1 python3 scripts/run_public_eval_api.py \
  --eval-records datasets/public_eval/real_api_candidate_records.jsonl \
  --runtime-profile nvidia_ubuntu_online_api --run-api \
  --max-records 2 --max-per-class 1 --output-dir outputs/api_eval_tiny_real
```
