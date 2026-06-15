# Medium-scale Qwen3.5 RAG test summary

- API actually run: false
- Endpoint kind: HF Router
- Base URL host: `router.huggingface.co`
- Model name: `Qwen/Qwen3.5-27B:novita`
- Selected records: 96
- Technique success/failure/timeout/illegal/json_parse: 0/96/0/0/0
- Stage success/failure/timeout/illegal/json_parse: 0/96/0/0/0
- Stage_from_technique fallback used for CSV: false
- CSV exported: false
- Portscan scan_group predicted `TA43_01`: false
- CTU botnet-like tendency toward `TA11_02`: 0/0 predictions
- CTU normal-like tendency toward `TN01_01`: 0/0 predictions
- RAG prompt issue observed: none from static prompt checks; prompts exclude `candidate_hint` and public labels.
- Cautious conclusion: no medium-scale online effect conclusion is available unless API is explicitly run; current artifacts prepare a bounded public feasibility evaluation.
- Expand to 200 records: no, not until a medium-scale online run completes with stable timeout behavior.
- Recommendation for tomorrow: consider switching to a local model endpoint if HF Router timeouts continue.
- Missing category samples: `TA43_02`, `TA03_01`, `TA11_01`.
- Verdict: `NEEDS_FIX`
