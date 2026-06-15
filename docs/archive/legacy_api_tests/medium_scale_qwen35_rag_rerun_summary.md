# Medium-scale Qwen3.5 RAG rerun summary

- API actually run: false
- Base URL host: `router.huggingface.co`
- Model name: `Qwen/Qwen3.5-27B:novita`
- Selected records: 96
- Max records for this rerun: 50
- Technique_rag success/failure/timeout/illegal/json_parse: 0/0/0/0/0
- Stage_from_technique fallback used: false
- CSV exported: false
- Portscan scan_group predicted `TA43_01`: not evaluated in this rerun
- CTU botnet-like tendency toward `TA11_02`: not evaluated in this rerun
- CTU normal-like tendency toward `TN01_01`: not evaluated in this rerun
- Public label rough evaluation: not run; no new model predictions were produced
- Expand to 96 records: no, rerun is blocked until `RUN_API=1` is present
- Recommendation for tomorrow: keep local endpoint option ready if HF Router timeout behavior continues after enabling API
- Verdict: `NEEDS_FIX`

Blocking condition: `RUN_API` was not set to `1`; no API call was made.
