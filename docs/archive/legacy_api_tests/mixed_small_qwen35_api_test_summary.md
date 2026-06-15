# Mixed small Qwen3.5 API test summary

## Scope

- API actually run: yes; requests were sent to Hugging Face Router, but several requests stalled until manually or externally terminated to keep the run small.
- Base URL host: `router.huggingface.co`
- Model name: `Qwen/Qwen3.5-27B:novita`
- Selected records: 10
- Contains portscan scan_group: true
- Token printed: no

## Results

- technique_rag success: 7
- technique_rag failed/interrupted: 3
- technique_rag JSON parse failures: 0
- technique_rag invalid code count: 0
- stage_rag success: 0
- stage_rag failed/interrupted: 1
- stage_rag JSON parse failures: 0
- stage_rag invalid code count: 0
- Portscan scan_group predicted as `TA43_01`: true
- CTU botnet-like records tended toward `TA11_02`: false (`TA11_02` count 0/6)
- CSV exported: false; partial model results were not converted into official CSV because missing selected records would require fabricated codes.
- Recommendation: do not expand to 30 or 50 until request timeout/stall behavior is fixed and prompt ordering keeps scan_group early.

## Verdict

`NEEDS_FIX`

## Notes

- Raw API responses and parsed per-batch outputs are under ignored `outputs/api_tests/**/raw/` and `outputs/api_tests/**/parsed/` paths.
- The successful scan_group technique prediction was `TA43_01` with high confidence.
