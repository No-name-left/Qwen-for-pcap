# Mixed small rerun plan

- Do not add selected records.
- Technique rerun records: 3
- Stage rerun records: 9
- Keep temperature 0, max tokens 512, and sleep between calls.
- Stop immediately on 401 or 402.

## Technique command

```bash
RUN_API=1 python3 scripts/run_qwen_openai_compatible.py \
  --prompt-dir outputs/api_tests/mixed_small/prompts_technique_rag \
  --output-dir outputs/api_tests/mixed_small/rerun_technique_rag \
  --result-name results.json \
  --summary-name summary.md \
  --only-record-ids outputs/api_tests/mixed_small/failed_technique_records.json \
  --failed-records-out outputs/api_tests/mixed_small/rerun_technique_rag/failed_records.json \
  --max-files 3 --temperature 0 --max-tokens 512 --sleep-seconds 2 \
  --retry-failed-once --continue-on-error --require-run-api-flag
```

## Stage command

```bash
RUN_API=1 python3 scripts/run_qwen_openai_compatible.py \
  --prompt-dir outputs/api_tests/mixed_small/prompts_stage_rag_scan_group_first \
  --output-dir outputs/api_tests/mixed_small/rerun_stage_rag \
  --result-name results.json \
  --summary-name summary.md \
  --only-record-ids outputs/api_tests/mixed_small/failed_stage_records.json \
  --failed-records-out outputs/api_tests/mixed_small/rerun_stage_rag/failed_records.json \
  --max-files 10 --temperature 0 --max-tokens 512 --sleep-seconds 2 \
  --retry-failed-once --continue-on-error --require-run-api-flag
```
