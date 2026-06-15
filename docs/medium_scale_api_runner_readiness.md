# Medium-scale API runner readiness

- `--prompt-dir`: supported
- `--output-dir`: supported
- `--max-files`: supported
- `--temperature`: supported
- `--max-tokens`: supported
- `--sleep-seconds`: supported
- `--timeout-seconds`: supported
- `--continue-on-error`: supported
- `--retry-failed-once`: supported
- `--require-run-api-flag`: supported
- `--resume`: supported
- Failed records are recorded by `record_id` and prompt filename when `--failed-records-out` is set.
- 401/402 errors stop the run; timeout/provider/rate-limit errors can be retried and continued with the appropriate flags.
- Token values are not printed by the runner.
- Raw and parsed model outputs are written below ignored output subdirectories.
