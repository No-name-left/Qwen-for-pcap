# Mixed small failure diagnosis

## Findings

- Selected records: 10
- Technique successful records: 7
- Technique missing/failed records: 3
- Stage successful records: 1
- Stage missing/failed records: 9
- 401 unauthorized evidence: false
- 402 quota depleted evidence: false
- 429 rate limit evidence: false
- JSON parse failure evidence: false
- Illegal code evidence: false

## Technique Failures

- ctu13_scenario1::session::000197: interrupted by script logic; No per-record provider error was persisted; the previous primary technique run stopped after six successes, and this selected record was not completed.
- ctu13_scenario1::session::000196: interrupted by script logic; No per-record provider error was persisted; the previous primary technique run stopped after six successes, and this selected record was not completed.
- ctu13_scenario1::session::000191: interrupted by script logic; No per-record provider error was persisted; the previous primary technique run stopped after six successes, and this selected record was not completed.

## Stage Failures

- Stage did not fail because of a technique stop condition. The persisted summary shows scan_group stage success, then `ctu13_scenario1::session::000002` timed out.
- The remaining stage records were not completed because the run was stopped to keep the test bounded.

## Recommendation

- Rerun only the failed technique records and missing stage records when `RUN_API=1` and all LLM environment variables are set.
- No prompt change is indicated by the previous results; successful outputs were valid JSON with legal codes.
- Runner changes are useful: failed record export, record-id filtering, retry-once, continue-on-error, and immediate stop on 401/402.
