# Public dataset and paired-evaluation implementation report

Date: 2026-06-22

## Protected starting point

- The pre-round working tree is preserved in `docs/reports/first_round_worktree_checkpoint.patch`.
- No pre-existing modifications were discarded.
- Mainline checks after this round: runtime Suricata hits `0`; active RAG-input hits `0`; stage prompt files `0`.

## Public data assets

- Candidate catalog: 10 dataset families.
- Label mapping candidates: 47 rows with explicit `high` / `medium` / `low` confidence and manual-review flags.
- Download manifest: 41 rows.
- Status totals: 15 `downloaded`, 13 `already_exists`, 7 `manual_required`, 5 `skipped_large`, 1 historical `failed` zero-byte artifact.
- This run downloaded 687,718,224 bytes: three additional CTU-13 botnet-only PCAPs, their three flow-label files, three scenario READMEs, and six official/source-page snapshots.
- No malware binary or protected malware archive was downloaded or extracted.
- Full CIC/UNSW/IoT/BoT-IoT corpora remain skipped or manual; no single file over 10GB was downloaded.

## Current official-code coverage

| Code | Locally runnable source | Confidence / limitation |
|---|---|---|
| `TA43_01` | Controlled Nmap Zeek `scan_group` | high controlled; only one environment |
| `TA43_02` | none | service-scan/enumeration candidates remain medium/low |
| `TA01_01` | CSE-CIC-IDS2018 FTP/SSH brute-force rows | high, flow-only |
| `TA01_02` | CSE-CIC-IDS2018 SQL Injection/XSS rows | medium, flow-only |
| `TA03_01` | none | infiltration/backdoor-family candidates require manual phase evidence |
| `TA11_01` | none | requires direction and existing-backdoor context |
| `TA11_02` | CTU-13 botnet PCAP/labels; CSE Bot rows | CTU high; CSE medium flow-only |
| `TN01_01` | CSE Benign; CTU `From-Normal*` candidate | explicit benign/normal high; background excluded |

All eight codes have documented candidates, but `TA43_02`, `TA03_01`, and `TA11_01` are intentionally left empty in the runnable split rather than filled with guessed high-confidence labels.

## Public evaluation loop

- `prepare_public_eval_records.py` normalizes existing trusted labels and removes hidden truth from `classification_record`.
- `build_public_eval_split.py` generated 20 records: 16 `flow_only` and 4 PCAP sessions/scan-groups, with primary and exploratory confidence tiers kept distinct.
- Paired prompt generation supports the same records in no-RAG and RAG modes and is dry-run by default.
- A local deterministic mock exercised five records in both modes (10 API calls) and produced all required result files. Its 1.0 accuracy is plumbing validation only, not model performance.
- Online and local vLLM endpoints use the same OpenAI-compatible runner. Qwen thinking is disabled by default; `--disable-extra-body` supports providers that reject Qwen-specific parameters.

## Validation performed

- `python3 -m compileall -q scripts`
- `bash scripts/check_env.sh`
- `python3 scripts/test_rag_retrieval.py` — 15/15 passed
- `python3 scripts/download_public_datasets.py --dry-run --profile coverage`
- `python3 scripts/download_public_datasets.py --profile coverage --max-gb 1`
- public-eval preparation and split generation
- paired prompt-only dry-run
- paired local mock API run and evaluator output checks
- deterministic stage-map assertion
- illegal-code and malformed-JSON rejection assertions
- empty parsed-input rejection assertion
- `git diff --check` on authored code/docs; verbatim official-page snapshots and the checkpoint patch are excluded from whitespace normalization.

## Recommended next experiment

Run 10–20 high-confidence paired records against the configured real endpoint, then focus RAG/prompt changes on false-normal boundaries: brute force versus normal, exploit versus normal, callback versus normal, and port scan versus vulnerability scan. Add curated PCAP evidence for the three missing classes before drawing eight-class accuracy conclusions.
