# example-s3-0623 observable evidence report

## Official sample availability

Checked the requested locations on 2026-06-23:

- `/data/competition_input/raw/example-s3-0623.zip`
- `/data/competition_input/example-s3`
- `/data/competition_input/example-s3-pcaps`
- `/data/competition_input/example-s3_result_table.csv`
- matching `结果对照表.xlsx` paths under the available data/workspace trees

None was present. Therefore official-sample PCAP count, parsed count, per-PCAP session counts, metadata-only PCAPs, and result-table correspondence are not claimable in this environment. No answer table was read or used in RAG/prompt construction.

## Safe substitute regression

To validate the exact visibility path without executing anything, the localhost-only controlled generator was extended with inert URI and POST-body text containing `;exec master..xp_cmdshell 'whoami';` and a dummy token used solely to verify redaction. Fixed handlers discarded requests and never executed or saved content.

| Metric | Result |
|---|---:|
| Controlled PCAPs | 8 |
| Successfully parsed by Zeek or TShark | 8 |
| Session cards | 60 |
| Final classification records | 41 |
| Scan groups | 1 |
| Sessions with HTTP evidence | 40 |
| Sessions with suspicious snippets | 15 |
| Sessions with positive `xp_cmdshell` | 2 |
| Plaintext-HTTP sessions | 40 |
| Metadata-only sessions | 20 |

Per controlled PCAP:

| Scenario fixture | Sessions | HTTP sessions | Suspicious-snippet sessions | Positive `xp_cmdshell` |
|---|---:|---:|---:|---:|
| `TA01_01` auth retry | 10 | 10 | 0 | 0 |
| `TA01_02` inert exploit text | 5 | 5 | 5 | 2 |
| `TA03_01` harmless upload | 3 | 3 | 3 | 0 |
| `TA11_01` mock access | 3 | 3 | 3 | 0 |
| `TA11_02` dummy callback | 8 | 8 | 0 | 0 |
| `TA43_01` closed-port scan | 20 | 0 | 0 | 0 |
| `TA43_02` mock scanner | 8 | 8 | 4 | 0 |
| `TN01_01` benign HTTP | 3 | 3 | 0 | 0 |

The structured evidence was clearest for `TA01_02` (body/URI injection strings), `TA43_02` (scanner UA/probe paths), `TA01_01` (repeated login plus 401), `TA03_01` (upload context), and `TA11_01` (mock webshell path). `TA11_02` uses interval/fixed-endpoint evidence and remains deliberately more cautious because benign callbacks can look similar. The metadata-only controlled PCAP was the closed-port `TA43_01` fixture.

## End-to-end visibility and budget

The inert `xp_cmdshell` and `exec` strings appeared in the sanitized TShark observation, session cards, classification records, RAG queries, and both prompt variants. The dummy token value appeared nowhere in parsed safe observations, cards, records, or prompts; only `[REDACTED]` remained.

All 41 no-RAG and 41 RAG prompts used `observable_boundary_rag_v3`. Maximum sizes were 5,728 characters / 1,910 estimated tokens for no-RAG and 8,508 characters / 2,836 estimated tokens for RAG, below the dry-run/Ascend limit of 10,200 characters / 3,400 estimated tokens. No prompt needed budget truncation in this regression.

## What remains unverified

The official Wireshark-visible packet cannot be compared until the archive is mounted. Once available, rerun parsing into a separate output directory, search `observable_http.jsonl`, cards, records, queries, and prompts for `xp_cmdshell|cmdshell|exec`, and use the result table only after inference for offline correspondence/sanity checks. If Wireshark still sees text that this pipeline misses, likely causes are reassembly, unusual HTTP decoding, compression, HTTP/2/3, nonstandard ports, or uncertain stream/session mapping; these should be recorded in `extraction_warnings`, not inferred as normal traffic.

## Validation commands

The following completed successfully:

- `python3 -m compileall -q scripts`
- `bash scripts/check_env.sh` (Zeek 8.0.5 and TShark found; no API/model call)
- `python3 scripts/build_rag_chunks.py`
- `python3 scripts/build_keyword_index.py`
- `python3 scripts/test_rag_retrieval.py` (26/26)
- `python3 scripts/test_observable_evidence.py`
- `python3 scripts/test_prompt_budget.py`
- `python3 scripts/test_data_tiering.py`
- `python3 scripts/test_submission_export.py` (stage1 and stage2 schemas passed)
- Controlled generator, parser, session-card, classification-record, query, retrieval, and prompt builders over eight localhost PCAPs
- TShark-only fallback regression: 5 sessions, 2 positive `xp_cmdshell` sessions, no raw URI column in `packets.csv`
- `git diff --check`

Repository/status checks found no new raw PCAP, model file, answer table, API secret, complete payload dump, Suricata runtime integration, or direct model loading in the observable-evidence business path. No new dependency was installed.
