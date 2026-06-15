# Official-code data, RAG, SFT, and small-test summary

- Clear verdict: `DATA_COVERAGE_INCOMPLETE_NEEDS_MANUAL_REVIEW`
- API was run after data/RAG/eval/SFT gates completed.
- The small test completed technically, but the model result is not strong enough to expand yet.

## 1. Official 8-class data coverage

| code | quality/status | primary eval | secondary eval | note |
| --- | --- | --- | --- | --- |
| TA43_01 | high_controlled / high | True | True | controlled local nmap portscan PCAP; Zeek scan_group under outputs/zeek_rebuild |
| TA43_02 | missing / missing | False | False | No local public PCAP/flow row with clear vulnerability scan label distinct from generic port scan or exploit. |
| TA01_01 | high_flow_only / high | False | True | No matching raw PCAP/Zeek evidence in local tree. |
| TA01_02 | medium_flow_only / medium | False | True | Flow-only labels lack payload/HTTP evidence; web brute force rows are not exploitation. |
| TA03_01 | low / low | False | False | No reliable evidence of installation/persistence/dropper distinct from access or callback. |
| TA11_01 | missing / missing | False | False | No local sample showing operator/inbound access to existing backdoor distinct from implant or callback. |
| TA11_02 | high_pcap_and_medium_flow / high_for_CTU_medium_for_CSE | True | True | CTU-13 From-Botnet joined to Zeek conn records; CSE-CIC-IDS2018 Bot flow CSV |
| TN01_01 | high_flow_only_or_low_ctu_background / high_for_CSE_low_for_CTU_background | False | True | No high-confidence normal PCAP+Zeek eval set in current tree. |

- High-confidence PCAP-based coverage: TA43_01, TA11_02.
- Medium/flow-only or missing/low classes: TA43_02, TA01_01, TA01_02, TA03_01, TA11_01, TN01_01.
- `TA43_02`, `TA03_01`, and `TA11_01` remain missing/low-confidence and are not used for primary eval.

## 2. RAG coverage

- RAG gate: `PASS`
- Official-code docs ready: 8/8
- Required boundary docs ready: 5/5
- RAG rebuild and retrieval smoke test passed with no zero-hit queries.

## 3. Eval sets

- Balanced eval set gate: `PARTIAL_PASS`
- Balanced eval records: 121
- Small coverage records: 20

| code | eval count | primary | secondary | small test |
| --- | ---: | ---: | ---: | ---: |
| TA43_01 | 1 | 1 | 1 | 1 |
| TA43_02 | 0 | 0 | 0 | 0 |
| TA01_01 | 30 | 0 | 30 | 5 |
| TA01_02 | 30 | 0 | 30 | 5 |
| TA03_01 | 0 | 0 | 0 | 0 |
| TA11_01 | 0 | 0 | 0 | 0 |
| TA11_02 | 30 | 20 | 30 | 5 |
| TN01_01 | 30 | 0 | 30 | 4 |

## 4. SFT candidate audit

- SFT audit gate: `PASS`
- Total candidates: 181
- accept_high: 57
- accept_medium_needs_review: 94
- rejected/heldout/low: 30
- Recommend immediate LoRA: False
- Reason: Do not train LoRA yet: three official codes are missing, most non-C2 candidates are flow-only and need manual review, and small coverage holdout records must remain excluded.

## 5. Small API test

- API actually ran: True
- Model: `Qwen/Qwen3.5-27B:novita`
- Endpoint host: `router.huggingface.co`
- Prompt count: 20
- Successful predictions: 20
- Failed batches: 0
- JSON parse failures: 0
- Illegal code count: 0
- Timeout count: 0

## 6. Small-test result

- Technique accuracy: 5/20 = 0.250
- Stage fallback accuracy: 5/20 = 0.250
- Primary eval: 1/4 = 0.250
- Secondary eval: 5/20 = 0.250
- Portscan scan_group predicted `TA43_01`: True

| expected code | total | correct | confusion |
| --- | ---: | ---: | --- |
| TA43_01 | 1 | 1 | `{"TA43_01": 1}` |
| TA43_02 | 0 | 0 | `{}` |
| TA01_01 | 5 | 0 | `{"TN01_01": 5}` |
| TA01_02 | 5 | 0 | `{"TN01_01": 5}` |
| TA03_01 | 0 | 0 | `{}` |
| TA11_01 | 0 | 0 | `{}` |
| TA11_02 | 5 | 0 | `{"TA43_01": 3, "TN01_01": 2}` |
| TN01_01 | 4 | 4 | `{"TN01_01": 4}` |

## 7. CSV and local outputs

- CSV export completed locally:
  - `outputs/api_tests/small_coverage/submissions/stage2_submission_model_test.csv`
  - `outputs/api_tests/small_coverage/submissions/stage1_submission_from_technique_fallback.csv`
- Stage labels are deterministic fallback from model technique labels.
- Prompt directories, raw API responses, parsed model outputs, and detailed results remain ignored and should not be committed.

## 8. Cautious conclusion and next steps

- Current RAG coverage is ready for official-code boundary retrieval.
- Current data coverage is incomplete for an 8-class benchmark.
- Flow-only records provide weak prompt evidence; this likely caused brute-force and exploit rows to be predicted as `TN01_01`.
- Before expanding API tests, add vetted samples for `TA43_02`, `TA03_01`, and `TA11_01`, and improve flow-only prompt evidence or restrict evaluation conclusions to PCAP/Zeek-primary records.
- Do not start LoRA yet; first complete manual review of medium candidates and prevent holdout leakage.
