# Real API paired-evaluation token and cost plan

- Candidate records: `datasets/public_eval/real_api_candidate_records.jsonl`
- Prompt version: `observable_boundary_rag_v3`
- Runtime profile: `ascend_openeuler_qwen35_27b`
- Thinking: off
- Expected output: 128 tokens/call (profile maximum 384)
- Price parameters: input $0.3/1M, output $2.4/1M tokens

| Scenario | Records | Calls | Avg chars | Avg input tokens | Total input | Total output | Cost 0% | Cost 10% | Cost 20% |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `smoke_5` | 5 | 10 | 4695.0 | 1565.4 | 15654 | 1280 | $0.007768 | $0.008545 | $0.009322 |
| `per_class_tiny_3` | 24 | 48 | 4651.0 | 1550.7 | 74434 | 6144 | $0.037076 | $0.040783 | $0.044491 |
| `small_paired_10` | 10 | 20 | 4560.5 | 1520.5 | 30411 | 2560 | $0.015267 | $0.016794 | $0.018321 |
| `medium_paired_20` | 20 | 40 | 4559.5 | 1520.2 | 60808 | 5120 | $0.030530 | $0.033583 | $0.036636 |

## Retry sensitivity

| Scenario | Failed/retried | Adjusted input tokens | Adjusted output tokens | Estimated USD |
|---|---:|---:|---:|---:|
| `smoke_5` | 0% | 15654 | 1280 | $0.007768 |
| `smoke_5` | 10% | 17219 | 1408 | $0.008545 |
| `smoke_5` | 20% | 18785 | 1536 | $0.009322 |
| `per_class_tiny_3` | 0% | 74434 | 6144 | $0.037076 |
| `per_class_tiny_3` | 10% | 81877 | 6758 | $0.040783 |
| `per_class_tiny_3` | 20% | 89321 | 7373 | $0.044491 |
| `small_paired_10` | 0% | 30411 | 2560 | $0.015267 |
| `small_paired_10` | 10% | 33452 | 2816 | $0.016794 |
| `small_paired_10` | 20% | 36493 | 3072 | $0.018321 |
| `medium_paired_20` | 0% | 60808 | 5120 | $0.030530 |
| `medium_paired_20` | 10% | 66889 | 5632 | $0.033583 |
| `medium_paired_20` | 20% | 72970 | 6144 | $0.036636 |

## Assumptions and risks

- Each selected record is called once no-RAG and once RAG.
- Input tokens use the repository's conservative character estimator, not the provider tokenizer.
- Thinking off is required. Thinking on may produce hidden/visible reasoning, longer output, schema failures and materially higher cost.
- Prices are estimates only; use the provider's current pricing. Credits, billing, retries and actual completion length change the final charge.
- HTTP 402 commonly indicates insufficient credits/billing and should stop a batch immediately.
