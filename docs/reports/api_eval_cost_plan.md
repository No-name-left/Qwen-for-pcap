# Real API paired-evaluation token and cost plan

- Candidate records: `datasets/public_eval/real_api_candidate_records.jsonl`
- Prompt version: `boundary_rag_v2`
- Runtime profile: `ascend_openeuler_qwen35_27b`
- Thinking: off
- Expected output: 128 tokens/call (profile maximum 384)
- Price parameters: input $0.3/1M, output $2.4/1M tokens

| Scenario | Records | Calls | Avg chars | Avg input tokens | Total input | Total output | Cost 0% | Cost 10% | Cost 20% |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `smoke_5` | 5 | 10 | 3883.5 | 1294.9 | 12949 | 1280 | $0.006957 | $0.007652 | $0.008348 |
| `per_class_tiny_3` | 24 | 48 | 3832.8 | 1277.9 | 61340 | 6144 | $0.033148 | $0.036462 | $0.039777 |
| `small_paired_10` | 10 | 20 | 3805.7 | 1269.0 | 25379 | 2560 | $0.013758 | $0.015133 | $0.016509 |
| `medium_paired_20` | 20 | 40 | 3838.1 | 1279.7 | 51187 | 5120 | $0.027644 | $0.030409 | $0.033173 |

## Retry sensitivity

| Scenario | Failed/retried | Adjusted input tokens | Adjusted output tokens | Estimated USD |
|---|---:|---:|---:|---:|
| `smoke_5` | 0% | 12949 | 1280 | $0.006957 |
| `smoke_5` | 10% | 14244 | 1408 | $0.007652 |
| `smoke_5` | 20% | 15539 | 1536 | $0.008348 |
| `per_class_tiny_3` | 0% | 61340 | 6144 | $0.033148 |
| `per_class_tiny_3` | 10% | 67474 | 6758 | $0.036462 |
| `per_class_tiny_3` | 20% | 73608 | 7373 | $0.039777 |
| `small_paired_10` | 0% | 25379 | 2560 | $0.013758 |
| `small_paired_10` | 10% | 27917 | 2816 | $0.015133 |
| `small_paired_10` | 20% | 30455 | 3072 | $0.016509 |
| `medium_paired_20` | 0% | 51187 | 5120 | $0.027644 |
| `medium_paired_20` | 10% | 56306 | 5632 | $0.030409 |
| `medium_paired_20` | 20% | 61424 | 6144 | $0.033173 |

## Assumptions and risks

- Each selected record is called once no-RAG and once RAG.
- Input tokens use the repository's conservative character estimator, not the provider tokenizer.
- Thinking off is required. Thinking on may produce hidden/visible reasoning, longer output, schema failures and materially higher cost.
- Prices are estimates only; use the provider's current pricing. Credits, billing, retries and actual completion length change the final charge.
- HTTP 402 commonly indicates insufficient credits/billing and should stop a batch immediately.
