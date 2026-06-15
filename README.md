# Qwen-for-pcap

Qwen-for-pcap is a PCAP/session-level network traffic classification pipeline for official competition stage and technique codes. The current mainline is Zeek-first, with Suricata evidence and tshark fallback only when Zeek or `conn.log` is unavailable.

## Current Mainline

```text
PCAP
-> Zeek / Suricata / tshark fallback
-> session cards and scan_group records
-> deterministic RAG query
-> keyword RAG retrieval
-> Qwen3.5-27B or another OpenAI-compatible endpoint
-> official technique_code
-> deterministic stage fallback
-> CSV export
```

Core scripts live in `scripts/`. Runtime configuration is in `configs/`. RAG knowledge and indexes live in `rag/`. Lightweight data/eval metadata live in `datasets/metadata/`, `outputs/eval_sets/`, and `data/sft_candidates/`.

## Official Codes

Stage codes:

| code | meaning |
| --- | --- |
| `TA43` | reconnaissance |
| `TA01` | initial access |
| `TA03` | persistence |
| `TA11` | command and control |
| `TN01` | normal/business traffic |

Technique codes:

| code | meaning |
| --- | --- |
| `TA43_01` | port scan |
| `TA43_02` | vulnerability scan |
| `TA01_01` | password brute force |
| `TA01_02` | vulnerability exploitation |
| `TA03_01` | backdoor installation |
| `TA11_01` | backdoor access |
| `TA11_02` | trojan callback |
| `TN01_01` | normal/business access |

Technique-to-stage fallback is deterministic: `TA43_* -> TA43`, `TA01_* -> TA01`, `TA03_01 -> TA03`, `TA11_* -> TA11`, and `TN01_01 -> TN01`.

## Current Data Coverage

- High-confidence PCAP/Zeek coverage: `TA43_01`, `TA11_02`.
- Secondary flow-only coverage: `TA01_01`, `TA01_02`, `TN01_01`.
- Missing or low-confidence coverage: `TA43_02`, `TA03_01`, `TA11_01`.

See `docs/official_code_data_rag_sft_small_test_summary.md` and `datasets/metadata/official_code_data_coverage_audit.md` for details.

## Current Evaluation Status

The latest small coverage API test used 20 records across 5 available official codes. It completed without timeout, JSON parse failure, or illegal code, but accuracy was low:

- technique accuracy: `5/20 = 0.25`
- stage fallback accuracy: `5/20 = 0.25`
- main confusion: `TA01_01/TA01_02 -> TN01_01`, and `TA11_02 -> TA43_01/TN01_01`
- portscan `scan_group` was correctly predicted as `TA43_01`

This is a smoke test, not a final model quality claim. Before expanding to 50-100 records, audit the 20 errors and improve prompt/RAG/evidence summaries.

## Current SFT Status

SFT candidates have been audited, but immediate LoRA training is not recommended:

- total candidates: 181
- `accept_high`: 57
- `accept_medium_needs_review`: 94
- rejected/holdout/low-confidence: 30

Medium candidates need manual review, and the missing classes should not be filled with weak labels.

## Quick Commands

Environment check:

```bash
bash scripts/check_env.sh
```

Rebuild local RAG:

```bash
python3 scripts/build_rag_chunks.py
python3 scripts/build_keyword_index.py
```

Offline parsing/session pipeline entry points:

```bash
bash run_stage1.sh
bash run_stage2.sh
```

API configuration is environment-only:

```bash
export LLM_BASE_URL="https://router.huggingface.co/v1"
export LLM_API_KEY="<set outside repo>"
export LLM_MODEL_NAME="Qwen/Qwen3.5-27B:novita"
export RUN_API=1
```

Do not run API batches blindly. Use the current small coverage set first, inspect the reports, then expand only if error analysis improves.

## Important Documents

- `docs/current_project_status_for_assistant.md`
- `docs/project_mainline_manifest.md`
- `docs/official_code_data_rag_sft_small_test_summary.md`
- `docs/final_zeek_based_large_scale_test_summary.md`
- `docs/sft_candidate_review_report.md`
- `docs/project_cleanup_summary.md`

Archived legacy reports are under `docs/archive/`, `rag/reports/archive/`, and `datasets/metadata/archive/`.

## Safety Rules

- Do not commit `.env`, tokens, PCAP/cap/pcapng, binetflow, large raw datasets, prompt directories, API raw responses, parsed model outputs, model weights, or LoRA adapters.
- Do not use official test data for training, RAG, or local eval construction.
- Do not treat low-confidence or flow-only labels as high-confidence PCAP evidence.
- Zeek is the main parser; tshark is only a fallback.
