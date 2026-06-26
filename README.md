# Qwen-for-pcap

Qwen-for-pcap is a PCAP/session-level network traffic classification pipeline for official competition stage and technique codes. The current mainline is Zeek-first, with tshark packet-level assistance and fallback when Zeek or `conn.log` is unavailable. Suricata is not part of the current mainline.

## Current Mainline

```text
PCAP
-> Zeek / tshark fallback
-> session cards and scan/auth/C2 behavior records
-> optional PCAP-level aggregation with technique evidence profiles and soft candidate scores
-> deterministic RAG query
-> keyword RAG retrieval plus feature-triggered confusion-boundary cards
-> Qwen3.5 or another OpenAI-compatible endpoint makes a boundary-aware decision
-> CSV export plus candidate/conflict diagnostics
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

- External-high PCAP coverage: `TA43_01=3`, `TA11_02=3` evaluation records.
- External-high flow-only coverage: `TA01_01=5`, `TN01_01=4`; external-medium: `TA01_02=5`, `TA11_02=2`.
- External gaps: `TA43_02`, `TA03_01`, `TA11_01`; each has three localhost `synthetic_controlled` coverage fixtures, never strict evidence.
- Real-API readiness candidates: 24 records (three per technique); 6 legacy rows still meet the stricter observable-evidence filter.
- Corrected observable-v3 strict gate: 9 records (`TA43_01=3`, behavior-group `TA11_02=3`, `TN01_01=3`); current flow data cannot support a strict `TA01_01` record.

See `docs/official_code_data_rag_sft_small_test_summary.md` and `datasets/metadata/official_code_data_coverage_audit.md` for details.
The current tiered review is `docs/reports/data_completion_round_report.md`.

## Current Evaluation Status

The latest guarded real-API gate used 9 corrected strict records in paired no-RAG/RAG mode. Both modes reached `9/9` technique and stage accuracy, with 100% API success, JSON parsing, and legal-label output. RAG produced 9 correct ties, no helpful changes, and no harmful changes.

The earlier 12-record 50% result mixed isolated weak-auth flows and normal-looking sessions carrying broad infected-host labels. Those six rows were removed after a granularity audit; callback cases are now endpoint-aligned behavior groups, while `TA01_01` remains absent until strong authentication evidence is acquired. The corrected result passes the small VM-readiness gate but covers only three classes and is not a final model-quality claim.

See `docs/reports/small_online_api_eval_observable_v3_strict_fixed.md` and `docs/reports/small_api_eval_error_audit.md`.

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
python3 scripts/check_remote_api_readiness.py --dry-run
```

Rebuild local RAG:

```bash
python3 scripts/build_rag_chunks.py
python3 scripts/build_keyword_index.py
python3 scripts/test_rag_retrieval.py
```

Offline parsing/session pipeline entry points:

```bash
bash run_stage1.sh
bash run_stage2.sh
```

`run_stage1.sh` exports the five-class stage label; `run_stage2.sh` exports the eight-class technique label. Both use the same technique-first model prompts, and stage1 maps technique to stage deterministically. Select deployment and prompt limits with `--runtime-profile`; see `configs/runtime_profiles.yaml` and `docs/runtime_profiles.md`.

API configuration is environment-only:

```bash
export BASE_URL="http://127.0.0.1:8000/v1"
export API_KEY="EMPTY"
export MODEL="qwen3.5"
```

The runner sends Qwen `chat_template_kwargs.enable_thinking=false` by default. Use `--disable-extra-body` for online providers that reject this extension. The offline stage scripts never call an API; invoke `scripts/run_qwen_openai_compatible.py` explicitly with a technique prompt directory. `dry_run_mock` exercises result parsing and export without a network call.

Targeted RAG is not unconditional prompt padding. Scan, authentication, Web/exploit, backdoor-direction, or outbound TLS/DNS/C2 features select only the relevant short boundary cards; ordinary top-ranked RAG follows within the runtime-profile budget.

The Phase-1 VM runner defaults to `granularity: pcap`, the recommended mode for current Phase-1 samples. It still builds session/group evidence, then aggregates it through `evidence profiles -> soft candidate scoring -> RAG -> LLM boundary decision -> optional safe calibration`. PCAP-level records include `candidate_technique_scores`, `top_rule_candidates`, evidence/counter-evidence, margin, strength, benign-download scores, payload-observability gaps, weak-evidence flags, and safe-calibration metadata. `candidate_scores.csv`, `candidate_score_report.md`, and `conflict_cases.jsonl` help diagnose benign download false positives, weak dynamic POST/no-body uncertainty, model-vs-rule conflicts, and conservative calibration decisions. `--granularity session` preserves the earlier per-session/group behavior. The evaluator supports the official sample answer column `攻击技术名称或正常流量`. See `README_PHASE1_VM.md` for VM usage and output details.

Do not run API batches blindly. Use the current small coverage set first, inspect the reports, then expand only if error analysis improves.

Real API execution is additionally gated by a passing readiness report, `RUN_REAL_API_TEST=1`, and at most two paired records (four calls). `scripts/estimate_api_eval_cost.py` estimates larger plans without making calls.

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
- Zeek is the main parser; tshark provides packet-level assistance and fallback. Suricata is not used.
