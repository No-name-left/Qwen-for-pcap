# observable_boundary_rag_v3 small online API evaluation

Date: 2026-06-24 UTC

## 1. Purpose and scope

This was a guarded local/development evaluation, not a VM deployment or a final benchmark. It tested whether the current session-card, prompt, and targeted-RAG path is technically stable and whether model quality on existing high-confidence evidence is strong enough to justify VM adaptation.

The official `example-s3-0623` samples and answer table were not used as inputs, retrieval content, labels, or comparison data.

## 2. Data selection

The source was `datasets/public_eval/real_api_candidate_records.jsonl` after rebuilding existing PCAP-derived cards with commit `45af2bdfb6e03e5157a02fabc332891554b3da9b`.

- Smoke: 2 strict records, one `external_high_pcap` TA43_01 and one `external_high_flow` TA01_01.
- Strict small eval: 12 records, exactly 3 each for TA43_01, TA01_01, TA11_02, and TN01_01.
- Strict tiers: 6 `external_high_pcap` and 6 `external_high_flow`.
- `external_medium` and `synthetic_controlled` records were excluded from the main result.
- Optional 24-record coverage evaluation was not run because strict quality did not clear the continuation gate.

These are high-confidence public mappings, not official competition ground truth. In particular, CTU `From-Botnet` membership and flow-level attack labels can be broader than the network behavior visible in one selected session.

## 3. API and safety configuration

- Base URL: `https://router.huggingface.co/v1`
- Model: `Qwen/Qwen3.5-27B:novita`
- Temperature: 0
- Maximum visible output: 384 tokens
- Prompt version: `observable_boundary_rag_v3`
- Thinking: disabled; all accepted A/B responses reported 0 reasoning tokens.
- API key: present, never printed or written; exact-key leak scan passed.
- `RUN_REAL_API_TEST=1`: required and set for the real run.
- Every call saved record ID, mode, prompt version/path, request/response ID, latency, token usage, parse/label status, and error summary.

An initial two-call probe accidentally omitted the Qwen thinking flag because the online profile suppressed `extra_body`. Both responses parsed, but they used 5,397 reasoning tokens in total and were excluded. The run was stopped before B, the runner was fixed to force `chat_template_kwargs.enable_thinking=false`, and a hard failure was added for any future nonzero reasoning-token response. Known excluded-probe cost was about $0.014427; one interrupted in-flight request has unknown provider-side cost.

## 4. Prompt, RAG, and evidence checks

- All 28 accepted calls contained `PROMPT_VERSION: observable_boundary_rag_v3` and `OBSERVABLE_EVIDENCE_FROM_PCAP`.
- All prompts stayed within the selected runtime budget; maximum estimated strict prompt size was 3,337 tokens.
- Six PCAP-derived strict records included observable fields; six flow-only records correctly did not invent PCAP payload evidence.
- RAG prompts included 77 chunks in total; 11/12 had targeted boundary cards.
- Two CTU records activated `c2_indicators` and `observable_backdoor_access_vs_callback` targeted retrieval.
- One CTU record had bounded field-level truncation in both modes, but neither prompt approached the overall 19,500-character budget.
- `xp_cmdshell`, `exec`, `powershell`, `/bin/sh`, and `union select` had no positive match in this strict set and did not appear as false-positive prompt evidence. False-valued internal schema keys were removed by sparse prompt serialization.
- Existing cookie, authorization, credential, token, and payload redaction tests passed.

## 5. Smoke result

Smoke passed the engineering gate: 4/4 calls succeeded, 4/4 parsed as JSON, and 4/4 used a legal label. Both no-RAG and RAG technique/stage accuracy were 1/2, with the same predictions.

## 6. Strict aggregate result

| Mode | API success | JSON parse | Valid label | Technique accuracy | Stage accuracy |
|---|---:|---:|---:|---:|---:|
| no-RAG | 12/12 | 12/12 | 12/12 | 6/12 (50%) | 6/12 (50%) |
| RAG | 12/12 | 12/12 | 12/12 | 6/12 (50%) | 6/12 (50%) |

Stage codes were never model-generated; all were mapped deterministically from the predicted technique code. There were no mapping errors.

Both `external_high_pcap` and `external_high_flow` scored 3/6 in each mode. This apparent equality hides different behavior: port-scan PCAPs were strong, C2 PCAP sessions were weak, benign flows were strong, and attack-labeled authentication flows were weak.

## 7. Per-class result and confusion

| Ground truth | N | no-RAG correct | RAG correct | Main prediction |
|---|---:|---:|---:|---|
| `TA43_01` | 3 | 3 | 3 | `TA43_01` |
| `TA01_01` | 3 | 0 | 0 | `TN01_01` |
| `TA11_02` | 3 | 0 | 0 | `TN01_01` |
| `TN01_01` | 3 | 3 | 3 | `TN01_01` |

All six errors crossed into the normal class, so technique and stage accuracy were identical.

## 8. RAG effect

- Helpful: 0
- Harmful: 0
- Ties: 12
- Prediction disagreements: 0

RAG did not measurably help or hurt this strict set. It generally made reasons more explicit, but did not change a label. This is not evidence that RAG is useless: the evaluated attack records lacked decisive per-session auth/C2 evidence, so boundary guidance could not safely override the primary record.

## 9. Observable-evidence use

The model clearly used strong observable behavior for all three TA43_01 records, citing approximately 1,000 unique ports and 99.45%-100% failed connections while correctly refusing to upgrade them to vulnerability scans.

For TA11_02, the model also followed the visible session evidence, but that evidence conflicted with the broad source label: it saw a Google Update HTTP request, a WPAD DNS query, and a single ordinary DNS query. Even when two records exposed weak aggregate C2 indicators, the model prioritized the current session and predicted normal.

## 10. Error attribution

| Error group | Records | Primary attribution |
|---|---:|---|
| TA01_01 -> TN01_01 | 3 | Session-card/source evidence insufficiency: each record is an isolated flow to port 21 without repeated attempts, failures, credentials, or payload. |
| TA11_02 -> TN01_01 | 3 | Label/session granularity mismatch and weak current-session evidence: broad CTU botnet labels do not make every Google Update/WPAD/DNS session visibly C2. |
| RAG harmful | 0 | No observed RAG-induced regression. |
| API/parser/schema | 0 | No engineering failure in accepted A/B calls. |

The dominant issue is therefore not JSON stability and not a demonstrated RAG regression. It is the mismatch between coarse source labels and the evidence available in individual classification records, plus insufficient cross-session behavioral summarization for authentication and C2 decisions. Model overconfidence is still a concern: five of six wrong record pairs were predicted normal with confidence 0.85-0.95; only one no-RAG error was as low as 0.65.

## 11. Typical cases

- Correct: `realapi_record_001` was classified TA43_01 in both modes from 1,002 unique destination ports and 99.9% failure rate.
- Correct: `realapi_record_022` was classified TN01_01 in both modes from a single short TLS flow without attack behavior.
- Error: `realapi_record_007` was labeled TA01_01 by the source but showed only one FTP flow; both modes reasonably rejected brute force.
- Error: `realapi_record_019` was labeled TA11_02 by CTU membership but looked like a standard Google Update request; both modes predicted normal.

## 12. Cost and latency

- Accepted smoke: 6,085 input + 618 output tokens; approximately $0.003309.
- Accepted strict: 38,661 input + 3,803 output tokens; approximately $0.020725.
- Accepted A+B total: approximately $0.024034.
- Excluded thinking-on probe, known completed calls: approximately $0.014427, plus one interrupted request with unknown charge.
- Strict total observed latency: 162.796 seconds; mean 6.783 seconds/call; observed p95 12.407 seconds.

Prices used for estimation were $0.30/M input tokens and $2.40/M output tokens. Provider billing is authoritative.

## 13. Gate decision

- Engineering usability gate: **PASS**.
- JSON/closed-label/stage-mapping/security gates: **PASS**.
- Strict technique target (60%-70%): **FAIL** at 50%.
- Strict stage target (75%): **FAIL** at 50%.
- RAG non-regression: **PASS**, but with no improvement.
- Stable TA43_01: **PASS**.
- Stable TA11_02: **FAIL**.
- Worth entering VM adaptation now: **NO**.

This is a small readiness result, not a final quality claim. The current pipeline is technically ready for online inference, but the available strict evidence and resulting model quality do not justify VM adaptation yet.

## 14. Recommended next steps

1. Rebuild TA01_01 evaluation units as auth-attempt groups or same-endpoint windows instead of isolated flow rows; require failure/credential evidence.
2. Revisit CTU TA11_02 labeling at session granularity. Keep only sessions with direct callback/beacon evidence, or evaluate a clearly defined group-level C2 record.
3. Calibrate confidence so evidence-insufficient normal predictions are not reported at 0.95.
4. Add focused regression records where positive observable payload indicators are genuinely present; do not borrow official example answers.
5. Rerun the same 12-record paired gate after evidence/label repair. Run the optional 24-record medium/synthetic coverage tier only after strict quality improves.

Local output: `outputs/api_eval/small_eval_20260624_observable_v3/`.
