# Small online API evaluation: strict observable-v3 fixed

- Generated: 2026-06-24
- Scope: guarded local/development evaluation; no competition VM or official `example-s3-0623` sample/answer data was used.
- Model: `Qwen/Qwen3.5-27B:novita`
- API: OpenAI-compatible Hugging Face router
- Prompt version: `observable_boundary_rag_v3`
- Modes: paired no-RAG and RAG, temperature 0, thinking disabled

## Executive conclusion

The corrected strict set contains 9 records and 3 supported classes. Both no-RAG and RAG achieved `9/9` technique accuracy and `9/9` deterministic stage accuracy. All 18 strict calls succeeded, parsed as JSON, and returned legal labels. Together with the 4 smoke calls, the run made 22 accepted API calls at an estimated actual cost of `$0.019906`.

This passes the small engineering gate and supports moving to VM adaptation and one-click execution work while retaining this set as a regression gate. It is not a final model-quality claim: the set is small, TA01_01 has no admissible strong-evidence record, benign records remain flow-secondary, and the three callback groups come from only two correlated CTU scenarios.

## Why the prior 50% was not a clean capability estimate

The prior strict set reported `6/12 = 50%` in both modes. Its six failures were all evidence-granularity problems rather than demonstrated errors against decisive visible evidence:

- Three `TA01_01` rows were isolated FTP flow rows. They showed port 21 and flow statistics, but no endpoint identity, repeated attempt window, `USER`/`PASS`, failure response, username count, or success-after-failure sequence. Predicting `TN01_01` was consistent with the visible evidence.
- Three `TA11_02` rows were individual Google Update, WPAD/DNS, or single-DNS sessions inherited from broadly infected-host captures. None was itself a callback sequence. Assigning a host/capture-level botnet label to those sessions created a session/label mismatch.

The error audit found no decisive positive source field that had merely been omitted from the prompt. Prompt or RAG wording therefore could not repair those six evaluation units.

## Granularity corrections

### Authentication attempts

Core `auth_attempt_group` support was added for repeated same-endpoint authentication attempts. The group can expose safe aggregates such as attempt count/rate, username presence and unique count, password-field presence, FTP response codes, failed-login count, SSH failure hints, HTTP login paths, and success after failures. Credential values are not exposed.

Strict admission requires repeated attempts plus explicit failure or credential evidence. The available CSE-CIC source CSV lacks endpoint IPs and application authentication fields, so no honest high-confidence `TA01_01` group could be built. The former three rows were marked `weak_auth_evidence`, excluded from strict, and retained only as coverage-level source material.

### Callback behavior

Core `c2_callback_group` support was added for repeated same-endpoint behavior, including connection count, interval/duration/byte patterns, source-initiated direction, DNS/SNI/URI repetition, periodicity, and beacon score. Three groups were admitted only after their PCAP endpoint behavior matched explicit public CTU `From-Botnet ... TCP-CC` flow labels:

| Record | Visible group evidence | Public-label alignment |
|---|---|---|
| `strict_v3_ta11_02_001` | 197 source-initiated connections, fixed endpoint `:5678`, beacon `0.90`, periodicity `0.621` | 199 `TCP-CC73` labeled flows |
| `strict_v3_ta11_02_002` | 5 source-initiated connections, fixed endpoint `:5296`, beacon `0.80`, periodicity `0.933` | 9 `TCP-CC55` labeled flows |
| `strict_v3_ta11_02_003` | 54 source-initiated HTTP connections, repeated callback paths, beacon `0.75`, periodicity `0.640` | 53 `TCP-CC53` labeled flows |

## Corrected strict set

Evidence quality was prioritized over artificial class balance. Synthetic and external-medium records were excluded.

| Technique | Evidence tier | Count |
|---|---|---:|
| `TA43_01` | `high_confidence_pcap_scan_group` | 3 |
| `TA11_02` | `high_confidence_pcap_callback_group` | 3 |
| `TN01_01` | `high_confidence_flow_secondary` | 3 |
| `TA01_01` | no currently admissible evidence | 0 |

Expected labels and source-label alignment metadata remained outside the classification records and prompts.

## Real API results

The smoke gate used 2 records and 4 calls. The strict phase then used all 9 records and 18 calls.

| Mode | API success | JSON parse | Legal label | Technique | Stage |
|---|---:|---:|---:|---:|---:|
| no-RAG | `9/9` (100%) | `9/9` (100%) | `9/9` (100%) | `9/9` (100%) | `9/9` (100%) |
| RAG | `9/9` (100%) | `9/9` (100%) | `9/9` (100%) | `9/9` (100%) | `9/9` (100%) |

| Technique | N | no-RAG | RAG |
|---|---:|---:|---:|
| `TA43_01` | 3 | `3/3` | `3/3` |
| `TA11_02` | 3 | `3/3` | `3/3` |
| `TN01_01` | 3 | `3/3` | `3/3` |

The model correctly used scan fanout for `TA43_01`, ordinary low-signal flow evidence for `TN01_01`, and the fixed endpoint, source-initiated repetition, periodicity, unusual ports, and repeated small exchanges for the three `TA11_02` groups. There were no strict prediction errors to attribute in this run.

## RAG effect

- Helpful: 0
- Harmful: 0
- Correct ties: 9
- Prediction disagreements: 0

For callback groups, targeted retrieval was activated by positive `c2_indicators` and placed the observable callback boundary card before general confusion cards. RAG did not change any already-correct prediction. This run establishes non-regression, not incremental RAG benefit.

## Cost, tokens, and latency

| Phase | Records | Calls | Input tokens | Output tokens | Actual estimated cost | Mean latency | Observed p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Smoke | 2 | 4 | 7,328 | 764 | `$0.004032` | 7.155 s | 6.125 s |
| Strict | 9 | 18 | 28,936 | 2,997 | `$0.015874` | 7.985 s | 11.076 s |
| Total | - | 22 | 36,264 | 3,761 | `$0.019906` | - | - |

No call used reasoning tokens, and no API error, timeout, parse error, or illegal code occurred.

## Remaining limits

- `TA01_01` remains untested under strong observable authentication evidence. A PCAP with repeated SSH/FTP/RDP/HTTP failures and endpoint alignment is still needed.
- The callback result covers three groups but only two CTU scenarios; two groups share one scenario. More C2 families and benign periodic/update negatives are needed.
- `TN01_01` is high-confidence flow-secondary evidence, not payload-visible benign PCAP.
- Only three of the eight official codes are represented. The result must not be generalized to missing techniques.
- The comparison from 50% to 100% reflects a corrected evaluation definition and changed composition, not a simple model improvement measurement.

## Gate decision

- Engineering usability gate: **PASS**
- Enter VM adaptation and one-click execution work: **YES, cautiously**
- Expand to optional coverage evaluation now: **NO; not run in this round**
- Final quality claim: **NO**

The next stage should keep this fixed strict set as a pre-deployment regression check, then validate parser paths, dependency packaging, resource limits, and one-click execution in the target VM. In parallel, acquire strong authentication PCAP and broader independent C2/benign families before making a broader model-quality judgment.

Supporting details are in `docs/reports/small_api_eval_error_audit.md`, `docs/reports/strict_observable_v3_selection.md`, and `outputs/api_eval/small_eval_20260624_observable_v3_strict_fixed/`.
