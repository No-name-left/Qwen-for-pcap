# Small API evaluation error audit

Source evaluation: `outputs/api_eval/small_eval_20260624_observable_v3/strict/`

This audit separates model behavior from evidence and label granularity. The prior 50% result should not be treated as a clean estimate of model capability.

## 1. All strict records

| Record | True label | no-RAG | RAG | Audit disposition |
|---|---|---|---|---|
| `realapi_record_001` | TA43_01 | TA43_01 | TA43_01 | Keep; high-confidence PCAP scan group |
| `realapi_record_002` | TA43_01 | TA43_01 | TA43_01 | Keep; high-confidence PCAP scan group |
| `realapi_record_003` | TA43_01 | TA43_01 | TA43_01 | Keep; high-confidence PCAP scan group |
| `realapi_record_007` | TA01_01 | TN01_01 | TN01_01 | Remove from strict; weak flow-only auth evidence |
| `realapi_record_008` | TA01_01 | TN01_01 | TN01_01 | Remove from strict; weak flow-only auth evidence |
| `realapi_record_009` | TA01_01 | TN01_01 | TN01_01 | Remove from strict; weak flow-only auth evidence |
| `realapi_record_019` | TA11_02 | TN01_01 | TN01_01 | Replace with group; visible Google Update session is normal-like |
| `realapi_record_020` | TA11_02 | TN01_01 | TN01_01 | Replace with group; WPAD/DNS session lacks callback behavior |
| `realapi_record_021` | TA11_02 | TN01_01 | TN01_01 | Replace with group; one DNS session is not a callback record |
| `realapi_record_022` | TN01_01 | TN01_01 | TN01_01 | Keep as high-confidence flow secondary |
| `realapi_record_023` | TN01_01 | TN01_01 | TN01_01 | Keep as high-confidence flow secondary |
| `realapi_record_024` | TN01_01 | TN01_01 | TN01_01 | Keep as high-confidence flow secondary |

## 2. TA01_01 evidence audit

All three rows came from the CSE-CIC-IDS2018 Wednesday flow CSV. Their visible records contained only one flow each, destination port 21, packet/byte counts, duration, and protocol metadata.

Missing evidence in every row:

- Source and destination identity needed for same-endpoint grouping.
- Repeated authentication attempts in a bounded window.
- FTP `USER`/`PASS` presence.
- FTP failure response such as 430/530.
- Username/password field presence or username count.
- SSH authentication failure, HTTP login path, or 401/403/407 sequence.
- Success-after-failures evidence.

The source CSV itself does not contain endpoint IPs or application authentication fields, so these omissions cannot be fixed by prompt changes. The three rows are now classified as `weak_auth_evidence` and removed from strict. They may remain coverage-only flow secondary records.

The model's TN01_01 prediction was evidence-consistent: its reasons correctly noted a single FTP flow and the absence of fanout, failures, or payload. These are not demonstrated model-judgment errors under the information supplied.

## 3. TA11_02 evidence audit

### `realapi_record_019`

- Visible behavior: one HTTP Google Update request to `cr-tools.clients.google.com` with a Google Update user agent.
- C2 evidence: no periodicity, fixed endpoint, small repeated payload, unusual port, repeated DNS/SNI, or beacon score.
- Verdict: broad host-level `From-Botnet` labeling does not make this normal-looking update session a callback record.

### `realapi_record_020`

- Visible behavior: DNS for WPAD and Google client infrastructure.
- C2 evidence: fixed endpoint and repeated DNS aggregate, but no periodicity; beacon score 0.3.
- Verdict: weak host/endpoint context, insufficient for a high-confidence session-level callback label.

### `realapi_record_021`

- Visible behavior: one DNS query for `irc.zief.pl`.
- C2 evidence: the same weak aggregate as record 020, with no per-session callback sequence; beacon score 0.3.
- Verdict: potentially relevant context, but one DNS session is not a reliable callback evaluation unit.

All three are session-label granularity mismatches. They are removed and replaced by `c2_callback_group` records whose PCAP endpoint behavior aligns with explicit public `TCP-CC` flow labels.

## 4. Model errors versus evaluation errors

- Demonstrated model errors on strong visible evidence: none among the six prior failures.
- Session/label granularity mismatch: all three TA11_02 failures.
- Evidence-insufficient flow labels: all three TA01_01 failures.
- Stable strong-evidence behavior: all TA43_01 and TN01_01 records were correct in both modes.
- Confidence calibration concern: several evidence-consistent TN01_01 decisions were reported at 0.85-0.95 despite benchmark disagreement.

This does not prove the model is strong. It means the previous six errors cannot cleanly measure whether the model can use decisive authentication or callback evidence, because that evidence was absent from the evaluation units.

## 5. RAG audit

RAG changed no prediction because it was instructed to remain subordinate to the current record. Boundary cards explained that TA01_01 requires repeated auth/failure evidence and TA11_02 requires callback/beacon behavior; neither can be manufactured from an isolated flow or ordinary update/DNS session. The unchanged predictions are therefore expected and are not evidence of RAG failure.

## 6. Prompt evidence audit

- TA01_01: the prompt displayed the complete available flow record, but the source record had no observable auth evidence. This was a data limitation, not prompt omission.
- TA11_02: observable fields were present. Records 020 and 021 included `c2_indicators` and triggered callback/C2 RAG cards. Record 019 correctly showed Google Update HTTP evidence and no positive C2 indicators.
- No decisive positive observable field was present in a source record but omitted from the final prompt.

## 7. Corrective action

- Add core `auth_attempt_group` support, but admit a group to strict only when repeated attempts and explicit failure/credential evidence are both present.
- Downgrade the current CSE-CIC TA01_01 rows; no high-confidence TA01_01 can be built from the available flow CSV.
- Add core `c2_callback_group` support with endpoint repetition, interval, byte, direction, DNS/TLS, and beacon evidence.
- Replace the three CTU single sessions with groups jointly supported by PCAP behavior and explicit public `From-Botnet ... TCP-CC` endpoint labels.
