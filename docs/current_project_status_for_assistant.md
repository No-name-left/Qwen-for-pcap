# Current project status for assistant

- Project: Qwen-for-pcap
- Status date: 2026-06-15
- Latest committed baseline before cleanup: `da4273e Complete official-code data RAG coverage and small evaluation`
- Current cleanup commit: see `git log -1 --oneline` after this cleanup commit lands.

## Current mainline

The mainline is a Zeek-first PCAP/session-level classifier:

```text
PCAP -> Zeek/Suricata/tshark fallback -> session cards / scan_group
-> RAG retrieval -> Qwen3.5-27B or OpenAI-compatible endpoint
-> official technique code -> deterministic stage fallback -> CSV
```

Zeek is the primary parser. tshark is a fallback only when Zeek or `conn.log` is unavailable.

## Completed

- Zeek and Suricata tool checks.
- Zeek rebuild with 31,920 session cards and 31,740 classification records.
- scan_group handling for portscan.
- official 8-code RAG docs and 5 key boundary docs.
- RAG chunk/index rebuild and retrieval smoke test.
- official-code data coverage audit.
- balanced eval metadata and 20-record small coverage set.
- SFT candidate first-pass audit.
- 20-record small coverage API test.
- project cleanup/archive pass.

## Reliable conclusions

- High-confidence PCAP/Zeek coverage exists for `TA43_01` and `TA11_02`.
- Flow-only secondary coverage exists for `TA01_01`, `TA01_02`, and `TN01_01`.
- RAG coverage for all 8 official technique codes and required boundaries is in place.
- The portscan `scan_group` sample is correctly handled and was predicted as `TA43_01` in the small test.

## Not reliable yet

- `TA43_02`, `TA03_01`, and `TA11_01` do not have reliable local samples.
- The 20-record small test is not a stable quality estimate.
- Flow-only brute-force/exploit/normal records do not validate the PCAP parser.
- Immediate LoRA training is not recommended.

## Data coverage

- `TA43_01`: high-confidence PCAP/Zeek.
- `TA43_02`: missing.
- `TA01_01`: high-confidence flow-only secondary.
- `TA01_02`: medium-confidence flow-only secondary.
- `TA03_01`: low/missing.
- `TA11_01`: missing.
- `TA11_02`: high-confidence CTU Zeek plus medium flow-only Bot.
- `TN01_01`: flow-only secondary; CTU background remains low confidence.

## Eval set

- Balanced eval metadata: 121 records.
- Per-code counts: `TA43_01=1`, `TA43_02=0`, `TA01_01=30`, `TA01_02=30`, `TA03_01=0`, `TA11_01=0`, `TA11_02=30`, `TN01_01=30`.
- Small coverage set: 20 records across 5 available codes.

## Small test result

- API ran: yes.
- Model: `Qwen/Qwen3.5-27B:novita`.
- Endpoint host: `router.huggingface.co`.
- Success: 20/20.
- Timeout: 0.
- JSON parse failure: 0.
- Illegal code: 0.
- Technique accuracy: 5/20 = 0.25.
- Stage fallback accuracy: 5/20 = 0.25.
- Main confusion: `TA01_01/TA01_02 -> TN01_01`; `TA11_02 -> TA43_01/TN01_01`.

## SFT candidate status

- Candidates: 181.
- `accept_high`: 57.
- `accept_medium_needs_review`: 94.
- rejected/holdout/low-confidence: 30.
- Recommendation: do not train LoRA yet.

## Next priorities

1. Audit the 20 small coverage errors record by record.
2. Improve prompt/RAG/evidence summaries for flow-only and callback cases.
3. Re-run the same 20-record small test.
4. If accuracy improves, expand to 50-100 records.
5. Keep SFT on hold until medium candidates and missing classes are reviewed.

## Do not do next

- Do not blindly expand API runs.
- Do not train LoRA immediately.
- Do not treat low-confidence samples as high-confidence.
- Do not submit tokens, PCAPs, prompt directories, raw API outputs, parsed model outputs, weights, or adapters.
