# Targeted patch after Zeek eval

## Observed failures

- Completed API subset was tiny because HF Router stalled during smoke10 batch 7.
- All six non-portscan completed records were predicted as TN01_01, including CTU TA11_02 and flow-only TA01 records.
- Portscan scan_group remained TA43_01.

## Patch applied

- Added `conservative_normal_vs_callback_boundary` RAG document.
- Rebalanced prompt policy: weak evidence remains conservative, but strong multi-field attack evidence should not be collapsed to TN01_01.
- Marked flow-only CIC/CSE rows as secondary evidence, not primary PCAP parser validation.

## Retest

- Patch-test prompts were prepared, but API retest was skipped due HF Router long-tail risk.
