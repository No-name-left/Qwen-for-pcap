# Patch test report

- API patch retest run: false
- Reason: Skipped API patch retest because HF Router long-tail stalled during zeek_eval smoke10 batch 7; avoiding additional quota/time burn.
- Candidate prompt records prepared: 20
- Contains portscan scan_group: true
- Expected-code mix: `{"TA01_01": 5, "TA01_02": 5, "TA11_02": 5, "TA43_01": 1, "TN01_01": 4}`
- Patch effects require a stable local endpoint or a later HF Router window to measure.
