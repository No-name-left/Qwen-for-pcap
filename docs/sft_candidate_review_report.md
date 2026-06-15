# SFT candidate review report

- Gate: `PASS`
- Total candidates: 181
- accept_high: 57
- accept_medium_needs_review: 94
- rejected: 30
- needs_manual_review: 0
- Recommend immediate LoRA: False

## Per-class review

| code | accept_high | accept_medium_needs_review | rejected/heldout/low | needs_manual_review | training status |
| --- | ---: | ---: | ---: | ---: | --- |
| TA43_01 | 0 | 0 | 1 | 0 | not enough reliable candidates |
| TA43_02 | 0 | 0 | 0 | 0 | not enough reliable candidates |
| TA01_01 | 0 | 25 | 5 | 0 | possible after manual review; not high-confidence only |
| TA01_02 | 0 | 25 | 5 | 0 | possible after manual review; not high-confidence only |
| TA03_01 | 0 | 0 | 0 | 0 | not enough reliable candidates |
| TA11_01 | 0 | 0 | 0 | 0 | not enough reliable candidates |
| TA11_02 | 57 | 18 | 5 | 0 | usable as high-confidence seed, still imbalanced |
| TN01_01 | 0 | 26 | 14 | 0 | possible after manual review; not high-confidence only |

## Recommendation

- Do not start LoRA training yet.
- Use `accept_high` as a clean seed only after reserving evaluation holdouts.
- Flow-only candidates marked `accept_medium_needs_review` require human inspection of label mapping and session evidence.
- Missing classes (`TA43_02`, `TA03_01`, `TA11_01`) should be filled before claiming an 8-class SFT set.
