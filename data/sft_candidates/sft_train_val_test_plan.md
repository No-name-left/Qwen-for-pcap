# SFT train/val/test plan

- Gate: `PASS`
- Recommendation: `do_not_train_yet`
- Training target: official technique code only.
- Stage target: deterministic fallback from technique code; do not train a separate stage label first.

## Pools

- accept_high records available after holdout removal: 57
- medium records requiring manual review: 94
- excluded small coverage holdout: 20

## Split policy

- Split by source_dataset and pcap/source_file groups; never place the same PCAP/source file in both train and val/test.
- Keep small coverage records as holdout and out of SFT.
- Do not include missing or low-confidence categories to fill class balance.

## Minimum before training

- Human review accepted for medium flow-only candidates.
- Additional vetted samples for TA43_02, TA03_01, and TA11_01 or explicit decision to train only a reduced-class model.
- Separate validation/test groups not sharing source PCAPs with train.
