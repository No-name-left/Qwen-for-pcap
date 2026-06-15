# Git commit summary: official-code coverage and small test

## Intended commit message

```text
Complete official-code data RAG coverage and small evaluation
```

## Files intended for commit

- Dataset coverage audit and supplement metadata under `datasets/metadata/`.
- Official-code RAG docs, boundary docs, rebuilt chunks/index, and RAG reports.
- Balanced eval and small coverage eval metadata under `outputs/eval_sets/`.
- SFT audit inventory, reviewed manifest, train/val/test plan, and review report.
- Final project summary docs.

## Files intentionally not committed

- `.env` and any token-bearing files.
- PCAP/pcapng/cap/binetflow/raw downloaded datasets and large CSVs.
- Zeek/Suricata parsed logs and full session-card/classification-record outputs.
- `outputs/api_tests/**/prompts_*` full prompt directories.
- `outputs/api_tests/**/raw`, `outputs/api_tests/**/parsed`, API `results.json`, and other model raw/parsed outputs.
- Model weights, LoRA adapters, and caches.

## Local generated outputs kept ignored

- `outputs/api_tests/small_coverage/` contains prompt generation artifacts, API run outputs, CSV exports, and evaluation reports for local inspection.
- Detailed model outputs are intentionally local-only.
