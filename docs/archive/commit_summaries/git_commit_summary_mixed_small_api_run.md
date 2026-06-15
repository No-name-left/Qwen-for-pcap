# Git commit summary: mixed small API run

## Included

- Added capped mixed-small API test-set builder.
- Hardened OpenAI-compatible runner with `RUN_API=1`, `--max-files`, request-size controls, raw/parsed ignored output directories, and code statistics.
- Added mixed-small API test summary document.

## Excluded

- `.env` and token values.
- API raw responses.
- Per-batch parsed API outputs.
- Prompt subset files under `outputs/`.
- PCAP, binetflow, parsed logs, large CSVs, model weights, and adapters.

## Result

- API was actually attempted.
- Technique partially succeeded; stage stalled and was stopped.
- Verdict: `NEEDS_FIX`.
