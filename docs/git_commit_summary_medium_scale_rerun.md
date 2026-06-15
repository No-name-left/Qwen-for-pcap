# Git commit summary: medium-scale rerun

## Included

- Medium-scale API rerun environment-check report.
- Rerun summary documenting that no API call was made because `RUN_API` was not set to `1`.

## Excluded

- `.env` and token values.
- API raw responses and parsed model outputs.
- Full prompt directories.
- PCAP, binetflow, parsed logs, large CSVs, model weights, and adapters.

Result: rerun blocked before API execution.
