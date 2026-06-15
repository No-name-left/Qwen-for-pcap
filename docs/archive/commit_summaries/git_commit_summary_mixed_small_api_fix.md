# Git commit summary: mixed small API fix

## Included

- Runner safety and retry controls for failure-only reruns.
- Mixed-small diagnosis, merge, and conditional export helper.
- Fix summary for the partial API test.

## Excluded

- API raw responses.
- Parsed model outputs.
- Prompt directories.
- `.env`, token values, PCAP, binetflow, parsed logs, large CSVs, model weights, and adapters.

Verdict: `PARTIAL_SUCCESS_USABLE_FOR_BASTION_PREP`.
