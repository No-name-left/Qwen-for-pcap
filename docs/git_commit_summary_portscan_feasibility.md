# Git commit summary: portscan feasibility

## Commit scope

This commit includes code, docs, manifests, reports, and small metadata only. Large PCAP/CSV/zip/parser outputs remain ignored.

## Ignored data classes

- `*.pcap`, `*.pcapng`, `*.cap`
- `*.zip`, `*.tar.gz`
- `*.binetflow`
- large public CSV files
- `outputs/parsed/`, `outputs/session_cards/`, `outputs/submissions/`
- `outputs/api_tests/**/raw/`, `outputs/api_tests/**/parsed/`
- `.env`, token-like files, model weights, and LoRA adapters

## Portscan result

- Portscan source: controlled localhost TCP connect scan PCAP.
- Session cards: 368.
- Scan groups: 1.
- Classification records: 6.
- Prompt outputs: non-empty.
- Dry-run CSV outputs: non-empty placeholders, not model predictions.

## Verdict

`PORTSCAN_SCAN_GROUP_READY_FOR_API_TEST`
