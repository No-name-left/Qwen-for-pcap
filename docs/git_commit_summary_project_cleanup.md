# Git commit summary: project cleanup

## Intended commit message

```text
Organize Qwen-for-pcap mainline documentation and archive old reports
```

## Included

- README refresh for the current Zeek-first official-code mainline.
- `.gitignore` safety updates for prompt directories, raw/parsed API outputs, submissions, logs, weights, and local caches.
- Project inventory, mainline manifest, archive manifest, outputs cleanup report, current status handoff, and cleanup summary.
- Archive moves for old docs, old RAG reports, old data-search/supplement metadata, old tracked API-test reports, and earlier unbalanced eval metadata.

## Excluded

- `.env`
- raw PCAP/cap/pcapng/binetflow datasets
- large raw CSVs
- prompt full directories
- API raw responses
- parsed model outputs
- generated submission CSVs
- Zeek/Suricata logs
- model weights and LoRA adapters

## Safety checks to run before commit

- `git status`
- `git diff --stat`
- staged path scan for `.env`, PCAPs, prompt dirs, raw/parsed outputs, weights, adapters, and token-like strings.
