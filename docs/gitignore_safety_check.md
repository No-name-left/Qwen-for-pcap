# Gitignore safety check

## Status

- `.env`: ignored.
- PCAP/cap/pcapng: ignored.
- binetflow: ignored.
- compressed raw datasets: ignored.
- prompt directories: ignored.
- API raw/parsed outputs: ignored.
- generated submission CSVs: ignored.
- Zeek logs: ignored.
- Suricata logs: ignored.
- model weights/checkpoints: ignored.
- LoRA adapters: ignored.
- local cache directories: ignored.

## Mainline exceptions

The following lightweight metadata/report paths are intentionally allowed:

- `outputs/README.md`
- `outputs/eval_sets/*.json`
- `outputs/eval_sets/*.csv`
- `outputs/eval_sets/*.md`
- `outputs/tool_checks/*.json`
- `outputs/tool_checks/*.md`
- `outputs/zeek_rebuild/*summary*.json`
- `outputs/zeek_rebuild/*summary*.md`
- `outputs/zeek_rebuild/*comparison*.json`
- `outputs/zeek_rebuild/*comparison*.md`

These exceptions keep small mainline metadata trackable without opening raw output directories.

## Notes

- Existing tracked files remain tracked even if they match ignore rules. This cleanup does not delete historical tracked files that may still be useful as crosswalk/debug material.
- Safety checks before commit should still scan staged paths and staged content for token-like strings.
