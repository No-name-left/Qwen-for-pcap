# Release package plan

The release package should contain the mainline code and documentation needed to reproduce the offline competition skeleton.

## Include

- `configs/`
- `docs/`
- `rag/knowledge/`
- `rag/chunks/`
- `rag/index/`
- `rag/metadata/`
- `rag/reports/`
- `scripts/`
- `README.md`
- `README_DEPLOY.md`
- `requirements.txt`
- `run_stage1.sh`
- `run_stage2.sh`
- `export_submission.sh`

## Exclude by default

- `_non_mainline_archive/`
- raw PCAP files
- old results and large generated outputs
- `.git/`
- virtual environments
- tokens, API keys, cookies, SSH keys, and local `.env`

## Transfer

The formal environment may require web file transfer through a bastion or VPN portal. Build the archive locally, upload it through the approved channel, then unpack it on the target host.

## Model execution

The package supports offline prompt generation and CSV dry-run. Model execution is not automatic. If enabled later, it should use an OpenAI-compatible local endpoint such as `http://127.0.0.1:8000/v1`.
