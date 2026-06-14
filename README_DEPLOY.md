# Deployment README

This repository now supports an offline session-level competition skeleton:

```bash
bash scripts/check_env.sh
bash run_stage1.sh
bash run_stage2.sh
bash export_submission.sh --dry-run
```

The default scripts do not call online APIs and do not consume model quota.

## Environment

- Python 3 is required.
- `pip` is required for installing Python dependencies.
- `tshark`, Zeek, and Suricata are recommended for parsing PCAPs.
- Docker is optional unless the organizer provides a required image.
- openEuler hosts may use `dnf` or `yum`; do not assume `apt`.

## Deployment constraints

Formal access may require VPN plus bastion. VS Code Remote or Codex may not be available. Prepare a release archive and upload it through the approved web file-transfer path when necessary.

## Model service

If model execution is explicitly enabled later, configure an OpenAI-compatible local endpoint:

```bash
export LLM_BASE_URL="http://127.0.0.1:8000/v1"
export LLM_MODEL_NAME="Qwen3.5-27B"
export LLM_API_KEY="<set outside repo if required by the local gateway>"
```

The scripts only report whether `LLM_API_KEY` exists; they never print the value.
