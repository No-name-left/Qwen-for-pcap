# Deployment README

This repository now supports an offline session-level competition skeleton:

```bash
bash scripts/check_env.sh
bash run_stage1.sh
bash run_stage2.sh
bash export_submission.sh --dry-run
```

The default scripts do not call online APIs and do not consume model quota.

Select one profile from `configs/runtime_profiles.yaml`:

```bash
export RUNTIME_PROFILE=ascend_openeuler_qwen35_27b
# or: nvidia_ubuntu_online_api / dry_run_mock
```

## Environment

- Python 3 is required.
- `pip` is required for installing Python dependencies.
- Zeek is the primary PCAP parser; `tshark` is required for packet-level assistance and fallback. Suricata is not used by the current mainline.
- Docker is optional unless the organizer provides a required image.
- openEuler hosts may use `dnf` or `yum`; do not assume `apt`.

## Deployment constraints

Formal access may require VPN plus bastion. VS Code Remote or Codex may not be available. Prepare a release archive and upload it through the approved web file-transfer path when necessary.

## Model service

If model execution is explicitly enabled later, configure an OpenAI-compatible local endpoint:

```bash
export BASE_URL="http://127.0.0.1:8000/v1"
export MODEL="qwen3.5"
export API_KEY="EMPTY"
```

`LLM_BASE_URL`, `LLM_MODEL_NAME`, and `LLM_API_KEY` remain supported aliases. The scripts only report whether an API key exists; they never print its value. The model predicts `technique_code` only; `stage_code` is mapped deterministically.

Qwen/vLLM requests use `enable_thinking=false` by default. Add `--disable-extra-body` when an online provider does not accept Qwen chat-template parameters.

The Ascend profile assumes a vLLM-Ascend service configured around `--max-model-len 4096 --max-num-seqs 1 --max-num-batched-tokens 2048 --gpu-memory-utilization 0.85`. Model service startup is deployment work; the classification scripts never import `torch_npu`, `transformers`, or load weights directly.

Use GitHub as the code source on both Linux environments: clone once, then `git pull` reviewed commits. Do not maintain a divergent VM ZIP copy. Raw PCAPs, weights, secrets and large outputs stay outside Git; see `docs/vm_operation_notes.md`.
