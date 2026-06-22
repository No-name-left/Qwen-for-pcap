# openEuler deployment notes

openEuler environments may use `dnf` or `yum` instead of `apt`. Deployment scripts and runbooks should avoid assuming Debian or Ubuntu package names.

## System checks

- Confirm Python 3 is available.
- Confirm `pip` or a site-approved Python package workflow is available.
- Confirm Zeek and `tshark` availability if local PCAP parsing is required. Suricata is not required.
- Docker may or may not be installed; treat it as optional unless the organizer image requires it.

## Package installation

Use the platform package manager provided by the environment:

```bash
dnf install python3 python3-pip wireshark-cli zeek
```

or:

```bash
yum install python3 python3-pip wireshark-cli zeek
```

Exact package names can differ by mirror and organizer image. Record final commands in the deployment log rather than hard-coding them into the main pipeline.

## Model endpoint

The offline pipeline does not call a model. If an online/local model service is explicitly enabled later, use an OpenAI-compatible local endpoint such as:

```text
http://127.0.0.1:8000/v1
```

Store `BASE_URL`, `MODEL`, and `API_KEY` (or their `LLM_*` aliases) only in environment variables.

Use `RUNTIME_PROFILE=ascend_openeuler_qwen35_27b`. The repository profile budgets prompts for a 4096-token Qwen3.5 service and disables thinking. vLLM-Ascend owns model/NPU loading; the PCAP/RAG/export scripts remain hardware-neutral.
