# openEuler deployment notes

openEuler environments may use `dnf` or `yum` instead of `apt`. Deployment scripts and runbooks should avoid assuming Debian or Ubuntu package names.

## System checks

- Confirm Python 3 is available.
- Confirm `pip` or a site-approved Python package workflow is available.
- Confirm `tshark`, Zeek, and Suricata availability if local PCAP parsing is required.
- Docker may or may not be installed; treat it as optional unless the organizer image requires it.

## Package installation

Use the platform package manager provided by the environment:

```bash
dnf install python3 python3-pip wireshark-cli zeek suricata
```

or:

```bash
yum install python3 python3-pip wireshark-cli zeek suricata
```

Exact package names can differ by mirror and organizer image. Record final commands in the deployment log rather than hard-coding them into the main pipeline.

## Model endpoint

The offline pipeline does not call a model. If an online/local model service is explicitly enabled later, use an OpenAI-compatible local endpoint such as:

```text
http://127.0.0.1:8000/v1
```

Store `LLM_BASE_URL`, `LLM_MODEL_NAME`, and `LLM_API_KEY` only in environment variables.
