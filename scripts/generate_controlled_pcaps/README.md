# Controlled PCAP fixtures

`generate_safe_http_scenarios.py` captures loopback-only, fixed-response traffic for eight competition technique boundaries. It never scans a non-loopback host, executes a command, persists an upload, implements a functional shell/backdoor, or uses malware.

Generated PCAPs are `synthetic_controlled`: parser/prompt/RAG coverage fixtures only. They must never be reported as public/external data or included in strict metrics.

```bash
python3 scripts/generate_controlled_pcaps/generate_safe_http_scenarios.py --variants 3
```
