---
doc_id: competition_phase_codes
title: Official competition stage codes
category: competition_labels
attack_types: [normal, port_scan, exploit, backdoor, trojan_callback, c2, other_attack]
attack_stages: [none, reconnaissance, initial_access, persistence, command_and_control]
keywords: [TA43, TA01, TA03, TA11, TN01, stage_code, official code, macro-F1]
source_type: official_or_distilled
safe_for_llm: true
---

# Official competition stage codes

Stage prediction must use only `TA43`, `TA01`, `TA03`, `TA11`, or `TN01`.

- `TA43` is reconnaissance, including clear scanning and probing behavior.
- `TA01` is initial access, including password brute force and vulnerability exploitation.
- `TA03` is persistence, including implant or backdoor placement evidence.
- `TA11` is command and control, including backdoor access or malware callback behavior.
- `TN01` is normal browsing or business access, and is also the fallback for weak evidence.

The model must not output legacy labels such as `port_scan`, `exploit`, `backdoor`, `c2`, or `normal` as final stage labels.

Predictions must be made per session or per scan-group classification record. PCAP files are independent, and no context can be shared across PCAPs.

IP and domain reputation must not be used. Anonymous IP/domain relationship features inside the same PCAP may be used.
