---
doc_id: competition_technique_codes
title: Official competition technique codes
category: competition_labels
attack_types: [normal, port_scan, exploit, backdoor, trojan_callback, c2, other_attack]
attack_stages: [none, reconnaissance, initial_access, persistence, command_and_control]
keywords: [TA43_01, TA43_02, TA01_01, TA01_02, TA03_01, TA11_01, TA11_02, TN01_01, technique_code]
source_type: official_or_distilled
safe_for_llm: true
---

# Official competition technique codes

Technique prediction must use only these official codes:

- `TA43_01`: port scan.
- `TA43_02`: vulnerability scan.
- `TA01_01`: password brute force.
- `TA01_02`: vulnerability exploitation.
- `TA03_01`: implant backdoor.
- `TA11_01`: access backdoor.
- `TA11_02`: malware callback.
- `TN01_01`: normal browsing or business access.

Legacy internal labels are only intermediate hints. Final output must be the official code.

For weak, ambiguous, or purely reputation-based evidence, prefer `TN01_01` rather than forcing an attack code.

No expected labels, answer sheets, or raw test answers belong in this knowledge base.
