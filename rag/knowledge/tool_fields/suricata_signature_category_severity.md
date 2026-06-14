---
doc_id: "suricata_signature_category_severity"
title: "Suricata signature category and severity"
category: "tool_fields"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["Suricata", "signature", "category", "severity", "ET", "alert"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Suricata signature category and severity

## Evidence

Signature names often contain the most useful semantic hint, while category gives a coarse class and severity gives rule priority. Specific family or CVE names usually carry stronger meaning than generic protocol warnings.

## Judgment

High severity increases attention but does not replace evidence. A low severity protocol anomaly may be less important than repeated malware-family alerts.

## Stage mapping

Category can guide stage mapping: scan to reconnaissance, exploit to initial_access, malware command and control to command_and_control.

## Boundaries

Do not overfit severity alone. Some noisy environments trigger many low-signal alerts.
