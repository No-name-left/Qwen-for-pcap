---
doc_id: "suricata_eve_alerts"
title: "Suricata EVE alerts"
category: "tool_fields"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["Suricata", "eve.json", "alert", "signature", "category", "severity"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Suricata EVE alerts

## Evidence

Suricata eve.json alert records provide signature, category, severity, action, flow, protocol, and addresses. In event cards, suricata_alerts and suricata_alert_count are strong IDS evidence.

## Judgment

Use signature text and category to map behavior. Malware CnC categories support c2; exploit categories support exploit; scan categories support port_scan.

## Stage mapping

The stage follows the signature meaning and traffic context.

## Boundaries

IDS alerts can be false positives or broad signatures. Combine alert count, signature specificity, protocol, port, and Zeek/tshark context.

## Source grounding

Grounded by Suricata EVE JSON format documentation and local ET Open rule metadata. `alert.signature`, `alert.category`, and `alert.severity` are IDS evidence and often strong retrieval keys, but they must be interpreted with protocol, port, flow, and Zeek/tshark context. Protocol anomaly alerts need low-confidence handling unless corroborated.
