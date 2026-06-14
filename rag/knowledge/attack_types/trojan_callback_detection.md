---
doc_id: "trojan_callback_detection"
title: "Trojan callback detection"
category: "attack_types"
attack_types: ["trojan_callback"]
attack_stages: ["command_and_control"]
keywords: ["trojan", "callback", "malware download", "phone home", "HTTP callback"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Trojan callback detection

## Evidence

Trojan callback evidence includes malware-family alerts, suspicious HTTP or TLS outbound contact, file retrieval followed by callback, or signatures describing a Trojan checkin.

## Judgment

Use trojan_callback when the evidence emphasizes malware calling home rather than a general-purpose C2 channel. If the signature explicitly says CnC or botnet, c2 may be more precise.

## Stage mapping

Most callbacks map to command_and_control because the compromised host is contacting external infrastructure.

## Boundaries

Do not classify ordinary software update checks as trojan_callback without malware-specific signatures or suspicious domain, URI, or payload evidence.
