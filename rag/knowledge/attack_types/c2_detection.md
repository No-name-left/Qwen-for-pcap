---
doc_id: "c2_detection"
title: "C2 detection"
category: "attack_types"
attack_types: ["c2"]
attack_stages: ["command_and_control"]
keywords: ["C2", "CnC", "beacon", "checkin", "botnet", "command_and_control"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# C2 detection

## Evidence

C2 evidence includes malware checkin signatures, beacon-like periodicity, suspicious external domains, repeated small connections, botnet categories, or known command-and-control protocol indicators.

## Judgment

Classify as C2-like behavior when repeated outbound sessions suggest an established channel for remote instructions or status exchange. Require multiple corroborating connection, timing, service, DNS, HTTP, or TLS indicators.

## Stage mapping

C2 maps to command_and_control because the traffic supports remote coordination after compromise.

## Boundaries

Periodic traffic alone is not proof of C2. Combine timing with domain reputation, alert signature, protocol behavior, payload hints, or unusual destination context.
