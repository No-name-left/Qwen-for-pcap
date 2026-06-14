---
doc_id: "dos_ddos_detection"
title: "DoS and DDoS detection"
category: "attack_types"
attack_types: ["other_attack"]
attack_stages: ["initial_access"]
keywords: ["DoS", "DDoS", "flood", "SYN flood", "high_volume_activity"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# DoS and DDoS detection

## Evidence

DoS evidence includes extreme packet or connection volume, many sources hitting one service, repeated reset or timeout states, and signatures naming floods or denial-of-service behavior.

## Judgment

Because the closed attack_type set has no dos label, classify strong DoS evidence as other_attack with subtype dos_ddos.

## Stage mapping

DoS does not fit neatly into the listed stages; use initial_access when the event is an active attack against availability, and explain the mapping.

## Boundaries

High volume alone is not enough. Large file transfers, backups, or scans can be noisy; require flood pattern, service impact indicators, or IDS support.
