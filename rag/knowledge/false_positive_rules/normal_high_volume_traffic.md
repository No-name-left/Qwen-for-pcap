---
doc_id: "normal_high_volume_traffic"
title: "Normal high volume traffic"
category: "false_positive_rules"
attack_types: ["normal", "other_attack"]
attack_stages: ["none", "initial_access"]
keywords: ["high volume", "packet_count", "conn_count", "backup", "monitoring"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Normal high volume traffic

## Evidence

High packet_count or conn_count can come from backups, monitoring, vulnerability management, file transfers, CDN traffic, or busy services.

## Judgment

High volume supports attack only when the pattern matches scan, flood, exfiltration, or malware behavior.

## Stage mapping

Without attack semantics, the stage should remain none.

## Boundaries

Do not equate high_volume_activity with DoS. Require rate, many sources, target pressure, or IDS flood signatures.
