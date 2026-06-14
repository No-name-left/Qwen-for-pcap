---
doc_id: "data_exfiltration_detection"
title: "Data exfiltration detection"
category: "attack_types"
attack_types: ["other_attack"]
attack_stages: ["command_and_control"]
keywords: ["exfiltration", "large outbound", "DNS tunnel", "HTTP upload", "data transfer"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Data exfiltration detection

## Evidence

Exfiltration evidence includes unusual outbound volume, suspicious upload paths, DNS tunneling patterns, or alerts naming data leakage and covert channels.

## Judgment

With the current closed vocabulary, strong exfiltration evidence should be other_attack with subtype data_exfiltration unless it is better described as c2.

## Stage mapping

Exfiltration often occurs after access and may share infrastructure with command_and_control, so use command_and_control when the event is outbound coordination or covert transfer.

## Boundaries

Normal uploads and cloud synchronization can be large. Require unusual destination, protocol misuse, alert context, or clear covert-channel indicators.
