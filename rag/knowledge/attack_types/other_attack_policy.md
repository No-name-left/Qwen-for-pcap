---
doc_id: "other_attack_policy"
title: "Other attack policy"
category: "attack_types"
attack_types: ["other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["other_attack", "policy", "uncertain", "closed vocabulary"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Other attack policy

## Evidence

other_attack is for clear malicious or attack-like evidence that does not fit normal, port_scan, exploit, backdoor, trojan_callback, or c2.

## Judgment

Use other_attack sparingly and name the subtype, such as brute_force, dos_ddos, web_attack, protocol_abuse, or data_exfiltration. If evidence is insufficient, choose normal instead.

## Stage mapping

The stage should still be selected from the closed stage list according to behavior.

## Boundaries

Do not hide uncertainty in other_attack. Low evidence belongs in normal/none with low confidence and a direct evidence statement.
