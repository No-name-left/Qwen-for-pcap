---
doc_id: "attack_type_mapping"
title: "Attack type mapping policy"
category: "attack_types"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["attack_type", "taxonomy", "normal", "exploit", "c2"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Attack type mapping policy

## Evidence

Event cards should be mapped to the smallest supported attack_type that is directly supported by evidence. The output vocabulary is closed: normal, port_scan, exploit, backdoor, trojan_callback, c2, and other_attack.

## Judgment

Use port_scan for scanning evidence, exploit for vulnerability-use evidence, backdoor for implant access, trojan_callback for malware calling home, c2 for established command-and-control, and other_attack only when strong attack evidence does not fit the main classes.

## Stage mapping

The stage should follow the observed behavior, not the file source. Reconnaissance maps to discovery, initial_access to attempted entry, persistence to durable access, command_and_control to remote control, and none to benign or insufficient evidence.

## Boundaries

Do not use other_attack as a synonym for uncertain. If evidence is weak or missing, prefer normal with low confidence and explain the missing evidence.
