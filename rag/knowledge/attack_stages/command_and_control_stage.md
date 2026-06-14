---
doc_id: "command_and_control_stage"
title: "Command and control stage"
category: "attack_stages"
attack_types: ["c2", "trojan_callback", "backdoor"]
attack_stages: ["command_and_control"]
keywords: ["command_and_control", "C2", "CnC", "beacon", "callback"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Command and control stage

## Evidence

Command-and-control evidence includes CnC checkins, beaconing, botnet traffic, malware callback signatures, and repeated outbound control-channel behavior.

## Judgment

Use command_and_control when the event supports remote instructions, status reporting, or malware infrastructure contact.

## Stage mapping

C2 and trojan_callback usually map here; backdoor may map here when active control is visible.

## Boundaries

Scheduled software updates and normal telemetry can look periodic. Require suspicious indicators or strong IDS evidence.

## Source grounding

Grounded by MITRE ATT&CK Command and Control tactic pages, Suricata C2/malware categories, STRRAT public references, and local rule metadata for CnC/checkin behavior. Malware checkins, callbacks, suspicious DNS/HTTP/TLS destinations, and beacon-like sessions support `command_and_control`.
