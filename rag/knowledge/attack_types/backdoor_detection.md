---
doc_id: "backdoor_detection"
title: "Backdoor detection"
category: "attack_types"
attack_types: ["backdoor"]
attack_stages: ["persistence", "command_and_control"]
keywords: ["backdoor", "implant", "beacon", "shell", "DOUBLEPULSAR"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Backdoor detection

## Evidence

Backdoor evidence includes implant beacons, unauthorized remote shell behavior, suspicious listener access, or signatures naming a backdoor family or post-exploitation implant.

## Judgment

Use backdoor when evidence points to a persistent or implanted access mechanism. If the behavior is only a callback from a Trojan, trojan_callback may be narrower.

## Stage mapping

Backdoor traffic can map to persistence when it indicates durable access, or command_and_control when it shows active remote control.

## Boundaries

A successful connection to an admin service is not automatically a backdoor. Require implant, unauthorized shell, or backdoor-specific signature evidence.
