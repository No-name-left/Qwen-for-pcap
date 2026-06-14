---
doc_id: "event_to_pcap_aggregation"
title: "Event to PCAP aggregation policy"
category: "aggregation_policy"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["aggregate_events_to_pcap", "aggregation", "high confidence", "attack summary"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Event to PCAP aggregation policy

## Evidence

PCAP-level aggregation should preserve the strongest and most specific high-confidence attack events. A few strong exploit or C2 events can be enough to mark the PCAP as attack.

## Judgment

Aggregate by collecting attack types, stages, top evidence, alert counts, and representative events. Keep normal counts as context, not as a vote to suppress attacks.

## Stage mapping

The PCAP-level stage can summarize the highest-confidence observed stages or an attack chain.

## Boundaries

Do not let many low-signal normal events outweigh a small number of concrete malicious alerts.
