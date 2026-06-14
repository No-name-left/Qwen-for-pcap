---
doc_id: "stage_mapping_overview"
title: "Attack stage mapping overview"
category: "attack_stages"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["attack_stage", "none", "reconnaissance", "initial_access", "command_and_control"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Attack stage mapping overview

## Evidence

Stage selection should describe what the event is doing, not what the surrounding PCAP is known for. Use event-level evidence such as scan breadth, exploit signatures, callback alerts, and connection summaries.

## Judgment

The stage vocabulary is closed: none, reconnaissance, initial_access, persistence, and command_and_control.

## Stage mapping

Choose reconnaissance for probing, initial_access for entry attempts, persistence for durable access mechanisms, command_and_control for remote coordination, and none for benign or unsupported events.

## Boundaries

A case may contain several stages. Do not force every event into the same stage when local evidence is weak.
