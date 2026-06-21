---
doc_id: "case_level_vs_event_level_labels"
title: "Case-level versus event-level labels"
category: "aggregation_policy"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["case-level", "event-level", "rough agreement", "evaluation"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Case-level versus event-level labels

## Evidence

Case-level labels describe the overall capture or scenario, while event-level labels describe individual traffic slices. These can differ in mixed captures.

## Judgment

Use case-level labels only for rough agreement, not strict event accuracy. Event cards should be judged from their own evidence.

## Stage mapping

A PCAP-level exploit label does not mean every event is exploit; some windows may be normal or C2.

## Boundaries

Future evaluation should add precise event-level labels where possible.

## Relevant event card fields

When evaluating model output, compare the prediction to the session's own evidence first. Case-level references can be useful for rough agreement, but Zeek connection state/history, failed-connection rate, tshark destination-port fanout, and protocol semantic samples are better evidence for an individual decision.
