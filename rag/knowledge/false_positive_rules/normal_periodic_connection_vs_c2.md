---
doc_id: "normal_periodic_connection_vs_c2"
title: "Normal periodic connection versus C2"
category: "false_positive_rules"
attack_types: ["normal", "c2", "trojan_callback"]
attack_stages: ["none", "command_and_control"]
keywords: ["periodic", "beacon", "telemetry", "update", "C2"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Normal periodic connection versus C2

## Evidence

Periodic connections can be benign software updates, telemetry, time sync, monitoring, or cloud service heartbeats.

## Judgment

C2 requires more than periodicity: suspicious domain, malware alert, unusual destination, beacon payload hint, or known family signature.

## Stage mapping

Confirmed callback maps to command_and_control; ordinary telemetry maps to none.

## Boundaries

Avoid over-alerting on regular intervals alone.
