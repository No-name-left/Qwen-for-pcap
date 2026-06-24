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

Periodic connections can be benign software updates, WPAD, DNS refresh, NTP, telemetry, monitoring, cloud sync, or service health checks. A regular sub-second request burst is not a long-running beacon.

## Judgment

C2 requires more than periodicity: stable source-initiated remote contact over time plus corroboration such as unusual port, repeated DNS/SNI, similar transfers, callback context, malware alert, or known family signature. Encryption does not make traffic normal, but it also does not make it C2.

## Stage mapping

Confirmed callback maps to command_and_control; ordinary telemetry maps to none.

## Boundaries

Avoid over-alerting on regular intervals alone.
