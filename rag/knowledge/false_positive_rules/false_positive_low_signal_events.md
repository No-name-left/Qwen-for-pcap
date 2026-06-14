---
doc_id: "false_positive_low_signal_events"
title: "Low signal event handling"
category: "false_positive_rules"
attack_types: ["normal"]
attack_stages: ["none"]
keywords: ["low signal", "packet_count", "conn_count", "no alert", "empty fields"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Low signal event handling

## Evidence

Low-signal events have very small packet_count or conn_count, no Suricata alerts, no meaningful DNS/HTTP/TLS samples, and no suspicious connection pattern.

## Judgment

Such events should usually be normal with attack_stage none. Evidence should state which strong indicators are absent.

## Stage mapping

none is appropriate because the event does not support an attack phase.

## Boundaries

Do not let surrounding dataset context or candidate hints turn empty evidence into an attack.
