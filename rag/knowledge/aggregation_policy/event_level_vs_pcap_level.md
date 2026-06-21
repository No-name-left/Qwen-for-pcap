---
doc_id: "event_level_vs_pcap_level"
title: "Event-level versus PCAP-level judgment"
category: "aggregation_policy"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["event level", "pcap level", "aggregation", "mixed traffic"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Event-level versus PCAP-level judgment

## Evidence

An event-level decision describes one traffic slice or flow group. A PCAP-level decision summarizes all events in the capture.

## Judgment

One PCAP may contain normal traffic, scanning, exploit attempts, callbacks, and C2 events. Do not force every event to inherit the same class.

## Stage mapping

Stages can differ across events within the same capture.

## Boundaries

Event-level normal results do not erase separate high-confidence attack events.

## Relevant event card fields

For session-level judgment, use only fields present in the current record: Zeek connection/application summaries, tshark packet/stream features, and within-PCAP behavior statistics. Preserve each record's strongest evidence instead of replacing it with a majority vote from many low-signal records.

## Source grounding

Grounded by project aggregation policy and general intrusion-analysis practice. Event-level decisions must be made from the current event card fields, while PCAP-level summaries aggregate representative high-confidence events. A PCAP can contain normal events alongside scan, exploit, callback, or C2 events; the RAG must not encode current test answers or evaluation mappings.
