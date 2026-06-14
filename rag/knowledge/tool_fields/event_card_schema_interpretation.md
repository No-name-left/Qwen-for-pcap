---
doc_id: "event_card_schema_interpretation"
title: "Event card schema interpretation"
category: "tool_fields"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["event card", "source_presence", "candidate_labels", "rag_query", "preliminary_observation"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Event card schema interpretation

## Evidence

An event card aggregates tshark, Zeek, and Suricata evidence for one traffic slice. source_presence tells which tools contributed data; candidate_labels are heuristic hints, not ground truth.

## Judgment

The model should cite concrete fields such as packet_count, unique_dst_ports, conn_count, failed_conn_rate, dns_queries, http_uri_samples, tls_sni_samples, suricata_alert_count, and top signatures.

## Stage mapping

The final attack_type and attack_stage must be inferred from evidence, not copied from candidate labels.

## Boundaries

If source_presence shows no IDS alert and semantic fields are empty, confidence should usually be lower unless traffic shape is very strong.
