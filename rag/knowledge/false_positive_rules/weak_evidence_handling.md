---
doc_id: "weak_evidence_handling"
title: "Weak evidence handling"
category: "false_positive_rules"
attack_types: ["normal"]
attack_stages: ["none"]
keywords: ["weak evidence", "candidate_labels", "source_presence", "confidence"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Weak evidence handling

## Evidence

Weak evidence includes empty semantic samples, no alerts, low counts, or candidate labels generated from broad heuristics only.

## Judgment

When evidence is weak, choose normal/none or use low confidence. Candidate labels should guide retrieval, not decide classification.

## Stage mapping

none is the correct stage when no attack behavior is supported.

## Boundaries

A model should cite absence of strong fields rather than invent hidden activity.

## Relevant event card fields

Weak evidence often appears as low `tshark_features.packet_count`, low `zeek_features.conn_count`, empty `zeek_features.http_uris`, empty `zeek_features.dns_queries`, empty `zeek_features.tls_sni`, and zero `suricata_features.suricata_alert_count`. In that situation, use `attack_type=normal`, `attack_stage=none`, and a low confidence unless another concrete field provides stronger evidence.
