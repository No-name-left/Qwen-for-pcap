---
doc_id: "zeek_weird_notice_logs"
title: "Zeek weird and notice logs"
category: "tool_fields"
attack_types: ["normal", "other_attack"]
attack_stages: ["none", "initial_access"]
keywords: ["Zeek", "weird.log", "notice.log", "anomaly", "protocol weird"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Zeek weird and notice logs

## Evidence

Zeek weird.log records protocol irregularities and parser observations; notice.log records higher-level notices when policy scripts trigger.

## Judgment

These logs are useful triage signals but vary by policy and environment. Treat notices as stronger than weird entries when they identify a security-relevant condition.

## Stage mapping

Protocol anomalies may support initial_access only when they align with exploit behavior or alerts.

## Boundaries

Many weird entries are low-confidence parser or network artifacts. Do not high-confidence classify attacks from generic weird messages alone.
