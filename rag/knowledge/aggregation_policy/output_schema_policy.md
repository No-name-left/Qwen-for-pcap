---
doc_id: "output_schema_policy"
title: "Output schema policy"
category: "aggregation_policy"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["JSON", "schema", "attack_type", "attack_stage", "evidence"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Output schema policy

## Evidence

LLM output should use the closed eight-value `technique_code` vocabulary, include confidence from 0 to 1, and cite concrete evidence fields. It must not predict `stage_code`.

## Judgment

Evidence should mention fields such as Zeek connection state/history, unique destination ports, failed-connection rate, packet/byte counts, DNS queries, HTTP URIs, or TLS SNI when relevant.

## Stage mapping

The exporter derives `stage_code` deterministically from `technique_code`. Schema validity is separate from correctness; a valid JSON object may still be a poor judgment if evidence is weak.

## Boundaries

Do not include hidden chain-of-thought or data not present in the event card.
