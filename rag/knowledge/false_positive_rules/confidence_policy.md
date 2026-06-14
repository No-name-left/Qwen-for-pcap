---
doc_id: "confidence_policy"
title: "Confidence policy"
category: "false_positive_rules"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["confidence", "evidence", "severity", "alert_count", "uncertainty"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Confidence policy

## Evidence

Confidence should reflect evidence strength. Specific family or CVE signatures with matching protocol context justify higher confidence. Weak shape-only evidence or isolated anomalies require lower confidence.

## Judgment

Use high confidence for specific, corroborated evidence; medium confidence for plausible but partial evidence; low confidence for missing or ambiguous evidence.

## Stage mapping

Stage confidence should match the same evidence. Do not confidently assign command_and_control without callback, beacon, or C2 evidence.

## Boundaries

Confidence is not a probability from the tools; it is the model's calibrated judgment from event-card evidence.
