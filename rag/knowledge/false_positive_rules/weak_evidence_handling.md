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

Weak evidence often appears as low packet/connection counts, empty HTTP/DNS/TLS summaries, low byte volume, and no repeated behavior pattern. In that situation, use `TN01_01` with appropriately low confidence unless another concrete field provides stronger evidence.
