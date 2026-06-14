---
doc_id: "persistence_stage"
title: "Persistence stage"
category: "attack_stages"
attack_types: ["backdoor"]
attack_stages: ["persistence"]
keywords: ["persistence", "backdoor", "implant", "autorun", "durable access"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Persistence stage

## Evidence

Persistence evidence includes backdoor implants, recurring unauthorized access mechanisms, or signatures that indicate installed malware maintaining access.

## Judgment

Use persistence when evidence points to durable access rather than one-time exploitation or ordinary callback.

## Stage mapping

Backdoor and implant signatures are the most common mapping.

## Boundaries

Network-only evidence may not prove persistence. If the event only shows a live control channel, command_and_control may be safer.
