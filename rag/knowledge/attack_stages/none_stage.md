---
doc_id: "none_stage"
title: "None stage"
category: "attack_stages"
attack_types: ["normal"]
attack_stages: ["none"]
keywords: ["none", "normal", "insufficient evidence", "low signal"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# None stage

## Evidence

Use none when event evidence does not support an attack. Low packet_count, missing alerts, ordinary protocol use, or empty semantic fields usually point here.

## Judgment

The correct output for insufficient evidence is normal/none, even if the larger dataset contains attacks elsewhere.

## Stage mapping

none means no attack stage is supported for this event.

## Boundaries

Do not convert uncertainty into other_attack. State which expected evidence is absent and keep confidence low.
