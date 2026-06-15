---
doc_id: competition_TN01_01_normal_business
title: TN01_01 normal business access
category: competition_labels
attack_types: [normal]
attack_stages: [none]
keywords: [TN01_01, TN01, normal, business access, benign, weak evidence, low signal, false positive]
source_type: official_or_distilled
safe_for_llm: true
---

# TN01_01 normal business access

Use `TN01_01` for normal browsing, ordinary business service access, routine DNS/NBNS, software updates, benign telemetry, isolated failed access, and low-signal records without enough evidence for attack technique codes.

`TN01_01` is normal activity. It should map to stage `TN01`.

# Conservative policy

Evidence-insufficient records should usually fall back to `TN01_01`, but this is not permission to ignore clear attack evidence. Clear scan fanout, brute-force authentication patterns, exploit payloads, implant installation, backdoor access, or malware callback should use their attack codes.

# Boundary cues

Avoid false positives from high volume alone, uncommon ports alone, anonymous IP/domain strings, missing payload, single weak alerts, or ordinary periodic traffic.

Prefer `TA11_02` when periodic outbound traffic has clear malware callback or C2 evidence, not just normal telemetry shape.
