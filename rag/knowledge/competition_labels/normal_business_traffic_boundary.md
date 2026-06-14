---
doc_id: competition_normal_business_traffic_boundary
title: Normal business traffic boundary
category: competition_labels
attack_types: [normal, other_attack, c2, exploit]
attack_stages: [none, command_and_control, initial_access]
keywords: [TN01_01, TN01, normal business, weak evidence, low signal, false positive]
source_type: official_or_distilled
safe_for_llm: true
---

# Normal business traffic boundary

Use `TN01_01` for normal browsing, normal business access, weak evidence, low-signal sessions, isolated benign protocol anomalies, and records without a clear attack pattern.

Do not overuse attack codes solely because traffic has high volume, uncommon ports, anonymous entities, missing payload, one alert with weak context, or periodic behavior that could be normal telemetry.

For macro-F1 and per-class F1, the goal is balanced correct classification, not maximizing the normal ratio or overall accuracy alone.

Do not rely on IP/domain reputation or test-answer knowledge.
