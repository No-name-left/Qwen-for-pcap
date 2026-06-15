---
doc_id: competition_boundary_TA11_02_vs_TN01_01
title: Boundary TA11_02 trojan callback versus TN01_01 normal outbound access
category: competition_labels
attack_types: [trojan_callback, c2, normal]
attack_stages: [command_and_control, none]
keywords: [TA11_02, TN01_01, trojan callback, C2, beacon, normal telemetry, periodic traffic, false positive]
source_type: official_or_distilled
safe_for_llm: true
---

# Boundary: TA11_02 vs TN01_01

`TA11_02` requires malware callback or C2 evidence such as botnet/RAT signatures, repeated outbound beacons, callback URI patterns, C2-like protocol use, suspicious repeated failed callbacks, or clear compromised-host check-ins.

`TN01_01` is appropriate for normal DNS, NBNS, web access, software update checks, telemetry, CDN traffic, and other ordinary outbound business access.

Periodic traffic alone is not enough for `TA11_02`; many legitimate services check in periodically.

Do not classify clear malware callback traffic as normal merely because payload is absent. Use flow shape, alerts, endpoint role, service, duration, bytes, and repeated behavior together.
