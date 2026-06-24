---
doc_id: observable_beacon_timing_boundary
title: Beacon intervals and benign periodic traffic boundary
category: observable_evidence
attack_types: [trojan_callback, c2, normal]
attack_stages: [command_and_control, none]
keywords: [interval_summary, regularity_score, beacon_score, fixed_endpoint_duration, benign_periodic_hints, TA11_02, TN01_01]
source_type: project_distilled
safe_for_llm: true
---

# Closed-set use

Repeated source-initiated contact with one endpoint, stable multi-second intervals, similar transfer sizes, unusual port, repeated DNS/SNI, or callback context can jointly support `TA11_02`. These metadata remain useful for encrypted TLS, SSH, and QUIC.

# Benign boundary

Periodicity alone is not malicious. Software updates, WPAD, DNS refresh, NTP, monitoring, cloud sync, health checks, and telemetry can be regular and should remain `TN01_01` without additional callback evidence. A sub-second application request burst is not a beacon merely because its intervals are regular.
