---
doc_id: observable_beacon_timing_boundary
title: Beacon intervals and benign periodic traffic boundary
category: observable_evidence
attack_types: [trojan_callback, c2, normal]
attack_stages: [command_and_control, none]
keywords: [interval_summary, regularity_score, beacon_score, fixed_endpoint_duration, fixed endpoint, small packets, packet size pattern, TLS SNI, DNS query, benign_periodic_hints, software update, DNS refresh, NTP, cloud sync, health check, browser background, WPAD, TA11_02, TN01_01]
source_type: project_distilled
safe_for_llm: true
---

# Closed-set use

Repeated source-initiated contact with one endpoint, stable multi-second intervals, similar transfer sizes, small packets, unusual port, repeated DNS/SNI, suspicious domain/SNI/URI, or callback context can jointly support `TA11_02`. These metadata remain useful for encrypted TLS, SSH, and QUIC.

# Benign boundary

Periodicity alone is not malicious. Software updates, WPAD, DNS refresh, NTP, monitoring, cloud sync, browser background connections, health checks, and telemetry can be regular and should remain `TN01_01` without additional callback evidence. Normal domain/SNI, common services, common ports, and business access context reduce malicious probability. A sub-second application request burst is not a beacon merely because its intervals are regular.

# Retrieval cues

Use this card when the record exposes `beacon_score`, `regularity_score`, `fixed_endpoint_duration`, `interval_summary`, `bytes_pattern`, `packet size pattern`, TLS SNI/DNS query repetition, fixed endpoint, or `benign_periodic_hints`.
