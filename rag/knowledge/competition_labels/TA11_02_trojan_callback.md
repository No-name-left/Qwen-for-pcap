---
doc_id: competition_TA11_02_trojan_callback
title: TA11_02 trojan callback
category: competition_labels
attack_types: [trojan_callback, c2]
attack_stages: [command_and_control]
keywords: [TA11_02, TA11, trojan callback, malware callback, C2, beacon, check-in, botnet, RAT]
source_type: official_or_distilled
safe_for_llm: true
---

# TA11_02 trojan callback

Use `TA11_02` when the record indicates malware outbound callback or command-and-control check-in. Strong evidence includes repeated outbound beacons, RAT or botnet signatures, callback URI patterns, IRC/HTTP/TLS C2-like communication, asymmetric small request and response patterns, repeated failed callbacks, or recurring contact from an internal host to a suspicious external endpoint.

`TA11_02` is command and control. It should map to stage `TA11`.

# Normal and background avoidance

Do not classify ordinary DNS, NBNS, software updates, telemetry, CDN access, or normal periodic business traffic as `TA11_02` without stronger malware/C2 evidence.

High connection volume alone is not enough. Prefer `TN01_01` when the record lacks malware/callback evidence.

# Boundary cues

Prefer `TA11_01` when the traffic shows interactive access to an already installed backdoor.

Prefer `TA03_01` when the evidence is installation or persistence rather than callback.
