---
doc_id: competition_conservative_normal_vs_callback_boundary
title: Conservative normal versus callback boundary
category: competition_labels
attack_types: [normal, trojan_callback, c2]
attack_stages: [none, command_and_control]
keywords: [TN01_01, TA11_02, normal boundary, callback boundary, high fanout, failed rate, flow-only limitation]
source_type: official_or_distilled
safe_for_llm: true
---

# Conservative normal versus callback boundary

Conservative normal policy means avoiding attack labels when the record has only generic DNS, NBNS, short connection, or low-detail flow features. It does not mean every record without a Suricata alert is normal.

Use `TA11_02` when the record evidence shows compromised-host outbound communication patterns such as repeated external callbacks, many outbound connections from the same source, high failed-connection context, asymmetric bytes, IRC/HTTP callback-like services, or C2/callback signatures.

Use `TN01_01` when the record is ordinary business access, isolated DNS/NBNS, benign web access, or a flow-only row with insufficient fields to prove brute force, exploit, implant, backdoor access, or callback.

Flow-only CIC/CSE rows can support secondary evaluation when labels are hidden from prompts, but they should not be treated as primary PCAP evidence because source/destination identity, payload, Zeek service context, and packet-level timing may be unavailable.
