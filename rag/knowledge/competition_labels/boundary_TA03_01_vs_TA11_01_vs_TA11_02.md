---
doc_id: competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02
title: Boundary TA03_01 install versus TA11_01 access versus TA11_02 callback
category: competition_labels
attack_types: [backdoor, trojan_callback, c2]
attack_stages: [persistence, command_and_control]
keywords: [TA03_01, TA11_01, TA11_02, backdoor install, backdoor access, trojan callback, implant, beacon, C2]
source_type: official_or_distilled
safe_for_llm: true
---

# Boundary: TA03_01 vs TA11_01 vs TA11_02

`TA03_01` is installation or persistence. Choose it for webshell upload, implant placement, dropper delivery, service creation, scheduled task creation, autorun persistence, or alerts that describe backdoor installation.

`TA11_01` is access to an existing backdoor. Choose it for webshell command use, reverse-shell interaction, operator-driven backdoor protocol activity, or command execution through a backdoor channel.

`TA11_02` is malware callback. Choose it for outbound C2 check-ins, recurring beacons, RAT or botnet callback signatures, callback URIs, or automated command-and-control communication.

If the record only shows exploitation without persistence, use `TA01_02`. If it only shows normal remote administration without unauthorized backdoor evidence, use `TN01_01`.
