---
doc_id: competition_TA03_01_backdoor_install
title: TA03_01 backdoor installation
category: competition_labels
attack_types: [backdoor]
attack_stages: [persistence]
keywords: [TA03_01, TA03, backdoor install, implant, persistence, dropper, webshell upload, service creation, autorun]
source_type: official_or_distilled
safe_for_llm: true
---

# TA03_01 backdoor installation

Use `TA03_01` when the record evidence indicates installation or creation of durable unauthorized access. Strong evidence includes webshell upload or placement, implant or dropper delivery, service creation, scheduled task or autorun persistence, backdoor file transfer, or alerts that explicitly describe implant/persistence installation.

`TA03_01` is persistence. It should map to stage `TA03`.

# Normal and background avoidance

Do not classify ordinary file downloads, software updates, normal admin transfers, generic malware callback traffic, or exploit attempts without installation evidence as `TA03_01`.

If the record only shows command-and-control check-ins after compromise, prefer a TA11 code.

# Boundary cues

Prefer `TA11_01` when the evidence is interactive access to an already installed backdoor.

Prefer `TA11_02` when the evidence is outbound malware callback, beaconing, or check-in traffic.

Prefer `TA01_02` when the evidence is exploitation but persistence is not shown.
