---
doc_id: competition_TA11_01_backdoor_access
title: TA11_01 backdoor access
category: competition_labels
attack_types: [backdoor, c2]
attack_stages: [command_and_control]
keywords: [TA11_01, TA11, backdoor access, webshell command, reverse shell, interactive shell, operator access]
source_type: official_or_distilled
safe_for_llm: true
---

# TA11_01 backdoor access

Use `TA11_01` when the record shows access to an already present backdoor or shell. Strong evidence includes webshell command requests, reverse-shell interaction, inbound or operator-driven backdoor protocol use, command execution through a known backdoor channel, or alerts describing backdoor access rather than installation.

`TA11_01` is command and control. It should map to stage `TA11`.

# Normal and background avoidance

Do not classify normal remote administration, ordinary SSH/RDP use, or isolated external connections as backdoor access without unauthorized backdoor evidence.

Do not classify periodic malware check-ins as `TA11_01` unless there is evidence of interactive access or backdoor command use.

# Boundary cues

Prefer `TA03_01` when the evidence is installing or placing the backdoor.

Prefer `TA11_02` when the evidence is outbound callback, beaconing, or automated check-in.
