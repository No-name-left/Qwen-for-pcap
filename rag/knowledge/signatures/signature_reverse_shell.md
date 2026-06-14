---
doc_id: "signature_reverse_shell"
title: "Reverse shell signature"
category: "signatures"
attack_types: ["backdoor", "c2"]
attack_stages: ["command_and_control"]
keywords: ["reverse shell", "shell", "callback", "connect back", "nc"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Reverse shell signature

## Evidence

Reverse shell signatures indicate a host connecting outward to provide an interactive command channel. Evidence may include shell keywords, unusual outbound sessions, or alert categories naming shellcode or reverse shell.

## Judgment

Classify as backdoor or c2 depending on whether the evidence emphasizes unauthorized shell access or command channel operation.

## Stage mapping

The usual stage is command_and_control because it enables remote control.

## Boundaries

Outbound connections are common. Require shell-specific evidence or strong IDS support.
