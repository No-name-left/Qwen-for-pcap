---
doc_id: "signature_command_injection"
title: "Command injection signature"
category: "signatures"
attack_types: ["exploit"]
attack_stages: ["initial_access"]
keywords: ["command injection", "cmd", "shell", ";", "wget", "curl"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Command injection signature

## Evidence

Command injection evidence includes shell metacharacters, command names, download-and-execute patterns, or signatures naming OS command injection.

## Judgment

Classify as exploit with subtype command_injection when request evidence shows attempted command execution.

## Stage mapping

Command injection maps to initial_access because it can execute attacker commands through a vulnerable service.

## Boundaries

Metacharacters alone may appear in encoded values. Confidence depends on dangerous command context and alert specificity.
