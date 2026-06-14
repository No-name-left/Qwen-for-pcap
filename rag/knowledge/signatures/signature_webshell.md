---
doc_id: "signature_webshell"
title: "Webshell signature"
category: "signatures"
attack_types: ["backdoor", "c2"]
attack_stages: ["persistence", "command_and_control"]
keywords: ["webshell", "shell", "cmd", "upload", "backdoor"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Webshell signature

## Evidence

Webshell signatures indicate a server-side script or endpoint used for unauthorized command execution. Evidence may include known webshell names, command parameters, or upload paths.

## Judgment

Classify as backdoor when the evidence suggests persistent unauthorized access; use c2 when the event shows active remote command exchange.

## Stage mapping

Webshells often map to persistence or command_and_control.

## Boundaries

A shell-like filename alone is weak. Require signature, command parameters, or suspicious repeated access.
