---
doc_id: "protocol_smb"
title: "SMB protocol interpretation"
category: "protocols"
attack_types: ["normal", "exploit", "backdoor", "trojan_callback", "c2"]
attack_stages: ["none", "initial_access", "persistence", "command_and_control"]
keywords: ["SMB", "SMBv1", "port 445", "port 139", "MS17-010", "Windows file sharing"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# SMB protocol interpretation

## Evidence

SMB commonly uses ports 445 and 139 for Windows file sharing, named pipes, and administrative operations. Vulnerability evidence may mention SMBv1, MS17-010, malformed transactions, or implant beacons.

## Judgment

SMB exploit classification requires vulnerability-specific evidence, not just port use. Post-exploitation SMB implant signatures may map to backdoor, trojan_callback, or c2.

## Stage mapping

SMB exploit maps to initial_access; implant or beacon behavior can map to persistence or command_and_control.

## Boundaries

Normal Windows networks generate SMB traffic. Avoid over-alerting on port 445 alone.
