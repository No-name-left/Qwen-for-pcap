---
doc_id: "signature_ms17_010_smb"
title: "MS17-010 SMB exploit evidence"
category: "signatures"
attack_types: ["exploit"]
attack_stages: ["initial_access"]
keywords: ["MS17-010", "SMB", "SMBv1", "port 445", "EternalBlue", "exploit"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# MS17-010 SMB exploit evidence

## Evidence

MS17-010 refers to SMBv1 remote code execution vulnerabilities. Evidence may include Suricata signatures naming MS17-010, EternalBlue, SMB exploit, or vulnerability-specific SMB behavior on ports 445 or 139.

## Judgment

If an alert signature contains SMB exploit and MS17-010 terms, classify as exploit with subtype smb_exploit or ms17_010. The evidence should cite signature, protocol, and port when available.

## Stage mapping

The stage is initial_access because the exploit attempts to gain code execution or unauthorized access through SMB.

## Boundaries

Port 445 alone is not enough. Ordinary file sharing, domain operations, and administration also use SMB.

## Relevant event card fields

Useful fields include `suricata_alerts.signature` with MS17-010, EternalBlue, or SMB exploit wording; `suricata_alerts.category` indicating exploit activity; destination port evidence such as port 445; and protocol context from SMB or TCP features. Together these support `attack_type=exploit`, subtype `smb_exploit`, and `attack_stage=initial_access`.

## Source grounding

Grounded by Microsoft MS17-010 official bulletin, SMB/EternalBlue public references, Suricata alert metadata, and local ET Open rule messages. MS17-010 relates to SMBv1 remote code execution; when MS17-010, SMBv1, port 445, and SMB exploit wording appear together, the mapping is usually `exploit / initial_access`. If MS17-010 and DOUBLEPULSAR both appear, MS17-010 describes vulnerability use while DOUBLEPULSAR is closer to post-exploitation implant or callback behavior.
