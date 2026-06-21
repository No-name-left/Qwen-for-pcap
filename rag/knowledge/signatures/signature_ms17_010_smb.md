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

MS17-010 refers to SMBv1 remote code execution vulnerabilities. Evidence may include MS17-010/EternalBlue strings, abnormal SMB exploit exchanges, or vulnerability-specific behavior on ports 445 or 139.

## Judgment

If an alert signature contains SMB exploit and MS17-010 terms, classify as exploit with subtype smb_exploit or ms17_010. The evidence should cite signature, protocol, and port when available.

## Stage mapping

The stage is initial_access because the exploit attempts to gain code execution or unauthorized access through SMB.

## Boundaries

Port 445 alone is not enough. Ordinary file sharing, domain operations, and administration also use SMB.

## Relevant event card fields

Useful fields include MS17-010, EternalBlue, or SMB exploit wording in available content; destination-port evidence such as 445; and SMB/TCP connection context. Together these can support `TA01_02` when exploitation rather than scanning is shown.

## Source grounding

Grounded by Microsoft MS17-010 official bulletin and SMB/EternalBlue public references. When MS17-010, SMBv1, port 445, and exploit behavior appear together, the mapping is usually `TA01_02`. DOUBLEPULSAR evidence is closer to post-exploitation implant, access, or callback boundaries.
