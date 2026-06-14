---
doc_id: "signature_http_c2"
title: "HTTP C2 signature"
category: "signatures"
attack_types: ["c2", "trojan_callback"]
attack_stages: ["command_and_control"]
keywords: ["HTTP C2", "callback", "beacon", "User-Agent", "URI"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# HTTP C2 signature

## Evidence

HTTP C2 signatures indicate malware using web requests for checkin, tasking, or data exchange. Evidence may include repeated URI paths, suspicious user agents, malware family names, or C2 categories.

## Judgment

Use c2 when the signature names command-and-control. Use trojan_callback when it mainly shows phone-home behavior.

## Stage mapping

The stage is command_and_control.

## Boundaries

HTTP is ubiquitous. Do not infer C2 from HTTP alone without signature or suspicious behavior.
