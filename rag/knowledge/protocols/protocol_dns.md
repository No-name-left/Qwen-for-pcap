---
doc_id: "protocol_dns"
title: "DNS protocol interpretation"
category: "protocols"
attack_types: ["normal", "c2", "trojan_callback", "other_attack"]
attack_stages: ["none", "command_and_control"]
keywords: ["DNS", "dns_queries", "NXDOMAIN", "DNS tunnel", "domain"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# DNS protocol interpretation

## Evidence

DNS normally resolves names before connections. Evidence includes queried domains, query types, response codes, repetition, and domain shape.

## Judgment

Suspicious DNS includes long encoded labels, many subdomains, high NXDOMAIN rates, known malware domains, or signatures naming DNS tunnel or C2.

## Stage mapping

DNS can support command_and_control when it resolves malware infrastructure or carries covert data.

## Boundaries

Do not call ordinary lookups C2. A single unfamiliar domain is weak without alert or behavior support.
