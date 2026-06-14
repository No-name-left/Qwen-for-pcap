---
doc_id: "zeek_dns_log_fields"
title: "Zeek DNS log fields"
category: "tool_fields"
attack_types: ["normal", "c2", "other_attack", "trojan_callback"]
attack_stages: ["none", "command_and_control"]
keywords: ["Zeek", "dns.log", "dns_queries", "query", "NXDOMAIN"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Zeek DNS log fields

## Evidence

Zeek DNS fields expose queried domains, query types, response codes, and sometimes answers. In event cards, dns_queries show sample domains and can indicate lookup behavior before outbound contact.

## Judgment

Normal DNS is common. Suspicious evidence includes long encoded subdomains, repeated failed lookups, algorithmic-looking names, or domains tied to malware alerts.

## Stage mapping

DNS can support command_and_control when it helps identify callback infrastructure or tunneling.

## Boundaries

A domain name alone is rarely enough. Avoid judging C2 without alert context, unusual query structure, or matching connection behavior.
