---
doc_id: "port_scan_detection"
title: "Port scan detection"
category: "attack_types"
attack_types: ["port_scan"]
attack_stages: ["reconnaissance"]
keywords: ["port_scan", "Nmap", "SYN", "unique_dst_ports", "failed_conn_rate"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Port scan detection

## Evidence

A port scan often appears as many connection attempts from one source toward many destination ports or hosts. Useful features include high unique_dst_ports, high tcp_syn_count, low tcp_ack_count, many Zeek S0 or REJ states, and high failed_conn_rate.

## Judgment

When the main evidence is systematic probing rather than exploitation, classify as port_scan. A single blocked connection is not enough; the pattern should show breadth, repetition, or scanning-like sequencing.

## Stage mapping

Port scanning normally maps to reconnaissance because the actor is discovering exposed services before choosing an entry point.

## Boundaries

High volume alone is not always a scan. Backup jobs, monitoring systems, or service discovery can touch many hosts; require scan-like port or host diversity and failed connection evidence.
