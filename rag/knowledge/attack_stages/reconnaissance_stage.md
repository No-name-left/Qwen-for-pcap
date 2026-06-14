---
doc_id: "reconnaissance_stage"
title: "Reconnaissance stage"
category: "attack_stages"
attack_types: ["port_scan"]
attack_stages: ["reconnaissance"]
keywords: ["reconnaissance", "scan", "probe", "unique_dst_ports", "SYN"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Reconnaissance stage

## Evidence

Reconnaissance evidence includes probing many ports or hosts, service discovery, OS fingerprinting, repeated SYNs, and high failed connection rates.

## Judgment

Classify the stage as reconnaissance when the event is mainly gathering information and not yet exploiting a vulnerability.

## Stage mapping

Port scans and service scans usually map here.

## Boundaries

A single failed connection or a small number of probes may be normal troubleshooting; require breadth or scan-like pattern.

## Source grounding

Grounded by MITRE ATT&CK Reconnaissance tactic pages, scan-related local rule metadata, tshark packet statistics, and Zeek connection summaries. Event-card features such as many destination ports, high SYN counts, high failed-connection rates, and scan signatures support `reconnaissance`.
