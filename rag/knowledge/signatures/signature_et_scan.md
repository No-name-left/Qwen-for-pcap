---
doc_id: "signature_et_scan"
title: "ET scan signatures"
category: "signatures"
attack_types: ["port_scan"]
attack_stages: ["reconnaissance"]
keywords: ["ET SCAN", "scan", "Nmap", "probe", "reconnaissance"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# ET scan signatures

## Evidence

ET scan signatures commonly identify scanning tools, probes, or reconnaissance behavior. They are stronger when they align with many destination ports or hosts.

## Judgment

Classify as port_scan when scan signatures and traffic shape agree.

## Stage mapping

Scan signatures map to reconnaissance.

## Boundaries

Some monitoring and vulnerability scanners are authorized. The model should classify observed behavior, not intent, and keep confidence aligned with evidence.
