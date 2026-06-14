---
doc_id: "attack_chain_summary"
title: "Attack chain summary policy"
category: "aggregation_policy"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["attack chain", "reconnaissance", "initial_access", "command_and_control"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Attack chain summary policy

## Evidence

An attack chain summary should order observed stages such as reconnaissance, initial_access, persistence, and command_and_control when event evidence supports them.

## Judgment

Summaries should cite representative event evidence rather than assume missing stages.

## Stage mapping

Multiple stages can be present in one capture, but the chain should not invent stages absent from event cards.

## Boundaries

If only C2 is visible, do not invent the exploit path. If only scanning is visible, do not infer compromise.
