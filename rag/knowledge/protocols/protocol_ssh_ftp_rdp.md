---
doc_id: "protocol_ssh_ftp_rdp"
title: "SSH FTP and RDP interpretation"
category: "protocols"
attack_types: ["normal", "other_attack"]
attack_stages: ["none", "initial_access"]
keywords: ["SSH", "FTP", "RDP", "22", "21", "3389", "bruteforce"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# SSH FTP and RDP interpretation

## Evidence

SSH, FTP, and RDP are common remote access protocols. Attack evidence often involves repeated login failures, many usernames, many sources, or brute-force signatures.

## Judgment

The closed attack_type set maps brute force to other_attack with subtype brute_force.

## Stage mapping

Authentication attacks map to initial_access.

## Boundaries

A connection to port 22, 21, or 3389 is normal in many networks. Require repeated authentication evidence or alerts.
