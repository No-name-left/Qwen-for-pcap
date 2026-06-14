---
doc_id: "signature_irc_botnet"
title: "IRC botnet signature"
category: "signatures"
attack_types: ["c2"]
attack_stages: ["command_and_control"]
keywords: ["IRC", "botnet", "C2", "channel", "PRIVMSG"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# IRC botnet signature

## Evidence

IRC botnet signatures indicate command channels that use IRC servers or IRC-like commands. Evidence may include botnet categories, channel joins, PRIVMSG commands, or known bot family signatures.

## Judgment

Classify as c2 when the event shows botnet command behavior.

## Stage mapping

IRC botnet traffic maps to command_and_control.

## Boundaries

IRC can be legitimate in some environments, but explicit botnet signatures are strong evidence.
