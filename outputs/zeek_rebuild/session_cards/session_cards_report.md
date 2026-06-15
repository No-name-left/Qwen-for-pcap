# Session cards report

- Parsed input: `outputs/zeek_rebuild/parsed`
- Session cards: 31920
- Original uncapped session cards: 31920
- Max cards cap: none
- Output: `outputs/zeek_rebuild/session_cards/session_cards_all.json`
- LLM-safe output: `outputs/zeek_rebuild/session_cards/llm_session_cards_all.json`

## Per PCAP counts

- ctu13_scenario1: 31736
- feasibility_portscan: 184

## Safety notes

- Expected labels and answer files are not read.
- Context features are computed within each PCAP only.
- IP/domain reputation is not used.
- LLM-safe output removes known leakage-prone keys through shared sanitizer.

## Warnings

- none
