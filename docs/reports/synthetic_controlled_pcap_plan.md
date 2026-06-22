# Synthetic controlled PCAP plan and execution record

## Purpose

Provide three small parser/prompt/RAG boundary fixtures per official code when public phase-specific PCAP is unavailable. These fixtures never become `external_high_pcap` and are not training data.

## Implemented scenarios

| Intended label | Harmless observable behavior | Variants |
|---|---|---:|
| `TA43_01` | TCP connect attempts to 20 closed localhost ports | 3 |
| `TA43_02` | fixed local HTTP service receives Nmap-NSE/Nikto-labelled service/path probes | 3 |
| `TA01_01` | ten dummy `/login` POSTs receive 401 | 3 |
| `TA01_02` | inert traversal/SQLi/command/XSS-shaped strings receive 400 | 3 |
| `TA03_01` | non-executable marker upload is read then discarded; response 201 | 3 |
| `TA11_01` | mock-webshell URI returns a fixed disabled status; no command input or execution | 3 |
| `TA11_02` | eight fixed heartbeat POSTs to a dummy callback URI | 3 |
| `TN01_01` | ordinary index/docs/health GET requests | 3 |

## Safety controls

- Target is hard-coded `127.0.0.1`; no target/address option exists.
- Capture filters restrict traffic to the scenario port/range.
- Server responses are fixed. Upload bytes are discarded and never saved, parsed or executed.
- No arbitrary-command parameter, shell, reverse shell, backdoor functionality, malware, external DNS, TLS service or public scan is used.
- Raw PCAPs remain Git-ignored. Only scripts, hashes, classification evidence and tiered manifests are committed.

## Validation

Twenty-four PCAP files total 183,114 bytes. TShark and Zeek parsed all 24. The pipeline generated 177 session cards and 120 classification records, including three scan groups. One representative per PCAP was chosen for candidate construction, producing three records per intended code.

Limitations: localhost timing, repeated variants and explicit marker URIs make these fixtures easier and less realistic than external traffic. They validate evidence paths and confusion boundaries only.
