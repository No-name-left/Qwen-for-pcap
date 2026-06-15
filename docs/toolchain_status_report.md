# Toolchain status report

- OS: PRETTY_NAME="Ubuntu 22.04.5 LTS"
- User: root
- PWD: `/root/autodl-tmp/Qwen-for-pcap`
- Python: `Python 3.12.3`
- tshark available: true
- tshark path: `/usr/bin/tshark`
- Zeek installed: true
- Zeek path used: `/opt/zeek/bin/zeek`
- Zeek version: `/opt/zeek/bin/zeek version 8.0.5`
- Suricata available: true
- Suricata version: `This is Suricata version 6.0.4 RELEASE`
- suricata-update: `/usr/bin/suricata-update`
- Running as root: true
- Sudo: not needed; current user is root.
- Current project can fallback to tshark: true

## PATH note

- `zeek` is not on the current PATH, but `/opt/zeek/bin/zeek` is usable. Add `export PATH=/opt/zeek/bin:$PATH` to `~/.bashrc` if interactive shells should find it by name.
