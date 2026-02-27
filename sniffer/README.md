# Scapy-Integrated AF_PACKET Sniffer

Live packet capture with deep dissection + tool-chain orchestrator.

## Architecture

```
spawn.py
├── subprocess: scapy_sniffer.py   ← Scapy backend (fallback: stdlib AF_PACKET)
│     ├── Ether / ARP / IPv6
│     ├── IP / TCP (flags, TLS hint, HTTP hint)
│     ├── UDP / DNS (full qname + answers)
│     ├── ICMP
│     └── Raw (optional hex, printable)
│     └── JSONL → /workdir/captures/capture_<epoch>.jsonl
│     └── sentinel → /workdir/.capture_ready
│
├── subprocess: orchestrator.py    ← polls sentinel, fires chain
│     ├── dissector.py             ← protocol matrix, DNS/TLS/HTTP/ARP inventory
│     ├── gen_chart.py             ← Plotly proto pie + top ports bar
│     └── chain_log_<epoch>.json
│
└── threading.Thread: watcher      ← sentinel → event_q
      └── queue.Queue events
```

## Dissection Layers

| Layer | Fields |
|---|---|
| Ethernet | `eth_src`, `eth_dst`, `eth_type`, `iface` |
| ARP | `arp_op` (who-has/is-at), `arp_psrc/pdst`, `arp_hwsrc` |
| IPv6 | `ip_src/dst`, `ip_proto`, `ip_hlim` |
| IPv4 | `ip_src/dst`, `ip_ttl`, `ip_proto`, `ip_len`, `ip_id`, `ip_flags`, `ip_frag` |
| TCP | `src/dst_port`, `tcp_seq/ack/window`, `tcp_flags` (e.g. `SA`, `S`, `FA`) |
| TCP+TLS | `tls_hint` (ClientHello), `tls_version` (hex), `tls_len` |
| TCP+HTTP | `http_hint` (first request/response line, 120 chars) |
| UDP | `src/dst_port`, `udp_len` |
| UDP+DNS | `dns.qname`, `dns.qtype`, `dns.qr`, `dns.answers[].rdata` |
| ICMP | `icmp_type`, `icmp_code` |
| Raw | `raw_hex` (64B), `raw_len`, `printable` (opt, `SNIFFER_STORE_RAW=1`) |

## Quick Start

```bash
# Install scapy
pip install scapy

# Run 30-second capture on all ifaces, batch=50
python3 spawn.py --runtime 30 --batch 50

# BPF-filtered capture, eth0 only, store raw payload
python3 spawn.py --runtime 60 --iface eth0 --bpf "tcp port 80 or port 443" --store-raw

# Import as library
from spawn import start_pipeline
pl = start_pipeline(runtime=15, batch=20)
pl.wait()
print(pl.drain_events())
```

## Environment Variables

| Var | Default | Description |
|---|---|---|
| `SNIFFER_WORKDIR` | `/workdir` | Base directory for captures + reports |
| `SNIFFER_BATCH` | `50` | Packets per JSONL flush |
| `SNIFFER_RUNTIME` | `0` (∞) | Max capture seconds |
| `SNIFFER_IFACE` | `` (all) | Comma-separated interface list |
| `SNIFFER_BPF` | `` | BPF filter string passed to Scapy |
| `SNIFFER_STORE_RAW` | `0` | `1` = include hex payload in JSON |
| `ORCH_POLL` | `1.5` | Orchestrator sentinel poll interval (s) |
