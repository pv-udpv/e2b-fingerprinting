#!/usr/bin/env python3
"""
scapy_sniffer.py
----------------
Live packet sniffer using Scapy for deep dissection on ALL interfaces.
Falls back to pure AF_PACKET stdlib mode if scapy is unavailable.

Dissection layers supported:
  Scapy mode:  Ether / ARP / IPv6 / IP / TCP / UDP / ICMP /
               DNS / HTTP(S) hint / TLS ClientHello / Raw payload
  Fallback:    Ether / IP / TCP / UDP / ICMP (struct-based)

Output: JSONL batches → $SNIFFER_WORKDIR/captures/capture_<epoch>.jsonl
Signal: $SNIFFER_WORKDIR/.capture_ready  (path of latest file)

Env vars:
  SNIFFER_WORKDIR   base working directory  (default /workdir)
  SNIFFER_BATCH     packets per JSONL file  (default 50)
  SNIFFER_RUNTIME   max seconds, 0=forever  (default 0)
  SNIFFER_IFACE     comma-sep iface list,   (default ALL)
  SNIFFER_BPF       BPF filter string       (default "")
  SNIFFER_STORE_RAW 1 = store hex payload   (default 0)
"""
import os, sys, time, json, struct, socket, threading, signal, pathlib

# ── config ────────────────────────────────────────────────────────────────────
WORKDIR     = pathlib.Path(os.environ.get("SNIFFER_WORKDIR", "/workdir"))
CAPTURE_DIR = WORKDIR / "captures"
SENTINEL    = WORKDIR / ".capture_ready"
BATCH_SIZE  = int(os.environ.get("SNIFFER_BATCH",   "50"))
MAX_RUNTIME = int(os.environ.get("SNIFFER_RUNTIME", "0"))
IFACES_ENV  = os.environ.get("SNIFFER_IFACE", "")
BPF_FILTER  = os.environ.get("SNIFFER_BPF",   "")
STORE_RAW   = os.environ.get("SNIFFER_STORE_RAW", "0") == "1"
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

_stop  = threading.Event()
_batch = []
_lock  = threading.Lock()
signal.signal(signal.SIGTERM, lambda *_: _stop.set())
signal.signal(signal.SIGINT,  lambda *_: _stop.set())

# ── flush helper ─────────────────────────────────────────────────────────────
def _flush(batch: list) -> None:
    epoch = int(time.time())
    out   = CAPTURE_DIR / f"capture_{epoch}.jsonl"
    with open(out, "a") as fh:
        for r in batch:
            fh.write(json.dumps(r, default=str) + "\n")
    SENTINEL.write_text(str(out))
    print(f"[sniffer] flushed {len(batch)} pkts → {out.name}", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
# SCAPY MODE
# ══════════════════════════════════════════════════════════════════════════════
def _try_scapy() -> bool:
    try:
        import importlib
        importlib.import_module("scapy")
        return True
    except ImportError:
        return False


def _dissect_scapy(pkt) -> dict:
    """Convert a Scapy packet to a flat JSON-serialisable dict."""
    from scapy.all import Ether, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, Raw

    rec: dict = {"ts": float(pkt.time)}

    # ── Ethernet ──────────────────────────────────────────────────────────────
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        rec["eth_src"]   = eth.src
        rec["eth_dst"]   = eth.dst
        rec["eth_type"]  = hex(eth.type)
        rec["iface"]     = getattr(pkt, "sniffed_on", "?")

    # ── ARP ───────────────────────────────────────────────────────────────────
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        rec["layer"]    = "ARP"
        rec["arp_op"]   = {1: "who-has", 2: "is-at"}.get(arp.op, arp.op)
        rec["arp_psrc"] = arp.psrc
        rec["arp_pdst"] = arp.pdst
        rec["arp_hwsrc"]= arp.hwsrc
        return rec

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    if pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        rec["layer"]   = "IPv6"
        rec["ip_src"]  = ip6.src
        rec["ip_dst"]  = ip6.dst
        rec["ip_proto"]= ip6.nh
        rec["ip_hlim"] = ip6.hlim

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    if pkt.haslayer(IP):
        ip = pkt[IP]
        rec["layer"]   = "IP"
        rec["ip_src"]  = ip.src
        rec["ip_dst"]  = ip.dst
        rec["ip_ttl"]  = ip.ttl
        rec["ip_proto"]= ip.proto
        rec["ip_len"]  = ip.len
        rec["ip_id"]   = ip.id
        rec["ip_flags"]= str(ip.flags)
        rec["ip_frag"] = ip.frag

    # ── TCP ───────────────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec["transport"]  = "TCP"
        rec["src_port"]   = tcp.sport
        rec["dst_port"]   = tcp.dport
        rec["tcp_seq"]    = tcp.seq
        rec["tcp_ack"]    = tcp.ack
        rec["tcp_window"] = tcp.window
        rec["tcp_flags"]  = tcp.sprintf("%TCP.flags%")
        # TLS ClientHello fingerprint (JA3-style hint)
        if tcp.dport in (443, 8443, 4443) or tcp.sport in (443, 8443, 4443):
            payload = bytes(tcp.payload)
            if payload and payload[0] == 0x16 and len(payload) > 5:
                rec["tls_hint"]     = "ClientHello" if payload[5] == 0x01 else "TLS"
                rec["tls_version"]  = hex(int.from_bytes(payload[1:3], 'big'))
                rec["tls_len"]      = int.from_bytes(payload[3:5], 'big')
        # HTTP/1.x hint
        if tcp.dport in (80, 8080, 3000, 5000, 8000, 8888) or tcp.sport in (80, 8080):
            try:
                raw_payload = bytes(tcp.payload)
                if raw_payload:
                    first_line = raw_payload.split(b"\r\n")[0].decode("utf-8", errors="replace")
                    if any(first_line.startswith(m) for m in
                           ("GET ","POST ","PUT ","DELETE ","PATCH ","HEAD ","OPTIONS ",
                            "HTTP/1","HTTP/2")):
                        rec["http_hint"] = first_line[:120]
            except Exception:
                pass

    # ── UDP ───────────────────────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec["transport"] = "UDP"
        rec["src_port"]  = udp.sport
        rec["dst_port"]  = udp.dport
        rec["udp_len"]   = udp.len
        # DNS dissection
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            rec["dns"] = {
                "id":    dns.id,
                "qr":    dns.qr,   # 0=query 1=reply
                "opcode":dns.opcode,
                "rcode": dns.rcode,
                "qdcount":dns.qdcount,
                "ancount":dns.ancount,
            }
            if dns.qd:
                try:
                    rec["dns"]["qname"] = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                    rec["dns"]["qtype"] = dns.qd.qtype
                except Exception:
                    pass
            if dns.an:
                answers = []
                ans = dns.an
                while ans:
                    try:
                        answers.append({"rrname": str(ans.rrname), "type": ans.type,
                                        "rdata": str(getattr(ans, 'rdata', ''))})
                    except Exception:
                        pass
                    ans = ans.payload if hasattr(ans, 'payload') else None
                    if not hasattr(ans, 'rrname'):
                        break
                rec["dns"]["answers"] = answers

    # ── ICMP ──────────────────────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        rec["transport"]  = "ICMP"
        rec["icmp_type"]  = icmp.type
        rec["icmp_code"]  = icmp.code

    # ── Raw payload (optional hex) ────────────────────────────────────────────
    if STORE_RAW and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        rec["raw_hex"]    = raw[:64].hex()
        rec["raw_len"]    = len(raw)
        rec["printable"]  = raw[:64].decode("utf-8", errors="replace")

    rec["frame_len"] = len(pkt)
    return rec


def run_scapy() -> None:
    from scapy.all import sniff, conf
    conf.verb = 0

    ifaces = [i.strip() for i in IFACES_ENV.split(",") if i.strip()] or None
    t0     = time.time()

    print(f"[sniffer/scapy] ifaces={ifaces or 'ALL'}  bpf={BPF_FILTER!r}  "
          f"batch={BATCH_SIZE}  runtime={MAX_RUNTIME}s", flush=True)

    def _callback(pkt):
        if _stop.is_set():
            return
        if MAX_RUNTIME and (time.time() - t0) > MAX_RUNTIME:
            _stop.set()
            return
        rec = _dissect_scapy(pkt)
        with _lock:
            _batch.append(rec)
            if len(_batch) >= BATCH_SIZE:
                _flush(_batch.copy())
                _batch.clear()

    sniff(
        iface=ifaces,
        filter=BPF_FILTER or None,
        prn=_callback,
        store=False,
        stop_filter=lambda _: _stop.is_set(),
        timeout=MAX_RUNTIME if MAX_RUNTIME else None,
    )
    with _lock:
        if _batch:
            _flush(_batch.copy())
            _batch.clear()
    print("[sniffer/scapy] done", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
# FALLBACK: pure stdlib AF_PACKET
# ══════════════════════════════════════════════════════════════════════════════
def run_stdlib() -> None:
    ETH_P_ALL = 0x0003
    ETH_P_IP  = 0x0800

    def _parse_eth(raw):
        if len(raw) < 14: return None
        return {"eth_dst": ':'.join(f'{b:02x}' for b in raw[0:6]),
                "eth_src": ':'.join(f'{b:02x}' for b in raw[6:12]),
                "eth_proto": struct.unpack('!H', raw[12:14])[0],
                "payload": raw[14:]}

    def _parse_ip(payload):
        if len(payload) < 20: return {}
        ihl   = (payload[0] & 0x0F) * 4
        proto = payload[9]
        src   = socket.inet_ntoa(payload[12:16])
        dst   = socket.inet_ntoa(payload[16:20])
        body  = payload[ihl:]
        rec   = {"ip_src": src, "ip_dst": dst, "ip_proto": proto, "ip_ttl": payload[8]}
        if proto == 6 and len(body) >= 20:
            sp, dp, seq, ack = struct.unpack('!HHII', body[:12])
            flags = body[13]
            rec.update({"transport":"TCP","src_port":sp,"dst_port":dp,
                        "tcp_seq":seq,"tcp_ack":ack,
                        "tcp_flags":{"SYN":bool(flags&2),"ACK":bool(flags&16),
                                     "RST":bool(flags&4),"FIN":bool(flags&1),
                                     "PSH":bool(flags&8),"URG":bool(flags&32)}})
        elif proto == 17 and len(body) >= 8:
            sp, dp, ln = struct.unpack('!HHH', body[:6])
            rec.update({"transport":"UDP","src_port":sp,"dst_port":dp,"udp_len":ln})
        elif proto == 1 and len(body) >= 4:
            rec.update({"transport":"ICMP","icmp_type":body[0],"icmp_code":body[1]})
        return rec

    print(f"[sniffer/stdlib] AF_PACKET fallback  batch={BATCH_SIZE}  runtime={MAX_RUNTIME}s",
          flush=True)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.settimeout(1.0)
    batch, t0 = [], time.time()
    while not _stop.is_set():
        if MAX_RUNTIME and (time.time() - t0) > MAX_RUNTIME:
            break
        try:
            raw, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        eth = _parse_eth(raw)
        if not eth: continue
        rec = {"ts": time.time(), "iface": addr[0],
               "eth_dst": eth["eth_dst"], "eth_src": eth["eth_src"],
               "eth_proto_hex": hex(eth["eth_proto"]), "frame_len": len(raw)}
        if eth["eth_proto"] == ETH_P_IP:
            rec.update(_parse_ip(eth["payload"]))
        batch.append(rec)
        if len(batch) >= BATCH_SIZE:
            _flush(batch); batch = []
    if batch: _flush(batch)
    sock.close()
    print("[sniffer/stdlib] done", flush=True)


# ── entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if _try_scapy():
        print("[sniffer] backend=scapy", flush=True)
        run_scapy()
    else:
        print("[sniffer] backend=stdlib (scapy not available)", flush=True)
        run_stdlib()
