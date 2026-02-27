#!/usr/bin/env python3
"""
dissector.py
-----------
Post-capture deep dissector: reads JSONL captures and produces
enriched analysis — protocol matrix, DNS inventory, TLS hints,
HTTP endpoint map, flow graph, anomaly scoring.

Can be used as a library (import dissector) or run standalone.
"""
import json, pathlib, os, collections, sys
from typing import Any

WORKDIR = pathlib.Path(os.environ.get("SNIFFER_WORKDIR", "/workdir"))


def load_captures(workdir: pathlib.Path | None = None) -> list[dict]:
    d = (workdir or WORKDIR) / "captures"
    records = []
    for f in sorted(d.glob("capture_*.jsonl")):
        records += [json.loads(l) for l in f.read_text().splitlines() if l.strip()]
    return records


def protocol_matrix(records: list[dict]) -> dict:
    """Transport protocol distribution + port heatmap."""
    protos     = collections.Counter(r.get("transport", r.get("eth_type", "?")) for r in records)
    src_ports  = collections.Counter(r["src_port"] for r in records if "src_port" in r)
    dst_ports  = collections.Counter(r["dst_port"] for r in records if "dst_port" in r)
    ip_pairs   = collections.Counter(
        (r.get("ip_src","?"), r.get("ip_dst","?")) for r in records if "ip_src" in r
    )
    return {
        "proto_dist":    dict(protos.most_common()),
        "top_dst_ports": dict(dst_ports.most_common(20)),
        "top_src_ports": dict(src_ports.most_common(10)),
        "top_flows":     [{
            "flow": f"{s} → {d}", "count": c
        } for (s, d), c in ip_pairs.most_common(15)],
    }


def dns_inventory(records: list[dict]) -> list[dict]:
    """All DNS queries + answers extracted from dissected records."""
    seen: list[dict] = []
    for r in records:
        if "dns" in r:
            entry = {
                "ts":      r["ts"],
                "src":     r.get("ip_src", "?"),
                "qname":   r["dns"].get("qname"),
                "qtype":   r["dns"].get("qtype"),
                "qr":      "reply" if r["dns"].get("qr") else "query",
                "answers": r["dns"].get("answers", []),
            }
            seen.append(entry)
    return seen


def tls_inventory(records: list[dict]) -> list[dict]:
    """Collect TLS ClientHello hints for fingerprinting."""
    return [
        {"ts": r["ts"], "src": r.get("ip_src"),
         "dst": r.get("ip_dst"), "dst_port": r.get("dst_port"),
         "tls_hint": r["tls_hint"], "tls_version": r.get("tls_version")}
        for r in records if "tls_hint" in r
    ]


def http_inventory(records: list[dict]) -> list[dict]:
    """Extract HTTP/1.x request lines."""
    return [
        {"ts": r["ts"], "src": r.get("ip_src"), "dst": r.get("ip_dst"),
         "dst_port": r.get("dst_port"), "http": r["http_hint"]}
        for r in records if "http_hint" in r
    ]


def arp_inventory(records: list[dict]) -> list[dict]:
    """ARP who-has / is-at table."""
    return [
        {"ts": r["ts"], "op": r.get("arp_op"),
         "src_ip": r.get("arp_psrc"), "src_mac": r.get("arp_hwsrc"),
         "dst_ip": r.get("arp_pdst")}
        for r in records if "arp_op" in r
    ]


def anomaly_score(records: list[dict]) -> list[dict]:
    """Lightweight scoring: SYN flood, port scan, DNS exfil, ICMP flood."""
    syn   = collections.Counter(
        r["ip_src"] for r in records
        if r.get("transport") == "TCP" and "S" in r.get("tcp_flags", "")
        and "A" not in r.get("tcp_flags", "")
    )
    dports = collections.defaultdict(set)
    for r in records:
        if "ip_src" in r and "dst_port" in r:
            dports[r["ip_src"]].add(r["dst_port"])
    icmp = collections.Counter(
        r.get("ip_src") for r in records if r.get("transport") == "ICMP"
    )
    dns_sizes = [
        r.get("udp_len", 0) for r in records
        if r.get("transport") == "UDP" and r.get("dst_port") == 53
    ]

    anomalies = []
    for src, cnt in syn.most_common():
        score = min(10, cnt // 5)
        if score > 0:
            anomalies.append({"type": "SYN_FLOOD", "src": src,
                               "count": cnt, "score": score})
    for src, ports in dports.items():
        if len(ports) > 10:
            anomalies.append({"type": "PORT_SCAN", "src": src,
                               "unique_ports": len(ports),
                               "score": min(10, len(ports) // 5)})
    for src, cnt in icmp.most_common():
        if cnt > 30:
            anomalies.append({"type": "ICMP_FLOOD", "src": src,
                               "count": cnt, "score": min(10, cnt // 10)})
    if dns_sizes and max(dns_sizes) > 512:
        anomalies.append({"type": "DNS_LARGE_QUERY",
                           "max_bytes": max(dns_sizes), "score": 5})
    return sorted(anomalies, key=lambda x: -x["score"])


def full_report(workdir: pathlib.Path | None = None) -> dict:
    records = load_captures(workdir)
    return {
        "total": len(records),
        "protocol_matrix": protocol_matrix(records),
        "dns": dns_inventory(records),
        "tls": tls_inventory(records),
        "http": http_inventory(records),
        "arp": arp_inventory(records),
        "anomalies": anomaly_score(records),
    }


if __name__ == "__main__":
    report = full_report()
    out = WORKDIR / "reports" / "dissector_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps(report, indent=2, default=str))
