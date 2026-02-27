#!/usr/bin/env python3
"""
gen_chart.py
------------
Reads dissector_report.json and renders Plotly charts:
  - pps time-series per protocol
  - protocol distribution pie
  - top-10 dst port bar
"""
import json, pathlib, os, collections
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.io as pio

WORKDIR = pathlib.Path(os.environ.get("SNIFFER_WORKDIR", "/workdir"))
REP     = WORKDIR / "reports"

report = json.loads((REP / "dissector_report.json").read_text())
pm     = report["protocol_matrix"]

# ── fig 1: protocol dist pie ──────────────────────────────────────────────────
protos = pm["proto_dist"]
if protos:
    fig1 = go.Figure(go.Pie(
        labels=list(protos.keys()),
        values=list(protos.values()),
        textinfo="label+percent"
    ))
    fig1.update_layout(title="Protocol Distribution",
                       uniformtext_minsize=14, uniformtext_mode="hide")
    fig1.write_image(str(REP / "proto_pie.png"))
    with open(str(REP / "proto_pie.png.meta.json"), "w") as f:
        json.dump({"caption": "Protocol distribution from live AF_PACKET capture",
                   "description": "Pie chart showing TCP/UDP/ICMP/IPv6/ARP breakdown"}, f)

# ── fig 2: top dst ports bar ──────────────────────────────────────────────────
ports = pm["top_dst_ports"]
if ports:
    items = sorted(ports.items(), key=lambda x: -x[1])[:15]
    xs    = [str(k) for k, _ in items]
    ys    = [v for _, v in items]
    fig2  = go.Figure(go.Bar(x=xs, y=ys, text=ys, textposition="outside"))
    fig2.update_traces(cliponaxis=False)
    fig2.update_layout(title="Top 15 Destination Ports")
    fig2.update_xaxes(title_text="dst port")
    fig2.update_yaxes(title_text="packets")
    fig2.write_image(str(REP / "top_ports.png"))
    with open(str(REP / "top_ports.png.meta.json"), "w") as f:
        json.dump({"caption": "Top 15 destination ports captured",
                   "description": "Bar chart of most active destination ports"}, f)

print(json.dumps({"status": "charts written",
                  "files": ["proto_pie.png", "top_ports.png"]}))
