#!/usr/bin/env python3
"""
orchestrator.py
---------------
Watches for .capture_ready sentinel and fires the analysis tool chain:
  1. dissector.py   — deep protocol analysis (DNS/TLS/HTTP/ARP/flows)
  2. anomaly step   — already inside dissector.full_report()
  3. gen_chart.py   — Plotly pps + protocol chart
  4. (extensible)   — append any tool to STEPS

Each step result is logged to reports/chain_log_<epoch>.json.
"""
import subprocess, time, pathlib, os, json, signal, sys, threading

WORKDIR  = pathlib.Path(os.environ.get("SNIFFER_WORKDIR", "/workdir"))
SENTINEL = WORKDIR / ".capture_ready"
SCRIPTS  = pathlib.Path(__file__).parent
STEPS    = ["dissector.py", "gen_chart.py"]
POLL_INT = float(os.environ.get("ORCH_POLL", "1.5"))
env      = {**os.environ, "SNIFFER_WORKDIR": str(WORKDIR)}
_stop    = False
signal.signal(signal.SIGTERM, lambda *_: globals().update(_stop=True))
signal.signal(signal.SIGINT,  lambda *_: globals().update(_stop=True))


def run_chain(capture_path: str) -> dict:
    results = {}
    print(f"[orch] chain triggered by: {capture_path}", flush=True)
    for script in STEPS:
        path = SCRIPTS / script
        if not path.exists():
            results[script] = {"rc": -1, "error": "not found"}
            continue
        print(f"[orch] ▶ {script}", flush=True)
        r = subprocess.run([sys.executable, str(path)],
                           capture_output=True, text=True, env=env, timeout=30)
        results[script] = {"rc": r.returncode,
                           "stdout": r.stdout[:3000],
                           "stderr": r.stderr[:500]}
        print(f"[orch]   rc={r.returncode}", flush=True)
        if r.stdout: print(r.stdout[:400], flush=True)
        if r.returncode != 0:
            print(f"[orch] ✗ chain aborted at {script}", flush=True)
            break
    log = WORKDIR / "reports" / f"chain_log_{int(time.time())}.json"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(json.dumps(results, indent=2))
    return results


print(f"[orch] watching {SENTINEL}  poll={POLL_INT}s", flush=True)
while not _stop:
    if SENTINEL.exists():
        path = SENTINEL.read_text().strip()
        SENTINEL.unlink(missing_ok=True)
        run_chain(path)
    time.sleep(POLL_INT)
