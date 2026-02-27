#!/usr/bin/env python3
"""
spawn.py
--------
Entry point: spawns sniffer + orchestrator as background subprocesses,
wires a watcher thread and an event queue.

Usage:
    python3 spawn.py [--runtime 30] [--batch 50] [--iface eth0,lo] [--bpf "tcp"]

Can also be imported:
    from spawn import start_pipeline
    pipeline = start_pipeline(runtime=30, batch=50)
    pipeline.wait()
"""
import subprocess, sys, threading, time, queue, pathlib, os, argparse, json

SCRIPTS = pathlib.Path(__file__).parent


def start_pipeline(
    workdir : str  = "/workdir",
    runtime : int  = 0,
    batch   : int  = 50,
    iface   : str  = "",
    bpf     : str  = "",
    store_raw: bool = False,
):
    wdir = pathlib.Path(workdir)
    (wdir / "captures").mkdir(parents=True, exist_ok=True)
    (wdir / "reports").mkdir(parents=True, exist_ok=True)

    base_env = {
        **os.environ,
        "SNIFFER_WORKDIR":   str(wdir),
        "SNIFFER_BATCH":     str(batch),
        "SNIFFER_RUNTIME":   str(runtime),
        "SNIFFER_IFACE":     iface,
        "SNIFFER_BPF":       bpf,
        "SNIFFER_STORE_RAW": "1" if store_raw else "0",
    }

    sniffer_log = open(wdir / "sniffer.log", "w")
    orch_log    = open(wdir / "orch.log", "w")

    sniffer = subprocess.Popen(
        [sys.executable, str(SCRIPTS / "scapy_sniffer.py")],
        env=env, stdout=sniffer_log, stderr=subprocess.STDOUT
    )
    orch = subprocess.Popen(
        [sys.executable, str(SCRIPTS / "orchestrator.py")],
        env=base_env, stdout=orch_log, stderr=subprocess.STDOUT
    )

    print(f"[spawn] sniffer PID={sniffer.pid}  orch PID={orch.pid}")

    event_q: queue.Queue = queue.Queue()
    sentinel = wdir / ".capture_ready"

    def _watch():
        while sniffer.poll() is None:
            if sentinel.exists():
                path = sentinel.read_text().strip()
                sentinel.unlink(missing_ok=True)
                event_q.put(("capture_ready", path))
            time.sleep(0.5)
        event_q.put(("sniffer_exit", sniffer.returncode))

    watcher = threading.Thread(target=_watch, daemon=True, name="sentinel-watcher")
    watcher.start()

    class Pipeline:
        def __init__(self):
            self.sniffer  = sniffer
            self.orch     = orch
            self.events   = event_q
            self.sniffer_log = sniffer_log
            self.orch_log    = orch_log

        def wait(self, timeout=None):
            sniffer.wait(timeout=timeout)
            orch.terminate()
            sniffer_log.close()
            orch_log.close()

        def stop(self):
            sniffer.terminate()
            orch.terminate()

        def drain_events(self, count=10):
            evts = []
            try:
                while len(evts) < count:
                    evts.append(event_q.get(timeout=1))
            except queue.Empty:
                pass
            return evts

    return Pipeline()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir",  default="/workdir")
    ap.add_argument("--runtime",  type=int, default=10)
    ap.add_argument("--batch",    type=int, default=50)
    ap.add_argument("--iface",    default="")
    ap.add_argument("--bpf",      default="")
    ap.add_argument("--store-raw",action="store_true")
    args = ap.parse_args()

    pl = start_pipeline(
        workdir=args.workdir, runtime=args.runtime, batch=args.batch,
        iface=args.iface, bpf=args.bpf, store_raw=args.store_raw
    )
    print("[spawn] pipeline running — waiting for sniffer to finish...")
    pl.wait(timeout=args.runtime + 10)
    evts = pl.drain_events()
    print(f"[spawn] events: {evts}")
    print(f"[spawn] sniffer log:\n{pathlib.Path(args.workdir, 'sniffer.log').read_text()[-600:]}")
