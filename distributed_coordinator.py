#!/usr/bin/env python3
"""distributed_coordinator.py — Plan E+ Fase 4.

Lightweight HTTP-based coordinator for 2+ node distributed attacks.
Uses aiohttp (already a dep). Workers POST stats every 1s; coordinator
aggregates RPS/bandwidth/errors across all nodes and exposes a dashboard.

Run coordinator (control plane):
    python3 distributed_coordinator.py coordinator --port 9000

Run worker (attack plane, points to coordinator):
    python3 distributed_coordinator.py worker --coord http://1.2.3.4:9000 \
        --node-id node-A --target https://victim.com --duration 120

Endpoints (coordinator):
    GET  /              — HTML dashboard
    POST /register      — worker registers itself {node_id, host, ts}
    POST /stats         — worker pushes 1s stats {node_id, rps, bytes, errors, ts}
    POST /command       — coordinator broadcasts attack command (out-of-scope v1: workers poll)
    GET  /aggregate     — JSON aggregate {total_rps, nodes:[...], total_bytes, ...}
    GET  /workers       — list registered workers
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List

try:
    from aiohttp import web, ClientSession, ClientTimeout
except ImportError:
    print("[dist] aiohttp required. pip install aiohttp", file=sys.stderr)
    sys.exit(1)


# ---------- Coordinator state ----------
class CoordState:
    """Holds the cluster state: workers + their last stats history."""

    def __init__(self) -> None:
        self.start_ts = time.time()
        # node_id → {host, registered_ts, last_seen_ts}
        self.workers: Dict[str, Dict[str, Any]] = {}
        # node_id → deque of last 60 stats samples
        self.stats: Dict[str, Deque[Dict[str, Any]]] = defaultdict(lambda: deque(maxlen=60))
        # current attack command broadcast to workers (None=idle)
        self.command: Dict[str, Any] = {"action": "idle"}

    def register(self, node_id: str, host: str) -> None:
        now = time.time()
        existing = self.workers.get(node_id)
        if existing is None:
            self.workers[node_id] = {
                "host": host, "registered_ts": now, "last_seen_ts": now,
            }
        else:
            existing["last_seen_ts"] = now
            existing["host"] = host

    def push_stats(self, node_id: str, payload: Dict[str, Any]) -> None:
        if node_id not in self.workers:
            self.register(node_id, payload.get("host", "?"))
        self.workers[node_id]["last_seen_ts"] = time.time()
        payload.setdefault("ts", time.time())
        self.stats[node_id].append(payload)

    def aggregate(self) -> Dict[str, Any]:
        """Sum RPS / bytes / errors across all workers seen in last 5s."""
        now = time.time()
        nodes_summary = []
        total_rps = 0.0
        total_bytes = 0
        total_errors = 0
        for node_id, samples in self.stats.items():
            if not samples:
                continue
            recent = [s for s in samples if now - s.get("ts", 0) <= 5.0]
            if not recent:
                continue
            last = recent[-1]
            avg_rps = sum(s.get("rps", 0) for s in recent) / max(1, len(recent))
            avg_bytes = sum(s.get("bytes", 0) for s in recent) / max(1, len(recent))
            errors_sum = sum(s.get("errors", 0) for s in recent)
            total_rps += avg_rps
            total_bytes += avg_bytes
            total_errors += errors_sum
            host = self.workers.get(node_id, {}).get("host", "?")
            alive = (now - self.workers.get(node_id, {}).get("last_seen_ts", 0)) < 10.0
            nodes_summary.append({
                "node_id": node_id, "host": host, "alive": alive,
                "rps": round(avg_rps, 1), "bytes_per_s": round(avg_bytes, 1),
                "errors": errors_sum, "samples": len(recent),
                "last_ts": round(last.get("ts", 0), 1),
            })
        return {
            "uptime_s": round(now - self.start_ts, 1),
            "n_workers": len(self.workers),
            "n_alive": sum(1 for n in nodes_summary if n["alive"]),
            "total_rps": round(total_rps, 1),
            "total_bytes_per_s": round(total_bytes, 1),
            "total_errors": total_errors,
            "nodes": nodes_summary,
            "command": self.command,
        }


COORD_STATE = CoordState()


# ---------- HTTP handlers ----------
async def h_index(request: web.Request) -> web.Response:
    """Live HTML dashboard. Auto-refresh every 1.5s via JS fetch."""
    html = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MHDDoS Distributed Dashboard</title>
<style>
body { font-family: -apple-system, sans-serif; background: #0a0a0a; color: #e0e0e0;
       max-width: 1100px; margin: 30px auto; padding: 20px; }
h1 { color: #ff6644; border-bottom: 3px solid #ff6644; padding-bottom: 10px; }
.summary { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
.card { background: #1a1a1a; padding: 15px; border-radius: 6px; flex: 1; min-width: 150px;
        border-left: 3px solid #66aaff; }
.card .lbl { font-size: 11px; text-transform: uppercase; color: #888; }
.card .val { font-size: 24px; font-weight: bold; color: #00ff88; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; margin: 20px 0; }
th, td { padding: 10px; border-bottom: 1px solid #333; text-align: left; }
th { background: #1a1a1a; color: #66aaff; font-size: 12px; text-transform: uppercase; }
.alive { color: #00ff88; }
.dead { color: #ff6644; }
.footer { color: #666; font-size: 11px; margin-top: 30px; padding-top: 15px;
          border-top: 1px solid #333; }
</style></head><body>
<h1>🌐 MHDDoS Distributed Dashboard</h1>
<div id="summary" class="summary"></div>
<h2 style="color:#66aaff;">Workers</h2>
<table id="nodes_table"><thead><tr>
<th>Node ID</th><th>Host</th><th>Status</th><th>RPS</th><th>BW (B/s)</th>
<th>Errors</th><th>Samples</th><th>Last Update</th>
</tr></thead><tbody id="nodes_body"></tbody></table>
<div class="footer">Auto-refresh every 1.5s. Coordinator uptime: <span id="uptime">?</span>s.</div>
<script>
async function tick() {
  try {
    const r = await fetch('/aggregate');
    const d = await r.json();
    document.getElementById('uptime').textContent = d.uptime_s;
    document.getElementById('summary').innerHTML = `
      <div class="card"><div class="lbl">Workers</div>
        <div class="val">${d.n_alive}/${d.n_workers}</div></div>
      <div class="card"><div class="lbl">Total RPS</div>
        <div class="val">${d.total_rps}</div></div>
      <div class="card"><div class="lbl">Total BW/s</div>
        <div class="val">${d.total_bytes_per_s}</div></div>
      <div class="card"><div class="lbl">Total Errors</div>
        <div class="val" style="color:#ff6644;">${d.total_errors}</div></div>`;
    const tbody = document.getElementById('nodes_body');
    tbody.innerHTML = d.nodes.map(n => `<tr>
      <td><b>${n.node_id}</b></td><td>${n.host}</td>
      <td class="${n.alive ? 'alive' : 'dead'}">● ${n.alive ? 'ALIVE' : 'DEAD'}</td>
      <td>${n.rps}</td><td>${n.bytes_per_s}</td>
      <td>${n.errors}</td><td>${n.samples}</td>
      <td>${new Date(n.last_ts * 1000).toLocaleTimeString()}</td>
    </tr>`).join('');
  } catch (e) { console.error(e); }
}
setInterval(tick, 1500); tick();
</script>
</body></html>"""
    return web.Response(text=html, content_type="text/html")


async def h_register(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "invalid json"}, status=400)
    node_id = data.get("node_id")
    host = data.get("host", "?")
    if not node_id:
        return web.json_response({"error": "node_id required"}, status=400)
    COORD_STATE.register(node_id, host)
    return web.json_response({"ok": True, "command": COORD_STATE.command})


async def h_stats(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "invalid json"}, status=400)
    node_id = data.get("node_id")
    if not node_id:
        return web.json_response({"error": "node_id required"}, status=400)
    COORD_STATE.push_stats(node_id, data)
    return web.json_response({"ok": True, "command": COORD_STATE.command})


async def h_command(request: web.Request) -> web.Response:
    """Coordinator broadcasts attack command. Workers poll via /register or /stats."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "invalid json"}, status=400)
    COORD_STATE.command = data
    return web.json_response({"ok": True, "command": data})


async def h_aggregate(request: web.Request) -> web.Response:
    return web.json_response(COORD_STATE.aggregate())


async def h_workers(request: web.Request) -> web.Response:
    return web.json_response({"workers": COORD_STATE.workers})


def create_coord_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", h_index)
    app.router.add_post("/register", h_register)
    app.router.add_post("/stats", h_stats)
    app.router.add_post("/command", h_command)
    app.router.add_get("/aggregate", h_aggregate)
    app.router.add_get("/workers", h_workers)
    return app


# ---------- Worker (test driver) ----------
async def run_worker(coord_url: str, node_id: str, target: str,
                     duration: int, rps_simulated: int = 100) -> None:
    """A simple worker that posts simulated RPS stats to the coordinator.

    NOTE: For Plan E+ Fase 4 v1, this worker SIMULATES traffic (does not
    actually attack). It exists to validate the coordinator + dashboard +
    aggregation logic. Real attack workers can integrate with gui.py
    AttackThread later in v2.
    """
    print(f"[worker {node_id}] connecting to {coord_url}", flush=True)
    timeout = ClientTimeout(total=5)

    async with ClientSession(timeout=timeout) as session:
        # Register
        try:
            async with session.post(f"{coord_url}/register",
                                     json={"node_id": node_id, "host": target}) as r:
                resp = await r.json()
                print(f"[worker {node_id}] registered: {resp}", flush=True)
        except Exception as e:
            print(f"[worker {node_id}] register failed: {e}", flush=True)
            return

        start = time.time()
        i = 0
        while time.time() - start < duration:
            i += 1
            # Simulated stats — in real worker this would be REAL counters
            payload = {
                "node_id": node_id,
                "host": target,
                "ts": time.time(),
                "rps": rps_simulated + (i % 10) * 5,
                "bytes": (rps_simulated + (i % 10) * 5) * 600,
                "errors": (i % 7),
            }
            try:
                async with session.post(f"{coord_url}/stats", json=payload) as r:
                    pass
            except Exception as e:
                print(f"[worker {node_id}] stats push failed: {e}", flush=True)
            await asyncio.sleep(1)
        print(f"[worker {node_id}] finished after {duration}s", flush=True)


def main():
    parser = argparse.ArgumentParser(description="MHDDoS Distributed Coordinator")
    sub = parser.add_subparsers(dest="mode", required=True)
    p_coord = sub.add_parser("coordinator", help="Run the coordinator/dashboard")
    p_coord.add_argument("--host", default="0.0.0.0")
    p_coord.add_argument("--port", type=int, default=9000)
    p_worker = sub.add_parser("worker", help="Run a test worker (simulated stats)")
    p_worker.add_argument("--coord", required=True, help="Coordinator URL e.g. http://1.2.3.4:9000")
    p_worker.add_argument("--node-id", required=True)
    p_worker.add_argument("--target", default="https://example.com")
    p_worker.add_argument("--duration", type=int, default=60)
    p_worker.add_argument("--rps", type=int, default=100)
    args = parser.parse_args()

    if args.mode == "coordinator":
        app = create_coord_app()
        print(f"[coord] 🌐 Dashboard at http://{args.host}:{args.port}/", flush=True)
        print(f"[coord]    POST /register, POST /stats, GET /aggregate", flush=True)
        web.run_app(app, host=args.host, port=args.port, access_log=None)
    elif args.mode == "worker":
        asyncio.run(run_worker(args.coord, args.node_id, args.target,
                               args.duration, args.rps))


if __name__ == "__main__":
    main()
