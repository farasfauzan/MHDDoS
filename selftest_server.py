#!/usr/bin/env python3
"""
selftest_server.py — Local target server for MHDDoS Self-Test Lab.

Spins up a realistic-ish HTTP target on localhost:8888 with multiple endpoints
that simulate production behavior (CPU-bound work, rate-limiting, WAF blocks).
Use this to validate that the attack tool actually works without hitting
real websites and risking IP blacklist or legal issues.

Run standalone:
    python3 selftest_server.py [--port 8888] [--host 127.0.0.1]

Endpoints:
    GET  /              — landing, fast (~1ms)
    GET  /api/heavy     — CPU-bound, ~100ms work per request
    GET  /api/protected — rate-limited (50 req/s/IP → 429)
    GET  /admin         — always 403 (simulates WAF block)
    GET  /health        — instant (used for monitor probes)
    GET  /__stats__     — JSON stats: rps, p50/p99 ms, errors, cpu, mem
    POST /__reset__     — zero out counters
"""
from __future__ import annotations
import argparse
import asyncio
import json
import os
import sys
import time
from collections import defaultdict, deque
from typing import Deque, Dict

try:
    from aiohttp import web
except ImportError:
    print("[selftest] aiohttp not installed. Run: pip install aiohttp", file=sys.stderr)
    sys.exit(1)

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


# ---------- Global stats (single-process, no shared memory needed) ----------
class Stats:
    def __init__(self) -> None:
        self.start_ts: float = time.time()
        self.requests_total: int = 0
        self.errors_total: int = 0
        self.bytes_in: int = 0
        # Last 5 s of (timestamp, latency_ms) for percentile calc.
        self.latencies: Deque[tuple[float, float]] = deque(maxlen=5000)
        # Per-IP rate limiter buckets: {ip: deque of timestamps}.
        self.rate_buckets: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=100))
        # Per-endpoint hit count.
        self.endpoints: Dict[str, int] = defaultdict(int)
        # Per-status code count.
        self.status_codes: Dict[int, int] = defaultdict(int)

    def record(self, path: str, status: int, latency_ms: float, body_bytes: int) -> None:
        now = time.time()
        self.requests_total += 1
        self.bytes_in += body_bytes
        self.latencies.append((now, latency_ms))
        self.endpoints[path] += 1
        self.status_codes[status] += 1
        if status >= 400:
            self.errors_total += 1

    def snapshot(self) -> dict:
        now = time.time()
        # Keep only last 5 s for RPS calc + percentiles.
        recent = [lat for ts, lat in self.latencies if now - ts <= 5.0]
        rps = len(recent) / 5.0 if recent else 0.0
        if recent:
            sorted_lat = sorted(recent)
            p50 = sorted_lat[len(sorted_lat) // 2]
            p99 = sorted_lat[max(0, int(len(sorted_lat) * 0.99) - 1)]
        else:
            p50 = p99 = 0.0
        elapsed = now - self.start_ts

        cpu = mem = -1.0
        if _HAS_PSUTIL:
            try:
                p = psutil.Process(os.getpid())
                cpu = p.cpu_percent(interval=None)
                mem = p.memory_info().rss / (1024 * 1024)
            except Exception:
                pass

        return {
            "uptime_s": round(elapsed, 1),
            "requests_total": self.requests_total,
            "errors_total": self.errors_total,
            "bytes_in": self.bytes_in,
            "rps_5s": round(rps, 1),
            "p50_ms": round(p50, 1),
            "p99_ms": round(p99, 1),
            "cpu_pct": round(cpu, 1),
            "mem_mb": round(mem, 1),
            "endpoints": dict(self.endpoints),
            "status_codes": {str(k): v for k, v in self.status_codes.items()},
        }

    def reset(self) -> None:
        self.requests_total = 0
        self.errors_total = 0
        self.bytes_in = 0
        self.latencies.clear()
        self.rate_buckets.clear()
        self.endpoints.clear()
        self.status_codes.clear()
        self.start_ts = time.time()


STATS = Stats()


# ---------- Middleware: time + record every request ----------
@web.middleware
async def stats_middleware(request: web.Request, handler) -> web.StreamResponse:
    t0 = time.perf_counter()
    body_bytes = int(request.headers.get("content-length") or 0)
    try:
        resp = await handler(request)
    except web.HTTPException as e:
        latency_ms = (time.perf_counter() - t0) * 1000
        STATS.record(request.path, e.status, latency_ms, body_bytes)
        raise
    except Exception:
        latency_ms = (time.perf_counter() - t0) * 1000
        STATS.record(request.path, 500, latency_ms, body_bytes)
        raise
    latency_ms = (time.perf_counter() - t0) * 1000
    STATS.record(request.path, resp.status, latency_ms, body_bytes)
    return resp


# ---------- Endpoint handlers ----------
async def h_root(request: web.Request) -> web.Response:
    return web.Response(
        text="<html><body><h1>MHDDoS Self-Test Target</h1>"
             "<p>Endpoints: /api/heavy /api/protected /admin /health /__stats__</p>"
             "</body></html>",
        content_type="text/html",
    )


async def h_heavy(request: web.Request) -> web.Response:
    # Simulate CPU-bound work: 100ms sleep (await yields to other coros, so
    # this models I/O-bound DB query rather than truly burning CPU; that's
    # realistic for most web apps).
    await asyncio.sleep(0.1)
    return web.json_response({"data": "x" * 1000, "ts": time.time()})


async def h_protected(request: web.Request) -> web.Response:
    # Rate limit: max 50 req/s/IP → 429 after that.
    ip = request.remote or "unknown"
    bucket = STATS.rate_buckets[ip]
    now = time.time()
    # Evict timestamps older than 1 s.
    while bucket and now - bucket[0] > 1.0:
        bucket.popleft()
    if len(bucket) >= 50:
        return web.Response(
            status=429,
            text="429 Too Many Requests — rate limited",
            headers={"Retry-After": "1", "X-RateLimit": "50/s"},
        )
    bucket.append(now)
    return web.json_response({"ok": True, "remaining": 50 - len(bucket)})


async def h_admin(request: web.Request) -> web.Response:
    # Always 403 — simulates WAF block.
    return web.Response(
        status=403,
        text="403 Forbidden — admin area protected",
        headers={"X-WAF": "MHDDoS-SelfTest", "Server": "MHDDoS-Test/1.0"},
    )


async def h_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def h_stats(request: web.Request) -> web.Response:
    return web.json_response(STATS.snapshot())


async def h_reset(request: web.Request) -> web.Response:
    STATS.reset()
    return web.json_response({"reset": True})


# ---------- App factory ----------
def create_app() -> web.Application:
    app = web.Application(middlewares=[stats_middleware])
    app.router.add_get("/", h_root)
    app.router.add_get("/api/heavy", h_heavy)
    app.router.add_get("/api/protected", h_protected)
    app.router.add_get("/admin", h_admin)
    app.router.add_get("/health", h_health)
    app.router.add_get("/__stats__", h_stats)
    app.router.add_post("/__reset__", h_reset)
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="MHDDoS Self-Test target server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8888, help="Bind port (default: 8888)")
    args = parser.parse_args()

    app = create_app()
    print(f"[selftest] 🧪 Starting target server on http://{args.host}:{args.port}", flush=True)
    print(f"[selftest]    Endpoints: / /api/heavy /api/protected /admin /health /__stats__", flush=True)
    print(f"[selftest]    psutil available: {_HAS_PSUTIL}", flush=True)
    print(f"[selftest]    PID: {os.getpid()}", flush=True)
    try:
        web.run_app(app, host=args.host, port=args.port, access_log=None)
    except KeyboardInterrupt:
        print("\n[selftest] Shutting down (KeyboardInterrupt)", flush=True)


if __name__ == "__main__":
    main()
