"""Proxy management: download, rotate, load."""

from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from itertools import cycle
from pathlib import Path
from random import choice as randchoice
from threading import Lock
from typing import List, Optional, Set
import threading

from PyRoxy import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from requests import exceptions, get
import logging

from .utils import con, logger, bcolors, __dir__


class ProxyManager:
    @staticmethod
    def DownloadFromConfig(cf, proxy_type: int) -> Set[Proxy]:
        providers = [
            p
            for p in cf["proxy-providers"]
            if p["type"] == proxy_type or proxy_type == 0
        ]
        logger.info(
            f"{bcolors.WARNING}Downloading Proxies from {bcolors.OKBLUE}%d{bcolors.WARNING} Providers{bcolors.RESET}"
            % len(providers)
        )
        proxes: Set[Proxy] = set()
        with ThreadPoolExecutor(len(providers)) as executor:
            futures = {
                executor.submit(
                    ProxyManager.download,
                    p,
                    ProxyType.stringToProxyType(str(p["type"])),
                )
                for p in providers
            }
            for f in as_completed(futures):
                for pro in f.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(
            f"{bcolors.WARNING}Proxies from (URL: {bcolors.OKBLUE}%s{bcolors.WARNING}, Type: {bcolors.OKBLUE}%s{bcolors.WARNING}, Timeout: {bcolors.OKBLUE}%d{bcolors.WARNING}){bcolors.RESET}"
            % (provider["url"], proxy_type.name, provider["timeout"])
        )
        proxes: Set[Proxy] = set()
        with suppress(TimeoutError, exceptions.ConnectionError, exceptions.ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(data.splitlines(), proxy_type):
                    proxes.add(proxy)
            except Exception as e:
                logger.error(f"Download Proxy Error: {e}")
        return proxes


class ProxyRotator:
    """Round-robin proxy rotation with health tracking."""

    def __init__(self, proxies):
        self._proxies = list(proxies) if proxies else []
        self._index = 0
        self._lock = threading.Lock()
        self._fails = {}
        self._max_fails = 3

    def next(self):
        if not self._proxies:
            return None
        with self._lock:
            proxy = self._proxies[self._index]
            self._index = (self._index + 1) % len(self._proxies)
            return proxy

    def report_fail(self, proxy):
        addr = str(proxy)
        with self._lock:
            self._fails[addr] = self._fails.get(addr, 0) + 1
            if self._fails[addr] >= self._max_fails:
                with suppress(Exception):
                    self._proxies.remove(proxy)
                self._fails.pop(addr, None)

    def report_success(self, proxy):
        addr = str(proxy)
        with self._lock:
            self._fails[addr] = 0

    def __bool__(self):
        return bool(self._proxies)

    def __len__(self):
        return len(self._proxies)


def handle_proxy_list(proxy_li: Path, proxy_ty: int, url=None, threads=100):
    """Download, check, and load proxy list."""
    from .utils import exit

    if proxy_ty not in {4, 5, 1, 0, 6}:
        exit("Socks Type Not Found [4, 5, 1, 0, 6]")
    if proxy_ty == 6:
        proxy_ty = randchoice([4, 5, 1])
    if not proxy_li.exists():
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        with proxy_li.open("w") as wr:
            proxes = ProxyManager.DownloadFromConfig(con, proxy_ty)
            if proxes:
                proxes = ProxyChecker.checkAll(
                    proxes,
                    timeout=5,
                    threads=threads,
                    url=url.human_repr() if url else "http://httpbin.org/get",
                )
            if not proxes:
                wr.write("")
                return None
            wr.write("\n".join(p.__str__() for p in proxes))
            logger.info(f"Saved {len(proxes)} proxies to {proxy_li}")
    proxies = ProxyUtiles.readFromFile(proxy_li)
    if proxies:
        logger.info(
            f"{bcolors.WARNING}Proxy Count: {bcolors.OKBLUE}{len(proxies):,}{bcolors.RESET}"
        )
    else:
        logger.info(
            f"{bcolors.WARNING}Empty Proxy File, running flood without proxy{bcolors.RESET}"
        )
        proxies = None
    return proxies


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
