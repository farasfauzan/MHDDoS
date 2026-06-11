"""Reconnaissance suite: subdomain enum, port scan, WAF detection, report."""

from __future__ import annotations
import socket as sock
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict
from urllib.parse import urlparse
import requests
from .utils import logger


class ReconSuite:
    @staticmethod
    def scan(url: str, timeout: float = 8.0) -> Dict:
        """Run recon phases, return results dict."""
        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or url
        scheme = parsed.scheme or "https"

        result = {
            "url": url,
            "hostname": hostname,
            "ip": None,
            "waf": "Unknown",
            "server": "",
            "open_ports": [],
            "status": 0,
            "latency": 0,
            "recommended_methods": [],
        }

        try:
            result["ip"] = sock.gethostbyname(hostname)
        except Exception:
            result["ip"] = "?"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "text/html,*/*;q=0.8",
        }
        try:
            t0 = time.time()
            r = requests.get(
                url if "://" in url else f"https://{url}",
                headers=headers,
                timeout=timeout,
                verify=False,
            )
            result["status"] = r.status_code
            result["latency"] = time.time() - t0
            result["server"] = r.headers.get("Server", "")
            from .deathstar import WAFFingerprint

            result["waf"] = WAFFingerprint.detect_from_headers(dict(r.headers))
        except Exception as e:
            result["error"] = str(e)

        TOP_PORTS = [
            21,
            22,
            25,
            53,
            80,
            110,
            143,
            443,
            465,
            587,
            993,
            995,
            3306,
            5432,
            6379,
            8080,
            8443,
            9090,
            27017,
            9200,
        ]

        def _scan_port(p):
            try:
                s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((result["ip"], p))
                s.close()
                return p
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(_scan_port, p): p for p in TOP_PORTS}
            for f in as_completed(futures):
                res = f.result()
                if res:
                    result["open_ports"].append(res)
        result["open_ports"].sort()

        from .deathstar import WAFFingerprint

        result["recommended_methods"] = WAFFingerprint.BYPASS_MAP.get(
            result["waf"], WAFFingerprint.BYPASS_MAP["Unknown / None"]
        )

        return result
