#!/usr/bin/env python3
"""recon_suite.py — Plan E+ Fase 5: Recon Suite.

Multi-tool reconnaissance for target intelligence:
  1. Subdomain enumeration — crt.sh certificates + cert SAN extraction
  2. Origin IP discovery — find real server behind Cloudflare/CDN
  3. Endpoint fuzzer — probe common admin/api/sensitive paths
  4. HTML report generator — consolidated findings report

Usage:
    python3 recon_suite.py example.com                  # full scan
    python3 recon_suite.py example.com --subs           # subdomains only
    python3 recon_suite.py example.com --origin         # origin IP only
    python3 recon_suite.py example.com --fuzz           # endpoint fuzz only
    python3 recon_suite.py example.com --report out.html
"""
from __future__ import annotations
import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Set, Tuple

try:
    import requests
except ImportError:
    print("[recon] requests required. pip install requests", file=sys.stderr)
    sys.exit(1)


# ---------- 1. Subdomain enumeration ----------
def enumerate_subdomains_crtsh(domain: str, timeout: int = 15) -> Set[str]:
    """Query crt.sh for all certificates issued for *.domain → extract SANs.
    Free, no API key, returns ~50-500 unique subdomains for popular sites."""
    subs: Set[str] = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return subs
        for entry in r.json()[:500]:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lower().replace("*.", "")
                if n and "." in n and (n.endswith(domain) or n == domain):
                    subs.add(n)
    except Exception as e:
        print(f"[subs] crt.sh failed: {e}", file=sys.stderr)
    return subs


def resolve_subdomains(subdomains: Set[str], max_workers: int = 30,
                       timeout: float = 1.5) -> Dict[str, str]:
    """Resolve each subdomain to its IP (or '?' on failure). Concurrent."""
    results: Dict[str, str] = {}

    def _resolve(sub: str) -> Tuple[str, str]:
        try:
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(sub)
            return sub, ip
        except Exception:
            return sub, "?"

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_resolve, s): s for s in subdomains}
        for f in as_completed(futures):
            sub, ip = f.result()
            results[sub] = ip
    return results


# ---------- 2. Origin IP discovery ----------
# Cloudflare IP ranges (subset — most common). Subdomains resolving here are
# behind CDN; non-matching IPs are candidate origins.
CLOUDFLARE_PREFIXES = (
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "172.64.", "172.65.", "172.66.", "172.67.", "162.158.", "173.245.",
    "198.41.", "188.114.",
)


def is_cdn_ip(ip: str) -> bool:
    """Heuristic: is this IP from a known CDN range?"""
    if ip == "?" or not ip:
        return True
    return ip.startswith(CLOUDFLARE_PREFIXES)


def find_origin_candidates(domain: str, sub_to_ip: Dict[str, str]) -> List[Tuple[str, str, int]]:
    """From subdomain→IP map, find non-CDN IPs and probe with Host header.
    Returns list of (ip, found_via_subdomain, status_code) for verified origins."""
    candidates: Set[Tuple[str, str]] = set()
    for sub, ip in sub_to_ip.items():
        if not is_cdn_ip(ip):
            candidates.add((ip, sub))

    verified: List[Tuple[str, str, int]] = []
    for ip, via_sub in list(candidates)[:30]:
        try:
            r = requests.get(
                f"https://{ip}/", headers={"Host": domain},
                timeout=5, verify=False, allow_redirects=False,
            )
            if r.status_code in (200, 301, 302, 401, 403, 404):
                verified.append((ip, via_sub, r.status_code))
        except Exception:
            continue
    return verified


# ---------- 3. Endpoint fuzzer ----------
DEFAULT_FUZZ_PATHS = [
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/wp-admin/", "/wp-login.php", "/wp-config.php.bak",
    "/login", "/signin", "/auth", "/api/", "/api/v1/", "/api/v2/",
    "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    "/phpinfo.php", "/info.php", "/test.php", "/php_info.php",
    "/backup/", "/backups/", "/db.sql", "/dump.sql", "/database.sql",
    "/config/", "/config.json", "/config.yml", "/config.yaml", "/config.xml",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/graphql", "/graphiql", "/api/graphql",
    "/swagger.json", "/swagger-ui.html", "/api-docs",
    "/console", "/actuator", "/actuator/health", "/actuator/env",
    "/metrics", "/prometheus", "/_status", "/_admin",
    "/debug/", "/debug/vars", "/.DS_Store",
    "/CHANGELOG", "/README", "/README.md", "/LICENSE",
    "/jenkins/", "/jenkins/login", "/manager/html",  # Tomcat
    "/.aws/credentials", "/.ssh/id_rsa",
    "/wp-content/uploads/", "/wp-includes/",
]


def fuzz_endpoints(base_url: str, paths: List[str] = None,
                   max_workers: int = 20, timeout: float = 4.0) -> List[Dict[str, Any]]:
    """Probe a list of paths against base_url. Returns list of hits with status,
    size, and a flag for "interesting" responses (200/301/302/401/403)."""
    paths = paths or DEFAULT_FUZZ_PATHS
    results: List[Dict[str, Any]] = []
    base = base_url.rstrip("/")

    def _probe(path: str) -> Dict[str, Any]:
        url = base + path
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
            return {
                "path": path, "url": url, "status": r.status_code,
                "size": len(r.content),
                "ctype": r.headers.get("content-type", "?")[:50],
                "interesting": r.status_code in (200, 301, 302, 401, 403),
            }
        except Exception as e:
            return {"path": path, "url": url, "status": 0,
                    "size": 0, "ctype": "ERR", "interesting": False,
                    "error": str(e)[:50]}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_probe, p) for p in paths]
        for f in as_completed(futures):
            results.append(f.result())

    # Sort: interesting first, then by status, then path
    results.sort(key=lambda r: (not r["interesting"], r["status"], r["path"]))
    return results


# ---------- 4. HTML report ----------
def build_recon_report(domain: str, sub_to_ip: Dict[str, str],
                       origin_candidates: List[Tuple[str, str, int]],
                       fuzz_results: List[Dict[str, Any]]) -> str:
    """Build a self-contained HTML recon report from all 3 module outputs."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    n_subs = len(sub_to_ip)
    n_resolved = sum(1 for ip in sub_to_ip.values() if ip != "?")
    n_cdn = sum(1 for ip in sub_to_ip.values() if is_cdn_ip(ip))
    n_origin = len(origin_candidates)
    interesting = [r for r in fuzz_results if r.get("interesting")]
    n_interesting = len(interesting)

    # Subdomain rows
    sub_rows = []
    for sub, ip in sorted(sub_to_ip.items()):
        cdn_badge = "🛡 CDN" if is_cdn_ip(ip) else "🎯 ORIGIN?"
        sub_rows.append(
            f"<tr><td><code>{sub}</code></td><td>{ip}</td><td>{cdn_badge}</td></tr>"
        )

    # Origin candidates
    origin_rows = []
    for ip, via, code in origin_candidates:
        origin_rows.append(
            f"<tr><td><b>{ip}</b></td><td><code>{via}</code></td><td>{code}</td></tr>"
        )

    # Endpoint fuzzer
    fuzz_rows = []
    for r in fuzz_results:
        if r.get("status") == 0:
            continue
        cls = "interesting" if r.get("interesting") else "boring"
        fuzz_rows.append(
            f'<tr class="{cls}"><td><code>{r["path"]}</code></td>'
            f'<td>{r["status"]}</td><td>{r["size"]}</td>'
            f'<td>{r["ctype"]}</td></tr>'
        )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Recon Report — {domain}</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 1200px;
        margin: 30px auto; padding: 20px; background: #1a1a1a; color: #e0e0e0; }}
h1 {{ color: #66ddaa; border-bottom: 3px solid #66ddaa; padding-bottom: 10px; }}
h2 {{ color: #66aaff; margin-top: 30px; }}
.summary {{ display: flex; gap: 15px; flex-wrap: wrap; margin: 20px 0; }}
.card {{ background: #2a2a2a; padding: 15px; border-radius: 6px; flex: 1;
         min-width: 150px; border-left: 3px solid #66aaff; }}
.card .lbl {{ font-size: 11px; text-transform: uppercase; color: #888; }}
.card .val {{ font-size: 24px; font-weight: bold; color: #66ddaa; margin-top: 4px; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
th, td {{ padding: 8px; border-bottom: 1px solid #333; text-align: left; font-size: 13px; }}
th {{ background: #2a2a2a; color: #66aaff; text-transform: uppercase; font-size: 11px; }}
code {{ background: #111; padding: 2px 6px; border-radius: 3px; color: #aaffaa; }}
tr.interesting {{ background: #2a1a1a; }}
tr.interesting td {{ color: #ffaa66; font-weight: bold; }}
.footer {{ color: #666; font-size: 11px; margin-top: 40px;
           border-top: 1px solid #333; padding-top: 20px; }}
</style></head><body>
<h1>🔍 Recon Report — {domain}</h1>
<p><b>Generated:</b> {ts}</p>
<div class="summary">
  <div class="card"><div class="lbl">Subdomains</div>
    <div class="val">{n_subs}</div></div>
  <div class="card"><div class="lbl">Resolved</div>
    <div class="val">{n_resolved}</div></div>
  <div class="card"><div class="lbl">Behind CDN</div>
    <div class="val" style="color:#88ccff;">{n_cdn}</div></div>
  <div class="card"><div class="lbl">Origin Candidates</div>
    <div class="val" style="color:#ff9933;">{n_origin}</div></div>
  <div class="card"><div class="lbl">Interesting Paths</div>
    <div class="val" style="color:#ffaa66;">{n_interesting}</div></div>
</div>

<h2>🎯 Origin IP Candidates</h2>
<p>Non-CDN IPs that responded to <code>Host: {domain}</code> probe:</p>
<table><thead><tr><th>IP</th><th>Found via subdomain</th><th>HTTP status</th></tr></thead>
<tbody>{''.join(origin_rows) or '<tr><td colspan="3"><i>No origin candidates discovered</i></td></tr>'}</tbody></table>

<h2>🌐 Subdomains ({n_subs})</h2>
<table><thead><tr><th>Subdomain</th><th>IP</th><th>Status</th></tr></thead>
<tbody>{''.join(sub_rows) or '<tr><td colspan="3"><i>No subdomains found</i></td></tr>'}</tbody></table>

<h2>🔓 Endpoint Fuzzer Hits</h2>
<table><thead><tr><th>Path</th><th>Status</th><th>Size</th><th>Content-Type</th></tr></thead>
<tbody>{''.join(fuzz_rows) or '<tr><td colspan="4"><i>No paths probed</i></td></tr>'}</tbody></table>

<div class="footer">
Generated by MHDDoS recon_suite.py (Plan E+ Fase 5).<br>
For authorized security testing only.
</div>
</body></html>"""


# ---------- 5. CLI ----------
def main():
    parser = argparse.ArgumentParser(description="MHDDoS Recon Suite (Plan E+ Fase 5)")
    parser.add_argument("domain", help="Target domain (no scheme), e.g. example.com")
    parser.add_argument("--subs", action="store_true", help="Run subdomain enum only")
    parser.add_argument("--origin", action="store_true", help="Run origin IP discovery only")
    parser.add_argument("--fuzz", action="store_true", help="Run endpoint fuzzer only")
    parser.add_argument("--report", default=None, help="Save HTML report to this path")
    parser.add_argument("--max-subs", type=int, default=200,
                        help="Cap subdomain resolution count (default: 200)")
    args = parser.parse_args()

    domain = args.domain.replace("https://", "").replace("http://", "").rstrip("/")
    run_all = not (args.subs or args.origin or args.fuzz)

    sub_to_ip: Dict[str, str] = {}
    origin_candidates: List[Tuple[str, str, int]] = []
    fuzz_results: List[Dict[str, Any]] = []

    if args.subs or run_all:
        print(f"[1/3] Subdomain enumeration via crt.sh for {domain}...")
        subs = enumerate_subdomains_crtsh(domain)
        print(f"      Found {len(subs)} unique subdomains. Resolving (cap={args.max_subs})...")
        capped = set(list(subs)[: args.max_subs])
        sub_to_ip = resolve_subdomains(capped)
        resolved = sum(1 for ip in sub_to_ip.values() if ip != "?")
        print(f"      → resolved: {resolved}/{len(sub_to_ip)}")

    if args.origin or run_all:
        if not sub_to_ip:
            sub_to_ip = resolve_subdomains(enumerate_subdomains_crtsh(domain))
        print(f"[2/3] Origin IP discovery (probing non-CDN candidates)...")
        origin_candidates = find_origin_candidates(domain, sub_to_ip)
        print(f"      → {len(origin_candidates)} verified origin IPs")
        for ip, via, code in origin_candidates:
            print(f"        ✓ {ip} (via {via}) → HTTP {code}")

    if args.fuzz or run_all:
        base = f"https://{domain}"
        print(f"[3/3] Endpoint fuzzer on {base}...")
        fuzz_results = fuzz_endpoints(base)
        interesting = [r for r in fuzz_results if r.get("interesting")]
        print(f"      → {len(interesting)} interesting paths found")
        for r in interesting[:15]:
            print(f"        {r['status']} {r['path']} ({r['size']} bytes, {r['ctype']})")

    if args.report:
        html = build_recon_report(domain, sub_to_ip, origin_candidates, fuzz_results)
        with open(args.report, "w") as f:
            f.write(html)
        print(f"\n📄 HTML report saved to: {args.report}")
    else:
        # Print summary JSON
        print("\n" + json.dumps({
            "domain": domain,
            "subdomain_count": len(sub_to_ip),
            "origin_candidates": [{"ip": ip, "via": v, "status": c}
                                  for ip, v, c in origin_candidates],
            "fuzz_interesting": [r for r in fuzz_results if r.get("interesting")],
        }, indent=2, default=str))


if __name__ == "__main__":
    main()
