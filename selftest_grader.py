#!/usr/bin/env python3
"""selftest_grader.py — Auto-grader for MHDDoS Self-Test Lab (Plan E+ Fase 3).

Scoring model (0-100 per attack run):
   - rps_score       (0-40): peak RPS achieved vs baseline (10/req baseline)
   - latency_score   (0-25): how much p99 inflated under attack (higher = more impact)
   - cpu_score       (0-20): peak server CPU% during attack
   - errors_score    (0-15): 5xx + timeout count (server crashed = winning)
   Total = sum of above, capped at 100.

Usage from GUI:
   - Single-run grader: pass last 60s of stats deque snapshots → returns dict.
   - Sweep: spawn 1 server, run each method serially for short_duration s,
     collect stats, build comparison table, write HTML report with embedded
     matplotlib bar chart.

This module is import-safe (no Qt deps) so we can unit-test it standalone.
"""
from __future__ import annotations
import json
import statistics
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------- Scoring ----------
def grade_run(samples: List[Dict[str, Any]], baseline_rps: float = 10.0) -> Dict[str, Any]:
    """Score one attack run from a list of /__stats__ snapshots.

    Each snapshot dict should have: rps_5s, p50_ms, p99_ms, errors_total,
    cpu_pct, mem_mb (matches selftest_server.py JSON layout).
    """
    if not samples:
        return {"score": 0, "rps_score": 0, "latency_score": 0,
                "cpu_score": 0, "errors_score": 0,
                "peak_rps": 0, "peak_p99": 0, "peak_cpu": 0,
                "errors_delta": 0, "verdict": "no-data"}

    rps_vals = [s.get("rps_5s", 0) or 0 for s in samples]
    p99_vals = [s.get("p99_ms", 0) or 0 for s in samples]
    cpu_vals = [max(0, s.get("cpu_pct", 0) or 0) for s in samples]
    err_first = samples[0].get("errors_total", 0) or 0
    err_last = samples[-1].get("errors_total", 0) or 0

    peak_rps = max(rps_vals)
    peak_p99 = max(p99_vals)
    peak_cpu = max(cpu_vals)
    errors_delta = max(0, err_last - err_first)

    # rps_score: 40 pts at peak_rps >= 10x baseline
    rps_score = min(40.0, (peak_rps / max(baseline_rps, 1.0)) * 4.0)

    # latency_score: 25 pts when p99 >= 1000ms (severe impact)
    latency_score = min(25.0, (peak_p99 / 1000.0) * 25.0)

    # cpu_score: 20 pts at 100% CPU
    cpu_score = min(20.0, peak_cpu / 5.0)

    # errors_score: 15 pts at 100+ errors
    errors_score = min(15.0, errors_delta / 100.0 * 15.0)

    total = round(rps_score + latency_score + cpu_score + errors_score, 1)

    if total >= 80:
        verdict = "💀 DEVASTATING"
    elif total >= 60:
        verdict = "🔥 HEAVY"
    elif total >= 40:
        verdict = "⚠ MODERATE"
    elif total >= 20:
        verdict = "💤 LIGHT"
    else:
        verdict = "❌ INEFFECTIVE"

    return {
        "score": total,
        "rps_score": round(rps_score, 1),
        "latency_score": round(latency_score, 1),
        "cpu_score": round(cpu_score, 1),
        "errors_score": round(errors_score, 1),
        "peak_rps": round(peak_rps, 1),
        "peak_p99": round(peak_p99, 1),
        "peak_cpu": round(peak_cpu, 1),
        "errors_delta": errors_delta,
        "samples": len(samples),
        "verdict": verdict,
    }


# ---------- Stats fetcher ----------
def fetch_stats(port: int, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
    """Fetch /__stats__ from the selftest server. Returns None on error."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/__stats__",
                                     timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def reset_stats(port: int, timeout: float = 1.0) -> bool:
    """POST /__reset__ to zero out the server's counters."""
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/__reset__",
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


# ---------- HTML report ----------
def build_html_report(results: List[Dict[str, Any]], target_url: str,
                      duration_per_method: float) -> str:
    """Build a self-contained HTML report from sweep results.

    `results` = list of dicts with keys: method, score, peak_rps, peak_p99,
    peak_cpu, errors_delta, verdict.
    """
    # Sort by score desc
    sorted_results = sorted(results, key=lambda r: r.get("score", 0), reverse=True)

    rows = []
    for i, r in enumerate(sorted_results, 1):
        medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"#{i}"
        rows.append(
            f"<tr><td>{medal}</td><td><b>{r.get('method','?')}</b></td>"
            f"<td>{r.get('score', 0):.1f}</td>"
            f"<td>{r.get('peak_rps', 0):.1f}</td>"
            f"<td>{r.get('peak_p99', 0):.1f}ms</td>"
            f"<td>{r.get('peak_cpu', 0):.1f}%</td>"
            f"<td>{r.get('errors_delta', 0)}</td>"
            f"<td>{r.get('verdict', '?')}</td></tr>"
        )
    rows_html = "\n".join(rows)

    # Bar chart: SVG inline (no matplotlib dep — keeps report portable)
    max_score = max((r.get("score", 0) for r in sorted_results), default=1) or 1
    bars = []
    for r in sorted_results[:15]:  # top 15
        method = r.get("method", "?")
        score = r.get("score", 0)
        bar_w = (score / max_score) * 600
        color = ("#ff3333" if score >= 80 else
                 "#ff9933" if score >= 60 else
                 "#ffcc33" if score >= 40 else
                 "#88ccff")
        bars.append(
            f'<div style="display:flex;align-items:center;margin:4px 0;">'
            f'<span style="width:140px;font-family:monospace;color:#ccc;">{method}</span>'
            f'<div style="background:{color};width:{bar_w:.0f}px;height:18px;'
            f'border-radius:3px;margin-right:8px;"></div>'
            f'<span style="color:#fff;font-weight:bold;">{score:.1f}</span>'
            f'</div>'
        )
    bars_html = "\n".join(bars)

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    n = len(sorted_results)
    avg_score = (sum(r.get("score", 0) for r in sorted_results) / n) if n else 0

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MHDDoS Auto-Grader Report</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 1100px;
        margin: 30px auto; padding: 20px; background: #1a1a1a; color: #e0e0e0; }}
h1 {{ color: #ff9933; border-bottom: 3px solid #ff9933; padding-bottom: 10px; }}
h2 {{ color: #66aaff; margin-top: 30px; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
table th, table td {{ padding: 8px; border-bottom: 1px solid #333; text-align: left; }}
table th {{ background: #2a2a2a; color: #66aaff; }}
table tr:hover {{ background: #2a2a2a; }}
.summary {{ background: #2a2a2a; padding: 15px; border-radius: 6px;
            border-left: 4px solid #ff9933; }}
.bars {{ background: #111; padding: 15px; border-radius: 6px; margin: 20px 0; }}
.footer {{ color: #666; font-size: 11px; margin-top: 40px;
           border-top: 1px solid #333; padding-top: 20px; }}
</style></head><body>
<h1>🏆 MHDDoS Auto-Grader Report</h1>
<div class="summary">
<p><b>Generated:</b> {ts}</p>
<p><b>Target:</b> <code>{target_url}</code></p>
<p><b>Methods tested:</b> {n} | <b>Duration each:</b> {duration_per_method:.0f}s |
   <b>Avg score:</b> {avg_score:.1f}/100</p>
</div>
<h2>📊 Scoreboard (sorted by score)</h2>
<div class="bars">{bars_html}</div>
<h2>📋 Full Results</h2>
<table><thead><tr><th>Rank</th><th>Method</th><th>Score</th>
<th>Peak RPS</th><th>Peak p99</th><th>Peak CPU</th><th>Errors</th><th>Verdict</th>
</tr></thead><tbody>
{rows_html}
</tbody></table>
<div class="footer">
Self-test results don't translate 1:1 to WAF-protected real targets. Use this
to compare relative method effectiveness on the local test server.<br>
Generated by MHDDoS Auto-Grader (Plan E+ Fase 3).
</div>
</body></html>"""


if __name__ == "__main__":
    # Quick CLI test: poll a running server, grade 5 samples, print result.
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    samples = []
    print(f"Sampling /__stats__ on port {port} for 5 seconds...")
    for _ in range(5):
        s = fetch_stats(port)
        if s:
            samples.append(s)
        time.sleep(1)
    print(json.dumps(grade_run(samples), indent=2))
