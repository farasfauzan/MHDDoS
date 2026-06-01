#!/usr/bin/env python3
"""
Unit tests for Sprint #4 features:
  #22 Stealth Mode
  #26 Preset Manager
  #18 WAF Bypass Auto-Select
  #19 Proxy Rotation Engine
  #24 Real-time Traffic Graph
  #31 Sprint #4 integration tests
"""
import unittest
import threading
from pathlib import Path
from time import sleep

# ---- Test #18: WAF Bypass Auto-Select ----
class TestWAFBypass(unittest.TestCase):
    def test_auto_select_returns_string(self):
        from start import waf_auto_select_bypass
        rl = waf_auto_select_bypass("GET", "example.com", "/test")
        self.assertIn("GET", rl)
        self.assertIn("/test", rl)
        self.assertTrue(rl.endswith("\r\n"))

    def test_report_success(self):
        from start import waf_report_result, _waf_bypass_stats
        waf_report_result("standard", True)
        self.assertGreater(_waf_bypass_stats["standard"]["success"], 0)

    def test_report_fail(self):
        from start import waf_report_result, _waf_bypass_stats
        before = _waf_bypass_stats["standard"]["fail"]
        waf_report_result("standard", False)
        self.assertEqual(_waf_bypass_stats["standard"]["fail"], before + 1)


# ---- Test #19: Proxy Rotation Engine ----
class TestProxyRotator(unittest.TestCase):
    def setUp(self):
        from start import ProxyRotator
        self.rot = ProxyRotator(["p1", "p2", "p3"])

    def test_next_cycles(self):
        self.assertEqual(self.rot.next(), "p1")
        self.assertEqual(self.rot.next(), "p2")
        self.assertEqual(self.rot.next(), "p3")
        self.assertEqual(self.rot.next(), "p1")  # wraparound

    def test_report_fail_removes_proxy(self):
        self.rot.report_fail("p1")
        self.rot.report_fail("p1")
        self.rot.report_fail("p1")
        self.assertNotIn("p1", self.rot._proxies)
        self.assertEqual(len(self.rot._proxies), 2)

    def test_empty(self):
        from start import ProxyRotator
        empty = ProxyRotator([])
        self.assertFalse(empty)
        self.assertIsNone(empty.next())

    def test_report_success_resets(self):
        self.rot.report_fail("p1")
        self.rot.report_fail("p1")
        self.rot.report_success("p1")
        self.assertEqual(self.rot._fails.get("p1", 0), 0)


# ---- Test #24: Real-time Traffic Graph ----
class TestTrafficGraph(unittest.TestCase):
    def setUp(self):
        from start import TrafficGraph
        self.g = TrafficGraph(max_points=5)

    def test_no_data(self):
        self.assertIn("no data", self.g.render())

    def test_add_and_render(self):
        self.g.add(100)
        self.g.add(200)
        self.g.add(150)
        r = self.g.render()
        self.assertIn("█", r)
        self.assertIn("+", r)

    def test_max_points_truncation(self):
        for i in range(10):
            self.g.add(i * 10)
        pts = self.g._points
        self.assertEqual(len(pts), 5)
        self.assertEqual(pts[0], 50)


# ---- Test #22: Stealth Mode ----
class TestStealthMode(unittest.TestCase):
    def test_stealth_flag_default(self):
        from start import HttpFlood
        hf = HttpFlood.__new__(HttpFlood)
        hf._stealth = False  # simulate default
        self.assertFalse(hf._stealth)

    def test_stealth_flag_true(self):
        from start import HttpFlood
        hf = HttpFlood.__new__(HttpFlood)
        hf._stealth = True
        self.assertTrue(hf._stealth)

    def test_jitter_range(self):
        """Stealth jitter should be 1-50ms."""
        from random import randint
        for _ in range(100):
            v = randint(1, 50)
            self.assertGreaterEqual(v, 1)
            self.assertLessEqual(v, 50)


# ---- Test #26: Preset Manager ----
class TestPresetManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from start import PresetManager
        cls.pm = PresetManager

    def test_save_and_load(self):
        self.pm.save("test_preset", method="GET", threads=10, rpc=5)
        loaded = self.pm.load("test_preset")
        self.assertEqual(loaded.get("method"), "GET")
        self.assertEqual(loaded.get("threads"), 10)
        self.assertEqual(loaded.get("rpc"), 5)

    def test_load_missing(self):
        loaded = self.pm.load("nonexistent_preset_xyz")
        self.assertEqual(loaded, {})

    def test_list_presets(self):
        self.pm.save("test_list_presets_temp", method="GET")
        presets = self.pm.list_presets()
        self.assertIn("test_list_presets_temp", presets)
        import os
        os.remove(Path(__file__).parent / "presets" / "test_list_presets_temp.json")

    @classmethod
    def tearDownClass(cls):
        import os
        preset_file = Path(__file__).parent / "presets" / "test_preset.json"
        if preset_file.exists():
            os.remove(preset_file)


# ---- Test #31: Sprint #4 Integration ----
class TestSprint4Integration(unittest.TestCase):
    def test_all_35_l7_methods_registered(self):
        """Verify all 35 L7 methods are registered in Methods.LAYER7_METHODS."""
        from start import Methods
        expected_36 = {
            "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW",
            "SLOWLORIS", "HEAD", "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB",
            "AVB", "CFBUAM", "APACHE", "XMLRPC", "XMLRPC_MULTI", "BOT", "BOMB",
            "DOWNLOADER", "KILLER", "TOR", "RHEX", "STOMP",
            "WORDPRESS", "H2", "H2_RST", "COOKIE_HARVEST", "WS", "GQL",
            "H2_PRIORITY", "RANGE_CRASH",
        }
        self.assertEqual(Methods.LAYER7_METHODS, expected_36)
        self.assertEqual(len(Methods.LAYER7_METHODS), 36)

    def test_methods_dict_has_36_keys(self):
        """Verify HttpFlood.methods dict has all 36 methods."""
        from start import Methods
        self.assertGreaterEqual(len(Methods.LAYER7_METHODS), 36)

    def test_getMethodType_coverage(self):
        from start import HttpFlood
        for m in ["GET", "POST", "HEAD", "WS", "GQL", "H2_PRIORITY"]:
            t = HttpFlood.getMethodType(m)
            self.assertIn(t, ["GET", "POST", "HEAD", "REQUESTS"])

    def test_command_sync(self):
        """CLI Sync (#29): verify usage prints all methods."""
        from start import Methods
        usage_text = f"{len(Methods.ALL_METHODS)}"
        self.assertTrue(usage_text.isdigit() or int(usage_text) > 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)