# 🌑 MHDDoS Death Star Edition — GUI User Guide

Panduan lengkap pakai GUI MHDDoS yang udah di-customize. Disusun dari nol biar kamu bisa pakai mandiri tanpa perlu lihat source code.

> ⚠ **DISCLAIMER:** Tool ini cuma untuk **authorized penetration testing** — server sendiri, target yang udah kasih izin tertulis (bug bounty scope, contract pentest), atau lab self-test (`localhost`). Pakai ke target tanpa izin = tindak pidana di Indonesia (UU ITE Pasal 30/32) dan banyak negara lain. Saya tulis tools ini buat edukasi defensif, kamu yang tanggung jawab cara pakainya.

---

## Daftar Isi

1. [Instalasi](#1-instalasi)
2. [Struktur Folder](#2-struktur-folder)
3. [Jalanin GUI](#3-jalanin-gui)
4. [Tab Layer7 Attack](#4-tab-layer7-attack)
5. [Tab Layer4 Attack](#5-tab-layer4-attack)
6. [Tab Combined Attack — Inti Tools](#6-tab-combined-attack--inti-tools)
7. [Tab Self-Test Lab](#7-tab-self-test-lab)
8. [Adaptive AI Engine](#8-adaptive-ai-engine)
9. [Preset Buttons (One-Tap, Volumetric, WAF Bypass, Doomsday)](#9-preset-buttons)
10. [ML Auto-Pick (RandomForest WAF Classifier)](#10-ml-auto-pick)
11. [Profile Save/Load](#11-profile-saveload)
12. [Origin IP Discovery (Bypass Cloudflare)](#12-origin-ip-discovery)
13. [Proxy Management](#13-proxy-management)
14. [HTML Report Export](#14-html-report-export)
15. [Multiprocess Mode (8× firepower)](#15-multiprocess-mode)
16. [Method Reference (semua 25 L7 + 11 L4)](#16-method-reference)
17. [Troubleshooting](#17-troubleshooting)
18. [Skenario Real (cara dipake harian)](#18-skenario-real)

---

## 1. Instalasi

### Requirements
- Python 3.9+ (kamu pakai 3.9 dari CommandLineTools)
- macOS / Linux / Windows
- 8 GB RAM minimum (16 GB disarankan kalau pake Multiprocess Mode)

### Setup pertama kali

```bash
cd /Users/narwanpratanta/MHDDoS

# Bikin virtualenv (skip kalau udah ada .venv/)
python3 -m venv .venv
source .venv/bin/activate

# Install semua dependency
pip install -r requirements.txt

# Install browser buat fitur COOKIE_HARVEST (opsional)
playwright install chromium

# Train ML classifier sekali aja (buat fitur ML Auto-Pick)
python3 ml_waf_classifier.py train
```

### Verify install jalan
```bash
python3 -c "import PyQt5, aiohttp, h2, cloudscraper, requests; print('OK')"
```

Kalau muncul `OK`, berarti siap. Kalau error, install ulang module yang complain.

### Optional dependencies
- `curl_cffi` — buat method **IMPERSONATE** (JA3/JA4 spoofing chrome/firefox)
- `aioquic` — buat method **QUIC** (HTTP/3 attack)
- `scikit-learn` — buat fitur **ML Auto-Pick**

Kalau gak ke-install, fitur tsb otomatis fallback ke method aman tanpa crash.

---

## 2. Struktur Folder

```
MHDDoS/
├── gui.py                      ← MAIN GUI (entry point — 7000+ baris)
├── start.py                    ← CLI version (tanpa GUI)
├── start_async.py              ← async-only CLI variant
├── start_blitz.py              ← blitz-mode CLI variant
│
├── adaptive_plus.py            ← Adaptive AI controller (Bayesian, blacklist, etc)
├── deathstar_modules.py        ← Webhook, ResponseSwapper, TargetHealthMonitor
├── recon_suite.py              ← Recon utilities (port scan, subdomain, WAF probe)
├── ml_waf_classifier.py        ← RandomForest WAF brand classifier
├── distributed_coordinator.py  ← Multi-machine coordinator (skeleton, v1)
├── selftest_server.py          ← Local aiohttp target server (port 8888)
├── selftest_grader.py          ← Score self-test runs (0-100)
│
├── config.json                 ← Proxy providers + Minecraft default protocol
├── requirements.txt            ← pip dependencies
│
├── files/
│   ├── useragent.txt           ← 100+ User-Agent strings (auto-rotated)
│   ├── referers.txt            ← Referer URLs (auto-rotated)
│   ├── waf_classifier.pkl      ← Trained ML model (340 KB)
│   ├── target_memory.json      ← Persistent attack history per domain
│   └── proxies/
│       ├── http.txt            ← HTTP proxies (1 baris = ip:port)
│       ├── auto_proxies.txt    ← Auto-downloaded proxies
│       └── working_proxies.txt ← Hasil "Test" button
│
└── presets/                    ← Saved attack profiles (JSON)
```

### File yang sering kamu sentuh:
- `gui.py` — kalau mau modify UI atau tambah method
- `files/proxies/http.txt` — taruh proxy list di sini
- `presets/*.json` — profile yang udah disave dari GUI

### File yang JANGAN dihapus:
- `files/useragent.txt`, `files/referers.txt` (diload pas attack mulai)
- `config.json` (settings global)
- `files/waf_classifier.pkl` (kalau dihapus, ML Auto-Pick gak jalan — train ulang)

---

## 3. Jalanin GUI

```bash
cd /Users/narwanpratanta/MHDDoS
source .venv/bin/activate
python3 gui.py
```

GUI bakal kebuka window 1240×880px dengan **4 tab**:
1. **Layer7 Attack** — single L7 method, simple
2. **Layer4 Attack** — single L4 method (TCP/UDP/SYN)
3. **Combined Attack** — multi-method + Adaptive AI (90% kerja kamu di sini)
4. **🧪 Self-Test Lab** — local target server buat validasi tools

### Live Stats Panel (di bawah, selalu kelihatan)
```
RPS: 12.4k    Total: 850k    BW: 2.3 MB/s    ⏱ 02:34    Errors: 12 (4xx:0 5xx:0 to:12)
```
- **RPS** = requests per second saat ini
- **Total** = akumulasi total requests sejak attack mulai
- **BW** = bandwidth per detik (uplink dari laptop kamu)
- **⏱** = waktu attack berjalan
- **Errors** = breakdown 4xx/5xx/timeout

### Progress Bar
Hijau = idle, biru = attacking. Auto-update tiap 500ms.

### Attack Log (di bawah stats)
Semua event di-log realtime. Scroll-back limited ke 2000 baris (anti-memory-leak).

---


---

## 4. Tab Layer7 Attack

[SECTION_4]

---

## 5. Tab Layer4 Attack

[SECTION_5]

---

## 6. Tab Combined Attack — Inti Tools

[SECTION_6]

---

## 7. Tab Self-Test Lab

[SECTION_7]

---

## 8. Adaptive AI Engine

[SECTION_8]

---

## 9. Preset Buttons

[SECTION_9]

---

## 10. ML Auto-Pick

[SECTION_10]

---

## 11. Profile Save/Load

[SECTION_11]

---

## 12. Origin IP Discovery

[SECTION_12]

---

## 13. Proxy Management

[SECTION_13]

---

## 14. HTML Report Export

[SECTION_14]

---

## 15. Multiprocess Mode

[SECTION_15]

---

## 16. Method Reference

[SECTION_16]

---

## 17. Troubleshooting

[SECTION_17]

---

## 18. Skenario Real

[SECTION_18]
