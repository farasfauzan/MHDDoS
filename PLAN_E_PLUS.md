# Plan E+ — Death Star Edition Roadmap

**Goal:** Self-Test Lab + 2-node distributed + recon suite + ML fingerprinting.
**Estimasi:** 5-7 sesi panjang, ~3000 baris code total.
**Status sesi ini:** Fase 1 dimulai (Self-Test Lab).

---

## Fase 1 — 🧪 Self-Test Lab (sesi sekarang)

**Output file:** `selftest_server.py` + tab GUI baru.

### Komponen:
1. **Local target server** — aiohttp di `localhost:8888`. Endpoints:
   - `/` — landing, fast response.
   - `/api/heavy` — CPU-bound (sleep 100ms simulating DB query).
   - `/api/protected` — rate-limited (50 req/s/IP, return 429 after).
   - `/admin` — selalu 403 (simulate WAF block).
   - `/health` — instan, untuk probe.
2. **Stats endpoint** — `/__stats__` returns JSON `{rps, p50_ms, p99_ms, errors_total, mem_mb, cpu_pct}`.
3. **Live latency tracking** — server-side tracks per-request latency, exposed via stats.
4. **GUI tab "🧪 Self-Test"** — tombol "Spawn Server" + "Stop Server" + indicator status hijau/merah.
5. **Auto-target field** — saat server hidup, tombol "Attack Localhost" auto-set URL ke `http://localhost:8888/api/heavy` di Combined tab.

### Acceptance criteria sesi ini:
- [x] Plan doc dibuat
- [x] `selftest_server.py` jalan, listen di 8888, log request count
- [x] GUI tab spawn server via subprocess.Popen, kill on stop
- [x] User bisa attack localhost → lihat server log mounting RPS
- [x] py_compile clean
- [x] **BONUS**: Health-check loop setelah spawn (10×200ms /health probe, deteksi crash)
- [x] **BONUS**: Live stats panel di tab (poll /__stats__ tiap 1s — RPS/Total/Errors/p50/p99/CPU/Mem)
- [x] **BONUS**: closeEvent auto-cleanup (kill server proc + multiprocess workers + clear attack event)
- [x] **BONUS**: Port spinner disabled saat running (prevent UI race)
- [x] End-to-end smoke test passed: spawn→health→stats→terminate ≤0.1s graceful

### Out-of-scope (pindah ke fase berikutnya):
- Live latency graph (Fase 2 — matplotlib embed)
- Auto-grader scoring (Fase 3)
- Comparison mode per-method (Fase 4)

---

## Fase 2 — 📊 Live Visualization ✅ DONE
- [x] Matplotlib FigureCanvasQTAgg embed di Self-Test tab
- [x] 3 subplots: RPS line+fill, latency p50+p99, CPU%+Mem MB
- [x] 60-sample rolling deque history (60s window @ 1Hz)
- [x] Render tiap stats poll (cheap ~10ms via draw_idle)
- [x] Lazy import — kalau matplotlib gak ada, charts skip silent
- [x] Verifikasi: py_compile clean, 7 selftest methods present, headless render 24KB PNG OK
- [ ] Replay-able session log (out of scope — moved to Fase 3 if needed)

## Fase 3 — 🏆 Auto-Grader & Comparison ✅ DONE
- [x] selftest_grader.py — score 0-100 per attack run (40% RPS + 25% latency + 20% CPU + 15% errors)
- [x] grade_run() — converts /__stats__ snapshots → score + verdict (DEVASTATING/HEAVY/MODERATE/LIGHT/INEFFECTIVE)
- [x] fetch_stats() + reset_stats() helpers — standalone, no Qt deps
- [x] build_html_report() — self-contained HTML with inline SVG bar chart
- [x] GUI: "📊 Grade Last Run" button — scores last 60s of polled history
- [x] GUI: "🏆 Save HTML Report" button — exports report via QFileDialog
- [x] Color-coded verdict label in tab (red >=80, orange >=60, yellow >=40, blue <40)
- [x] Verifikasi: py_compile clean, 9 selftest methods present, smoke-tested score=99.6 + 2990B HTML
- [ ] Sweep multi-method (run all 45 methods sequentially) — moved to Fase 3.5 if needed

## Fase 4 — 🌐 2-Node Distributed Coordinator ✅ DONE (v1)
- [x] distributed_coordinator.py — aiohttp-based (HTTP, not gRPC — simpler, same dep stack)
- [x] CoordState class — workers dict + per-node stats deque (60-sample rolling)
- [x] 6 endpoints: GET / (HTML dashboard), POST /register, POST /stats, POST /command, GET /aggregate, GET /workers
- [x] Live HTML dashboard with auto-refresh JS (1.5s interval, summary cards + worker table)
- [x] Worker CLI mode — simulated stats pusher for testing infra (real attack worker = v2)
- [x] Smoke test passed: 2 workers × 5s → total_rps=340 (correctly aggregated 120+220), total_bytes=204KB/s, both alive
- [ ] Real attack worker integration with gui.py AttackThread (v2 — out of Fase 4 scope)
- [ ] SSH auto-deploy to VPS (v2)

## Fase 5 — 🎯 Recon Suite ✅ DONE
- [x] recon_suite.py — standalone module + CLI (no Qt deps)
- [x] Subdomain enumerator via crt.sh (free, no API key, ~50-500 subs typical)
- [x] Concurrent DNS resolver (30 workers, 1.5s timeout)
- [x] Origin IP discovery — Cloudflare prefix detection + Host-header probe verification
- [x] Endpoint fuzzer — 56 default paths (admin/api/.env/.git/swagger/etc), concurrent (20 workers)
- [x] HTML report generator — 5-card summary + 3 tables (origin/subs/fuzzer hits)
- [x] CLI flags: --subs / --origin / --fuzz / --report path / --max-subs N
- [x] Verifikasi: py_compile clean, smoke test 5-path fuzz on google.com → 0.9s, 2 hits (200) + 3 misses (404)
- [ ] Tech stack deep fingerprint (existing in gui.py ScanThread already covers this)
- [ ] PDF report (out of scope — HTML covers the use case)

## Fase 6 — 🤖 ML Fingerprinting Classifier ✅ DONE
- [x] ml_waf_classifier.py — sklearn RandomForest, 16 features, 10 classes, ~250 LoC
- [x] 16-dim feature extraction (cf-ray, x-amz-cf-id, x-akamai, x-sucuri-id, x-iinfo, x-fastly, x-vercel-id, ddg, modsec, server family, body keywords)
- [x] Hardcoded training data: 69 samples × 10 classes (no external dataset needed)
- [x] RandomForest 100 estimators, max_depth=8, class_weight=balanced
- [x] 5-fold CV: **98.5% accuracy ± 3.1%** stdev
- [x] Save/load via pickle to `files/waf_classifier.pkl`
- [x] Confidence threshold (default 0.65) → "uncertain" fallback when below
- [x] 11 method playbooks (cloudflare/ddos_guard/akamai/sucuri/imperva/fastly/vercel/aws_cf/wordfence/modsec/none/uncertain)
- [x] CLI: train / predict <url> / playbook <waf>
- [x] End-to-end smoke test: cloudflare.com → cloudflare 83.1% conf ✓, github.com → uncertain 45.2% (correctly below threshold)

---

## Risk & Tradeoff

| Risk | Mitigation |
|---|---|
| Localhost attack jadi over-reliance, user lupa physics gap | Kasih banner di Self-Test tab: "Hasil disini gak translate ke target ber-WAF" |
| 2-node distributed = user butuh VPS = biaya | Kasih cost estimator + docker-compose untuk testing local 2-process |
| ML classifier overfit ke training data terbatas | Cross-validation + minimum confidence threshold |
| Banyak fitur nambah → maintenance burden | Tiap fase wajib lulus py_compile + smoke test sebelum lanjut |

---

## Acceptance overall
- Tiap sesi end-state: kode compile, GUI bisa run, fitur fase ke-X berfungsi standalone.
- README updated tiap fase.
- Tiap fase commit terpisah supaya bisa rollback.
