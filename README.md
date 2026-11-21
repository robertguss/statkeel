# ⚓ statkeel

[![CI](https://github.com/robertguss/statkeel/actions/workflows/ci.yml/badge.svg)](https://github.com/robertguss/statkeel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/robertguss/statkeel)](https://github.com/robertguss/statkeel/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Blazing-fast, single-binary Rust EDA data profiler, cross-source join health checker, and live SQL query trust auditor — built for both Humans (DX) and AI Agents (AX).**

Part of the **Keel Data Stack** (`datakeel` · `sqlkeel` · `loadkeel` · `fetchkeel` · `runkeel` · `dapkeel` · **`statkeel`**).

---

## Why `statkeel`?

1. **Instant `ydata-profiling` (`pandas-profiling`) replacement (`statkeel profile`):** Profile CSV, TSV, JSON/JSONL, Parquet, SQLite, or PostgreSQL tables in milliseconds — zero Python/Pandas/matplotlib dependency tree. Emits a **zero-dependency self-contained interactive HTML report** (inline SVG histograms, categorical charts, correlation table, dark/light toggle) **and** a compact `--format agent` statistical brief.
2. **Cross-Source Join Health & Auto-Diagnosis (`statkeel join`):** Before joining two systems (e.g., Populi SIS ↔ Canvas LMS), empirically measure cardinality (`1:1`, `1:N`, `N:1`, `M:N`), exact fan-out multipliers, orphan coverage, and sample unmatched keys — plus automatic normalization probing (*"stripping leading zeros lifts match rate +84.2%"*).
3. **Proof-Carrying AI SQL Queries (`statkeel audit`):** Stop guessing whether an AI-written analytical query silently multiplied rows or dropped 25% of your cohort. `statkeel audit` runs **static semantic traps** + **configurable domain guardrails** + a **live read-only CTE/JOIN row-count waterfall** + **3-row spot-check receipts** so both you and your AI agent get verifiable proof before trusting any number.

---

## Quick Start

### Install
```bash
# From GitHub Releases (prebuilt binaries & Python wheels) or cargo:
cargo install --git https://github.com/robertguss/statkeel
```

### 1. Profile any file or Postgres table
```bash
# Generate an offline interactive HTML report + human summary
statkeel profile data/students.parquet --html profile.html

# Token-budgeted brief for AI agents
statkeel profile postgres://user:pass@localhost/lake#canvas.pseudonyms --format agent

# Infer a datakeel.toml or ODCS v3.2.0 YAML contract directly from real data
statkeel profile data/students.csv --to-contract odcs
```

### 2. Check cross-source join health
```bash
statkeel join \
  postgres://user:pass@localhost/lake#populi.students \
  postgres://user:pass@localhost/lake#canvas.pseudonyms \
  --left-key person_id \
  --right-key sis_user_id \
  --max-fanout 1.0 \
  --min-left-coverage 95 \
  --html join-report.html
```

### 3. Audit an AI-written SQL query (strictly read-only!)
```bash
statkeel audit query.sql \
  --db "$DATABASE_URL" \
  --rules examples/populi-canvas-rules.toml \
  --html trust-receipt.html
```

Example output:
```text
⚓ statkeel audit  Verdict: [FAIL]  (live+static)
   Final rows: 1289

Row-Count Waterfall:
  base:populi.students                   1240 rows          —        —
  LEFT JOIN canvas.pseudonyms            1289 rows        +49   1.040x  FAN-OUT +49 (1.040x)
  after:WHERE                            1102 rows       -187   0.855x  -14.5% filtered
  final:output                           1102 rows         +0   1.000x

Findings:
  [HIGH:S001_DEMOTED_LEFT_JOIN] WHERE clause filters LEFT JOIN table `canvas.pseudonyms` ...
  [HIGH:L001_LIVE_JOIN_FANOUT]  `LEFT JOIN canvas.pseudonyms` multiplied rows 1240 -> 1289 ...
```

### 4. Install the bundled Agent Skill
```bash
statkeel skill --install .agents/skills
```

---

## Safety Guarantees
- **Strictly read-only:** SQLite opens with `SQLITE_OPEN_READ_ONLY`; PostgreSQL always executes inside `BEGIN TRANSACTION READ ONLY` with `SET LOCAL statement_timeout`; `audit` rejects any non-`SELECT`/`WITH` SQL at the AST level (`E_UNSAFE_SQL`).
- **Clean exit codes:** `0` = pass · `1` = audit failure / threshold violation · `2` = I/O, SQL parse, DB, or config error.

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
