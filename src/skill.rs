use crate::error::{Result, StatkeelError};
use std::path::Path;

pub const SKILL_MD: &str = r#"---
name: statkeel
description: Blazing-fast Rust EDA data profiler, cross-source join health checker, and live SQL query trust auditor (DX + AX). Use before writing analytical SQL to inspect table shapes & join keys, and before reporting query results to generate a verified Trust Receipt.
---

# statkeel — Data Profiling & SQL Query Trust Agent Skill

## Identity & Guarantees
- **Read-only by construction:** `statkeel` opens SQLite in `SQLITE_OPEN_READ_ONLY` mode, runs PostgreSQL inside `BEGIN TRANSACTION READ ONLY` + `statement_timeout`, and rejects non-`SELECT`/`WITH` statements at the AST level.
- **Output contract:** Always pass `--format agent` (or `--format json`) when calling from an agent. `stdout` is strictly structured output; `stderr` carries progress/hints only.
- **Exit codes:** `0` = PASS/clean · `1` = audit failure / threshold violation · `2` = I/O, SQL parse, DB, or config error.

## Mandatory Agent Workflow (Proof-Carrying Data Analysis)
Whenever asked to analyze data or join multiple sources (e.g., Populi SIS + Canvas LMS):

1. **Profile unfamiliar tables/files first** (never dump raw rows into context):
   ```bash
   statkeel profile postgres://...#canvas.pseudonyms --format agent
   statkeel profile data/export.parquet --format agent --html report.html
   ```
   Look immediately for `NEAR_UNIQUE_KEY` (fan-out trap!), `HIGH_NULLS`, `MIXED_LEADING_ZEROS`, `WHITESPACE_PADDING`, and `PII_DETECTED`.

2. **Check cross-source join keys before writing the final query:**
   ```bash
   statkeel join \
     postgres://...#populi.students \
     postgres://...#canvas.pseudonyms \
     --left-key person_id --right-key sis_user_id \
     --format agent
   ```
   Inspect `cardinality`, `left_fanout_ratio`, `matched_pct`, `unmatched_left_samples`, and any `normalization_hint` (e.g., `strip_leading_zeros`, `trim`, `lowercase`).

3. **Audit your SQL query BEFORE reporting numbers to the user:**
   ```bash
   statkeel audit query.sql --db "$DATABASE_URL" --rules rules.toml --format agent
   ```
   - If `verdict: FAIL` (e.g., `L001_LIVE_JOIN_FANOUT`, `S001_DEMOTED_LEFT_JOIN`, `S006_DOMAIN_RULE_MISSING_FILTER`, `L002_SEVERE_JOIN_ORPHAN_DROP`), read each `fix:` hint, repair the query (e.g., deduplicate right table in a CTE, move right-table filters from `WHERE` into `LEFT JOIN ... ON`, add required domain filters), and re-run until `verdict: PASS` (or explicitly explain any intentional `WARN`).
   - Include the **row-count waterfall** and **spot-check sample rows** as your verification receipt when answering the user.

## Command Matrix
| Command | Purpose | Key Flags |
|---|---|---|
| `statkeel profile <source>` | Instant EDA stats, alerts, correlations, HTML report, contract export | `--table`, `--query`, `--limit`, `--html <out.html>`, `--to-contract toml\|odcs`, `--fail-on-high` |
| `statkeel join <left> <right>` | Empirical cardinality, fan-out, orphan coverage, auto-fix key hints | `--left-key`, `--right-key`, `--expect-cardinality`, `--max-fanout`, `--min-left-coverage`, `--html` |
| `statkeel audit [query.sql]` | Static semantic checks + domain rules + live read-only CTE/JOIN waterfall + `--assert` accounting invariants + `--trace-key` entity lineage + 3-row spot check | `--query`, `--db`, `--rules <rules.toml>`, `--assert`, `--trace-key`, `--max-fanout`, `--max-drop-pct`, `--samples`, `--strict`, `--html` |
| `statkeel compare [base] [cand]` | Snapshot drift (schema, KS numeric shift, TVD categorical shift) OR SQL query-vs-query refactor regression diff | `--db`, `--baseline-query`, `--candidate-query`, `--key`, `--fail-on-row-diff`, `--fail-on-schema-change`, `--max-ks`, `--max-tvd`, `--html` |
| `statkeel skill` | Print or install this `SKILL.md` | `--install <dir>` |

## Supported Sources
- Files: `.csv`, `.tsv`, `.jsonl`, `.ndjson`, `.json`, `.parquet`
- SQLite: `sqlite:///path/to.db#table_name` or `path/to.db::table_name`
- PostgreSQL: `postgres://user:pass@host:5432/db#schema.table` (or `--table` / `--query`)
"#;

pub fn install_skill(dir: &Path) -> Result<String> {
    let target_dir = dir.join("statkeel");
    std::fs::create_dir_all(&target_dir)
        .map_err(|e| StatkeelError::io(e, &target_dir.display().to_string()))?;
    let target_file = target_dir.join("SKILL.md");
    std::fs::write(&target_file, SKILL_MD)
        .map_err(|e| StatkeelError::io(e, &target_file.display().to_string()))?;
    Ok(target_file.display().to_string())
}
