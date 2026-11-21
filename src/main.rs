mod audit;
mod compare;
mod error;
mod html;
mod join;
mod output;
mod profile;
mod skill;
mod source;
mod trust;

use crate::audit::{AuditOptions, audit_query};
use crate::compare::{CompareOptions, compare_tables};
use crate::error::{Result, StatkeelError};
use crate::join::{JoinThresholds, analyze_join};
use crate::output::{
    OutputFormat, ResolvedFormat, print_audit, print_compare, print_error, print_join,
    print_profile,
};
use crate::profile::{AlertSeverity, export_contract, profile_table};
use crate::source::{LoadOptions, load_source};
use clap::{Parser, Subcommand};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "statkeel",
    version,
    about = "Blazing-fast, agent-first (DX + AX) Rust EDA data profiler, cross-source join checker, and live SQL query trust auditor."
)]
struct Cli {
    /// Output format: auto (human on TTY, agent when piped), human, agent, or json.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Auto)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Profile a CSV, Parquet, JSONL, SQLite, or PostgreSQL dataset (EDA stats + HTML + agent brief).
    Profile {
        /// File path (.csv, .tsv, .jsonl, .json, .parquet), sqlite:///db#table, or postgres://...#schema.table
        source: String,
        /// Optional table name for SQLite/PostgreSQL sources when not using `#table`.
        #[arg(long)]
        table: Option<String>,
        /// Optional read-only SQL SELECT query for SQLite/PostgreSQL sources.
        #[arg(long)]
        query: Option<String>,
        /// Cap maximum rows read (useful for very large tables).
        #[arg(long)]
        limit: Option<usize>,
        /// Statement timeout in seconds for PostgreSQL sources.
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Write a self-contained offline interactive HTML report to this path.
        #[arg(long)]
        html: Option<PathBuf>,
        /// Export an inferred data contract (`toml` for datakeel, `odcs` for ODCS v3.2.0 YAML) to stdout or --contract-out.
        #[arg(long)]
        to_contract: Option<String>,
        /// Destination file for --to-contract (defaults to stdout when omitted).
        #[arg(long)]
        contract_out: Option<PathBuf>,
        /// Exit with code 1 if any HIGH-severity data quality alert is found.
        #[arg(long)]
        fail_on_high: bool,
    },

    /// Analyze cross-source join cardinality, fan-out, orphan coverage, and key normalization fixes.
    Join {
        /// Left source (file, sqlite:///db#table, or postgres://...#schema.table).
        left: String,
        /// Right source (file, sqlite:///db#table, or postgres://...#schema.table).
        right: String,
        /// Comma-separated left join key column(s).
        #[arg(long)]
        left_key: String,
        /// Comma-separated right join key column(s).
        #[arg(long)]
        right_key: String,
        /// Optional table name for left DB source.
        #[arg(long)]
        left_table: Option<String>,
        /// Optional table name for right DB source.
        #[arg(long)]
        right_table: Option<String>,
        /// Optional row cap per side.
        #[arg(long)]
        limit: Option<usize>,
        /// Fail (exit 1) unless empirical cardinality matches (1:1, 1:N, N:1, M:N).
        #[arg(long)]
        expect_cardinality: Option<String>,
        /// Fail (exit 1) if LEFT JOIN fan-out ratio exceeds this value (e.g. 1.0).
        #[arg(long)]
        max_fanout: Option<f64>,
        /// Fail (exit 1) if left match coverage percentage is below this threshold (e.g. 95.0).
        #[arg(long)]
        min_left_coverage: Option<f64>,
        /// Write a self-contained HTML join health report.
        #[arg(long)]
        html: Option<PathBuf>,
    },

    /// Audit an analytical SQL query (static semantic checks + domain rules + live read-only waterfall & spot-check).
    Audit {
        /// Path to a .sql file (or `-` to read from stdin). Omit when passing --query.
        sql_file: Option<String>,
        /// Inline SQL SELECT / WITH query string.
        #[arg(long)]
        query: Option<String>,
        /// Optional read-only database URL (postgres://... or sqlite:///path.db) for live waterfall & spot-check.
        #[arg(long, env = "DATABASE_URL")]
        db: Option<String>,
        /// Optional TOML file defining table-level domain guardrails (required filters).
        #[arg(long)]
        rules: Option<String>,
        /// Maximum tolerated join row-multiplication ratio before flagging L001 (default 1.0).
        #[arg(long, default_value_t = 1.0)]
        max_fanout: f64,
        /// Maximum tolerated INNER JOIN orphan drop percentage before flagging L002 (default 20.0).
        #[arg(long, default_value_t = 20.0)]
        max_drop_pct: f64,
        /// Number of concrete spot-check rows to sample from the query result (default 3).
        #[arg(long, default_value_t = 3)]
        samples: usize,
        /// Statement timeout in seconds for live PostgreSQL probes (default 15).
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,
        /// Treat WARN findings as exit code 1 as well.
        #[arg(long)]
        strict: bool,
        /// Repeatable accounting invariant assertion (e.g. `unique(person_id)`, `final_rows == base_rows`, `sum(credits) <= 50000`).
        #[arg(long = "assert")]
        assertions: Vec<String>,
        /// Entity key column to trace end-to-end from base table to final output (typical, fan-out, and dropped rows).
        #[arg(long)]
        trace_key: Option<String>,
        /// Write a self-contained HTML Query Trust Receipt.
        #[arg(long)]
        html: Option<PathBuf>,
    },

    /// Compare two datasets or two SQL queries for schema, distribution (KS/TVD), and key-level row drift.
    Compare {
        /// Baseline source (file, sqlite:///db#table, or postgres://...#schema.table). Omit when using --db + --baseline-query.
        baseline: Option<String>,
        /// Candidate source (file, sqlite:///db#table, or postgres://...#schema.table). Omit when using --db + --candidate-query.
        candidate: Option<String>,
        /// Shared read-only DB URL (postgres://... or sqlite:///path.db) for comparing --baseline-query vs --candidate-query.
        #[arg(long, env = "DATABASE_URL")]
        db: Option<String>,
        /// Baseline SQL query (inline SELECT/WITH or path to a .sql file) run against --db.
        #[arg(long)]
        baseline_query: Option<String>,
        /// Candidate SQL query (inline SELECT/WITH or path to a .sql file) run against --db.
        #[arg(long)]
        candidate_query: Option<String>,
        /// Optional table name for baseline DB source.
        #[arg(long)]
        baseline_table: Option<String>,
        /// Optional table name for candidate DB source.
        #[arg(long)]
        candidate_table: Option<String>,
        /// Comma-separated primary key column(s) for exact row-level & cell-level diffing.
        #[arg(long)]
        key: Option<String>,
        /// Cap maximum rows read per side.
        #[arg(long)]
        limit: Option<usize>,
        /// Statement timeout in seconds for PostgreSQL queries (default 30).
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Fail (exit 1) if any column was added, removed, or changed type.
        #[arg(long)]
        fail_on_schema_change: bool,
        /// Fail (exit 1) if absolute row-count change % exceeds this limit.
        #[arg(long)]
        max_row_delta_pct: Option<f64>,
        /// Fail (exit 1) if max numeric Kolmogorov-Smirnov statistic exceeds this limit (0.0..1.0).
        #[arg(long)]
        max_ks: Option<f64>,
        /// Fail (exit 1) if max categorical Total Variation Distance exceeds this limit (0.0..1.0).
        #[arg(long)]
        max_tvd: Option<f64>,
        /// Fail (exit 1) if any row was added, removed, or changed under --key (ideal for SQL refactor tests).
        #[arg(long)]
        fail_on_row_diff: bool,
        /// Write a self-contained offline HTML comparison dashboard.
        #[arg(long)]
        html: Option<PathBuf>,
    },

    /// Print or install the bundled SKILL.md manual for AI coding & data agents.
    Skill {
        /// Install SKILL.md into `<dir>/statkeel/SKILL.md`.
        #[arg(long)]
        install: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let fmt = cli.format.resolve();

    match run(cli.command, fmt) {
        Ok(code) => code,
        Err(err) => {
            print_error(&err, fmt);
            ExitCode::from(2)
        }
    }
}

fn run(cmd: Commands, fmt: ResolvedFormat) -> Result<ExitCode> {
    match cmd {
        Commands::Profile {
            source,
            table,
            query,
            limit,
            timeout_secs,
            html: html_out,
            to_contract,
            contract_out,
            fail_on_high,
        } => {
            let opts = LoadOptions::with_defaults(table, query, limit, timeout_secs);
            let data = load_source(&source, &opts)?;
            let prof = profile_table(&data);

            if let Some(html_path) = html_out {
                let rendered = html::render_profile_html(&prof);
                std::fs::write(&html_path, rendered)
                    .map_err(|e| StatkeelError::io(e, &html_path.display().to_string()))?;
                eprintln!("Wrote HTML profile report to {}", html_path.display());
            }

            if let Some(contract_fmt) = to_contract {
                let rendered = export_contract(&prof, &contract_fmt);
                if let Some(out_path) = contract_out {
                    std::fs::write(&out_path, rendered)
                        .map_err(|e| StatkeelError::io(e, &out_path.display().to_string()))?;
                    eprintln!("Wrote contract to {}", out_path.display());
                    print_profile(&prof, fmt);
                } else {
                    print!("{rendered}");
                }
            } else {
                print_profile(&prof, fmt);
            }

            if fail_on_high
                && prof
                    .alerts
                    .iter()
                    .any(|a| a.severity == AlertSeverity::High)
            {
                return Ok(ExitCode::from(1));
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Join {
            left,
            right,
            left_key,
            right_key,
            left_table,
            right_table,
            limit,
            expect_cardinality,
            max_fanout,
            min_left_coverage,
            html: html_out,
        } => {
            let l_opts = LoadOptions::with_defaults(left_table, None, limit, 30);
            let r_opts = LoadOptions::with_defaults(right_table, None, limit, 30);
            let l_data = load_source(&left, &l_opts)?;
            let r_data = load_source(&right, &r_opts)?;

            let l_keys: Vec<String> = left_key
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let r_keys: Vec<String> = right_key
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let thresholds = JoinThresholds {
                expect_cardinality,
                max_fanout,
                min_left_coverage,
            };
            let report = analyze_join(&l_data, &l_keys, &r_data, &r_keys, &thresholds)?;

            if let Some(html_path) = html_out {
                let rendered = html::render_join_html(&report);
                std::fs::write(&html_path, rendered)
                    .map_err(|e| StatkeelError::io(e, &html_path.display().to_string()))?;
                eprintln!("Wrote HTML join report to {}", html_path.display());
            }

            print_join(&report, fmt);
            Ok(if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }

        Commands::Audit {
            sql_file,
            query,
            db,
            rules,
            max_fanout,
            max_drop_pct,
            samples,
            timeout_secs,
            strict,
            assertions,
            trace_key,
            html: html_out,
        } => {
            let sql_raw = if let Some(q) = query {
                q
            } else if let Some(path) = sql_file {
                if path == "-" {
                    let mut buf = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buf)
                        .map_err(|e| StatkeelError::io(e, "stdin"))?;
                    buf
                } else {
                    std::fs::read_to_string(&path).map_err(|e| StatkeelError::io(e, &path))?
                }
            } else {
                return Err(StatkeelError::config(
                    "Provide either a SQL file path or `--query \"SELECT ...\"`",
                    "Example: `statkeel audit query.sql --db \"$DATABASE_URL\"`",
                ));
            };

            let opts = AuditOptions {
                db,
                rules_path: rules,
                max_fanout,
                max_drop_pct,
                samples,
                timeout_secs,
                strict,
                assertions,
                trace_key,
            };
            let report = audit_query(&sql_raw, &opts)?;

            if let Some(html_path) = html_out {
                let rendered = html::render_audit_html(&report);
                std::fs::write(&html_path, rendered)
                    .map_err(|e| StatkeelError::io(e, &html_path.display().to_string()))?;
                eprintln!("Wrote HTML Query Trust Receipt to {}", html_path.display());
            }

            print_audit(&report, fmt);
            Ok(if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }

        Commands::Compare {
            baseline,
            candidate,
            db,
            baseline_query,
            candidate_query,
            baseline_table,
            candidate_table,
            key,
            limit,
            timeout_secs,
            fail_on_schema_change,
            max_row_delta_pct,
            max_ks,
            max_tvd,
            fail_on_row_diff,
            html: html_out,
        } => {
            let (mut base_data, mut cand_data) = if let (Some(bq_spec), Some(cq_spec)) =
                (baseline_query, candidate_query)
            {
                let db_url = db.ok_or_else(|| {
                        StatkeelError::config(
                            "`--baseline-query` and `--candidate-query` require `--db` (or `DATABASE_URL`)",
                            "Pass `--db postgres://...` or `--db sqlite:///path.db`.",
                        )
                    })?;
                let bq = load_sql_or_inline(&bq_spec)?;
                let cq = load_sql_or_inline(&cq_spec)?;
                let b_opts = LoadOptions::with_defaults(None, Some(bq), limit, timeout_secs);
                let c_opts = LoadOptions::with_defaults(None, Some(cq), limit, timeout_secs);
                let mut bd = load_source(&db_url, &b_opts)?;
                let mut cd = load_source(&db_url, &c_opts)?;
                bd.name = short_query_label(&bq_spec, "baseline_query");
                cd.name = short_query_label(&cq_spec, "candidate_query");
                (bd, cd)
            } else if let (Some(b_src), Some(c_src)) = (baseline, candidate) {
                let b_opts = LoadOptions::with_defaults(baseline_table, None, limit, timeout_secs);
                let c_opts = LoadOptions::with_defaults(candidate_table, None, limit, timeout_secs);
                (load_source(&b_src, &b_opts)?, load_source(&c_src, &c_opts)?)
            } else {
                return Err(StatkeelError::config(
                    "Provide either `<baseline> <candidate>` sources OR `--db` with `--baseline-query` and `--candidate-query`",
                    "Example: `statkeel compare fall25.csv fall26.csv --key student_id`",
                ));
            };

            if base_data.name == cand_data.name {
                base_data.name = format!("{} (baseline)", base_data.name);
                cand_data.name = format!("{} (candidate)", cand_data.name);
            }

            let keys: Vec<String> = key
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let opts = CompareOptions {
                keys,
                fail_on_schema_change,
                max_row_delta_pct,
                max_ks,
                max_tvd,
                fail_on_row_diff,
            };
            let report = compare_tables(&base_data, &cand_data, &opts)?;

            if let Some(html_path) = html_out {
                let rendered = html::render_compare_html(&report);
                std::fs::write(&html_path, rendered)
                    .map_err(|e| StatkeelError::io(e, &html_path.display().to_string()))?;
                eprintln!("Wrote HTML comparison report to {}", html_path.display());
            }

            print_compare(&report, fmt);
            Ok(if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }

        Commands::Skill { install } => {
            if let Some(dir) = install {
                let path = skill::install_skill(&dir)?;
                match fmt {
                    ResolvedFormat::Json => {
                        println!("{}", serde_json::json!({ "ok": true, "installed": path }));
                    }
                    _ => println!("Installed statkeel SKILL.md -> {path}"),
                }
            } else {
                print!("{}", skill::SKILL_MD);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn load_sql_or_inline(spec: &str) -> Result<String> {
    let p = std::path::Path::new(spec);
    if p.exists() && p.is_file() {
        std::fs::read_to_string(p).map_err(|e| StatkeelError::io(e, spec))
    } else {
        Ok(spec.to_string())
    }
}

fn short_query_label(spec: &str, fallback: &str) -> String {
    let p = std::path::Path::new(spec);
    if p.exists()
        && let Some(name) = p.file_name().and_then(|s| s.to_str())
    {
        return name.to_string();
    }
    fallback.to_string()
}
