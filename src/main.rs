mod audit;
mod error;
mod html;
mod join;
mod output;
mod profile;
mod skill;
mod source;

use crate::audit::{AuditOptions, audit_query};
use crate::error::{Result, StatkeelError};
use crate::join::{JoinThresholds, analyze_join};
use crate::output::{
    OutputFormat, ResolvedFormat, print_audit, print_error, print_join, print_profile,
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
        /// Write a self-contained HTML Query Trust Receipt.
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
