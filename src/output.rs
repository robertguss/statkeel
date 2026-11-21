use crate::audit::{AuditReport, FindingSeverity};
use crate::compare::CompareReport;
use crate::error::StatkeelError;
use crate::join::JoinReport;
use crate::profile::{AlertSeverity, DatasetProfile};
use clap::ValueEnum;
use owo_colors::OwoColorize;
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Auto,
    Human,
    Agent,
    Json,
}

impl OutputFormat {
    pub fn resolve(self) -> ResolvedFormat {
        match self {
            Self::Auto => {
                if std::io::stdout().is_terminal() {
                    ResolvedFormat::Human
                } else {
                    ResolvedFormat::Agent
                }
            }
            Self::Human => ResolvedFormat::Human,
            Self::Agent => ResolvedFormat::Agent,
            Self::Json => ResolvedFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedFormat {
    Human,
    Agent,
    Json,
}

pub fn print_error(err: &StatkeelError, fmt: ResolvedFormat) {
    match fmt {
        ResolvedFormat::Json => {
            let env = err.to_envelope();
            println!(
                "{}",
                serde_json::to_string_pretty(&env).unwrap_or_else(|_| "{}".to_string())
            );
        }
        ResolvedFormat::Agent => {
            let env = err.to_envelope();
            println!("status: ERROR");
            println!("code: {}", env.code);
            println!("message: {}", env.message);
            println!("fix_hint: {}", env.fix_hint);
            println!("retryable: {}", env.retryable);
        }
        ResolvedFormat::Human => {
            eprintln!("{} [{}] {}", "error:".red().bold(), err.code(), err);
            eprintln!("{} {}", "hint:".cyan().bold(), err.fix_hint());
        }
    }
}

pub fn print_profile(p: &DatasetProfile, fmt: ResolvedFormat) {
    match fmt {
        ResolvedFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(p).unwrap_or_else(|_| "{}".to_string())
            );
        }
        ResolvedFormat::Agent => {
            println!(
                "dataset: {} ({})\nrows: {} | cols: {} | missing: {:.2}% | duplicates: {} ({:.2}%){}",
                p.dataset,
                p.source_kind,
                p.row_count,
                p.column_count,
                p.missing_pct,
                p.duplicate_row_count,
                p.duplicate_row_pct,
                if p.sampled { " | sampled: true" } else { "" }
            );
            if !p.candidate_keys.is_empty() {
                println!("candidate_keys: [{}]", p.candidate_keys.join(", "));
            }
            if !p.alerts.is_empty() {
                println!("alerts ({}):", p.alerts.len());
                for a in p.alerts.iter().take(12) {
                    println!(
                        "  - [{:?}] {}: {} | fix: {}",
                        a.severity, a.code, a.message, a.fix_hint
                    );
                }
            }
            println!("columns:");
            for c in &p.columns {
                let mut detail = format!(
                    "type={} null={:.1}% distinct={} ({:.1}%)",
                    c.inferred_type, c.null_pct, c.distinct_count, c.unique_pct
                );
                if let Some(n) = &c.numeric {
                    detail.push_str(&format!(
                        " min={} p50={} mean={} max={}",
                        n.min, n.median, n.mean, n.max
                    ));
                } else if !c.top_values.is_empty() {
                    let top3: Vec<String> = c
                        .top_values
                        .iter()
                        .take(3)
                        .map(|v| format!("{}({:.0}%)", v.value, v.pct))
                        .collect();
                    detail.push_str(&format!(" top=[{}]", top3.join(", ")));
                }
                if !c.pii_flags.is_empty() {
                    detail.push_str(&format!(" pii=[{}]", c.pii_flags.join(",")));
                }
                println!("  - {}: {}", c.name, detail);
            }
            if !p.correlations.is_empty() {
                let top_corr: Vec<String> = p
                    .correlations
                    .iter()
                    .take(5)
                    .map(|c| format!("{}~{}:{:+.2}", c.col_a, c.col_b, c.pearson_r))
                    .collect();
                println!("top_correlations: [{}]", top_corr.join(", "));
            }
        }
        ResolvedFormat::Human => {
            println!(
                "{} {} ({})",
                "⚓ statkeel profile".cyan().bold(),
                p.dataset.bold(),
                p.source_kind
            );
            println!(
                "   Rows: {}  |  Columns: {}  |  Missing: {:.2}%  |  Duplicates: {} ({:.2}%)",
                p.row_count.to_string().bold(),
                p.column_count,
                p.missing_pct,
                p.duplicate_row_count,
                p.duplicate_row_pct
            );
            if !p.candidate_keys.is_empty() {
                println!("   Candidate keys: {}", p.candidate_keys.join(", ").green());
            }
            if !p.alerts.is_empty() {
                println!("\n{}", "Alerts:".bold());
                for a in &p.alerts {
                    let tag = match a.severity {
                        AlertSeverity::High => {
                            format!("[HIGH:{}]", a.code).red().bold().to_string()
                        }
                        AlertSeverity::Medium => {
                            format!("[WARN:{}]", a.code).yellow().bold().to_string()
                        }
                        AlertSeverity::Info => format!("[INFO:{}]", a.code).cyan().to_string(),
                    };
                    println!("  {tag} {}", a.message);
                    println!("         {} {}", "fix:".dimmed(), a.fix_hint.dimmed());
                }
            }
            println!("\n{}", "Columns:".bold());
            println!(
                "  {:<24} {:<12} {:>7} {:>9}  SUMMARY",
                "NAME", "TYPE", "NULL%", "DISTINCT"
            );
            for c in &p.columns {
                let summary = if let Some(n) = &c.numeric {
                    format!("min={} med={} max={}", n.min, n.median, n.max)
                } else {
                    c.top_values
                        .iter()
                        .take(3)
                        .map(|v| format!("{} ({:.0}%)", v.value, v.pct))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                println!(
                    "  {:<24} {:<12} {:>6.1}% {:>9}  {}",
                    c.name, c.inferred_type, c.null_pct, c.distinct_count, summary
                );
            }
        }
    }
}

pub fn print_join(r: &JoinReport, fmt: ResolvedFormat) {
    match fmt {
        ResolvedFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(r).unwrap_or_else(|_| "{}".to_string())
            );
        }
        ResolvedFormat::Agent => {
            println!(
                "status: {} | risk: {} | cardinality: {}",
                if r.ok { "PASS" } else { "FAIL" },
                r.risk_level.to_uppercase(),
                r.cardinality
            );
            println!(
                "left: {} ({}) rows={} distinct={} dup_keys={} nulls={} matched={} ({:.1}%) orphans={}",
                r.left.name,
                r.left.keys.join(","),
                r.left.total_rows,
                r.left.distinct_keys,
                r.left.duplicate_keys,
                r.left.null_keys,
                r.left.matched_rows,
                r.left.matched_pct,
                r.left.orphan_rows
            );
            println!(
                "right: {} ({}) rows={} distinct={} dup_keys={} max_mult={} nulls={} matched={} ({:.1}%) orphans={}",
                r.right.name,
                r.right.keys.join(","),
                r.right.total_rows,
                r.right.distinct_keys,
                r.right.duplicate_keys,
                r.right.max_rows_per_key,
                r.right.null_keys,
                r.right.matched_rows,
                r.right.matched_pct,
                r.right.orphan_rows
            );
            println!(
                "predicted_rows: inner={} ({:.3}x) | left={} ({:.3}x)",
                r.inner_join_rows, r.inner_fanout_ratio, r.left_join_rows, r.left_fanout_ratio
            );
            if !r.left.unmatched_samples.is_empty() {
                println!(
                    "unmatched_left_samples: [{}]",
                    r.left.unmatched_samples.join(", ")
                );
            }
            if !r.right.unmatched_samples.is_empty() {
                println!(
                    "unmatched_right_samples: [{}]",
                    r.right.unmatched_samples.join(", ")
                );
            }
            if !r.right.duplicate_samples.is_empty() {
                let ds: Vec<String> = r
                    .right
                    .duplicate_samples
                    .iter()
                    .map(|d| format!("{}({}x)", d.key, d.count))
                    .collect();
                println!("right_duplicate_samples: [{}]", ds.join(", "));
            }
            for h in &r.normalization_hints {
                println!(
                    "normalization_hint: {} (+{:.1}% -> {:.1}% coverage) | sql: {}",
                    h.transform, h.lift_pct, h.matched_left_pct_after, h.sql_hint
                );
            }
            for w in &r.warnings {
                println!("warning: {w}");
            }
            for f in &r.failures {
                println!("failure: {f}");
            }
        }
        ResolvedFormat::Human => {
            let risk_badge = match r.risk_level.as_str() {
                "high" => "HIGH RISK".red().bold().to_string(),
                "medium" => "MEDIUM RISK".yellow().bold().to_string(),
                _ => "LOW RISK".green().bold().to_string(),
            };
            println!(
                "{} {} ⋈ {}  [{}]  [{}]",
                "⚓ statkeel join".cyan().bold(),
                r.left.name.bold(),
                r.right.name.bold(),
                r.cardinality.bold(),
                risk_badge
            );
            println!(
                "   Left  ({}): {} rows | {:.1}% matched | {} orphans | {} dup keys (max {}x)",
                r.left.keys.join(","),
                r.left.total_rows,
                r.left.matched_pct,
                r.left.orphan_rows,
                r.left.duplicate_keys,
                r.left.max_rows_per_key
            );
            println!(
                "   Right ({}): {} rows | {:.1}% matched | {} orphans | {} dup keys (max {}x)",
                r.right.keys.join(","),
                r.right.total_rows,
                r.right.matched_pct,
                r.right.orphan_rows,
                r.right.duplicate_keys,
                r.right.max_rows_per_key
            );
            println!(
                "   Predicted rows: INNER = {} ({:.3}x)  |  LEFT = {} ({:.3}x)",
                r.inner_join_rows, r.inner_fanout_ratio, r.left_join_rows, r.left_fanout_ratio
            );
            if !r.normalization_hints.is_empty() {
                println!("\n{}", "Auto-Diagnosed Key Fixes:".green().bold());
                for h in &r.normalization_hints {
                    println!(
                        "  💡 {} lifts match rate +{:.1}% -> {:.1}%",
                        h.transform.bold(),
                        h.lift_pct,
                        h.matched_left_pct_after
                    );
                    println!("     SQL: {}", h.sql_hint.cyan());
                }
            }
            if !r.warnings.is_empty() {
                println!("\n{}", "Warnings:".yellow().bold());
                for w in &r.warnings {
                    println!("  ⚠ {w}");
                }
            }
            if !r.failures.is_empty() {
                println!("\n{}", "Threshold Failures:".red().bold());
                for f in &r.failures {
                    println!("  ✖ {f}");
                }
            }
        }
    }
}

pub fn print_audit(r: &AuditReport, fmt: ResolvedFormat) {
    match fmt {
        ResolvedFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(r).unwrap_or_else(|_| "{}".to_string())
            );
        }
        ResolvedFormat::Agent => {
            println!(
                "verdict: {} | ok: {} | mode: {} | final_rows: {} | high: {} | medium: {} | info: {}",
                r.verdict,
                r.ok,
                r.mode,
                r.final_row_count
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                r.high_count,
                r.medium_count,
                r.info_count
            );
            if !r.waterfall.is_empty() {
                println!("waterfall:");
                for w in &r.waterfall {
                    let delta = w.delta.map(|d| format!(" ({d:+})")).unwrap_or_default();
                    let ratio = w
                        .ratio_vs_prev
                        .map(|x| format!(" [{x:.3}x]"))
                        .unwrap_or_default();
                    let note = w
                        .note
                        .as_deref()
                        .map(|n| format!(" -- {n}"))
                        .unwrap_or_default();
                    println!("  - {}: {} rows{delta}{ratio}{note}", w.stage, w.row_count);
                }
            }
            if !r.findings.is_empty() {
                println!("findings:");
                for f in &r.findings {
                    println!(
                        "  - [{:?}:{}] {} | fix: {}",
                        f.severity, f.code, f.message, f.fix_hint
                    );
                }
            }
            if let Some(sc) = &r.spot_check
                && !sc.rows.is_empty()
            {
                println!("spot_check ({} rows):", sc.rows.len());
                println!("  columns: [{}]", sc.columns.join(", "));
                for (idx, row) in sc.rows.iter().enumerate() {
                    let vals: Vec<String> = row.iter().map(|v| v.to_string()).collect();
                    println!("  row_{}: [{}]", idx + 1, vals.join(", "));
                }
            }
        }
        ResolvedFormat::Human => {
            let verdict_styled = match r.verdict.as_str() {
                "FAIL" => "FAIL".red().bold().to_string(),
                "WARN" => "WARN".yellow().bold().to_string(),
                _ => "PASS".green().bold().to_string(),
            };
            println!(
                "{}  Verdict: [{}]  ({})",
                "⚓ statkeel audit".cyan().bold(),
                verdict_styled,
                r.mode
            );
            if let Some(cnt) = r.final_row_count {
                println!("   Final rows: {}", cnt.to_string().bold());
            }
            if !r.waterfall.is_empty() {
                println!("\n{}", "Row-Count Waterfall:".bold());
                for w in &r.waterfall {
                    let delta = w
                        .delta
                        .map(|d| format!("{d:+}"))
                        .unwrap_or_else(|| "—".to_string());
                    let ratio = w
                        .ratio_vs_prev
                        .map(|x| format!("{x:.3}x"))
                        .unwrap_or_else(|| "—".to_string());
                    let note = w.note.as_deref().unwrap_or("");
                    println!(
                        "  {:<32} {:>10} rows  {:>9}  {:>7}  {}",
                        w.stage, w.row_count, delta, ratio, note
                    );
                }
            }
            if !r.findings.is_empty() {
                println!("\n{}", "Findings:".bold());
                for f in &r.findings {
                    let tag = match f.severity {
                        FindingSeverity::High => {
                            format!("[HIGH:{}]", f.code).red().bold().to_string()
                        }
                        FindingSeverity::Medium => {
                            format!("[WARN:{}]", f.code).yellow().bold().to_string()
                        }
                        FindingSeverity::Info => format!("[INFO:{}]", f.code).cyan().to_string(),
                    };
                    println!("  {tag} {}", f.message);
                    println!("         {} {}", "fix:".dimmed(), f.fix_hint.dimmed());
                }
            }
            if let Some(sc) = &r.spot_check
                && !sc.rows.is_empty()
            {
                println!("\n{}", "Spot-Check Sample Rows:".bold());
                println!("  {}", sc.columns.join(" | ").dimmed());
                for row in &sc.rows {
                    let vals: Vec<String> = row
                        .iter()
                        .map(|v| match v {
                            serde_json::Value::Null => "NULL".to_string(),
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .collect();
                    println!("  {}", vals.join(" | "));
                }
            }
        }
    }
}

pub fn print_compare(r: &CompareReport, fmt: ResolvedFormat) {
    match fmt {
        ResolvedFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(r).unwrap_or_else(|_| "{}".to_string())
            );
        }
        ResolvedFormat::Agent => {
            let pct_s = r
                .row_delta_pct
                .map(|p| format!(" ({p:+.2}%)"))
                .unwrap_or_default();
            println!(
                "verdict: {} | ok: {} | baseline: {} ({} rows) | candidate: {} ({} rows) | row_delta: {:+}{pct_s}",
                r.verdict,
                r.ok,
                r.baseline_name,
                r.baseline_rows,
                r.candidate_name,
                r.candidate_rows,
                r.row_delta
            );
            println!(
                "schema: +{} added -{} removed ~{} type_changes | missing_delta: {:+.2}% | max_ks: {:.4} | max_tvd: {:.4}",
                r.added_columns.len(),
                r.removed_columns.len(),
                r.type_changes.len(),
                r.missing_pct_delta,
                r.max_ks,
                r.max_tvd
            );
            if !r.added_columns.is_empty() {
                println!("added_columns: [{}]", r.added_columns.join(", "));
            }
            if !r.removed_columns.is_empty() {
                println!("removed_columns: [{}]", r.removed_columns.join(", "));
            }
            if let Some(kd) = &r.key_diff {
                println!(
                    "key_diff ({}): +{} added | -{} removed | ~{} changed | {} unchanged",
                    kd.keys.join(","),
                    kd.added_keys_count,
                    kd.removed_keys_count,
                    kd.changed_rows,
                    kd.unchanged_rows
                );
                if !kd.added_key_samples.is_empty() {
                    println!("  added_keys: [{}]", kd.added_key_samples.join(", "));
                }
                if !kd.removed_key_samples.is_empty() {
                    println!("  removed_keys: [{}]", kd.removed_key_samples.join(", "));
                }
                for s in &kd.cell_diff_samples {
                    println!(
                        "  diff [key={} col={}]: {} -> {}",
                        s.key, s.column, s.baseline, s.candidate
                    );
                }
            }
            if !r.alerts.is_empty() {
                println!("alerts ({}):", r.alerts.len());
                for a in r.alerts.iter().take(12) {
                    println!(
                        "  - [{}:{}] {} | fix: {}",
                        a.severity.to_uppercase(),
                        a.code,
                        a.message,
                        a.fix_hint
                    );
                }
            }
            for f in &r.failures {
                println!("failure: {f}");
            }
        }
        ResolvedFormat::Human => {
            let badge = match r.verdict.as_str() {
                "FAIL" => "FAIL".red().bold().to_string(),
                "DRIFT_DETECTED" => "DRIFT_DETECTED".red().bold().to_string(),
                "LOW_DRIFT" => "LOW_DRIFT".yellow().bold().to_string(),
                _ => "IDENTICAL".green().bold().to_string(),
            };
            println!(
                "{} {} vs {}  [{}]",
                "⚓ statkeel compare".cyan().bold(),
                r.baseline_name.bold(),
                r.candidate_name.bold(),
                badge
            );
            let pct_s = r
                .row_delta_pct
                .map(|p| format!(" ({p:+.2}%)"))
                .unwrap_or_default();
            println!(
                "   Rows: {} -> {} ({:+}{pct_s})  |  Missing Δ: {:+.2}%  |  Max KS: {:.3}  |  Max TVD: {:.3}",
                r.baseline_rows,
                r.candidate_rows,
                r.row_delta,
                r.missing_pct_delta,
                r.max_ks,
                r.max_tvd
            );
            if !r.added_columns.is_empty() || !r.removed_columns.is_empty() {
                println!(
                    "   Schema: +[{}]  -[{}]",
                    r.added_columns.join(", "),
                    r.removed_columns.join(", ")
                );
            }
            if let Some(kd) = &r.key_diff {
                println!(
                    "\n{} ({}): +{} added | -{} removed | ~{} changed | {} unchanged",
                    "Key Diff".bold(),
                    kd.keys.join(", "),
                    kd.added_keys_count,
                    kd.removed_keys_count,
                    kd.changed_rows,
                    kd.unchanged_rows
                );
                for s in &kd.cell_diff_samples {
                    println!(
                        "  key={}  {} : {} -> {}",
                        s.key.cyan(),
                        s.column.bold(),
                        s.baseline.dimmed(),
                        s.candidate
                    );
                }
            }
            if !r.alerts.is_empty() {
                println!("\n{}", "Drift Alerts:".bold());
                for a in &r.alerts {
                    let tag = match a.severity.as_str() {
                        "high" => format!("[HIGH:{}]", a.code).red().bold().to_string(),
                        "medium" => format!("[WARN:{}]", a.code).yellow().bold().to_string(),
                        _ => format!("[INFO:{}]", a.code).cyan().to_string(),
                    };
                    println!("  {tag} {}", a.message);
                }
            }
            if !r.failures.is_empty() {
                println!("\n{}", "Threshold Failures:".red().bold());
                for f in &r.failures {
                    println!("  ✖ {f}");
                }
            }
        }
    }
}
