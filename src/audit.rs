use crate::error::{Result, StatkeelError};
use crate::source::{CellValue, connect_postgres, split_sqlite_spec};
use crate::trust::{
    AssertionResult, EntityTrace, run_assertions_postgres, run_assertions_sqlite,
    trace_entities_postgres, trace_entities_sqlite,
};
use indexmap::IndexMap;
use postgres::Client as PgClient;
use rusqlite::{Connection as SqliteConn, OpenFlags, types::ValueRef};
use serde::{Deserialize, Serialize};
use sqlparser::ast::{
    BinaryOperator, Distinct, Expr, InTarget, Join, JoinConstraint, JoinOperator, Query, Select,
    SetExpr, Statement, TableFactor,
};
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;
use std::collections::HashSet;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuditRulesFile {
    #[serde(default)]
    pub table_rules: Vec<TableRule>,
    #[serde(default)]
    pub assertions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TableRule {
    pub table: String,
    #[serde(default)]
    pub required_filters: Vec<String>,
    #[serde(default = "default_high")]
    pub severity: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub fix_hint: String,
}

fn default_high() -> String {
    "high".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    High,
    Medium,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub code: String,
    pub category: String, // "static" | "live" | "domain_rule"
    pub severity: FindingSeverity,
    pub message: String,
    pub fix_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WaterfallStep {
    pub stage: String,
    pub kind: String, // "cte" | "base" | "join" | "where" | "final"
    pub row_count: i64,
    pub delta: Option<i64>,
    pub ratio_vs_prev: Option<f64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveJoinDiag {
    pub join_label: String,
    pub join_type: String,
    pub condition: String,
    pub left_rows: i64,
    pub joined_rows: i64,
    pub fanout_ratio: f64,
    pub right_duplicate_keys: i64,
    pub right_max_rows_per_key: i64,
    pub left_matched_pct: Option<f64>,
    pub unmatched_left_samples: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpotCheckSample {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub ok: bool,
    pub verdict: String, // "PASS" | "WARN" | "FAIL"
    pub mode: String,    // "live+static" | "static-only"
    pub db_engine: Option<String>,
    pub query_preview: String,
    pub final_row_count: Option<i64>,
    pub high_count: usize,
    pub medium_count: usize,
    pub info_count: usize,
    pub findings: Vec<AuditFinding>,
    pub waterfall: Vec<WaterfallStep>,
    pub join_diagnostics: Vec<LiveJoinDiag>,
    pub assertions: Vec<AssertionResult>,
    pub entity_traces: Vec<EntityTrace>,
    pub spot_check: Option<SpotCheckSample>,
}

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub db: Option<String>,
    pub rules_path: Option<String>,
    pub max_fanout: f64,
    pub max_drop_pct: f64,
    pub samples: usize,
    pub timeout_secs: u64,
    pub strict: bool,
    pub assertions: Vec<String>,
    pub trace_key: Option<String>,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            db: None,
            rules_path: None,
            max_fanout: 1.0,
            max_drop_pct: 20.0,
            samples: 3,
            timeout_secs: 15,
            strict: false,
            assertions: Vec::new(),
            trace_key: None,
        }
    }
}

pub fn load_rules(path: &str) -> Result<AuditRulesFile> {
    let raw = std::fs::read_to_string(path).map_err(|e| StatkeelError::io(e, path))?;
    toml::from_str(&raw).map_err(|e| StatkeelError::Rules {
        message: format!("Invalid rules TOML `{path}`: {e}"),
        fix_hint: "Define rules with `[[table_rules]]`, `table`, and `required_filters = [...]`."
            .to_string(),
    })
}

pub fn audit_query(sql_raw: &str, opts: &AuditOptions) -> Result<AuditReport> {
    let sql = sql_raw.trim().trim_end_matches(';').trim();
    if sql.is_empty() {
        return Err(StatkeelError::SqlParse {
            message: "Empty SQL query".to_string(),
            fix_hint: "Provide a SELECT or WITH ... SELECT query via file, --query, or stdin."
                .to_string(),
        });
    }

    let rules = match &opts.rules_path {
        Some(p) => load_rules(p)?,
        None => AuditRulesFile::default(),
    };

    let is_sqlite = opts
        .db
        .as_deref()
        .map(|d| d.starts_with("sqlite://") || d.ends_with(".db") || d.ends_with(".sqlite"))
        .unwrap_or(false);

    let statements = if is_sqlite {
        Parser::parse_sql(&SQLiteDialect {}, sql)
    } else {
        Parser::parse_sql(&PostgreSqlDialect {}, sql)
    }
    .map_err(|e| StatkeelError::SqlParse {
        message: e.to_string(),
        fix_hint:
            "Check SQL syntax (Postgres dialect by default, or SQLite when --db points to SQLite)."
                .to_string(),
    })?;

    if statements.len() != 1 {
        return Err(StatkeelError::UnsafeSql {
            message: format!(
                "Expected exactly 1 SQL statement, found {}",
                statements.len()
            ),
            fix_hint: "Pass a single SELECT / WITH query to `statkeel audit`.".to_string(),
        });
    }

    let query = match &statements[0] {
        Statement::Query(q) => q.as_ref(),
        other => {
            return Err(StatkeelError::UnsafeSql {
                message: format!(
                    "Only read-only SELECT / WITH queries are permitted (got `{}`)",
                    stmt_kind(other)
                ),
                fix_hint: "statkeel audit is strictly read-only and refuses DML/DDL statements."
                    .to_string(),
            });
        }
    };

    let mut findings = Vec::new();
    run_static_checks(query, &rules, &mut findings);

    let mut waterfall = Vec::new();
    let mut join_diagnostics = Vec::new();
    let mut assertions_out = Vec::new();
    let mut entity_traces = Vec::new();
    let mut spot_check = None;
    let mut final_row_count = None;
    let mut db_engine = None;

    let mut all_assertions = rules.assertions.clone();
    all_assertions.extend(opts.assertions.clone());

    if let Some(db_spec) = &opts.db {
        if db_spec.starts_with("postgres://") || db_spec.starts_with("postgresql://") {
            db_engine = Some("postgres".to_string());
            let mut client = connect_postgres(db_spec)?;
            run_live_postgres(
                &mut client,
                sql,
                query,
                opts,
                &all_assertions,
                &mut waterfall,
                &mut join_diagnostics,
                &mut assertions_out,
                &mut entity_traces,
                &mut spot_check,
                &mut final_row_count,
                &mut findings,
            )?;
        } else {
            db_engine = Some("sqlite".to_string());
            let (path, _) = split_sqlite_spec(db_spec, None)?;
            let conn = SqliteConn::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| {
                    StatkeelError::db(
                        format!("Failed opening SQLite database `{path}`: {e}"),
                        "Check the SQLite file path and read permissions.",
                        false,
                    )
                })?;
            run_live_sqlite(
                &conn,
                sql,
                query,
                opts,
                &all_assertions,
                &mut waterfall,
                &mut join_diagnostics,
                &mut assertions_out,
                &mut entity_traces,
                &mut spot_check,
                &mut final_row_count,
                &mut findings,
            )?;
        }
    }

    // Sort findings High -> Medium -> Info.
    findings.sort_by_key(|f| match f.severity {
        FindingSeverity::High => 0,
        FindingSeverity::Medium => 1,
        FindingSeverity::Info => 2,
    });

    let high_count = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::High)
        .count();
    let medium_count = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Medium)
        .count();
    let info_count = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Info)
        .count();

    let verdict = if high_count > 0 {
        "FAIL"
    } else if medium_count > 0 {
        "WARN"
    } else {
        "PASS"
    }
    .to_string();

    let ok = if opts.strict {
        high_count == 0 && medium_count == 0
    } else {
        high_count == 0
    };

    let preview = sql
        .lines()
        .take(3)
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(160)
        .collect::<String>();

    Ok(AuditReport {
        ok,
        verdict,
        mode: if opts.db.is_some() {
            "live+static".to_string()
        } else {
            "static-only".to_string()
        },
        db_engine,
        query_preview: preview,
        final_row_count,
        high_count,
        medium_count,
        info_count,
        findings,
        waterfall,
        join_diagnostics,
        assertions: assertions_out,
        entity_traces,
        spot_check,
    })
}

fn stmt_kind(stmt: &Statement) -> &'static str {
    match stmt {
        Statement::Insert(_) => "INSERT",
        Statement::Update { .. } => "UPDATE",
        Statement::Delete(_) => "DELETE",
        Statement::Drop { .. } => "DROP",
        Statement::AlterTable { .. } => "ALTER TABLE",
        Statement::Truncate { .. } => "TRUNCATE",
        Statement::CreateTable(_) => "CREATE TABLE",
        _ => "NON-SELECT",
    }
}

fn run_static_checks(query: &Query, rules: &AuditRulesFile, findings: &mut Vec<AuditFinding>) {
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            analyze_set_expr(&cte.query.body, rules, findings, &cte.alias.name.value);
        }
    }
    analyze_set_expr(&query.body, rules, findings, "main query");
}

fn analyze_set_expr(
    body: &SetExpr,
    rules: &AuditRulesFile,
    findings: &mut Vec<AuditFinding>,
    scope: &str,
) {
    match body {
        SetExpr::Select(sel) => analyze_select(sel, rules, findings, scope),
        SetExpr::Query(q) => run_static_checks(q, rules, findings),
        SetExpr::SetOperation { left, right, .. } => {
            analyze_set_expr(left, rules, findings, scope);
            analyze_set_expr(right, rules, findings, scope);
        }
        _ => {}
    }
}

fn analyze_select(
    sel: &Select,
    rules: &AuditRulesFile,
    findings: &mut Vec<AuditFinding>,
    scope: &str,
) {
    let mut left_join_aliases: Vec<(String, String)> = Vec::new();
    let mut all_tables: Vec<(String, String)> = Vec::new();
    let mut join_count = 0usize;

    for twj in &sel.from {
        if let Some((tname, alias)) = extract_table_name_alias(&twj.relation) {
            all_tables.push((tname, alias));
        }
        if let TableFactor::Derived { subquery, .. } = &twj.relation {
            run_static_checks(subquery, rules, findings);
        }
        for join in &twj.joins {
            join_count += 1;
            if let TableFactor::Derived { subquery, .. } = &join.relation {
                run_static_checks(subquery, rules, findings);
            }
            if let Some((tname, alias)) = extract_table_name_alias(&join.relation) {
                all_tables.push((tname.clone(), alias.clone()));
                if is_left_join(&join.join_operator) {
                    left_join_aliases.push((tname, alias));
                }
            }
        }
    }

    // S001: Demoted LEFT JOIN — right-hand table filtered in WHERE without IS NULL check.
    if let Some(where_expr) = &sel.selection {
        let mut referenced_non_null_aliases = HashSet::new();
        collect_non_null_filtered_aliases(where_expr, &mut referenced_non_null_aliases);
        for (tname, alias) in &left_join_aliases {
            let alias_lc = alias.to_ascii_lowercase();
            let short_tname = tname
                .split('.')
                .next_back()
                .unwrap_or(tname)
                .to_ascii_lowercase();
            if referenced_non_null_aliases.contains(&alias_lc)
                || referenced_non_null_aliases.contains(&short_tname)
            {
                findings.push(AuditFinding {
                    code: "S001_DEMOTED_LEFT_JOIN".to_string(),
                    category: "static".to_string(),
                    severity: FindingSeverity::High,
                    message: format!(
                        "[{scope}] WHERE clause filters LEFT JOIN table `{tname}` (alias `{alias}`), silently converting LEFT JOIN into INNER JOIN and dropping unmatched rows."
                    ),
                    fix_hint: format!(
                        "Move filters on `{alias}` into the `LEFT JOIN ... ON (...)` clause or guard with `({alias}.col = ... OR {alias}.col IS NULL)`."
                    ),
                });
            }
        }

        // S002: NOT IN (SELECT ...) nullable subquery trap.
        if has_not_in_subquery(where_expr) {
            findings.push(AuditFinding {
                code: "S002_NOT_IN_SUBQUERY".to_string(),
                category: "static".to_string(),
                severity: FindingSeverity::High,
                message: format!(
                    "[{scope}] `NOT IN (SELECT ...)` silently returns 0 rows if the subquery contains any NULL."
                ),
                fix_hint: "Replace `NOT IN (SELECT ...)` with `NOT EXISTS (SELECT 1 FROM ...)` or add `WHERE col IS NOT NULL` inside the subquery.".to_string(),
            });
        }
    }

    // S003: Uncast division in projections (Postgres integer division trap).
    let mut has_agg = false;
    let mut has_int_div_risk = false;
    for item in &sel.projection {
        let item_str = item.to_string();
        let upper = item_str.to_ascii_uppercase();
        if upper.contains("COUNT(") || upper.contains("SUM(") || upper.contains("AVG(") {
            has_agg = true;
        }
        if expr_has_uncast_division_str(&item_str) {
            has_int_div_risk = true;
        }
    }
    if has_int_div_risk {
        findings.push(AuditFinding {
            code: "S003_INTEGER_DIVISION_RISK".to_string(),
            category: "static".to_string(),
            severity: FindingSeverity::Medium,
            message: format!(
                "[{scope}] Division expression in SELECT lacks explicit float/numeric cast (`::numeric`/`1.0 *`) or `NULLIF(..., 0)` guard."
            ),
            fix_hint: "In Postgres, `int / int` truncates to 0! Rewrite as `a::numeric / NULLIF(b, 0)`.".to_string(),
        });
    }

    // S004: SELECT DISTINCT over JOINs (classic fan-out band-aid).
    if matches!(sel.distinct, Some(Distinct::Distinct)) && join_count > 0 {
        findings.push(AuditFinding {
            code: "S004_DISTINCT_OVER_JOIN".to_string(),
            category: "static".to_string(),
            severity: FindingSeverity::Medium,
            message: format!(
                "[{scope}] `SELECT DISTINCT` combined with {join_count} JOIN(s) often masks an unintended fan-out (and does not protect `SUM`/`AVG`)."
            ),
            fix_hint: "Deduplicate the right-hand table in a CTE before joining instead of relying on `SELECT DISTINCT`.".to_string(),
        });
    }

    // S005: Aggregation across JOINs (informational reminder to check waterfall).
    if has_agg && join_count > 0 {
        findings.push(AuditFinding {
            code: "S005_AGG_ACROSS_JOINS".to_string(),
            category: "static".to_string(),
            severity: FindingSeverity::Info,
            message: format!(
                "[{scope}] Aggregates (`COUNT`/`SUM`/`AVG`) run across {join_count} JOIN(s) — confirm grain and zero fan-out in the live waterfall."
            ),
            fix_hint: "Prefer `COUNT(DISTINCT entity_id)` or pre-aggregate child tables in CTEs before joining.".to_string(),
        });
    }

    // S006: Domain guardrail rules (`--rules rules.toml`).
    if !rules.table_rules.is_empty() {
        let mut filter_text = String::new();
        if let Some(w) = &sel.selection {
            filter_text.push_str(&w.to_string().to_ascii_lowercase());
            filter_text.push(' ');
        }
        for twj in &sel.from {
            for j in &twj.joins {
                if let Some(on_expr) = join_on_expr(&j.join_operator) {
                    filter_text.push_str(&on_expr.to_string().to_ascii_lowercase());
                    filter_text.push(' ');
                }
            }
        }

        for rule in &rules.table_rules {
            let rule_tbl = rule.table.to_ascii_lowercase();
            let rule_short = rule_tbl.split('.').next_back().unwrap_or(&rule_tbl);
            let matched_ref = all_tables.iter().find(|(tname, _)| {
                let t = tname.to_ascii_lowercase();
                let t_short = t.split('.').next_back().unwrap_or(&t);
                t == rule_tbl || t_short == rule_short
            });

            if let Some((tname, alias)) = matched_ref {
                let alias_lc = alias.to_ascii_lowercase();
                let t_short = tname
                    .split('.')
                    .next_back()
                    .unwrap_or(tname)
                    .to_ascii_lowercase();
                let multi_table = all_tables.len() > 1;
                let missing: Vec<&String> = rule
                    .required_filters
                    .iter()
                    .filter(|col| {
                        let col_lc = col.to_ascii_lowercase();
                        if multi_table {
                            let by_alias = format!("{alias_lc}.{col_lc}");
                            let by_table = format!("{t_short}.{col_lc}");
                            !filter_text.contains(&by_alias) && !filter_text.contains(&by_table)
                        } else {
                            !filter_text.contains(&col_lc)
                        }
                    })
                    .collect();
                if !missing.is_empty() {
                    let sev = match rule.severity.to_ascii_lowercase().as_str() {
                        "medium" | "warn" => FindingSeverity::Medium,
                        "info" => FindingSeverity::Info,
                        _ => FindingSeverity::High,
                    };
                    let missing_csv = missing
                        .iter()
                        .map(|s| format!("`{s}`"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let reason = if rule.reason.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", rule.reason)
                    };
                    findings.push(AuditFinding {
                        code: "S006_DOMAIN_RULE_MISSING_FILTER".to_string(),
                        category: "domain_rule".to_string(),
                        severity: sev,
                        message: format!(
                            "[{scope}] Table `{tname}` is missing required domain filter(s): {missing_csv}{reason}"
                        ),
                        fix_hint: if rule.fix_hint.is_empty() {
                            format!("Filter `{tname}` explicitly on {missing_csv}.")
                        } else {
                            rule.fix_hint.clone()
                        },
                    });
                }
            }
        }
    }
}

fn extract_table_name_alias(tf: &TableFactor) -> Option<(String, String)> {
    match tf {
        TableFactor::Table { name, alias, .. } => {
            let full = name
                .0
                .iter()
                .map(|p| p.to_string().trim_matches('"').to_string())
                .collect::<Vec<_>>()
                .join(".");
            let al = alias
                .as_ref()
                .map(|a| a.name.value.clone())
                .unwrap_or_else(|| full.split('.').next_back().unwrap_or(&full).to_string());
            Some((full, al))
        }
        TableFactor::Derived { alias: Some(a), .. } => {
            Some((a.name.value.clone(), a.name.value.clone()))
        }
        _ => None,
    }
}

fn is_left_join(op: &JoinOperator) -> bool {
    matches!(op, JoinOperator::Left(_) | JoinOperator::LeftOuter(_))
}

fn join_type_label(op: &JoinOperator) -> &'static str {
    match op {
        JoinOperator::Inner(_) | JoinOperator::Join(_) => "INNER JOIN",
        JoinOperator::Left(_) | JoinOperator::LeftOuter(_) => "LEFT JOIN",
        JoinOperator::Right(_) | JoinOperator::RightOuter(_) => "RIGHT JOIN",
        JoinOperator::FullOuter(_) => "FULL OUTER JOIN",
        JoinOperator::CrossJoin(_) => "CROSS JOIN",
        _ => "JOIN",
    }
}

fn join_on_expr(op: &JoinOperator) -> Option<&Expr> {
    match op {
        JoinOperator::Inner(JoinConstraint::On(e))
        | JoinOperator::Join(JoinConstraint::On(e))
        | JoinOperator::Left(JoinConstraint::On(e))
        | JoinOperator::LeftOuter(JoinConstraint::On(e))
        | JoinOperator::Right(JoinConstraint::On(e))
        | JoinOperator::RightOuter(JoinConstraint::On(e))
        | JoinOperator::FullOuter(JoinConstraint::On(e)) => Some(e),
        _ => None,
    }
}

/// Collects table aliases constrained by non-null-preserving predicates in WHERE
/// (e.g. `WHERE c.status = 'active'` demotes a LEFT JOIN, whereas `WHERE c.id IS NULL` does not).
fn collect_non_null_filtered_aliases(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::BinaryOp { left, op, right } => match op {
            BinaryOperator::And => {
                collect_non_null_filtered_aliases(left, out);
                collect_non_null_filtered_aliases(right, out);
            }
            BinaryOperator::Or => {
                // Only flag OR if neither side is an IS NULL escape hatch.
                if !contains_is_null(left) && !contains_is_null(right) {
                    collect_non_null_filtered_aliases(left, out);
                    collect_non_null_filtered_aliases(right, out);
                }
            }
            BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Gt
            | BinaryOperator::GtEq
            | BinaryOperator::Lt
            | BinaryOperator::LtEq => {
                collect_direct_aliases(left, out);
                collect_direct_aliases(right, out);
            }
            _ => {}
        },
        Expr::Nested(inner) => collect_non_null_filtered_aliases(inner, out),
        Expr::In { expr, .. } | Expr::Between { expr, .. } => {
            collect_direct_aliases(expr, out);
        }
        Expr::Like { expr, .. } | Expr::ILike { expr, .. } => {
            collect_direct_aliases(expr, out);
        }
        Expr::IsNull(_) | Expr::IsNotNull(_) => {
            // `IS NULL` is an anti-join (intentional); `IS NOT NULL` demotes LEFT JOIN.
            if let Expr::IsNotNull(inner) = expr {
                collect_direct_aliases(inner, out);
            }
        }
        _ => {}
    }
}

fn contains_is_null(expr: &Expr) -> bool {
    match expr {
        Expr::IsNull(_) => true,
        Expr::Nested(inner) => contains_is_null(inner),
        Expr::BinaryOp { left, right, .. } => contains_is_null(left) || contains_is_null(right),
        _ => false,
    }
}

fn collect_direct_aliases(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::CompoundIdentifier(idents) if idents.len() >= 2 => {
            out.insert(idents[0].value.to_ascii_lowercase());
        }
        Expr::Nested(inner) => collect_direct_aliases(inner, out),
        Expr::Function(f) => {
            // COALESCE(alias.col, 0) preserves NULLs! Don't flag COALESCE.
            let fname = f.name.to_string().to_ascii_lowercase();
            if fname != "coalesce" {
                let s = f.to_string();
                if let Some((prefix, _)) = s.split_once('.')
                    && let Some(alias) = prefix.split('(').next_back()
                {
                    let a = alias.trim();
                    if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        out.insert(a.to_ascii_lowercase());
                    }
                }
            }
        }
        _ => {}
    }
}

fn has_not_in_subquery(expr: &Expr) -> bool {
    match expr {
        Expr::In {
            negated: true,
            target: InTarget::Subquery(_),
            ..
        } => true,
        Expr::BinaryOp { left, right, .. } => {
            has_not_in_subquery(left) || has_not_in_subquery(right)
        }
        Expr::UnaryOp { expr, .. } | Expr::Nested(expr) => has_not_in_subquery(expr),
        _ => false,
    }
}

fn expr_has_uncast_division_str(expr: &str) -> bool {
    // Simple, reliable check: contains ` / ` outside string literals without float/numeric cast or decimal literal.
    if !expr.contains(" / ") {
        return false;
    }
    let upper = expr.to_ascii_uppercase();
    let has_cast = upper.contains("::NUMERIC")
        || upper.contains("::FLOAT")
        || upper.contains("::DOUBLE")
        || upper.contains("::REAL")
        || upper.contains("AS NUMERIC")
        || upper.contains("AS FLOAT")
        || upper.contains("AS REAL")
        || upper.contains("AS DOUBLE")
        || upper.contains("1.0 *")
        || upper.contains("* 1.0")
        || upper.contains("100.0 *")
        || upper.contains("* 100.0");
    !has_cast
}

/// Extract simple equality join pairs `left_expr = right_expr` from an `ON` expression.
fn extract_first_eq_pair(expr: &Expr) -> Option<(String, String)> {
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => Some((left.to_string(), right.to_string())),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => extract_first_eq_pair(left).or_else(|| extract_first_eq_pair(right)),
        Expr::Nested(inner) => extract_first_eq_pair(inner),
        _ => None,
    }
}

struct ProbePlan {
    cte_prefix: String,
    base_rel: Option<String>,
    cte_probes: Vec<(String, String)>, // (label, count_sql)
    base_probe: Option<(String, String)>,
    join_probes: Vec<JoinProbe>,
    where_probe: Option<(String, String)>,
    final_count_sql: String,
    sample_sql: String,
}

struct JoinProbe {
    label: String,
    join_type: String,
    is_left: bool,
    condition: String,
    count_sql: String,
    right_dup_sql: Option<String>,
    unmatched_left_sql: Option<String>,
}

fn build_probe_plan(full_sql: &str, query: &Query, samples: usize) -> ProbePlan {
    let mut cte_probes = Vec::new();
    let mut accumulated_ctes = Vec::new();
    let is_recursive = query.with.as_ref().map(|w| w.recursive).unwrap_or(false);
    let with_kw = if is_recursive {
        "WITH RECURSIVE"
    } else {
        "WITH"
    };

    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            accumulated_ctes.push(cte.to_string());
            let prefix = format!("{with_kw} {}", accumulated_ctes.join(", "));
            let cte_name = cte.alias.name.value.clone();
            let count_sql = format!("{prefix} SELECT COUNT(*) FROM {cte_name}");
            cte_probes.push((format!("cte:{cte_name}"), count_sql));
        }
    }

    let cte_prefix = if accumulated_ctes.is_empty() {
        String::new()
    } else {
        format!("{with_kw} {} ", accumulated_ctes.join(", "))
    };

    let mut base_probe = None;
    let mut base_rel = None;
    let mut join_probes = Vec::new();
    let mut where_probe = None;

    if let SetExpr::Select(sel) = query.body.as_ref()
        && let Some(twj) = sel.from.first()
    {
        let base_sql = twj.relation.to_string();
        base_rel = Some(base_sql.clone());
        let base_label = extract_table_name_alias(&twj.relation)
            .map(|(t, _)| t)
            .unwrap_or_else(|| base_sql.clone());

        base_probe = Some((
            format!("base:{base_label}"),
            format!("{cte_prefix}SELECT COUNT(*) FROM {base_sql}"),
        ));

        let mut running_from = base_sql.clone();
        for join in &twj.joins {
            let prev_from = running_from.clone();
            let j_str = join.to_string();
            running_from = format!("{running_from} {j_str}");

            let right_label = extract_table_name_alias(&join.relation)
                .map(|(t, _)| t)
                .unwrap_or_else(|| join.relation.to_string());
            let jtype = join_type_label(&join.join_operator).to_string();
            let on_str = join_on_expr(&join.join_operator)
                .map(|e| e.to_string())
                .unwrap_or_else(|| "(no ON)".to_string());

            let (right_dup_sql, unmatched_left_sql) =
                build_join_key_probes(&cte_prefix, &prev_from, join);

            join_probes.push(JoinProbe {
                label: format!("{jtype} {right_label}"),
                join_type: jtype,
                is_left: is_left_join(&join.join_operator),
                condition: on_str,
                count_sql: format!("{cte_prefix}SELECT COUNT(*) FROM {running_from}"),
                right_dup_sql,
                unmatched_left_sql,
            });
        }

        // Extra comma-separated FROM tables (rare, but handle cleanly).
        for extra in sel.from.iter().skip(1) {
            running_from = format!("{running_from}, {extra}");
        }

        if let Some(where_expr) = &sel.selection {
            where_probe = Some((
                "after:WHERE".to_string(),
                format!("{cte_prefix}SELECT COUNT(*) FROM {running_from} WHERE {where_expr}"),
            ));
        }
    }

    let final_count_sql = format!("SELECT COUNT(*) FROM ({full_sql}) AS _sk_final");
    let sample_sql = format!("SELECT * FROM ({full_sql}) AS _sk_sample LIMIT {samples}");

    ProbePlan {
        cte_prefix,
        base_rel,
        cte_probes,
        base_probe,
        join_probes,
        where_probe,
        final_count_sql,
        sample_sql,
    }
}

fn build_join_key_probes(
    cte_prefix: &str,
    prev_from: &str,
    join: &Join,
) -> (Option<String>, Option<String>) {
    let Some(on_expr) = join_on_expr(&join.join_operator) else {
        return (None, None);
    };
    let Some((lhs, rhs)) = extract_first_eq_pair(on_expr) else {
        return (None, None);
    };

    let right_rel = join.relation.to_string();
    let right_alias = extract_table_name_alias(&join.relation)
        .map(|(_, a)| a.to_ascii_lowercase())
        .unwrap_or_default();

    // Determine which side of `lhs = rhs` belongs to the right table.
    let (left_key_expr, right_key_expr) = if rhs
        .to_ascii_lowercase()
        .starts_with(&format!("{right_alias}."))
    {
        (lhs, rhs)
    } else if lhs
        .to_ascii_lowercase()
        .starts_with(&format!("{right_alias}."))
    {
        (rhs, lhs)
    } else {
        (lhs, rhs)
    };

    let right_dup_sql = format!(
        "{cte_prefix}SELECT COUNT(*), COALESCE(MAX(_c), 0) FROM (SELECT {right_key_expr} AS _k, COUNT(*) AS _c FROM {right_rel} WHERE {right_key_expr} IS NOT NULL GROUP BY {right_key_expr} HAVING COUNT(*) > 1) AS _sk_dups"
    );

    let unmatched_left_sql = format!(
        "{cte_prefix}SELECT CAST({left_key_expr} AS TEXT) FROM {prev_from} LEFT JOIN {right_rel} ON {on_expr} WHERE {left_key_expr} IS NOT NULL AND {right_key_expr} IS NULL LIMIT 5"
    );

    (Some(right_dup_sql), Some(unmatched_left_sql))
}

#[allow(clippy::too_many_arguments)]
fn run_live_postgres(
    client: &mut PgClient,
    full_sql: &str,
    query: &Query,
    opts: &AuditOptions,
    assertion_exprs: &[String],
    waterfall: &mut Vec<WaterfallStep>,
    join_diags: &mut Vec<LiveJoinDiag>,
    assertions_out: &mut Vec<AssertionResult>,
    entity_traces: &mut Vec<EntityTrace>,
    spot_check: &mut Option<SpotCheckSample>,
    final_row_count: &mut Option<i64>,
    findings: &mut Vec<AuditFinding>,
) -> Result<()> {
    let plan = build_probe_plan(full_sql, query, opts.samples);
    let _ = &plan.cte_prefix;

    let mut tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| {
            StatkeelError::db(
                format!("Failed starting READ ONLY transaction: {e}"),
                "Ensure DB user has SELECT privileges.",
                true,
            )
        })?;

    tx.batch_execute(&format!(
        "SET LOCAL statement_timeout = '{}s';",
        opts.timeout_secs
    ))
    .map_err(|e| StatkeelError::db(format!("SET statement_timeout failed: {e}"), "", false))?;

    // Helper closure using SAVEPOINT so one probe failing never aborts the read-only tx.
    let pg_count = |tx: &mut postgres::Transaction, q: &str| -> std::result::Result<i64, String> {
        let _ = tx.batch_execute("SAVEPOINT _sk_sp;");
        match tx.query_one(q, &[]) {
            Ok(row) => {
                let _ = tx.batch_execute("RELEASE SAVEPOINT _sk_sp;");
                Ok(row.get::<_, i64>(0))
            }
            Err(e) => {
                let _ = tx.batch_execute("ROLLBACK TO SAVEPOINT _sk_sp;");
                Err(e.to_string())
            }
        }
    };

    for (label, sql) in &plan.cte_probes {
        if let Ok(cnt) = pg_count(&mut tx, sql) {
            waterfall.push(WaterfallStep {
                stage: label.clone(),
                kind: "cte".to_string(),
                row_count: cnt,
                delta: None,
                ratio_vs_prev: None,
                note: None,
            });
        }
    }

    let mut prev_rows: Option<i64> = None;
    if let Some((label, sql)) = &plan.base_probe
        && let Ok(cnt) = pg_count(&mut tx, sql)
    {
        waterfall.push(WaterfallStep {
            stage: label.clone(),
            kind: "base".to_string(),
            row_count: cnt,
            delta: None,
            ratio_vs_prev: None,
            note: None,
        });
        prev_rows = Some(cnt);
    }

    for jp in &plan.join_probes {
        if let Ok(cnt) = pg_count(&mut tx, &jp.count_sql) {
            let (delta, ratio) = match prev_rows {
                Some(p) if p > 0 => (Some(cnt - p), Some(round4(cnt as f64 / p as f64))),
                Some(p) => (Some(cnt - p), None),
                None => (None, None),
            };

            let mut right_dups = 0i64;
            let mut right_max_mult = 1i64;
            if let Some(dup_sql) = &jp.right_dup_sql {
                let _ = tx.batch_execute("SAVEPOINT _sk_dup;");
                if let Ok(r) = tx.query_one(dup_sql, &[]) {
                    right_dups = r.get::<_, i64>(0);
                    right_max_mult = r.get::<_, i64>(1).max(1);
                    let _ = tx.batch_execute("RELEASE SAVEPOINT _sk_dup;");
                } else {
                    let _ = tx.batch_execute("ROLLBACK TO SAVEPOINT _sk_dup;");
                }
            }

            let mut unmatched_samples = Vec::new();
            if let Some(un_sql) = &jp.unmatched_left_sql {
                let _ = tx.batch_execute("SAVEPOINT _sk_unm;");
                if let Ok(rows) = tx.query(un_sql, &[]) {
                    for r in rows {
                        let v: Option<String> = r.get(0);
                        if let Some(s) = v {
                            unmatched_samples.push(s);
                        }
                    }
                    let _ = tx.batch_execute("RELEASE SAVEPOINT _sk_unm;");
                } else {
                    let _ = tx.batch_execute("ROLLBACK TO SAVEPOINT _sk_unm;");
                }
            }

            let left_rows = prev_rows.unwrap_or(0);
            let left_matched_pct = if left_rows > 0 && !jp.is_left {
                Some(round2(
                    (cnt.min(left_rows) as f64 / left_rows as f64) * 100.0,
                ))
            } else {
                None
            };

            let note = evaluate_join_step(
                jp,
                left_rows,
                cnt,
                ratio,
                right_dups,
                right_max_mult,
                &unmatched_samples,
                opts,
                findings,
            );

            waterfall.push(WaterfallStep {
                stage: jp.label.clone(),
                kind: "join".to_string(),
                row_count: cnt,
                delta,
                ratio_vs_prev: ratio,
                note,
            });

            join_diags.push(LiveJoinDiag {
                join_label: jp.label.clone(),
                join_type: jp.join_type.clone(),
                condition: jp.condition.clone(),
                left_rows,
                joined_rows: cnt,
                fanout_ratio: ratio.unwrap_or(0.0),
                right_duplicate_keys: right_dups,
                right_max_rows_per_key: right_max_mult,
                left_matched_pct,
                unmatched_left_samples: unmatched_samples,
            });

            prev_rows = Some(cnt);
        }
    }

    if let Some((label, sql)) = &plan.where_probe
        && let Ok(cnt) = pg_count(&mut tx, sql)
    {
        let (delta, ratio) = match prev_rows {
            Some(p) if p > 0 => (Some(cnt - p), Some(round4(cnt as f64 / p as f64))),
            Some(p) => (Some(cnt - p), None),
            None => (None, None),
        };
        let note = evaluate_where_step(prev_rows, cnt, findings);
        waterfall.push(WaterfallStep {
            stage: label.clone(),
            kind: "where".to_string(),
            row_count: cnt,
            delta,
            ratio_vs_prev: ratio,
            note,
        });
        prev_rows = Some(cnt);
    }

    // Final count (required — if this fails, the query itself is invalid against Postgres!).
    let fcnt = pg_count(&mut tx, &plan.final_count_sql).map_err(|e| {
        StatkeelError::db(
            format!("Query failed against PostgreSQL: {e}"),
            "Fix the SQL syntax or table/column references and re-run `statkeel audit`.",
            false,
        )
    })?;
    *final_row_count = Some(fcnt);
    let (delta, ratio) = match prev_rows {
        Some(p) if p > 0 => (Some(fcnt - p), Some(round4(fcnt as f64 / p as f64))),
        Some(p) => (Some(fcnt - p), None),
        None => (None, None),
    };
    waterfall.push(WaterfallStep {
        stage: "final:output".to_string(),
        kind: "final".to_string(),
        row_count: fcnt,
        delta,
        ratio_vs_prev: ratio,
        note: if fcnt == 0 {
            Some("0 rows returned!".to_string())
        } else {
            None
        },
    });
    if fcnt == 0 {
        findings.push(AuditFinding {
            code: "L003_ZERO_ROWS".to_string(),
            category: "live".to_string(),
            severity: FindingSeverity::High,
            message: "Query executed cleanly but returned 0 rows.".to_string(),
            fix_hint: "Inspect the row-count waterfall above to see which JOIN or WHERE step collapsed to 0.".to_string(),
        });
    }

    // Spot-check samples via row_to_json so every Postgres type works cleanly.
    if opts.samples > 0 {
        let meta_stmt = tx
            .prepare(&format!("SELECT * FROM ({full_sql}) AS _sk_m LIMIT 0"))
            .ok();
        let cols: Vec<String> = meta_stmt
            .map(|s| s.columns().iter().map(|c| c.name().to_string()).collect())
            .unwrap_or_default();
        let json_sql = format!(
            "SELECT row_to_json(_sk_s)::text FROM ({}) AS _sk_s",
            plan.sample_sql
        );
        if let Ok(rows) = tx.query(&json_sql, &[]) {
            let mut out_rows = Vec::with_capacity(rows.len());
            for r in rows {
                let s: String = r.get(0);
                if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(&s) {
                    let vals = cols
                        .iter()
                        .map(|c| map.get(c).cloned().unwrap_or(serde_json::Value::Null))
                        .collect();
                    out_rows.push(vals);
                }
            }
            *spot_check = Some(SpotCheckSample {
                columns: cols,
                rows: out_rows,
            });
        }
    }

    let base_rows_opt = waterfall
        .iter()
        .find(|w| w.kind == "base")
        .map(|w| w.row_count);
    if !assertion_exprs.is_empty() {
        *assertions_out = run_assertions_postgres(
            &mut tx,
            full_sql,
            base_rows_opt,
            fcnt,
            assertion_exprs,
            findings,
        )?;
    }
    if let Some(tk) = &opts.trace_key {
        *entity_traces = trace_entities_postgres(
            &mut tx,
            &plan.cte_prefix,
            plan.base_rel.as_deref(),
            full_sql,
            tk,
        )?;
    }

    let _ = tx.rollback();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_live_sqlite(
    conn: &SqliteConn,
    full_sql: &str,
    query: &Query,
    opts: &AuditOptions,
    assertion_exprs: &[String],
    waterfall: &mut Vec<WaterfallStep>,
    join_diags: &mut Vec<LiveJoinDiag>,
    assertions_out: &mut Vec<AssertionResult>,
    entity_traces: &mut Vec<EntityTrace>,
    spot_check: &mut Option<SpotCheckSample>,
    final_row_count: &mut Option<i64>,
    findings: &mut Vec<AuditFinding>,
) -> Result<()> {
    let plan = build_probe_plan(full_sql, query, opts.samples);
    let sqlite_count = |q: &str| -> std::result::Result<i64, String> {
        conn.query_row(q, [], |r| r.get::<_, i64>(0))
            .map_err(|e| e.to_string())
    };

    for (label, sql) in &plan.cte_probes {
        if let Ok(cnt) = sqlite_count(sql) {
            waterfall.push(WaterfallStep {
                stage: label.clone(),
                kind: "cte".to_string(),
                row_count: cnt,
                delta: None,
                ratio_vs_prev: None,
                note: None,
            });
        }
    }

    let mut prev_rows: Option<i64> = None;
    if let Some((label, sql)) = &plan.base_probe
        && let Ok(cnt) = sqlite_count(sql)
    {
        waterfall.push(WaterfallStep {
            stage: label.clone(),
            kind: "base".to_string(),
            row_count: cnt,
            delta: None,
            ratio_vs_prev: None,
            note: None,
        });
        prev_rows = Some(cnt);
    }

    for jp in &plan.join_probes {
        if let Ok(cnt) = sqlite_count(&jp.count_sql) {
            let (delta, ratio) = match prev_rows {
                Some(p) if p > 0 => (Some(cnt - p), Some(round4(cnt as f64 / p as f64))),
                Some(p) => (Some(cnt - p), None),
                None => (None, None),
            };

            let mut right_dups = 0i64;
            let mut right_max_mult = 1i64;
            if let Some(dup_sql) = &jp.right_dup_sql
                && let Ok((d, m)) = conn.query_row(dup_sql, [], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
                })
            {
                right_dups = d;
                right_max_mult = m.max(1);
            }

            let mut unmatched_samples = Vec::new();
            if let Some(un_sql) = &jp.unmatched_left_sql
                && let Ok(mut stmt) = conn.prepare(un_sql)
                && let Ok(mut rows) = stmt.query([])
            {
                while let Ok(Some(r)) = rows.next() {
                    if let Ok(Some(s)) = r.get::<_, Option<String>>(0) {
                        unmatched_samples.push(s);
                    }
                }
            }

            let left_rows = prev_rows.unwrap_or(0);
            let left_matched_pct = if left_rows > 0 && !jp.is_left {
                Some(round2(
                    (cnt.min(left_rows) as f64 / left_rows as f64) * 100.0,
                ))
            } else {
                None
            };

            let note = evaluate_join_step(
                jp,
                left_rows,
                cnt,
                ratio,
                right_dups,
                right_max_mult,
                &unmatched_samples,
                opts,
                findings,
            );

            waterfall.push(WaterfallStep {
                stage: jp.label.clone(),
                kind: "join".to_string(),
                row_count: cnt,
                delta,
                ratio_vs_prev: ratio,
                note,
            });

            join_diags.push(LiveJoinDiag {
                join_label: jp.label.clone(),
                join_type: jp.join_type.clone(),
                condition: jp.condition.clone(),
                left_rows,
                joined_rows: cnt,
                fanout_ratio: ratio.unwrap_or(0.0),
                right_duplicate_keys: right_dups,
                right_max_rows_per_key: right_max_mult,
                left_matched_pct,
                unmatched_left_samples: unmatched_samples,
            });

            prev_rows = Some(cnt);
        }
    }

    if let Some((label, sql)) = &plan.where_probe
        && let Ok(cnt) = sqlite_count(sql)
    {
        let (delta, ratio) = match prev_rows {
            Some(p) if p > 0 => (Some(cnt - p), Some(round4(cnt as f64 / p as f64))),
            Some(p) => (Some(cnt - p), None),
            None => (None, None),
        };
        let note = evaluate_where_step(prev_rows, cnt, findings);
        waterfall.push(WaterfallStep {
            stage: label.clone(),
            kind: "where".to_string(),
            row_count: cnt,
            delta,
            ratio_vs_prev: ratio,
            note,
        });
        prev_rows = Some(cnt);
    }

    let fcnt = sqlite_count(&plan.final_count_sql).map_err(|e| {
        StatkeelError::db(
            format!("Query failed against SQLite: {e}"),
            "Fix the SQL syntax or table/column references and re-run `statkeel audit`.",
            false,
        )
    })?;
    *final_row_count = Some(fcnt);
    let (delta, ratio) = match prev_rows {
        Some(p) if p > 0 => (Some(fcnt - p), Some(round4(fcnt as f64 / p as f64))),
        Some(p) => (Some(fcnt - p), None),
        None => (None, None),
    };
    waterfall.push(WaterfallStep {
        stage: "final:output".to_string(),
        kind: "final".to_string(),
        row_count: fcnt,
        delta,
        ratio_vs_prev: ratio,
        note: if fcnt == 0 {
            Some("0 rows returned!".to_string())
        } else {
            None
        },
    });
    if fcnt == 0 {
        findings.push(AuditFinding {
            code: "L003_ZERO_ROWS".to_string(),
            category: "live".to_string(),
            severity: FindingSeverity::High,
            message: "Query executed cleanly but returned 0 rows.".to_string(),
            fix_hint: "Inspect the row-count waterfall above to see which JOIN or WHERE step collapsed to 0.".to_string(),
        });
    }

    if opts.samples > 0
        && let Ok(mut stmt) = conn.prepare(&plan.sample_sql)
    {
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let col_count = cols.len();
        let mut out_rows = Vec::new();
        if let Ok(mut rows) = stmt.query([]) {
            while let Ok(Some(r)) = rows.next() {
                let mut vals = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let cell = match r.get_ref_unwrap(i) {
                        ValueRef::Null => CellValue::Null,
                        ValueRef::Integer(v) => CellValue::Int(v),
                        ValueRef::Real(v) => CellValue::Float(v),
                        ValueRef::Text(b) => CellValue::Str(String::from_utf8_lossy(b).to_string()),
                        ValueRef::Blob(b) => CellValue::Str(format!("<blob {}B>", b.len())),
                    };
                    vals.push(cell.to_json_value());
                }
                out_rows.push(vals);
            }
        }
        *spot_check = Some(SpotCheckSample {
            columns: cols,
            rows: out_rows,
        });
    }

    let base_rows_opt = waterfall
        .iter()
        .find(|w| w.kind == "base")
        .map(|w| w.row_count);
    if !assertion_exprs.is_empty() {
        *assertions_out = run_assertions_sqlite(
            conn,
            full_sql,
            base_rows_opt,
            fcnt,
            assertion_exprs,
            findings,
        )?;
    }
    if let Some(tk) = &opts.trace_key {
        *entity_traces = trace_entities_sqlite(
            conn,
            &plan.cte_prefix,
            plan.base_rel.as_deref(),
            full_sql,
            tk,
        )?;
    }

    let _ = IndexMap::<String, ()>::new();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_join_step(
    jp: &JoinProbe,
    left_rows: i64,
    joined_rows: i64,
    ratio: Option<f64>,
    right_dups: i64,
    right_max_mult: i64,
    unmatched_samples: &[String],
    opts: &AuditOptions,
    findings: &mut Vec<AuditFinding>,
) -> Option<String> {
    if let Some(r) = ratio {
        if r > opts.max_fanout + 1e-9 {
            let added = joined_rows - left_rows;
            findings.push(AuditFinding {
                code: "L001_LIVE_JOIN_FANOUT".to_string(),
                category: "live".to_string(),
                severity: FindingSeverity::High,
                message: format!(
                    "`{}` multiplied rows from {left_rows} -> {joined_rows} (+{added} rows, {r:.3}x; right side has {right_dups} duplicate key(s), max {right_max_mult} rows/key).",
                    jp.label
                ),
                fix_hint: format!(
                    "Deduplicate or pre-aggregate the right table in a CTE before `{}` (or raise `--max-fanout` if this grain change is intentional).",
                    jp.label
                ),
            });
            return Some(format!("FAN-OUT +{added} ({r:.3}x)"));
        }
        if !jp.is_left && left_rows > 0 {
            let drop_pct = ((left_rows - joined_rows).max(0) as f64 / left_rows as f64) * 100.0;
            if drop_pct > opts.max_drop_pct {
                let sample_hint = if unmatched_samples.is_empty() {
                    String::new()
                } else {
                    format!(
                        " Unmatched sample keys: [{}].",
                        unmatched_samples.join(", ")
                    )
                };
                findings.push(AuditFinding {
                    code: "L002_SEVERE_JOIN_ORPHAN_DROP".to_string(),
                    category: "live".to_string(),
                    severity: FindingSeverity::High,
                    message: format!(
                        "`{}` dropped {:.1}% of rows ({left_rows} -> {joined_rows}, threshold {:.1}%).{sample_hint}",
                        jp.label, drop_pct, opts.max_drop_pct
                    ),
                    fix_hint: "Run `statkeel join` on these two tables to diagnose key formatting mismatches (leading zeros, casing, NULLs) or switch to LEFT JOIN.".to_string(),
                });
                return Some(format!("DROPPED -{drop_pct:.1}%"));
            }
        }
    }
    None
}

fn evaluate_where_step(
    prev_rows: Option<i64>,
    cnt: i64,
    findings: &mut Vec<AuditFinding>,
) -> Option<String> {
    if let Some(p) = prev_rows
        && p > 0
    {
        let drop_pct = ((p - cnt).max(0) as f64 / p as f64) * 100.0;
        if cnt == 0 {
            findings.push(AuditFinding {
                code: "L004_WHERE_DROPPED_ALL_ROWS".to_string(),
                category: "live".to_string(),
                severity: FindingSeverity::High,
                message: format!("WHERE clause dropped 100% of rows ({p} -> 0)."),
                fix_hint: "Check filter values (case sensitivity, enum spelling, or demoted LEFT JOIN predicate).".to_string(),
            });
            return Some("DROPPED 100%!".to_string());
        } else if drop_pct > 0.0 {
            return Some(format!("-{drop_pct:.1}% filtered"));
        }
    }
    None
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}
