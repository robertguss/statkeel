use crate::audit::{AuditFinding, FindingSeverity};
use crate::error::{Result, StatkeelError};
use crate::source::CellValue;
use rusqlite::{Connection as SqliteConn, types::ValueRef};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AssertionResult {
    pub expr: String,
    pub passed: bool,
    pub observed: String,
    pub expected: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntityTrace {
    pub key_column: String,
    pub key_value: String,
    pub role: String, // "typical" | "fanout (Nx)" | "dropped"
    pub base_row: Option<serde_json::Value>,
    pub final_rows: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
enum ParsedAssertion {
    Unique(String),
    NotNull(String),
    CompareMetric {
        metric: MetricExpr,
        op: CmpOp,
        rhs: RhsVal,
    },
}

#[derive(Debug, Clone)]
enum MetricExpr {
    FinalRows,
    CountDistinct(String),
    Sum(String),
    Avg(String),
    Min(String),
    Max(String),
}

#[derive(Debug, Clone, Copy)]
enum CmpOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone)]
enum RhsVal {
    BaseRows,
    Number(f64),
}

fn parse_assertion(raw: &str) -> Result<ParsedAssertion> {
    let s = raw.trim();
    let lower = s.to_ascii_lowercase();
    if let Some(col) = extract_fn_arg(s, "unique") {
        return Ok(ParsedAssertion::Unique(col));
    }
    if let Some(col) = extract_fn_arg(s, "not_null") {
        return Ok(ParsedAssertion::NotNull(col));
    }

    for (tok, op) in [
        ("==", CmpOp::Eq),
        ("!=", CmpOp::Ne),
        (">=", CmpOp::Ge),
        ("<=", CmpOp::Le),
        (">", CmpOp::Gt),
        ("<", CmpOp::Lt),
    ] {
        if let Some((lhs, rhs)) = s.split_once(tok) {
            let metric = parse_metric(lhs.trim())?;
            let rhs_trim = rhs.trim();
            let rhs_val = if rhs_trim.eq_ignore_ascii_case("base_rows") {
                RhsVal::BaseRows
            } else if let Ok(n) = rhs_trim.parse::<f64>() {
                RhsVal::Number(n)
            } else {
                return Err(StatkeelError::config(
                    format!("Invalid assertion right-hand value `{rhs_trim}` in `{raw}`"),
                    "Use a number or `base_rows` (e.g., `final_rows == base_rows`, `sum(credits) <= 10000`).",
                ));
            };
            return Ok(ParsedAssertion::CompareMetric {
                metric,
                op,
                rhs: rhs_val,
            });
        }
    }

    let _ = lower;
    Err(StatkeelError::config(
        format!("Invalid --assert expression `{raw}`"),
        "Supported forms: `unique(col)`, `not_null(col)`, `final_rows == base_rows`, `count_distinct(col) == base_rows`, `sum(col) <= 1000`, `avg(col) >= 2.0`, `min(col) >= 0`, `max(col) <= 4.0`.",
    ))
}

fn extract_fn_arg(s: &str, name: &str) -> Option<String> {
    let low = s.to_ascii_lowercase();
    let pref = format!("{name}(");
    if low.starts_with(&pref) && s.ends_with(')') {
        let arg = s[pref.len()..s.len() - 1].trim().trim_matches('"');
        if !arg.is_empty() && is_safe_col(arg) {
            return Some(arg.to_string());
        }
    }
    None
}

fn parse_metric(s: &str) -> Result<MetricExpr> {
    if s.eq_ignore_ascii_case("final_rows") {
        return Ok(MetricExpr::FinalRows);
    }
    if let Some(c) = extract_fn_arg(s, "count_distinct") {
        return Ok(MetricExpr::CountDistinct(c));
    }
    if let Some(c) = extract_fn_arg(s, "sum") {
        return Ok(MetricExpr::Sum(c));
    }
    if let Some(c) = extract_fn_arg(s, "avg") {
        return Ok(MetricExpr::Avg(c));
    }
    if let Some(c) = extract_fn_arg(s, "min") {
        return Ok(MetricExpr::Min(c));
    }
    if let Some(c) = extract_fn_arg(s, "max") {
        return Ok(MetricExpr::Max(c));
    }
    Err(StatkeelError::config(
        format!("Unknown assertion metric `{s}`"),
        "Use `final_rows`, `count_distinct(col)`, `sum(col)`, `avg(col)`, `min(col)`, or `max(col)`.",
    ))
}

fn is_safe_col(c: &str) -> bool {
    !c.is_empty() && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn cmp_f64(lhs: f64, op: CmpOp, rhs: f64) -> bool {
    const EPS: f64 = 1e-6;
    match op {
        CmpOp::Eq => (lhs - rhs).abs() <= EPS,
        CmpOp::Ne => (lhs - rhs).abs() > EPS,
        CmpOp::Gt => lhs > rhs + EPS,
        CmpOp::Ge => lhs + EPS >= rhs,
        CmpOp::Lt => lhs + EPS < rhs,
        CmpOp::Le => lhs <= rhs + EPS,
    }
}

fn op_str(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
        CmpOp::Gt => ">",
        CmpOp::Ge => ">=",
        CmpOp::Lt => "<",
        CmpOp::Le => "<=",
    }
}

pub fn run_assertions_postgres(
    tx: &mut postgres::Transaction,
    full_sql: &str,
    base_rows: Option<i64>,
    final_rows: i64,
    exprs: &[String],
    findings: &mut Vec<AuditFinding>,
) -> Result<Vec<AssertionResult>> {
    let mut out = Vec::with_capacity(exprs.len());
    for raw in exprs {
        let parsed = parse_assertion(raw)?;
        let res = eval_assertion_pg(tx, full_sql, base_rows, final_rows, raw, &parsed);
        if !res.passed {
            findings.push(AuditFinding {
                code: "A001_ASSERTION_FAILED".to_string(),
                category: "assertion".to_string(),
                severity: FindingSeverity::High,
                message: format!(
                    "Accounting invariant failed: `{}` (observed {}, expected {}).",
                    res.expr, res.observed, res.expected
                ),
                fix_hint: "Inspect the row-count waterfall and entity traces to see why the invariant was violated.".to_string(),
            });
        }
        out.push(res);
    }
    Ok(out)
}

fn pg_scalar_f64(
    tx: &mut postgres::Transaction,
    sql: &str,
) -> std::result::Result<Option<f64>, String> {
    let _ = tx.batch_execute("SAVEPOINT _sk_asrt;");
    match tx.query_one(sql, &[]) {
        Ok(row) => {
            let _ = tx.batch_execute("RELEASE SAVEPOINT _sk_asrt;");
            Ok(row.get::<_, Option<f64>>(0))
        }
        Err(e) => {
            let _ = tx.batch_execute("ROLLBACK TO SAVEPOINT _sk_asrt;");
            Err(e.to_string())
        }
    }
}

fn eval_assertion_pg(
    tx: &mut postgres::Transaction,
    full_sql: &str,
    base_rows: Option<i64>,
    final_rows: i64,
    raw: &str,
    parsed: &ParsedAssertion,
) -> AssertionResult {
    match parsed {
        ParsedAssertion::Unique(col) => {
            let q = format!(
                "SELECT (COUNT(*) - COUNT(DISTINCT \"{col}\"))::double precision FROM ({full_sql}) AS _sk_a"
            );
            match pg_scalar_f64(tx, &q) {
                Ok(Some(dups)) => AssertionResult {
                    expr: raw.to_string(),
                    passed: dups.abs() < 1e-6,
                    observed: format!("{} duplicate row(s)", dups.round() as i64),
                    expected: "0 duplicates".to_string(),
                },
                Ok(None) => AssertionResult {
                    expr: raw.to_string(),
                    passed: true,
                    observed: "0 duplicate row(s)".to_string(),
                    expected: "0 duplicates".to_string(),
                },
                Err(e) => AssertionResult {
                    expr: raw.to_string(),
                    passed: false,
                    observed: format!("query error: {e}"),
                    expected: "0 duplicates".to_string(),
                },
            }
        }
        ParsedAssertion::NotNull(col) => {
            let q = format!(
                "SELECT SUM(CASE WHEN \"{col}\" IS NULL THEN 1 ELSE 0 END)::double precision FROM ({full_sql}) AS _sk_a"
            );
            match pg_scalar_f64(tx, &q) {
                Ok(v) => {
                    let nulls = v.unwrap_or(0.0).round() as i64;
                    AssertionResult {
                        expr: raw.to_string(),
                        passed: nulls == 0,
                        observed: format!("{nulls} NULL(s)"),
                        expected: "0 NULLs".to_string(),
                    }
                }
                Err(e) => AssertionResult {
                    expr: raw.to_string(),
                    passed: false,
                    observed: format!("query error: {e}"),
                    expected: "0 NULLs".to_string(),
                },
            }
        }
        ParsedAssertion::CompareMetric { metric, op, rhs } => {
            let rhs_num = match rhs {
                RhsVal::BaseRows => match base_rows {
                    Some(b) => b as f64,
                    None => {
                        return AssertionResult {
                            expr: raw.to_string(),
                            passed: false,
                            observed: "base_rows unavailable".to_string(),
                            expected: raw.to_string(),
                        };
                    }
                },
                RhsVal::Number(n) => *n,
            };
            let obs_res = match metric {
                MetricExpr::FinalRows => Ok(Some(final_rows as f64)),
                MetricExpr::CountDistinct(c) => pg_scalar_f64(
                    tx,
                    &format!(
                        "SELECT COUNT(DISTINCT \"{c}\")::double precision FROM ({full_sql}) AS _sk_a"
                    ),
                ),
                MetricExpr::Sum(c) => pg_scalar_f64(
                    tx,
                    &format!(
                        "SELECT COALESCE(SUM(\"{c}\"), 0)::double precision FROM ({full_sql}) AS _sk_a"
                    ),
                ),
                MetricExpr::Avg(c) => pg_scalar_f64(
                    tx,
                    &format!("SELECT AVG(\"{c}\")::double precision FROM ({full_sql}) AS _sk_a"),
                ),
                MetricExpr::Min(c) => pg_scalar_f64(
                    tx,
                    &format!("SELECT MIN(\"{c}\")::double precision FROM ({full_sql}) AS _sk_a"),
                ),
                MetricExpr::Max(c) => pg_scalar_f64(
                    tx,
                    &format!("SELECT MAX(\"{c}\")::double precision FROM ({full_sql}) AS _sk_a"),
                ),
            };
            let expected = format!("{} {}", op_str(*op), fmt_num(rhs_num));
            match obs_res {
                Ok(Some(v)) => AssertionResult {
                    expr: raw.to_string(),
                    passed: cmp_f64(v, *op, rhs_num),
                    observed: fmt_num(v),
                    expected,
                },
                Ok(None) => AssertionResult {
                    expr: raw.to_string(),
                    passed: false,
                    observed: "NULL".to_string(),
                    expected,
                },
                Err(e) => AssertionResult {
                    expr: raw.to_string(),
                    passed: false,
                    observed: format!("query error: {e}"),
                    expected,
                },
            }
        }
    }
}

pub fn run_assertions_sqlite(
    conn: &SqliteConn,
    full_sql: &str,
    base_rows: Option<i64>,
    final_rows: i64,
    exprs: &[String],
    findings: &mut Vec<AuditFinding>,
) -> Result<Vec<AssertionResult>> {
    let mut out = Vec::with_capacity(exprs.len());
    for raw in exprs {
        let parsed = parse_assertion(raw)?;
        let res = eval_assertion_sqlite(conn, full_sql, base_rows, final_rows, raw, &parsed);
        if !res.passed {
            findings.push(AuditFinding {
                code: "A001_ASSERTION_FAILED".to_string(),
                category: "assertion".to_string(),
                severity: FindingSeverity::High,
                message: format!(
                    "Accounting invariant failed: `{}` (observed {}, expected {}).",
                    res.expr, res.observed, res.expected
                ),
                fix_hint: "Inspect the row-count waterfall and entity traces to see why the invariant was violated.".to_string(),
            });
        }
        out.push(res);
    }
    Ok(out)
}

fn sqlite_scalar_f64(conn: &SqliteConn, sql: &str) -> std::result::Result<Option<f64>, String> {
    conn.query_row(sql, [], |r| r.get::<_, Option<f64>>(0))
        .map_err(|e| e.to_string())
}

fn eval_assertion_sqlite(
    conn: &SqliteConn,
    full_sql: &str,
    base_rows: Option<i64>,
    final_rows: i64,
    raw: &str,
    parsed: &ParsedAssertion,
) -> AssertionResult {
    match parsed {
        ParsedAssertion::Unique(col) => {
            let q = format!(
                "SELECT CAST((COUNT(*) - COUNT(DISTINCT \"{col}\")) AS REAL) FROM ({full_sql}) AS _sk_a"
            );
            match sqlite_scalar_f64(conn, &q) {
                Ok(v) => {
                    let dups = v.unwrap_or(0.0).round() as i64;
                    AssertionResult {
                        expr: raw.to_string(),
                        passed: dups == 0,
                        observed: format!("{dups} duplicate row(s)"),
                        expected: "0 duplicates".to_string(),
                    }
                }
                Err(e) => AssertionResult {
                    expr: raw.to_string(),
                    passed: false,
                    observed: format!("query error: {e}"),
                    expected: "0 duplicates".to_string(),
                },
            }
        }
        ParsedAssertion::NotNull(col) => {
            let q = format!(
                "SELECT CAST(COALESCE(SUM(CASE WHEN \"{col}\" IS NULL THEN 1 ELSE 0 END), 0) AS REAL) FROM ({full_sql}) AS _sk_a"
            );
            match sqlite_scalar_f64(conn, &q) {
                Ok(v) => {
                    let nulls = v.unwrap_or(0.0).round() as i64;
                    AssertionResult {
                        expr: raw.to_string(),
                        passed: nulls == 0,
                        observed: format!("{nulls} NULL(s)"),
                        expected: "0 NULLs".to_string(),
                    }
                }
                Err(e) => AssertionResult {
                    expr: raw.to_string(),
                    passed: false,
                    observed: format!("query error: {e}"),
                    expected: "0 NULLs".to_string(),
                },
            }
        }
        ParsedAssertion::CompareMetric { metric, op, rhs } => {
            let rhs_num = match rhs {
                RhsVal::BaseRows => match base_rows {
                    Some(b) => b as f64,
                    None => {
                        return AssertionResult {
                            expr: raw.to_string(),
                            passed: false,
                            observed: "base_rows unavailable".to_string(),
                            expected: raw.to_string(),
                        };
                    }
                },
                RhsVal::Number(n) => *n,
            };
            let obs_res = match metric {
                MetricExpr::FinalRows => Ok(Some(final_rows as f64)),
                MetricExpr::CountDistinct(c) => sqlite_scalar_f64(
                    conn,
                    &format!(
                        "SELECT CAST(COUNT(DISTINCT \"{c}\") AS REAL) FROM ({full_sql}) AS _sk_a"
                    ),
                ),
                MetricExpr::Sum(c) => sqlite_scalar_f64(
                    conn,
                    &format!(
                        "SELECT CAST(COALESCE(SUM(\"{c}\"), 0) AS REAL) FROM ({full_sql}) AS _sk_a"
                    ),
                ),
                MetricExpr::Avg(c) => sqlite_scalar_f64(
                    conn,
                    &format!("SELECT CAST(AVG(\"{c}\") AS REAL) FROM ({full_sql}) AS _sk_a"),
                ),
                MetricExpr::Min(c) => sqlite_scalar_f64(
                    conn,
                    &format!("SELECT CAST(MIN(\"{c}\") AS REAL) FROM ({full_sql}) AS _sk_a"),
                ),
                MetricExpr::Max(c) => sqlite_scalar_f64(
                    conn,
                    &format!("SELECT CAST(MAX(\"{c}\") AS REAL) FROM ({full_sql}) AS _sk_a"),
                ),
            };
            let expected = format!("{} {}", op_str(*op), fmt_num(rhs_num));
            match obs_res {
                Ok(Some(v)) => AssertionResult {
                    expr: raw.to_string(),
                    passed: cmp_f64(v, *op, rhs_num),
                    observed: fmt_num(v),
                    expected,
                },
                Ok(None) => AssertionResult {
                    expr: raw.to_string(),
                    passed: false,
                    observed: "NULL".to_string(),
                    expected,
                },
                Err(e) => AssertionResult {
                    expr: raw.to_string(),
                    passed: false,
                    observed: format!("query error: {e}"),
                    expected,
                },
            }
        }
    }
}

/// Trace up to 3 representative entities (typical, fan-out/multi-row, dropped/orphan) on PostgreSQL.
pub fn trace_entities_postgres(
    tx: &mut postgres::Transaction,
    cte_prefix: &str,
    base_rel: Option<&str>,
    full_sql: &str,
    trace_key: &str,
) -> Result<Vec<EntityTrace>> {
    if !is_safe_col(trace_key) {
        return Err(StatkeelError::config(
            format!("Invalid --trace-key `{trace_key}`"),
            "Pass a simple column name present in both the base table and query output (e.g. `person_id`).",
        ));
    }

    let mut targets: Vec<(String, String)> = Vec::new(); // (key_val, role)

    // 1. Find a fan-out / duplicate entity in final output (if any!)
    let dup_q = format!(
        "SELECT CAST(\"{trace_key}\" AS TEXT), COUNT(*) FROM ({full_sql}) AS _sk_f WHERE \"{trace_key}\" IS NOT NULL GROUP BY 1 HAVING COUNT(*) > 1 ORDER BY 2 DESC, 1 ASC LIMIT 1"
    );
    let _ = tx.batch_execute("SAVEPOINT _sk_tr1;");
    if let Ok(row) = tx.query_one(&dup_q, &[]) {
        let k: String = row.get(0);
        let c: i64 = row.get(1);
        targets.push((k, format!("fanout ({c}x)")));
        let _ = tx.batch_execute("RELEASE SAVEPOINT _sk_tr1;");
    } else {
        let _ = tx.batch_execute("ROLLBACK TO SAVEPOINT _sk_tr1;");
    }

    // 2. Find a dropped / orphan entity present in base table but absent from final output!
    if let Some(base) = base_rel {
        let drop_q = format!(
            "{cte_prefix}SELECT CAST(_b.\"{trace_key}\" AS TEXT) FROM (SELECT * FROM {base}) AS _b WHERE _b.\"{trace_key}\" IS NOT NULL AND NOT EXISTS (SELECT 1 FROM ({full_sql}) AS _f WHERE CAST(_f.\"{trace_key}\" AS TEXT) = CAST(_b.\"{trace_key}\" AS TEXT)) LIMIT 1"
        );
        let _ = tx.batch_execute("SAVEPOINT _sk_tr2;");
        if let Ok(row) = tx.query_one(&drop_q, &[]) {
            let k: String = row.get(0);
            if !targets.iter().any(|(x, _)| x == &k) {
                targets.push((k, "dropped".to_string()));
            }
            let _ = tx.batch_execute("RELEASE SAVEPOINT _sk_tr2;");
        } else {
            let _ = tx.batch_execute("ROLLBACK TO SAVEPOINT _sk_tr2;");
        }
    }

    // 3. Fill up to 3 traces with typical matched 1x entities
    let typ_q = format!(
        "SELECT CAST(\"{trace_key}\" AS TEXT) FROM ({full_sql}) AS _sk_f WHERE \"{trace_key}\" IS NOT NULL GROUP BY 1 HAVING COUNT(*) = 1 ORDER BY 1 ASC LIMIT 3"
    );
    let _ = tx.batch_execute("SAVEPOINT _sk_tr3;");
    if let Ok(rows) = tx.query(&typ_q, &[]) {
        for r in rows {
            if targets.len() >= 3 {
                break;
            }
            let k: String = r.get(0);
            if !targets.iter().any(|(x, _)| x == &k) {
                targets.push((k, "typical".to_string()));
            }
        }
        let _ = tx.batch_execute("RELEASE SAVEPOINT _sk_tr3;");
    } else {
        let _ = tx.batch_execute("ROLLBACK TO SAVEPOINT _sk_tr3;");
    }

    let mut traces = Vec::with_capacity(targets.len());
    for (kval, role) in targets {
        let escaped_k = kval.replace('\'', "''");
        let base_row = if let Some(base) = base_rel {
            let bq = format!(
                "{cte_prefix}SELECT row_to_json(_b)::text FROM (SELECT * FROM {base}) AS _b WHERE CAST(_b.\"{trace_key}\" AS TEXT) = '{escaped_k}' LIMIT 1"
            );
            let _ = tx.batch_execute("SAVEPOINT _sk_trb;");
            match tx.query_opt(&bq, &[]) {
                Ok(Some(r)) => {
                    let _ = tx.batch_execute("RELEASE SAVEPOINT _sk_trb;");
                    serde_json::from_str(&r.get::<_, String>(0)).ok()
                }
                _ => {
                    let _ = tx.batch_execute("ROLLBACK TO SAVEPOINT _sk_trb;");
                    None
                }
            }
        } else {
            None
        };

        let fq = format!(
            "SELECT row_to_json(_f)::text FROM ({full_sql}) AS _f WHERE CAST(_f.\"{trace_key}\" AS TEXT) = '{escaped_k}' LIMIT 5"
        );
        let _ = tx.batch_execute("SAVEPOINT _sk_trf;");
        let mut final_rows = Vec::new();
        if let Ok(rows) = tx.query(&fq, &[]) {
            for r in rows {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(0)) {
                    final_rows.push(v);
                }
            }
            let _ = tx.batch_execute("RELEASE SAVEPOINT _sk_trf;");
        } else {
            let _ = tx.batch_execute("ROLLBACK TO SAVEPOINT _sk_trf;");
        }

        traces.push(EntityTrace {
            key_column: trace_key.to_string(),
            key_value: kval,
            role,
            base_row,
            final_rows,
        });
    }

    Ok(traces)
}

/// Trace up to 3 representative entities (typical, fan-out/multi-row, dropped/orphan) on SQLite.
pub fn trace_entities_sqlite(
    conn: &SqliteConn,
    cte_prefix: &str,
    base_rel: Option<&str>,
    full_sql: &str,
    trace_key: &str,
) -> Result<Vec<EntityTrace>> {
    if !is_safe_col(trace_key) {
        return Err(StatkeelError::config(
            format!("Invalid --trace-key `{trace_key}`"),
            "Pass a simple column name present in both the base table and query output.",
        ));
    }

    let mut targets: Vec<(String, String)> = Vec::new();

    // 1. Fan-out / duplicate entity
    let dup_q = format!(
        "SELECT CAST(\"{trace_key}\" AS TEXT), COUNT(*) FROM ({full_sql}) AS _sk_f WHERE \"{trace_key}\" IS NOT NULL GROUP BY 1 HAVING COUNT(*) > 1 ORDER BY 2 DESC, 1 ASC LIMIT 1"
    );
    if let Ok((k, c)) = conn.query_row(&dup_q, [], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    }) {
        targets.push((k, format!("fanout ({c}x)")));
    }

    // 2. Dropped / orphan entity from base table
    if let Some(base) = base_rel {
        let drop_q = format!(
            "{cte_prefix}SELECT CAST(_b.\"{trace_key}\" AS TEXT) FROM (SELECT * FROM {base}) AS _b WHERE _b.\"{trace_key}\" IS NOT NULL AND NOT EXISTS (SELECT 1 FROM ({full_sql}) AS _f WHERE CAST(_f.\"{trace_key}\" AS TEXT) = CAST(_b.\"{trace_key}\" AS TEXT)) LIMIT 1"
        );
        if let Ok(k) = conn.query_row(&drop_q, [], |r| r.get::<_, String>(0))
            && !targets.iter().any(|(x, _)| x == &k)
        {
            targets.push((k, "dropped".to_string()));
        }
    }

    // 3. Typical matched entities
    let typ_q = format!(
        "SELECT CAST(\"{trace_key}\" AS TEXT) FROM ({full_sql}) AS _sk_f WHERE \"{trace_key}\" IS NOT NULL GROUP BY 1 HAVING COUNT(*) = 1 ORDER BY 1 ASC LIMIT 3"
    );
    if let Ok(mut stmt) = conn.prepare(&typ_q)
        && let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0))
    {
        for k in rows.flatten() {
            if targets.len() >= 3 {
                break;
            }
            if !targets.iter().any(|(x, _)| x == &k) {
                targets.push((k, "typical".to_string()));
            }
        }
    }

    let mut traces = Vec::with_capacity(targets.len());
    for (kval, role) in targets {
        let escaped_k = kval.replace('\'', "''");
        let base_row = base_rel.and_then(|base| {
            let bq = format!(
                "{cte_prefix}SELECT * FROM (SELECT * FROM {base}) AS _b WHERE CAST(_b.\"{trace_key}\" AS TEXT) = '{escaped_k}' LIMIT 1"
            );
            sqlite_rows_as_json(conn, &bq).into_iter().next()
        });
        let fq = format!(
            "SELECT * FROM ({full_sql}) AS _f WHERE CAST(_f.\"{trace_key}\" AS TEXT) = '{escaped_k}' LIMIT 5"
        );
        let final_rows = sqlite_rows_as_json(conn, &fq);
        traces.push(EntityTrace {
            key_column: trace_key.to_string(),
            key_value: kval,
            role,
            base_row,
            final_rows,
        });
    }

    Ok(traces)
}

fn sqlite_rows_as_json(conn: &SqliteConn, sql: &str) -> Vec<serde_json::Value> {
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut out = Vec::new();
    if let Ok(mut rows) = stmt.query([]) {
        while let Ok(Some(r)) = rows.next() {
            let mut map = serde_json::Map::new();
            for (i, c) in cols.iter().enumerate() {
                let cell = match r.get_ref_unwrap(i) {
                    ValueRef::Null => CellValue::Null,
                    ValueRef::Integer(v) => CellValue::Int(v),
                    ValueRef::Real(v) => CellValue::Float(v),
                    ValueRef::Text(b) => CellValue::Str(String::from_utf8_lossy(b).to_string()),
                    ValueRef::Blob(b) => CellValue::Str(format!("<blob {}B>", b.len())),
                };
                map.insert(c.clone(), cell.to_json_value());
            }
            out.push(serde_json::Value::Object(map));
        }
    }
    out
}

fn fmt_num(v: f64) -> String {
    if (v.fract()).abs() < 1e-9 {
        format!("{}", v.round() as i64)
    } else {
        format!("{v:.4}")
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }
}
