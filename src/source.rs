use crate::error::{Result, StatkeelError};
use indexmap::IndexSet;
use native_tls::TlsConnector;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field;
use postgres::{Client as PgClient, NoTls};
use postgres_native_tls::MakeTlsConnector;
use rusqlite::{Connection as SqliteConn, OpenFlags, types::ValueRef};
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use url::Url;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CellValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl CellValue {
    pub fn as_key_string(&self) -> Option<String> {
        match self {
            Self::Null => None,
            Self::Bool(b) => Some(b.to_string()),
            Self::Int(i) => Some(i.to_string()),
            Self::Float(f) => {
                if f.is_finite() {
                    Some(format!("{f}"))
                } else {
                    None
                }
            }
            Self::Str(s) => {
                if s.is_empty() {
                    None
                } else {
                    Some(s.clone())
                }
            }
        }
    }

    pub fn display_compact(&self) -> String {
        match self {
            Self::Null => "NULL".to_string(),
            Self::Bool(b) => b.to_string(),
            Self::Int(i) => i.to_string(),
            Self::Float(f) => format!("{f:.4}")
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string(),
            Self::Str(s) => s.clone(),
        }
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(b) => serde_json::Value::Bool(*b),
            Self::Int(i) => serde_json::json!(*i),
            Self::Float(f) => serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            Self::Str(s) => serde_json::Value::String(s.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TableData {
    pub name: String,
    pub source_kind: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<CellValue>>,
    pub sampled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    pub table: Option<String>,
    pub query: Option<String>,
    pub limit: Option<usize>,
    pub timeout_secs: u64,
}

impl LoadOptions {
    pub fn with_defaults(
        table: Option<String>,
        query: Option<String>,
        limit: Option<usize>,
        timeout_secs: u64,
    ) -> Self {
        Self {
            table,
            query,
            limit,
            timeout_secs: if timeout_secs == 0 { 30 } else { timeout_secs },
        }
    }
}

pub fn load_source(spec: &str, opts: &LoadOptions) -> Result<TableData> {
    if spec.starts_with("postgres://") || spec.starts_with("postgresql://") {
        load_postgres(spec, opts)
    } else if spec.starts_with("sqlite://") || is_sqlite_spec(spec) {
        load_sqlite(spec, opts)
    } else {
        let lower = spec.to_lowercase();
        if lower.ends_with(".parquet") || lower.ends_with(".pq") {
            load_parquet(spec, opts.limit)
        } else if lower.ends_with(".jsonl") || lower.ends_with(".ndjson") {
            load_jsonl(spec, opts.limit)
        } else if lower.ends_with(".json") {
            load_json(spec, opts.limit)
        } else if lower.ends_with(".tsv") {
            load_delimited(spec, b'\t', "tsv", opts.limit)
        } else if lower.ends_with(".csv") {
            load_delimited(spec, b',', "csv", opts.limit)
        } else {
            Err(StatkeelError::source(
                format!("Unsupported or unrecognized data source `{spec}`"),
                "Pass a .csv, .tsv, .jsonl, .json, .parquet, sqlite:///path.db#table, or postgres://...#schema.table source.",
            ))
        }
    }
}

fn is_sqlite_spec(spec: &str) -> bool {
    let base = spec.split("::").next().unwrap_or(spec);
    let base = base.split('#').next().unwrap_or(base);
    let lower = base.to_lowercase();
    lower.ends_with(".db") || lower.ends_with(".sqlite") || lower.ends_with(".sqlite3")
}

/// Parse CSV/TSV cell while preserving leading-zero numeric strings (e.g. `"001234"`)
/// so join key hazards are never silently erased.
pub fn parse_csv_cell(raw: &str) -> CellValue {
    if raw.is_empty() {
        return CellValue::Null;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return CellValue::Str(raw.to_string());
    }
    // Preserve whitespace-padded strings so profile/join can flag WHITESPACE_PADDING!
    if trimmed.len() != raw.len() {
        return CellValue::Str(raw.to_string());
    }
    let lower = raw.to_ascii_lowercase();
    if lower == "null" || lower == "none" || lower == "na" || lower == "n/a" || lower == "nan" {
        return CellValue::Null;
    }
    if lower == "true" {
        return CellValue::Bool(true);
    }
    if lower == "false" {
        return CellValue::Bool(false);
    }
    // Preserve leading-zero numeric IDs like "001234" as strings!
    let unsigned = raw.strip_prefix('-').unwrap_or(raw);
    if unsigned.len() > 1
        && unsigned.starts_with('0')
        && unsigned.bytes().all(|b| b.is_ascii_digit())
    {
        return CellValue::Str(raw.to_string());
    }
    if let Ok(i) = raw.parse::<i64>() {
        return CellValue::Int(i);
    }
    if let Ok(f) = raw.parse::<f64>()
        && f.is_finite()
    {
        return CellValue::Float(f);
    }
    CellValue::Str(raw.to_string())
}

fn json_to_cell(v: &serde_json::Value) -> CellValue {
    match v {
        serde_json::Value::Null => CellValue::Null,
        serde_json::Value::Bool(b) => CellValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CellValue::Int(i)
            } else if let Some(u) = n.as_u64() {
                if let Ok(i) = i64::try_from(u) {
                    CellValue::Int(i)
                } else {
                    CellValue::Float(u as f64)
                }
            } else if let Some(f) = n.as_f64() {
                CellValue::Float(f)
            } else {
                CellValue::Str(n.to_string())
            }
        }
        serde_json::Value::String(s) => CellValue::Str(s.clone()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => CellValue::Str(v.to_string()),
    }
}

fn load_delimited(
    path: &str,
    delimiter: u8,
    kind: &str,
    limit: Option<usize>,
) -> Result<TableData> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .from_path(path)
        .map_err(|e| StatkeelError::io(e, path))?;

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| {
            StatkeelError::source(
                format!("Failed reading headers from `{path}`: {e}"),
                "Ensure the file has a valid header row.",
            )
        })?
        .iter()
        .map(|s| s.to_string())
        .collect();

    let mut rows = Vec::new();
    let mut sampled = false;
    for rec in reader.records() {
        if let Some(max_rows) = limit
            && rows.len() >= max_rows
        {
            sampled = true;
            break;
        }
        let rec = rec.map_err(|e| {
            StatkeelError::source(
                format!("CSV parse error in `{path}`: {e}"),
                "Check quoting and delimiters in the file.",
            )
        })?;
        let mut row = Vec::with_capacity(headers.len());
        for i in 0..headers.len() {
            let cell = rec.get(i).map(parse_csv_cell).unwrap_or(CellValue::Null);
            row.push(cell);
        }
        rows.push(row);
    }

    let name = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string();

    Ok(TableData {
        name,
        source_kind: kind.to_string(),
        columns: headers,
        rows,
        sampled,
    })
}

fn load_jsonl(path: &str, limit: Option<usize>) -> Result<TableData> {
    let file = File::open(path).map_err(|e| StatkeelError::io(e, path))?;
    let reader = BufReader::new(file);
    let mut objects: Vec<serde_json::Map<String, serde_json::Value>> = Vec::new();
    let mut col_set: IndexSet<String> = IndexSet::new();
    let mut sampled = false;

    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| StatkeelError::io(e, path))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(max_rows) = limit
            && objects.len() >= max_rows
        {
            sampled = true;
            break;
        }
        let val: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
            StatkeelError::source(
                format!("Invalid JSON on line {} of `{path}`: {e}", idx + 1),
                "Ensure each non-empty line is a valid JSON object.",
            )
        })?;
        let obj = val.as_object().ok_or_else(|| {
            StatkeelError::source(
                format!("Line {} of `{path}` is not a JSON object", idx + 1),
                "JSONL files must contain one JSON object per line.",
            )
        })?;
        for k in obj.keys() {
            col_set.insert(k.clone());
        }
        objects.push(obj.clone());
    }

    let columns: Vec<String> = col_set.into_iter().collect();
    let rows = objects
        .into_iter()
        .map(|obj| {
            columns
                .iter()
                .map(|c| obj.get(c).map(json_to_cell).unwrap_or(CellValue::Null))
                .collect()
        })
        .collect();

    let name = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string();

    Ok(TableData {
        name,
        source_kind: "jsonl".to_string(),
        columns,
        rows,
        sampled,
    })
}

fn load_json(path: &str, limit: Option<usize>) -> Result<TableData> {
    let raw = std::fs::read_to_string(path).map_err(|e| StatkeelError::io(e, path))?;
    let val: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        StatkeelError::source(
            format!("Invalid JSON in `{path}`: {e}"),
            "Provide a valid JSON array of objects or use .jsonl for newline-delimited JSON.",
        )
    })?;
    let arr = val.as_array().ok_or_else(|| {
        StatkeelError::source(
            format!("Top-level JSON in `{path}` must be an array of objects"),
            "Wrap records in a JSON array `[...]` or use .jsonl format.",
        )
    })?;

    let mut col_set: IndexSet<String> = IndexSet::new();
    let mut objects = Vec::new();
    let mut sampled = false;
    for (idx, item) in arr.iter().enumerate() {
        if let Some(max_rows) = limit
            && objects.len() >= max_rows
        {
            sampled = true;
            break;
        }
        let obj = item.as_object().ok_or_else(|| {
            StatkeelError::source(
                format!("Element {idx} in `{path}` is not a JSON object"),
                "Every element in the JSON array must be an object.",
            )
        })?;
        for k in obj.keys() {
            col_set.insert(k.clone());
        }
        objects.push(obj);
    }

    let columns: Vec<String> = col_set.into_iter().collect();
    let rows = objects
        .into_iter()
        .map(|obj| {
            columns
                .iter()
                .map(|c| obj.get(c).map(json_to_cell).unwrap_or(CellValue::Null))
                .collect()
        })
        .collect();

    let name = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string();

    Ok(TableData {
        name,
        source_kind: "json".to_string(),
        columns,
        rows,
        sampled,
    })
}

fn parquet_field_to_cell(field: &Field) -> CellValue {
    match field {
        Field::Null => CellValue::Null,
        Field::Bool(b) => CellValue::Bool(*b),
        Field::Byte(v) => CellValue::Int(*v as i64),
        Field::Short(v) => CellValue::Int(*v as i64),
        Field::Int(v) => CellValue::Int(*v as i64),
        Field::Long(v) => CellValue::Int(*v),
        Field::UByte(v) => CellValue::Int(*v as i64),
        Field::UShort(v) => CellValue::Int(*v as i64),
        Field::UInt(v) => CellValue::Int(*v as i64),
        Field::ULong(v) => i64::try_from(*v)
            .map(CellValue::Int)
            .unwrap_or(CellValue::Float(*v as f64)),
        Field::Float(v) => CellValue::Float(*v as f64),
        Field::Double(v) => CellValue::Float(*v),
        Field::Str(s) => CellValue::Str(s.clone()),
        other => CellValue::Str(other.to_string()),
    }
}

fn load_parquet(path: &str, limit: Option<usize>) -> Result<TableData> {
    let file = File::open(path).map_err(|e| StatkeelError::io(e, path))?;
    let reader = SerializedFileReader::new(file).map_err(|e| {
        StatkeelError::source(
            format!("Failed reading Parquet file `{path}`: {e}"),
            "Ensure the file is a valid Apache Parquet file.",
        )
    })?;

    let schema = reader.metadata().file_metadata().schema_descr();
    let columns: Vec<String> = schema
        .root_schema()
        .get_fields()
        .iter()
        .map(|f| f.name().to_string())
        .collect();

    let iter = reader.get_row_iter(None).map_err(|e| {
        StatkeelError::source(
            format!("Failed iterating Parquet rows in `{path}`: {e}"),
            "Check Parquet schema compatibility.",
        )
    })?;

    let mut rows = Vec::new();
    let mut sampled = false;
    for row_res in iter {
        if let Some(max_rows) = limit
            && rows.len() >= max_rows
        {
            sampled = true;
            break;
        }
        let rec = row_res.map_err(|e| {
            StatkeelError::source(
                format!("Parquet row error in `{path}`: {e}"),
                "The Parquet file may be corrupted.",
            )
        })?;
        let mut out_row = Vec::with_capacity(columns.len());
        for (_, field) in rec.get_column_iter() {
            out_row.push(parquet_field_to_cell(field));
        }
        rows.push(out_row);
    }

    let name = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string();

    Ok(TableData {
        name,
        source_kind: "parquet".to_string(),
        columns,
        rows,
        sampled,
    })
}

pub fn split_sqlite_spec(spec: &str, table_opt: Option<&str>) -> Result<(String, Option<String>)> {
    let stripped = spec.strip_prefix("sqlite://").unwrap_or(spec);
    if let Some((path, tbl)) = stripped.split_once('#') {
        return Ok((path.to_string(), Some(tbl.to_string())));
    }
    if let Some((path, tbl)) = stripped.split_once("::") {
        return Ok((path.to_string(), Some(tbl.to_string())));
    }
    Ok((stripped.to_string(), table_opt.map(|s| s.to_string())))
}

pub fn quote_ident(name: &str) -> Result<String> {
    if name.trim().is_empty() {
        return Err(StatkeelError::config(
            "Empty table identifier",
            "Provide a valid table name (e.g. `schema.table` or `users`).",
        ));
    }
    let parts: Vec<String> = name
        .split('.')
        .map(|part| {
            let clean = part.trim().trim_matches('"');
            format!("\"{}\"", clean.replace('"', "\"\""))
        })
        .collect();
    Ok(parts.join("."))
}

fn load_sqlite(spec: &str, opts: &LoadOptions) -> Result<TableData> {
    let (path, spec_table) = split_sqlite_spec(spec, opts.table.as_deref())?;
    let conn =
        SqliteConn::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| {
            StatkeelError::db(
                format!("Failed opening SQLite database `{path}`: {e}"),
                "Verify the SQLite file exists and is readable.",
                false,
            )
        })?;

    let (sql, display_name) = if let Some(q) = &opts.query {
        (q.clone(), format!("sqlite:query({path})"))
    } else if let Some(tbl) = spec_table {
        let quoted = quote_ident(&tbl)?;
        let q = match opts.limit {
            Some(lim) => format!("SELECT * FROM {quoted} LIMIT {}", lim + 1),
            None => format!("SELECT * FROM {quoted}"),
        };
        (q, tbl)
    } else {
        return Err(StatkeelError::config(
            format!("SQLite source `{spec}` requires a table name or --query"),
            "Use `sqlite:///path/to.db#table_name` or pass `--table <name>`.",
        ));
    };

    let mut stmt = conn.prepare(&sql).map_err(|e| {
        StatkeelError::db(
            format!("SQLite query error: {e}"),
            "Check that the table or SQL query is valid in this SQLite database.",
            false,
        )
    })?;
    let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let col_count = columns.len();

    let mut rows = Vec::new();
    let mut sampled = false;
    let mut query_rows = stmt.query([]).map_err(|e| {
        StatkeelError::db(
            format!("SQLite execution error: {e}"),
            "Verify the SQLite query is a valid read-only SELECT.",
            false,
        )
    })?;

    while let Some(r) = query_rows.next().map_err(|e| {
        StatkeelError::db(
            format!("SQLite row read error: {e}"),
            "Check column types in the SQLite table.",
            false,
        )
    })? {
        if let Some(max_rows) = opts.limit
            && rows.len() >= max_rows
        {
            sampled = true;
            break;
        }
        let mut out = Vec::with_capacity(col_count);
        for i in 0..col_count {
            let cell = match r.get_ref_unwrap(i) {
                ValueRef::Null => CellValue::Null,
                ValueRef::Integer(v) => CellValue::Int(v),
                ValueRef::Real(v) => CellValue::Float(v),
                ValueRef::Text(bytes) => CellValue::Str(String::from_utf8_lossy(bytes).to_string()),
                ValueRef::Blob(bytes) => CellValue::Str(format!("<blob {}B>", bytes.len())),
            };
            out.push(cell);
        }
        rows.push(out);
    }

    Ok(TableData {
        name: display_name,
        source_kind: "sqlite".to_string(),
        columns,
        rows,
        sampled,
    })
}

pub fn connect_postgres(db_url: &str) -> Result<PgClient> {
    let clean_url = db_url.split('#').next().unwrap_or(db_url);
    let parsed = Url::parse(clean_url).map_err(|e| {
        StatkeelError::config(
            format!("Invalid PostgreSQL URL: {e}"),
            "Pass a valid URL like `postgres://user:pass@host:5432/dbname`.",
        )
    })?;

    let sslmode = parsed
        .query_pairs()
        .find(|(k, _)| k.eq_ignore_ascii_case("sslmode"))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    let host = parsed.host_str().unwrap_or("localhost");
    let is_local = host == "localhost" || host == "127.0.0.1" || host == "::1";

    let use_tls = match sslmode.as_str() {
        "disable" => false,
        "require" | "verify-ca" | "verify-full" => true,
        _ => !is_local,
    };

    if use_tls {
        let mut builder = TlsConnector::builder();
        if sslmode == "require" || sslmode.is_empty() {
            builder.danger_accept_invalid_certs(true);
        }
        let connector = builder.build().map_err(|e| {
            StatkeelError::db(
                format!("Failed initializing TLS connector: {e}"),
                "Check system TLS certificates or pass `?sslmode=disable` for local Postgres.",
                false,
            )
        })?;
        let tls = MakeTlsConnector::new(connector);
        PgClient::connect(clean_url, tls).map_err(|e| {
            StatkeelError::db(
                format!("PostgreSQL TLS connection failed: {e}"),
                "Verify host, port, credentials, and sslmode.",
                true,
            )
        })
    } else {
        PgClient::connect(clean_url, NoTls).map_err(|e| {
            StatkeelError::db(
                format!("PostgreSQL connection failed: {e}"),
                "Verify PostgreSQL is running and credentials/port are correct.",
                true,
            )
        })
    }
}

fn load_postgres(spec: &str, opts: &LoadOptions) -> Result<TableData> {
    let (url_part, frag_table) = match spec.split_once('#') {
        Some((u, t)) if !t.is_empty() => (u, Some(t.to_string())),
        _ => (spec, opts.table.clone()),
    };

    let (inner_sql, display_name) = if let Some(q) = &opts.query {
        let trimmed = q.trim().trim_end_matches(';');
        (trimmed.to_string(), "postgres:query".to_string())
    } else if let Some(tbl) = frag_table {
        let quoted = quote_ident(&tbl)?;
        (format!("SELECT * FROM {quoted}"), tbl)
    } else {
        return Err(StatkeelError::config(
            "PostgreSQL source requires `#schema.table`, `--table <schema.table>`, or `--query`",
            "Example: `statkeel profile postgres://user@host/db#public.users`",
        ));
    };

    let mut client = connect_postgres(url_part)?;
    let mut tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| {
            StatkeelError::db(
                format!("Failed starting READ ONLY transaction: {e}"),
                "Ensure the database user has SELECT permissions.",
                true,
            )
        })?;

    tx.batch_execute(&format!(
        "SET LOCAL statement_timeout = '{}s';",
        opts.timeout_secs
    ))
    .map_err(|e| {
        StatkeelError::db(
            format!("Failed setting statement_timeout: {e}"),
            "Check PostgreSQL session permissions.",
            false,
        )
    })?;

    // Discover exact column names & order even if result has 0 rows.
    let probe_sql = format!("SELECT * FROM ({inner_sql}) AS _sk_meta LIMIT 0");
    let stmt = tx.prepare(&probe_sql).map_err(|e| {
        StatkeelError::db(
            format!("PostgreSQL query failed: {e}"),
            "Verify the table exists and your user has SELECT privileges.",
            false,
        )
    })?;
    let columns: Vec<String> = stmt
        .columns()
        .iter()
        .map(|c| c.name().to_string())
        .collect();

    // Fetch every row via row_to_json(t)::text so NUMERIC, UUID, TIMESTAMPTZ, ENUM, etc. never fail decoding.
    let limited_sql = match opts.limit {
        Some(lim) => format!(
            "SELECT row_to_json(_sk_t)::text FROM ({inner_sql}) AS _sk_t LIMIT {}",
            lim + 1
        ),
        None => format!("SELECT row_to_json(_sk_t)::text FROM ({inner_sql}) AS _sk_t"),
    };

    let pg_rows = tx.query(&limited_sql, &[]).map_err(|e| {
        StatkeelError::db(
            format!("PostgreSQL execution failed: {e}"),
            "Verify the table/query is valid and finishes within --timeout-secs.",
            true,
        )
    })?;

    let mut rows = Vec::with_capacity(pg_rows.len());
    let mut sampled = false;
    for r in pg_rows {
        if let Some(max_rows) = opts.limit
            && rows.len() >= max_rows
        {
            sampled = true;
            break;
        }
        let json_str: String = r.get(0);
        let obj: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
            StatkeelError::source(
                format!("Failed decoding row_to_json payload: {e}"),
                "Report this as a statkeel bug.",
            )
        })?;
        let map = obj.as_object();
        let row = columns
            .iter()
            .map(|c| {
                map.and_then(|m| m.get(c))
                    .map(json_to_cell)
                    .unwrap_or(CellValue::Null)
            })
            .collect();
        rows.push(row);
    }

    let _ = tx.rollback();

    Ok(TableData {
        name: display_name,
        source_kind: "postgres".to_string(),
        columns,
        rows,
        sampled,
    })
}
