use crate::source::{CellValue, TableData};
use indexmap::IndexMap;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    High,
    Medium,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct QualityAlert {
    pub code: String,
    pub severity: AlertSeverity,
    pub column: Option<String>,
    pub message: String,
    pub fix_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistogramBin {
    pub start: f64,
    pub end: f64,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct NumericStats {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub std_dev: f64,
    pub skewness: f64,
    pub p5: f64,
    pub p25: f64,
    pub median: f64,
    pub p75: f64,
    pub p95: f64,
    pub iqr: f64,
    pub zeros_count: usize,
    pub zeros_pct: f64,
    pub negatives_count: usize,
    pub outlier_count: usize,
    pub outlier_pct: f64,
    pub histogram: Vec<HistogramBin>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValueCount {
    pub value: String,
    pub count: usize,
    pub pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringStats {
    pub min_len: usize,
    pub max_len: usize,
    pub mean_len: f64,
    pub empty_string_count: usize,
    pub whitespace_padded_count: usize,
    pub leading_zero_numeric_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ColumnProfile {
    pub name: String,
    pub inferred_type: String,
    pub non_null_count: usize,
    pub null_count: usize,
    pub null_pct: f64,
    pub distinct_count: usize,
    pub unique_pct: f64,
    pub is_unique: bool,
    pub is_constant: bool,
    pub pii_flags: Vec<String>,
    pub numeric: Option<NumericStats>,
    pub string: Option<StringStats>,
    pub top_values: Vec<ValueCount>,
    pub sample_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorrelationPair {
    pub col_a: String,
    pub col_b: String,
    pub pearson_r: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatasetProfile {
    pub dataset: String,
    pub source_kind: String,
    pub row_count: usize,
    pub column_count: usize,
    pub sampled: bool,
    pub duplicate_row_count: usize,
    pub duplicate_row_pct: f64,
    pub total_cells: usize,
    pub missing_cells: usize,
    pub missing_pct: f64,
    pub candidate_keys: Vec<String>,
    pub alerts: Vec<QualityAlert>,
    pub columns: Vec<ColumnProfile>,
    pub correlations: Vec<CorrelationPair>,
}

struct PatternDetectors {
    email: Regex,
    uuid: Regex,
    ssn: Regex,
    phone: Regex,
    url: Regex,
    iso_date: Regex,
    iso_timestamp: Regex,
}

fn detectors() -> &'static PatternDetectors {
    static DET: OnceLock<PatternDetectors> = OnceLock::new();
    DET.get_or_init(|| PatternDetectors {
        email: Regex::new(r"(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$").unwrap(),
        uuid: Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .unwrap(),
        ssn: Regex::new(r"^\d{3}-\d{2}-\d{4}$").unwrap(),
        phone: Regex::new(r"^(\+?1[-.\s]?)?(\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}$").unwrap(),
        url: Regex::new(r"(?i)^https?://\S+$").unwrap(),
        iso_date: Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap(),
        iso_timestamp: Regex::new(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap(),
    })
}

pub fn profile_table(table: &TableData) -> DatasetProfile {
    let row_count = table.rows.len();
    let column_count = table.columns.len();
    let total_cells = row_count * column_count;

    // Duplicate row detection via canonical serialized key.
    let mut seen_rows: HashSet<String> = HashSet::with_capacity(row_count);
    let mut duplicate_row_count = 0usize;
    for row in &table.rows {
        let mut key = String::new();
        for cell in row {
            key.push_str(&cell.display_compact());
            key.push('\u{1f}');
        }
        if !seen_rows.insert(key) {
            duplicate_row_count += 1;
        }
    }
    let duplicate_row_pct = pct(duplicate_row_count, row_count);

    let mut alerts: Vec<QualityAlert> = Vec::new();
    if duplicate_row_count > 0 {
        alerts.push(QualityAlert {
            code: "DUPLICATE_ROWS".to_string(),
            severity: if duplicate_row_pct >= 5.0 {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            },
            column: None,
            message: format!(
                "{duplicate_row_count} exact duplicate rows ({duplicate_row_pct:.2}%)"
            ),
            fix_hint: "Deduplicate upstream or verify primary key constraints before aggregating."
                .to_string(),
        });
    }

    let mut missing_cells = 0usize;
    let mut columns = Vec::with_capacity(column_count);
    let mut candidate_keys = Vec::new();
    let mut numeric_vectors: Vec<(String, Vec<Option<f64>>)> = Vec::new();

    for (col_idx, col_name) in table.columns.iter().enumerate() {
        let (col_prof, col_alerts, num_vec) =
            profile_column(col_name, &table.rows, col_idx, row_count);
        missing_cells += col_prof.null_count;
        if col_prof.is_unique && col_prof.null_count == 0 && row_count > 0 {
            candidate_keys.push(col_name.clone());
        }
        if let Some(v) = num_vec {
            numeric_vectors.push((col_name.clone(), v));
        }
        alerts.extend(col_alerts);
        columns.push(col_prof);
    }

    // Pairwise Pearson correlations across numeric columns (cap at first 20 numeric cols to stay instant).
    let mut correlations = Vec::new();
    let n_num = numeric_vectors.len().min(20);
    for i in 0..n_num {
        for j in (i + 1)..n_num {
            if let Some(r) = pearson(&numeric_vectors[i].1, &numeric_vectors[j].1) {
                correlations.push(CorrelationPair {
                    col_a: numeric_vectors[i].0.clone(),
                    col_b: numeric_vectors[j].0.clone(),
                    pearson_r: round4(r),
                });
                if r.abs() >= 0.85 {
                    alerts.push(QualityAlert {
                        code: "HIGH_CORRELATION".to_string(),
                        severity: AlertSeverity::Info,
                        column: Some(format!(
                            "{} <-> {}",
                            numeric_vectors[i].0, numeric_vectors[j].0
                        )),
                        message: format!(
                            "Strong linear correlation (r = {r:.3}) between `{}` and `{}`",
                            numeric_vectors[i].0, numeric_vectors[j].0
                        ),
                        fix_hint: "Check for redundant/derived features or collinearity."
                            .to_string(),
                    });
                }
            }
        }
    }
    correlations.sort_by(|a, b| {
        b.pearson_r
            .abs()
            .partial_cmp(&a.pearson_r.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Sort alerts: High -> Medium -> Info.
    alerts.sort_by_key(|a| match a.severity {
        AlertSeverity::High => 0,
        AlertSeverity::Medium => 1,
        AlertSeverity::Info => 2,
    });

    DatasetProfile {
        dataset: table.name.clone(),
        source_kind: table.source_kind.clone(),
        row_count,
        column_count,
        sampled: table.sampled,
        duplicate_row_count,
        duplicate_row_pct: round2(duplicate_row_pct),
        total_cells,
        missing_cells,
        missing_pct: round2(pct(missing_cells, total_cells)),
        candidate_keys,
        alerts,
        columns,
        correlations,
    }
}

fn profile_column(
    name: &str,
    rows: &[Vec<CellValue>],
    col_idx: usize,
    row_count: usize,
) -> (ColumnProfile, Vec<QualityAlert>, Option<Vec<Option<f64>>>) {
    let det = detectors();
    let mut alerts = Vec::new();

    let mut null_count = 0usize;
    let mut int_count = 0usize;
    let mut float_count = 0usize;
    let mut bool_count = 0usize;
    let mut str_count = 0usize;

    let mut freq: HashMap<String, usize> = HashMap::new();
    let mut numeric_vals: Vec<f64> = Vec::new();
    let mut aligned_num: Vec<Option<f64>> = Vec::with_capacity(row_count);

    let mut str_lengths: Vec<usize> = Vec::new();
    let mut empty_string_count = 0usize;
    let mut whitespace_padded_count = 0usize;
    let mut leading_zero_numeric_count = 0usize;
    let mut plain_numeric_str_count = 0usize;

    let mut email_hits = 0usize;
    let mut uuid_hits = 0usize;
    let mut ssn_hits = 0usize;
    let mut phone_hits = 0usize;
    let mut url_hits = 0usize;
    let mut date_hits = 0usize;
    let mut ts_hits = 0usize;

    for row in rows {
        let cell = row.get(col_idx).unwrap_or(&CellValue::Null);
        match cell {
            CellValue::Null => {
                null_count += 1;
                aligned_num.push(None);
            }
            CellValue::Bool(b) => {
                bool_count += 1;
                *freq.entry(b.to_string()).or_insert(0) += 1;
                aligned_num.push(None);
            }
            CellValue::Int(i) => {
                int_count += 1;
                let f = *i as f64;
                numeric_vals.push(f);
                aligned_num.push(Some(f));
                *freq.entry(i.to_string()).or_insert(0) += 1;
            }
            CellValue::Float(f) => {
                float_count += 1;
                if f.is_finite() {
                    numeric_vals.push(*f);
                    aligned_num.push(Some(*f));
                } else {
                    aligned_num.push(None);
                }
                *freq.entry(cell.display_compact()).or_insert(0) += 1;
            }
            CellValue::Str(s) => {
                str_count += 1;
                aligned_num.push(None);
                str_lengths.push(s.chars().count());
                if s.is_empty() {
                    empty_string_count += 1;
                } else {
                    if s.trim().len() != s.len() {
                        whitespace_padded_count += 1;
                    }
                    let t = s.trim();
                    if t.len() > 1 && t.starts_with('0') && t.bytes().all(|b| b.is_ascii_digit()) {
                        leading_zero_numeric_count += 1;
                    } else if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
                        plain_numeric_str_count += 1;
                    }
                    if det.email.is_match(t) {
                        email_hits += 1;
                    } else if det.uuid.is_match(t) {
                        uuid_hits += 1;
                    } else if det.ssn.is_match(t) {
                        ssn_hits += 1;
                    } else if det.phone.is_match(t) {
                        phone_hits += 1;
                    } else if det.url.is_match(t) {
                        url_hits += 1;
                    } else if det.iso_date.is_match(t) {
                        date_hits += 1;
                    } else if det.iso_timestamp.is_match(t) {
                        ts_hits += 1;
                    }
                }
                *freq.entry(s.clone()).or_insert(0) += 1;
            }
        }
    }

    let non_null_count = row_count.saturating_sub(null_count);
    let null_pct = pct(null_count, row_count);
    let distinct_count = freq.len();
    let unique_pct = pct(distinct_count, non_null_count);
    let is_unique = non_null_count > 0 && distinct_count == non_null_count;
    let is_constant = non_null_count > 1 && distinct_count == 1;

    let mut pii_flags = Vec::new();
    if email_hits > 0 && pct(email_hits, non_null_count) >= 50.0 {
        pii_flags.push("email".to_string());
    }
    if ssn_hits > 0 {
        pii_flags.push("ssn".to_string());
    }
    if phone_hits > 0 && pct(phone_hits, non_null_count) >= 50.0 {
        pii_flags.push("phone".to_string());
    }

    let inferred_type = if non_null_count == 0 {
        "empty".to_string()
    } else if str_count == 0 && bool_count == 0 {
        if float_count > 0 {
            "float".to_string()
        } else {
            "integer".to_string()
        }
    } else if bool_count == non_null_count {
        "boolean".to_string()
    } else if pct(uuid_hits, non_null_count) >= 80.0 {
        "uuid".to_string()
    } else if pct(email_hits, non_null_count) >= 80.0 {
        "email".to_string()
    } else if pct(url_hits, non_null_count) >= 80.0 {
        "url".to_string()
    } else if pct(date_hits, non_null_count) >= 80.0 {
        "date".to_string()
    } else if pct(ts_hits, non_null_count) >= 80.0 {
        "timestamp".to_string()
    } else if str_count == non_null_count && distinct_count <= 20 && distinct_count < non_null_count
    {
        "categorical".to_string()
    } else if str_count > 0 && (int_count > 0 || float_count > 0) {
        "mixed".to_string()
    } else {
        "string".to_string()
    };

    let numeric = if !numeric_vals.is_empty() && (int_count + float_count) * 2 >= non_null_count {
        Some(compute_numeric_stats(&mut numeric_vals))
    } else {
        None
    };

    let string = if !str_lengths.is_empty() {
        let min_len = *str_lengths.iter().min().unwrap_or(&0);
        let max_len = *str_lengths.iter().max().unwrap_or(&0);
        let mean_len = round2(str_lengths.iter().sum::<usize>() as f64 / str_lengths.len() as f64);
        Some(StringStats {
            min_len,
            max_len,
            mean_len,
            empty_string_count,
            whitespace_padded_count,
            leading_zero_numeric_count,
        })
    } else {
        None
    };

    // Top 10 values sorted by count desc, then value asc for deterministic output.
    let mut freq_vec: Vec<(String, usize)> = freq.into_iter().collect();
    freq_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_values: Vec<ValueCount> = freq_vec
        .iter()
        .take(10)
        .map(|(v, c)| ValueCount {
            value: truncate(v, 80),
            count: *c,
            pct: round2(pct(*c, non_null_count)),
        })
        .collect();
    let sample_values: Vec<String> = freq_vec
        .iter()
        .take(5)
        .map(|(v, _)| truncate(v, 60))
        .collect();

    // Generate data-quality alerts!
    if null_pct >= 20.0 {
        alerts.push(QualityAlert {
            code: "HIGH_NULLS".to_string(),
            severity: if null_pct >= 50.0 {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            },
            column: Some(name.to_string()),
            message: format!("`{name}` has {null_count} nulls ({null_pct:.1}%)"),
            fix_hint: format!(
                "Guard `{name}` with COALESCE/IS NOT NULL; avoid INNER JOIN on nullable keys."
            ),
        });
    }
    if is_constant {
        alerts.push(QualityAlert {
            code: "CONSTANT_COLUMN".to_string(),
            severity: AlertSeverity::Info,
            column: Some(name.to_string()),
            message: format!("`{name}` has only 1 distinct non-null value"),
            fix_hint: "Verify whether this column is unpopulated or a constant filter artifact."
                .to_string(),
        });
    }
    // Near-unique key alert: 90% <= unique_pct < 100% — #1 silent join fan-out trap!
    if non_null_count >= 10 && unique_pct >= 90.0 && !is_unique {
        let dup_rows = non_null_count - distinct_count;
        alerts.push(QualityAlert {
            code: "NEAR_UNIQUE_KEY".to_string(),
            severity: AlertSeverity::High,
            column: Some(name.to_string()),
            message: format!(
                "`{name}` is {unique_pct:.2}% unique ({dup_rows} duplicate values) — NOT a safe 1:1 join key"
            ),
            fix_hint: format!(
                "If joining on `{name}`, deduplicate in a CTE (e.g. ROW_NUMBER() OVER (PARTITION BY {name} ...)) to prevent silent row fan-out."
            ),
        });
    }
    if !pii_flags.is_empty() {
        alerts.push(QualityAlert {
            code: "PII_DETECTED".to_string(),
            severity: AlertSeverity::Medium,
            column: Some(name.to_string()),
            message: format!(
                "`{name}` contains likely PII patterns: {}",
                pii_flags.join(", ")
            ),
            fix_hint: "Avoid logging raw values or sharing unredacted exports externally."
                .to_string(),
        });
    }
    if whitespace_padded_count > 0 {
        alerts.push(QualityAlert {
            code: "WHITESPACE_PADDING".to_string(),
            severity: AlertSeverity::Medium,
            column: Some(name.to_string()),
            message: format!(
                "`{name}` has {whitespace_padded_count} values with leading/trailing whitespace"
            ),
            fix_hint: format!("Apply TRIM({name}) before joining or grouping on `{name}`."),
        });
    }
    if leading_zero_numeric_count > 0 && (plain_numeric_str_count > 0 || int_count > 0) {
        alerts.push(QualityAlert {
            code: "MIXED_LEADING_ZEROS".to_string(),
            severity: AlertSeverity::High,
            column: Some(name.to_string()),
            message: format!(
                "`{name}` mixes leading-zero numeric IDs ({leading_zero_numeric_count}) with plain numbers — join mismatch hazard"
            ),
            fix_hint: format!(
                "Normalize `{name}` via LTRIM({name}::text, '0') or consistent LPAD before joining across systems."
            ),
        });
    } else if leading_zero_numeric_count > 0 {
        alerts.push(QualityAlert {
            code: "LEADING_ZERO_IDS".to_string(),
            severity: AlertSeverity::Info,
            column: Some(name.to_string()),
            message: format!(
                "`{name}` contains {leading_zero_numeric_count} zero-padded numeric strings (e.g. `001234`)"
            ),
            fix_hint: format!(
                "Keep `{name}` as TEXT (never cast to INT carelessly) or normalize both sides when joining."
            ),
        });
    }
    if inferred_type == "mixed" {
        alerts.push(QualityAlert {
            code: "MIXED_TYPES".to_string(),
            severity: AlertSeverity::Medium,
            column: Some(name.to_string()),
            message: format!(
                "`{name}` mixes numeric ({}) and string ({str_count}) values",
                int_count + float_count
            ),
            fix_hint: "Inspect string values for sentinel codes ('N/A', 'TBD') or zero-padded IDs."
                .to_string(),
        });
    }
    if let Some(num) = &numeric {
        if num.zeros_pct >= 50.0 {
            alerts.push(QualityAlert {
                code: "HIGH_ZEROS".to_string(),
                severity: AlertSeverity::Info,
                column: Some(name.to_string()),
                message: format!(
                    "`{name}` is {:.1}% zeros ({} rows)",
                    num.zeros_pct, num.zeros_count
                ),
                fix_hint:
                    "Verify whether zeros represent real 0 measurements or missing-value defaults."
                        .to_string(),
            });
        }
        if num.skewness.abs() > 2.0 {
            alerts.push(QualityAlert {
                code: "SKEWED_DISTRIBUTION".to_string(),
                severity: AlertSeverity::Info,
                column: Some(name.to_string()),
                message: format!(
                    "`{name}` is heavily skewed (skewness = {:.2})",
                    num.skewness
                ),
                fix_hint: "Prefer median/percentiles over mean when summarizing this metric."
                    .to_string(),
            });
        }
        if num.outlier_pct >= 2.0 && num.outlier_count >= 3 {
            alerts.push(QualityAlert {
                code: "OUTLIERS_DETECTED".to_string(),
                severity: AlertSeverity::Info,
                column: Some(name.to_string()),
                message: format!(
                    "`{name}` has {} Tukey IQR outliers ({:.1}%)",
                    num.outlier_count, num.outlier_pct
                ),
                fix_hint: "Inspect extreme min/max values before computing averages or totals."
                    .to_string(),
            });
        }
    }

    let corr_vec = if numeric.is_some() {
        Some(aligned_num)
    } else {
        None
    };

    let prof = ColumnProfile {
        name: name.to_string(),
        inferred_type,
        non_null_count,
        null_count,
        null_pct: round2(null_pct),
        distinct_count,
        unique_pct: round2(unique_pct),
        is_unique,
        is_constant,
        pii_flags,
        numeric,
        string,
        top_values,
        sample_values,
    };

    (prof, alerts, corr_vec)
}

fn compute_numeric_stats(vals: &mut [f64]) -> NumericStats {
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = vals.len();
    let n_f = n as f64;
    let min = vals[0];
    let max = vals[n - 1];
    let mean = vals.iter().sum::<f64>() / n_f;
    let variance = if n > 1 {
        vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n_f - 1.0)
    } else {
        0.0
    };
    let std_dev = variance.sqrt();
    let skewness = if std_dev > 1e-12 && n >= 3 {
        vals.iter()
            .map(|v| ((v - mean) / std_dev).powi(3))
            .sum::<f64>()
            / n_f
    } else {
        0.0
    };

    let p5 = percentile_sorted(vals, 0.05);
    let p25 = percentile_sorted(vals, 0.25);
    let median = percentile_sorted(vals, 0.50);
    let p75 = percentile_sorted(vals, 0.75);
    let p95 = percentile_sorted(vals, 0.95);
    let iqr = p75 - p25;

    let zeros_count = vals.iter().filter(|v| **v == 0.0).count();
    let negatives_count = vals.iter().filter(|v| **v < 0.0).count();

    let low_fence = p25 - 1.5 * iqr;
    let high_fence = p75 + 1.5 * iqr;
    let outlier_count = if iqr > 0.0 {
        vals.iter()
            .filter(|v| **v < low_fence || **v > high_fence)
            .count()
    } else {
        0
    };

    let histogram = build_histogram(vals, min, max, 12);

    NumericStats {
        min: round4(min),
        max: round4(max),
        mean: round4(mean),
        std_dev: round4(std_dev),
        skewness: round4(skewness),
        p5: round4(p5),
        p25: round4(p25),
        median: round4(median),
        p75: round4(p75),
        p95: round4(p95),
        iqr: round4(iqr),
        zeros_count,
        zeros_pct: round2(pct(zeros_count, n)),
        negatives_count,
        outlier_count,
        outlier_pct: round2(pct(outlier_count, n)),
        histogram,
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = p * (sorted.len() - 1) as f64;
    let lo = idx.floor() as usize;
    let hi = idx.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = idx - lo as f64;
        sorted[lo] * (1.0 - frac) + sorted[hi] * frac
    }
}

fn build_histogram(sorted: &[f64], min: f64, max: f64, num_bins: usize) -> Vec<HistogramBin> {
    if sorted.is_empty() {
        return Vec::new();
    }
    if (max - min).abs() < 1e-12 {
        return vec![HistogramBin {
            start: round4(min),
            end: round4(max),
            count: sorted.len(),
        }];
    }
    let bins = num_bins.max(1);
    let width = (max - min) / bins as f64;
    let mut counts = vec![0usize; bins];
    for &v in sorted {
        let mut idx = ((v - min) / width).floor() as usize;
        if idx >= bins {
            idx = bins - 1;
        }
        counts[idx] += 1;
    }
    counts
        .into_iter()
        .enumerate()
        .map(|(i, count)| HistogramBin {
            start: round4(min + i as f64 * width),
            end: round4(min + (i + 1) as f64 * width),
            count,
        })
        .collect()
}

fn pearson(a: &[Option<f64>], b: &[Option<f64>]) -> Option<f64> {
    let mut pairs = Vec::new();
    for (x, y) in a.iter().zip(b.iter()) {
        if let (Some(xv), Some(yv)) = (x, y) {
            pairs.push((*xv, *yv));
        }
    }
    if pairs.len() < 3 {
        return None;
    }
    let n = pairs.len() as f64;
    let mean_x = pairs.iter().map(|(x, _)| *x).sum::<f64>() / n;
    let mean_y = pairs.iter().map(|(_, y)| *y).sum::<f64>() / n;
    let mut cov = 0.0;
    let mut vx = 0.0;
    let mut vy = 0.0;
    for (x, y) in pairs {
        let dx = x - mean_x;
        let dy = y - mean_y;
        cov += dx * dy;
        vx += dx * dx;
        vy += dy * dy;
    }
    let denom = (vx * vy).sqrt();
    if denom < 1e-12 {
        None
    } else {
        Some((cov / denom).clamp(-1.0, 1.0))
    }
}

/// Export inferred contract directly to `datakeel.toml` or ODCS v3.2.0 YAML.
pub fn export_contract(profile: &DatasetProfile, format: &str) -> String {
    match format {
        "odcs" | "yaml" => export_odcs(profile),
        _ => export_datakeel_toml(profile),
    }
}

fn export_datakeel_toml(profile: &DatasetProfile) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "name = \"{}\"\nversion = \"1.0.0\"\n\n",
        profile.dataset.replace('"', "")
    ));
    for col in &profile.columns {
        let dk_type = match col.inferred_type.as_str() {
            "integer" => "integer",
            "float" => "number",
            "boolean" => "boolean",
            "date" => "date",
            "timestamp" => "timestamp",
            _ => "string",
        };
        out.push_str(&format!("[columns.\"{}\"]\n", col.name));
        out.push_str(&format!("type = \"{dk_type}\"\n"));
        out.push_str(&format!("required = {}\n", col.null_count == 0));
        if col.is_unique && col.null_count == 0 && profile.row_count > 0 {
            out.push_str("unique = true\n");
        }
        if let Some(num) = &col.numeric {
            out.push_str(&format!("min = {}\nmax = {}\n", num.min, num.max));
        }
        if col.inferred_type == "categorical" && col.distinct_count <= 12 {
            let vals: Vec<String> = col
                .top_values
                .iter()
                .map(|v| format!("\"{}\"", v.value.replace('"', "\\\"")))
                .collect();
            out.push_str(&format!("enum = [{}]\n", vals.join(", ")));
        }
        out.push('\n');
    }
    out
}

fn export_odcs(profile: &DatasetProfile) -> String {
    let mut properties = Vec::new();
    for col in &profile.columns {
        let logical = match col.inferred_type.as_str() {
            "integer" => "integer",
            "float" => "number",
            "boolean" => "boolean",
            "date" => "date",
            "timestamp" => "timestamp",
            _ => "string",
        };
        let mut prop = IndexMap::new();
        prop.insert("name", serde_json::json!(col.name));
        prop.insert("logicalType", serde_json::json!(logical));
        prop.insert("required", serde_json::json!(col.null_count == 0));
        if col.is_unique && col.null_count == 0 && profile.row_count > 0 {
            prop.insert("unique", serde_json::json!(true));
        }
        properties.push(prop);
    }

    let doc = serde_json::json!({
        "apiVersion": "v3.2.0",
        "kind": "DataContract",
        "id": profile.dataset,
        "name": profile.dataset,
        "version": "1.0.0",
        "status": "draft",
        "schema": [
            {
                "name": profile.dataset,
                "physicalType": "table",
                "properties": properties
            }
        ]
    });
    serde_yaml_ng::to_string(&doc).unwrap_or_default()
}

fn pct(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

fn truncate(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let prefix: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}
