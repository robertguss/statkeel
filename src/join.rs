use crate::error::{Result, StatkeelError};
use crate::source::TableData;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize)]
pub struct DuplicateKeySample {
    pub key: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct NormalizationHint {
    pub transform: String,
    pub matched_left_pct_after: f64,
    pub lift_pct: f64,
    pub sql_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JoinSideSummary {
    pub name: String,
    pub keys: Vec<String>,
    pub total_rows: usize,
    pub non_null_keys: usize,
    pub null_keys: usize,
    pub null_pct: f64,
    pub distinct_keys: usize,
    pub duplicate_keys: usize,
    pub max_rows_per_key: usize,
    pub duplicate_samples: Vec<DuplicateKeySample>,
    pub matched_rows: usize,
    pub matched_pct: f64,
    pub orphan_rows: usize,
    pub unmatched_samples: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JoinReport {
    pub ok: bool,
    pub cardinality: String,
    pub left: JoinSideSummary,
    pub right: JoinSideSummary,
    pub inner_join_rows: usize,
    pub left_join_rows: usize,
    pub inner_fanout_ratio: f64,
    pub left_fanout_ratio: f64,
    pub risk_level: String,
    pub warnings: Vec<String>,
    pub normalization_hints: Vec<NormalizationHint>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct JoinThresholds {
    pub expect_cardinality: Option<String>,
    pub max_fanout: Option<f64>,
    pub min_left_coverage: Option<f64>,
}

pub fn analyze_join(
    left_table: &TableData,
    left_keys: &[String],
    right_table: &TableData,
    right_keys: &[String],
    thresholds: &JoinThresholds,
) -> Result<JoinReport> {
    if left_keys.is_empty() || right_keys.is_empty() {
        return Err(StatkeelError::config(
            "Both --left-key and --right-key must specify at least one column",
            "Example: `--left-key person_id --right-key sis_user_id`",
        ));
    }
    if left_keys.len() != right_keys.len() {
        return Err(StatkeelError::config(
            format!(
                "Key arity mismatch: left has {} column(s), right has {} column(s)",
                left_keys.len(),
                right_keys.len()
            ),
            "Pass the same number of comma-separated columns for --left-key and --right-key.",
        ));
    }

    let left_indices = resolve_key_indices(left_table, left_keys, "left")?;
    let right_indices = resolve_key_indices(right_table, right_keys, "right")?;

    let (left_counts, left_nulls, left_raw_keys) = extract_key_counts(left_table, &left_indices);
    let (right_counts, right_nulls, right_raw_keys) =
        extract_key_counts(right_table, &right_indices);

    let left_total = left_table.rows.len();
    let right_total = right_table.rows.len();
    let left_non_null = left_total.saturating_sub(left_nulls);
    let right_non_null = right_total.saturating_sub(right_nulls);

    let left_max_mult = left_counts.values().copied().max().unwrap_or(0);
    let right_max_mult = right_counts.values().copied().max().unwrap_or(0);

    let cardinality = if left_non_null == 0 || right_non_null == 0 {
        "empty".to_string()
    } else {
        match (left_max_mult > 1, right_max_mult > 1) {
            (false, false) => "1:1".to_string(),
            (false, true) => "1:N".to_string(),
            (true, false) => "N:1".to_string(),
            (true, true) => "M:N".to_string(),
        }
    };

    let mut inner_join_rows = 0usize;
    let mut left_matched_rows = 0usize;
    let mut left_unmatched_keys = Vec::new();
    for (k, &lc) in &left_counts {
        if let Some(&rc) = right_counts.get(k) {
            inner_join_rows += lc * rc;
            left_matched_rows += lc;
        } else {
            left_unmatched_keys.push((k.clone(), lc));
        }
    }
    let left_orphan_rows = left_total.saturating_sub(left_matched_rows);
    let left_join_rows = inner_join_rows + left_orphan_rows;

    let mut right_matched_rows = 0usize;
    let mut right_unmatched_keys = Vec::new();
    for (k, &rc) in &right_counts {
        if left_counts.contains_key(k) {
            right_matched_rows += rc;
        } else {
            right_unmatched_keys.push((k.clone(), rc));
        }
    }
    let right_orphan_rows = right_total.saturating_sub(right_matched_rows);

    let left_matched_pct = pct(left_matched_rows, left_total);
    let right_matched_pct = pct(right_matched_rows, right_total);

    let inner_fanout_ratio = if left_matched_rows == 0 {
        0.0
    } else {
        inner_join_rows as f64 / left_matched_rows as f64
    };
    let left_fanout_ratio = if left_total == 0 {
        0.0
    } else {
        left_join_rows as f64 / left_total as f64
    };

    let left_dups = collect_duplicates(&left_counts);
    let right_dups = collect_duplicates(&right_counts);

    left_unmatched_keys.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    right_unmatched_keys.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let left_dup_key_count = left_counts.values().filter(|&&c| c > 1).count();
    let right_dup_key_count = right_counts.values().filter(|&&c| c > 1).count();

    let normalization_hints = if left_matched_pct < 99.0 && left_non_null > 0 && right_non_null > 0
    {
        probe_normalizations(
            &left_raw_keys,
            &right_raw_keys,
            left_total,
            left_matched_pct,
            &left_keys.join(","),
            &right_keys.join(","),
        )
    } else {
        Vec::new()
    };

    let mut warnings = Vec::new();
    if right_max_mult > 1 {
        let extra = left_join_rows.saturating_sub(left_total);
        warnings.push(format!(
            "Right-side fan-out detected ({cardinality}): `{}` has {right_dup_key_count} duplicate keys (max {right_max_mult} rows/key). A LEFT JOIN will inflate {left_total} rows -> {left_join_rows} rows (+{extra} phantom rows, {left_fanout_ratio:.3}x).",
            right_table.name
        ));
    }
    if cardinality == "M:N" {
        warnings.push(
            "Many-to-many (M:N) join: BOTH sides contain duplicate keys — aggregations will multiply severely unless at least one side is deduplicated."
                .to_string(),
        );
    }
    if left_matched_pct < 95.0 && left_total > 0 {
        warnings.push(format!(
            "Left-side orphan drop: {:.1}% of `{}` rows ({left_orphan_rows}/{left_total}) have no match in `{}`.",
            100.0 - left_matched_pct,
            left_table.name,
            right_table.name
        ));
    }
    if left_nulls > 0 {
        warnings.push(format!(
            "Left join key has {left_nulls} NULL/empty values ({:.1}%) which will never match.",
            pct(left_nulls, left_total)
        ));
    }
    if right_nulls > 0 {
        warnings.push(format!(
            "Right join key has {right_nulls} NULL/empty values ({:.1}%) which will never match.",
            pct(right_nulls, right_total)
        ));
    }

    // Threshold assertions
    let mut failures = Vec::new();
    if let Some(expected) = &thresholds.expect_cardinality
        && !cardinality.eq_ignore_ascii_case(expected)
    {
        failures.push(format!(
            "Expected cardinality `{expected}`, observed `{cardinality}`"
        ));
    }
    if let Some(max_fan) = thresholds.max_fanout
        && left_fanout_ratio > max_fan + 1e-9
    {
        failures.push(format!(
            "LEFT JOIN fan-out ratio {left_fanout_ratio:.4}x exceeds --max-fanout {max_fan:.4}x"
        ));
    }
    if let Some(min_cov) = thresholds.min_left_coverage
        && left_matched_pct + 1e-9 < min_cov
    {
        failures.push(format!(
            "Left match coverage {left_matched_pct:.2}% is below --min-left-coverage {min_cov:.2}%"
        ));
    }

    let risk_level = if !failures.is_empty()
        || cardinality == "M:N"
        || left_fanout_ratio > 1.0
        || left_matched_pct < 80.0
    {
        "high"
    } else if !warnings.is_empty() {
        "medium"
    } else {
        "low"
    }
    .to_string();

    Ok(JoinReport {
        ok: failures.is_empty(),
        cardinality,
        left: JoinSideSummary {
            name: left_table.name.clone(),
            keys: left_keys.to_vec(),
            total_rows: left_total,
            non_null_keys: left_non_null,
            null_keys: left_nulls,
            null_pct: round2(pct(left_nulls, left_total)),
            distinct_keys: left_counts.len(),
            duplicate_keys: left_dup_key_count,
            max_rows_per_key: left_max_mult,
            duplicate_samples: left_dups,
            matched_rows: left_matched_rows,
            matched_pct: round2(left_matched_pct),
            orphan_rows: left_orphan_rows,
            unmatched_samples: left_unmatched_keys
                .into_iter()
                .take(5)
                .map(|(k, _)| k)
                .collect(),
        },
        right: JoinSideSummary {
            name: right_table.name.clone(),
            keys: right_keys.to_vec(),
            total_rows: right_total,
            non_null_keys: right_non_null,
            null_keys: right_nulls,
            null_pct: round2(pct(right_nulls, right_total)),
            distinct_keys: right_counts.len(),
            duplicate_keys: right_dup_key_count,
            max_rows_per_key: right_max_mult,
            duplicate_samples: right_dups,
            matched_rows: right_matched_rows,
            matched_pct: round2(right_matched_pct),
            orphan_rows: right_orphan_rows,
            unmatched_samples: right_unmatched_keys
                .into_iter()
                .take(5)
                .map(|(k, _)| k)
                .collect(),
        },
        inner_join_rows,
        left_join_rows,
        inner_fanout_ratio: round4(inner_fanout_ratio),
        left_fanout_ratio: round4(left_fanout_ratio),
        risk_level,
        warnings,
        normalization_hints,
        failures,
    })
}

fn resolve_key_indices(table: &TableData, keys: &[String], side: &str) -> Result<Vec<usize>> {
    let mut indices = Vec::with_capacity(keys.len());
    for k in keys {
        let pos = table
            .columns
            .iter()
            .position(|c| c == k)
            .or_else(|| table.columns.iter().position(|c| c.eq_ignore_ascii_case(k)));
        match pos {
            Some(idx) => indices.push(idx),
            None => {
                return Err(StatkeelError::config(
                    format!(
                        "{side} key column `{k}` not found in `{}` (available: {})",
                        table.name,
                        table.columns.join(", ")
                    ),
                    format!("Pass a valid column name for --{side}-key."),
                ));
            }
        }
    }
    Ok(indices)
}

fn extract_key_counts(
    table: &TableData,
    indices: &[usize],
) -> (HashMap<String, usize>, usize, Vec<String>) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut nulls = 0usize;
    let mut raw_keys = Vec::with_capacity(table.rows.len());

    for row in &table.rows {
        let mut parts = Vec::with_capacity(indices.len());
        let mut has_null = false;
        for &idx in indices {
            match row.get(idx).and_then(|c| c.as_key_string()) {
                Some(s) => parts.push(s),
                None => {
                    has_null = true;
                    break;
                }
            }
        }
        if has_null {
            nulls += 1;
        } else {
            let joined = if parts.len() == 1 {
                parts.into_iter().next().unwrap()
            } else {
                parts.join(" | ")
            };
            *counts.entry(joined.clone()).or_insert(0) += 1;
            raw_keys.push(joined);
        }
    }
    (counts, nulls, raw_keys)
}

fn collect_duplicates(counts: &HashMap<String, usize>) -> Vec<DuplicateKeySample> {
    let mut dups: Vec<(String, usize)> = counts
        .iter()
        .filter(|(_, c)| **c > 1)
        .map(|(k, c)| (k.clone(), *c))
        .collect();
    dups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    dups.into_iter()
        .take(5)
        .map(|(key, count)| DuplicateKeySample { key, count })
        .collect()
}

fn probe_normalizations(
    left_keys: &[String],
    right_keys: &[String],
    left_total: usize,
    baseline_pct: f64,
    lcol: &str,
    rcol: &str,
) -> Vec<NormalizationHint> {
    type TransformFn = fn(&str) -> String;
    let candidates: Vec<(&str, TransformFn, String)> = vec![
        (
            "trim",
            |s| s.trim().to_string(),
            format!("TRIM(l.{lcol}::text) = TRIM(r.{rcol}::text)"),
        ),
        (
            "lowercase",
            |s| s.trim().to_ascii_lowercase(),
            format!("LOWER(TRIM(l.{lcol}::text)) = LOWER(TRIM(r.{rcol}::text))"),
        ),
        (
            "strip_leading_zeros",
            |s| {
                let t = s.trim().trim_start_matches('0');
                if t.is_empty() {
                    "0".to_string()
                } else {
                    t.to_string()
                }
            },
            format!("LTRIM(TRIM(l.{lcol}::text), '0') = LTRIM(TRIM(r.{rcol}::text), '0')"),
        ),
        (
            "strip_non_alnum",
            |s| {
                s.chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .map(|c| c.to_ascii_lowercase())
                    .collect()
            },
            format!(
                "REGEXP_REPLACE(LOWER(l.{lcol}::text), '[^a-z0-9]', '', 'g') = REGEXP_REPLACE(LOWER(r.{rcol}::text), '[^a-z0-9]', '', 'g')"
            ),
        ),
        (
            "numeric_canonical",
            |s| {
                let t = s.trim();
                if let Ok(f) = t.parse::<f64>()
                    && f.is_finite()
                    && (f.fract().abs() < 1e-9)
                {
                    return format!("{}", f as i64);
                }
                t.to_string()
            },
            format!("CAST(l.{lcol} AS BIGINT) = CAST(r.{rcol} AS BIGINT)"),
        ),
    ];

    let mut hints = Vec::new();
    for (name, func, sql_hint) in candidates {
        let right_set: HashSet<String> = right_keys.iter().map(|k| func(k)).collect();
        let matched = left_keys
            .iter()
            .filter(|k| right_set.contains(&func(k)))
            .count();
        let after_pct = pct(matched, left_total);
        let lift = after_pct - baseline_pct;
        if lift >= 1.0 {
            hints.push(NormalizationHint {
                transform: name.to_string(),
                matched_left_pct_after: round2(after_pct),
                lift_pct: round2(lift),
                sql_hint,
            });
        }
    }
    hints.sort_by(|a, b| {
        b.lift_pct
            .partial_cmp(&a.lift_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hints
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
