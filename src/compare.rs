use crate::error::{Result, StatkeelError};
use crate::profile::{ColumnProfile, DatasetProfile, profile_table};
use crate::source::{CellValue, TableData};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Serialize)]
pub struct TypeChange {
    pub column: String,
    pub baseline_type: String,
    pub candidate_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftAlert {
    pub code: String,
    pub severity: String, // "high" | "medium" | "info"
    pub column: Option<String>,
    pub message: String,
    pub fix_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DualHistBin {
    pub start: f64,
    pub end: f64,
    pub baseline_pct: f64,
    pub candidate_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NumericDrift {
    pub baseline_mean: f64,
    pub candidate_mean: f64,
    pub mean_delta: f64,
    pub mean_delta_pct: Option<f64>,
    pub baseline_median: f64,
    pub candidate_median: f64,
    pub median_delta: f64,
    pub baseline_min: f64,
    pub candidate_min: f64,
    pub baseline_max: f64,
    pub candidate_max: f64,
    pub ks_stat: f64,
    pub dual_histogram: Vec<DualHistBin>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryShift {
    pub value: String,
    pub baseline_pct: f64,
    pub candidate_pct: f64,
    pub delta_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoricalDrift {
    pub tvd: f64,
    pub new_categories: Vec<String>,
    pub disappeared_categories: Vec<String>,
    pub top_shifts: Vec<CategoryShift>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ColumnComparison {
    pub name: String,
    pub baseline_type: String,
    pub candidate_type: String,
    pub baseline_null_pct: f64,
    pub candidate_null_pct: f64,
    pub null_pct_delta: f64,
    pub baseline_distinct: usize,
    pub candidate_distinct: usize,
    pub baseline_unique: bool,
    pub candidate_unique: bool,
    pub drift_level: String, // "high" | "medium" | "low"
    pub numeric: Option<NumericDrift>,
    pub categorical: Option<CategoricalDrift>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CellDiffSample {
    pub key: String,
    pub column: String,
    pub baseline: String,
    pub candidate: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyDiffSummary {
    pub keys: Vec<String>,
    pub baseline_unique_keys: usize,
    pub candidate_unique_keys: usize,
    pub baseline_duplicate_keys: usize,
    pub candidate_duplicate_keys: usize,
    pub added_keys_count: usize,
    pub removed_keys_count: usize,
    pub unchanged_rows: usize,
    pub changed_rows: usize,
    pub added_key_samples: Vec<String>,
    pub removed_key_samples: Vec<String>,
    pub changed_columns: BTreeMap<String, usize>,
    pub cell_diff_samples: Vec<CellDiffSample>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompareReport {
    pub ok: bool,
    pub verdict: String, // "IDENTICAL" | "LOW_DRIFT" | "DRIFT_DETECTED" | "FAIL"
    pub baseline_name: String,
    pub candidate_name: String,
    pub baseline_rows: usize,
    pub candidate_rows: usize,
    pub row_delta: i64,
    pub row_delta_pct: Option<f64>,
    pub baseline_missing_pct: f64,
    pub candidate_missing_pct: f64,
    pub missing_pct_delta: f64,
    pub baseline_duplicate_rows: usize,
    pub candidate_duplicate_rows: usize,
    pub added_columns: Vec<String>,
    pub removed_columns: Vec<String>,
    pub type_changes: Vec<TypeChange>,
    pub max_ks: f64,
    pub max_tvd: f64,
    pub alerts: Vec<DriftAlert>,
    pub columns: Vec<ColumnComparison>,
    pub key_diff: Option<KeyDiffSummary>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CompareOptions {
    pub keys: Vec<String>,
    pub fail_on_schema_change: bool,
    pub max_row_delta_pct: Option<f64>,
    pub max_ks: Option<f64>,
    pub max_tvd: Option<f64>,
    pub fail_on_row_diff: bool,
}

pub fn compare_tables(
    baseline: &TableData,
    candidate: &TableData,
    opts: &CompareOptions,
) -> Result<CompareReport> {
    let base_prof = profile_table(baseline);
    let cand_prof = profile_table(candidate);

    let base_map: HashMap<&str, &ColumnProfile> = base_prof
        .columns
        .iter()
        .map(|c| (c.name.as_str(), c))
        .collect();
    let cand_map: HashMap<&str, &ColumnProfile> = cand_prof
        .columns
        .iter()
        .map(|c| (c.name.as_str(), c))
        .collect();

    let added_columns: Vec<String> = candidate
        .columns
        .iter()
        .filter(|c| !base_map.contains_key(c.as_str()))
        .cloned()
        .collect();
    let removed_columns: Vec<String> = baseline
        .columns
        .iter()
        .filter(|c| !cand_map.contains_key(c.as_str()))
        .cloned()
        .collect();

    let row_delta = candidate.rows.len() as i64 - baseline.rows.len() as i64;
    let row_delta_pct = if baseline.rows.is_empty() {
        None
    } else {
        Some(round2(
            (row_delta as f64 / baseline.rows.len() as f64) * 100.0,
        ))
    };

    let mut alerts = Vec::new();
    if !removed_columns.is_empty() {
        alerts.push(DriftAlert {
            code: "SCHEMA_COLUMNS_REMOVED".to_string(),
            severity: "high".to_string(),
            column: None,
            message: format!("Removed column(s): {}", removed_columns.join(", ")),
            fix_hint: "Check downstream views/queries referencing these dropped columns."
                .to_string(),
        });
    }
    if !added_columns.is_empty() {
        alerts.push(DriftAlert {
            code: "SCHEMA_COLUMNS_ADDED".to_string(),
            severity: "info".to_string(),
            column: None,
            message: format!("Added column(s): {}", added_columns.join(", ")),
            fix_hint: "Update data contracts if these new columns should be tracked.".to_string(),
        });
    }
    if let Some(pct_d) = row_delta_pct
        && pct_d.abs() >= 10.0
    {
        alerts.push(DriftAlert {
            code: "ROW_VOLUME_SHIFT".to_string(),
            severity: if pct_d.abs() >= 25.0 {
                "high"
            } else {
                "medium"
            }
            .to_string(),
            column: None,
            message: format!(
                "Row count shifted {:+.2}% ({} -> {}, {:+})",
                pct_d,
                baseline.rows.len(),
                candidate.rows.len(),
                row_delta
            ),
            fix_hint:
                "Verify upstream filters, date windows, or join cardinality before trusting totals."
                    .to_string(),
        });
    }

    let mut type_changes = Vec::new();
    let mut columns = Vec::new();
    let mut max_ks = 0.0_f64;
    let mut max_tvd = 0.0_f64;

    for (base_idx, col_name) in baseline.columns.iter().enumerate() {
        let Some(cand_idx) = candidate.columns.iter().position(|c| c == col_name) else {
            continue;
        };
        let bp = base_map[col_name.as_str()];
        let cp = cand_map[col_name.as_str()];

        if bp.inferred_type != cp.inferred_type
            && bp.inferred_type != "empty"
            && cp.inferred_type != "empty"
        {
            type_changes.push(TypeChange {
                column: col_name.clone(),
                baseline_type: bp.inferred_type.clone(),
                candidate_type: cp.inferred_type.clone(),
            });
            alerts.push(DriftAlert {
                code: "SCHEMA_TYPE_CHANGE".to_string(),
                severity: "high".to_string(),
                column: Some(col_name.clone()),
                message: format!(
                    "`{col_name}` inferred type changed: {} -> {}",
                    bp.inferred_type, cp.inferred_type
                ),
                fix_hint: "Inspect casting/formatting changes (e.g., numeric ID turned string or mixed nulls).".to_string(),
            });
        }

        let null_pct_delta = round2(cp.null_pct - bp.null_pct);
        if null_pct_delta.abs() >= 5.0 {
            alerts.push(DriftAlert {
                code: "NULL_RATE_DRIFT".to_string(),
                severity: if null_pct_delta.abs() >= 15.0 {
                    "high"
                } else {
                    "medium"
                }
                .to_string(),
                column: Some(col_name.clone()),
                message: format!(
                    "`{col_name}` null rate shifted {:+.2}% ({:.2}% -> {:.2}%)",
                    null_pct_delta, bp.null_pct, cp.null_pct
                ),
                fix_hint:
                    "Check upstream extraction or LEFT JOIN coverage for newly missing values."
                        .to_string(),
            });
        }

        if bp.is_unique && !cp.is_unique && baseline.rows.len() >= 2 {
            alerts.push(DriftAlert {
                code: "KEY_UNIQUENESS_LOST".to_string(),
                severity: "high".to_string(),
                column: Some(col_name.clone()),
                message: format!(
                    "`{col_name}` was 100% unique in baseline but now has duplicates ({} distinct / {} non-null)",
                    cp.distinct_count, cp.non_null_count
                ),
                fix_hint: format!(
                    "Joining on `{col_name}` will now cause row fan-out! Deduplicate before joining."
                ),
            });
        }

        let numeric = if let (Some(bn), Some(cn)) = (&bp.numeric, &cp.numeric) {
            let b_vals = extract_numeric_column(baseline, base_idx);
            let c_vals = extract_numeric_column(candidate, cand_idx);
            let ks = round4(ks_two_sample(&b_vals, &c_vals));
            if ks > max_ks {
                max_ks = ks;
            }
            let mean_delta = round4(cn.mean - bn.mean);
            let mean_delta_pct = if bn.mean.abs() > 1e-12 {
                Some(round2((mean_delta / bn.mean) * 100.0))
            } else {
                None
            };
            let dual_histogram = build_dual_histogram(&b_vals, &c_vals, 10);
            if ks >= 0.15 {
                alerts.push(DriftAlert {
                    code: "NUMERIC_DISTRIBUTION_DRIFT".to_string(),
                    severity: if ks >= 0.25 { "high" } else { "medium" }.to_string(),
                    column: Some(col_name.clone()),
                    message: format!(
                        "`{col_name}` numeric distribution shifted (KS = {ks:.3}; mean {} -> {}, median {} -> {})",
                        bn.mean, cn.mean, bn.median, cn.median
                    ),
                    fix_hint: "Inspect cohort filter, unit/scale change, or outlier spike."
                        .to_string(),
                });
            }
            Some(NumericDrift {
                baseline_mean: bn.mean,
                candidate_mean: cn.mean,
                mean_delta,
                mean_delta_pct,
                baseline_median: bn.median,
                candidate_median: cn.median,
                median_delta: round4(cn.median - bn.median),
                baseline_min: bn.min,
                candidate_min: cn.min,
                baseline_max: bn.max,
                candidate_max: cn.max,
                ks_stat: ks,
                dual_histogram,
            })
        } else {
            None
        };

        let categorical = if numeric.is_none()
            && bp.distinct_count <= 200
            && cp.distinct_count <= 200
            && (bp.non_null_count > 0 || cp.non_null_count > 0)
        {
            let cat = compute_categorical_drift(baseline, base_idx, candidate, cand_idx);
            if cat.tvd > max_tvd {
                max_tvd = cat.tvd;
            }
            if cat.tvd >= 0.10 {
                alerts.push(DriftAlert {
                    code: "CATEGORICAL_DISTRIBUTION_DRIFT".to_string(),
                    severity: if cat.tvd >= 0.20 { "high" } else { "medium" }.to_string(),
                    column: Some(col_name.clone()),
                    message: format!(
                        "`{col_name}` category mix shifted (TVD = {:.3}; {} new, {} disappeared)",
                        cat.tvd,
                        cat.new_categories.len(),
                        cat.disappeared_categories.len()
                    ),
                    fix_hint: "Check enum/status definitions or upstream filter drift.".to_string(),
                });
            } else if !cat.new_categories.is_empty() && bp.distinct_count <= 25 {
                alerts.push(DriftAlert {
                    code: "NEW_CATEGORY_VALUES".to_string(),
                    severity: "info".to_string(),
                    column: Some(col_name.clone()),
                    message: format!(
                        "`{col_name}` has new unseen value(s): {}",
                        cat.new_categories.join(", ")
                    ),
                    fix_hint: "Confirm CASE/WHERE filters handle these new category values."
                        .to_string(),
                });
            }
            Some(cat)
        } else {
            None
        };

        let drift_level = if (bp.inferred_type != cp.inferred_type
            && bp.inferred_type != "empty"
            && cp.inferred_type != "empty")
            || null_pct_delta.abs() >= 15.0
            || (bp.is_unique && !cp.is_unique && baseline.rows.len() >= 2)
            || numeric.as_ref().map(|n| n.ks_stat >= 0.25).unwrap_or(false)
            || categorical.as_ref().map(|c| c.tvd >= 0.20).unwrap_or(false)
        {
            "high"
        } else if null_pct_delta.abs() >= 5.0
            || numeric.as_ref().map(|n| n.ks_stat >= 0.15).unwrap_or(false)
            || categorical.as_ref().map(|c| c.tvd >= 0.10).unwrap_or(false)
        {
            "medium"
        } else {
            "low"
        }
        .to_string();

        columns.push(ColumnComparison {
            name: col_name.clone(),
            baseline_type: bp.inferred_type.clone(),
            candidate_type: cp.inferred_type.clone(),
            baseline_null_pct: bp.null_pct,
            candidate_null_pct: cp.null_pct,
            null_pct_delta,
            baseline_distinct: bp.distinct_count,
            candidate_distinct: cp.distinct_count,
            baseline_unique: bp.is_unique,
            candidate_unique: cp.is_unique,
            drift_level,
            numeric,
            categorical,
        });
    }

    // Optional key-level row diff
    let key_diff = if !opts.keys.is_empty() {
        let kd = compute_key_diff(baseline, candidate, &opts.keys)?;
        if kd.added_keys_count > 0 || kd.removed_keys_count > 0 || kd.changed_rows > 0 {
            alerts.push(DriftAlert {
                code: "ROW_LEVEL_DIFF".to_string(),
                severity: "medium".to_string(),
                column: None,
                message: format!(
                    "Key diff on [{}]: +{} added, -{} removed, ~{} changed, {} unchanged",
                    opts.keys.join(", "),
                    kd.added_keys_count,
                    kd.removed_keys_count,
                    kd.changed_rows,
                    kd.unchanged_rows
                ),
                fix_hint:
                    "Review cell_diff_samples and added/removed keys to verify expected changes."
                        .to_string(),
            });
        }
        Some(kd)
    } else {
        None
    };

    // Sort alerts: high -> medium -> info
    alerts.sort_by_key(|a| match a.severity.as_str() {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    });

    // Enforce threshold assertions
    let mut failures = Vec::new();
    if opts.fail_on_schema_change
        && (!added_columns.is_empty() || !removed_columns.is_empty() || !type_changes.is_empty())
    {
        failures.push(format!(
            "Schema changed: +{} added, -{} removed, {} type change(s)",
            added_columns.len(),
            removed_columns.len(),
            type_changes.len()
        ));
    }
    if let (Some(max_pct), Some(actual_pct)) = (opts.max_row_delta_pct, row_delta_pct)
        && actual_pct.abs() > max_pct + 1e-9
    {
        failures.push(format!(
            "Row delta {actual_pct:+.2}% exceeds --max-row-delta-pct {max_pct:.2}%"
        ));
    }
    if let Some(limit_ks) = opts.max_ks
        && max_ks > limit_ks + 1e-9
    {
        failures.push(format!(
            "Max KS statistic {max_ks:.4} exceeds --max-ks {limit_ks:.4}"
        ));
    }
    if let Some(limit_tvd) = opts.max_tvd
        && max_tvd > limit_tvd + 1e-9
    {
        failures.push(format!(
            "Max categorical TVD {max_tvd:.4} exceeds --max-tvd {limit_tvd:.4}"
        ));
    }
    if opts.fail_on_row_diff {
        if let Some(kd) = &key_diff {
            if kd.added_keys_count > 0 || kd.removed_keys_count > 0 || kd.changed_rows > 0 {
                failures.push(format!(
                    "Row diff detected (+{} added, -{} removed, ~{} changed) under --fail-on-row-diff",
                    kd.added_keys_count, kd.removed_keys_count, kd.changed_rows
                ));
            }
        } else {
            return Err(StatkeelError::config(
                "`--fail-on-row-diff` requires `--key <col>`",
                "Pass `--key student_id` alongside `--fail-on-row-diff`.",
            ));
        }
    }

    let is_identical = row_delta == 0
        && added_columns.is_empty()
        && removed_columns.is_empty()
        && type_changes.is_empty()
        && max_ks < 1e-9
        && max_tvd < 1e-9
        && key_diff
            .as_ref()
            .map(|k| k.added_keys_count == 0 && k.removed_keys_count == 0 && k.changed_rows == 0)
            .unwrap_or(true);

    let verdict = if !failures.is_empty() {
        "FAIL"
    } else if is_identical {
        "IDENTICAL"
    } else if alerts.iter().any(|a| a.severity == "high") {
        "DRIFT_DETECTED"
    } else {
        "LOW_DRIFT"
    }
    .to_string();

    Ok(CompareReport {
        ok: failures.is_empty(),
        verdict,
        baseline_name: base_prof.dataset,
        candidate_name: cand_prof.dataset,
        baseline_rows: base_prof.row_count,
        candidate_rows: cand_prof.row_count,
        row_delta,
        row_delta_pct,
        baseline_missing_pct: base_prof.missing_pct,
        candidate_missing_pct: cand_prof.missing_pct,
        missing_pct_delta: round2(cand_prof.missing_pct - base_prof.missing_pct),
        baseline_duplicate_rows: base_prof.duplicate_row_count,
        candidate_duplicate_rows: cand_prof.duplicate_row_count,
        added_columns,
        removed_columns,
        type_changes,
        max_ks: round4(max_ks),
        max_tvd: round4(max_tvd),
        alerts,
        columns,
        key_diff,
        failures,
    })
}

fn extract_numeric_column(table: &TableData, col_idx: usize) -> Vec<f64> {
    let mut vals = Vec::new();
    for row in &table.rows {
        if let Some(cell) = row.get(col_idx) {
            match cell {
                CellValue::Int(i) => vals.push(*i as f64),
                CellValue::Float(f) if f.is_finite() => vals.push(*f),
                _ => {}
            }
        }
    }
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    vals
}

/// Exact two-sample Kolmogorov-Smirnov statistic (max |F_1(x) - F_2(x)|) on sorted slices.
fn ks_two_sample(a: &[f64], b: &[f64]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let na = a.len() as f64;
    let nb = b.len() as f64;
    let mut i = 0usize;
    let mut j = 0usize;
    let mut max_d = 0.0_f64;

    while i < a.len() && j < b.len() {
        let va = a[i];
        let vb = b[j];
        let x = va.min(vb);
        while i < a.len() && a[i] <= x {
            i += 1;
        }
        while j < b.len() && b[j] <= x {
            j += 1;
        }
        let d = ((i as f64 / na) - (j as f64 / nb)).abs();
        if d > max_d {
            max_d = d;
        }
    }
    max_d.clamp(0.0, 1.0)
}

fn build_dual_histogram(a: &[f64], b: &[f64], bins: usize) -> Vec<DualHistBin> {
    if a.is_empty() && b.is_empty() {
        return Vec::new();
    }
    let min_v = a
        .first()
        .copied()
        .into_iter()
        .chain(b.first().copied())
        .fold(f64::INFINITY, f64::min);
    let max_v = a
        .last()
        .copied()
        .into_iter()
        .chain(b.last().copied())
        .fold(f64::NEG_INFINITY, f64::max);

    if !min_v.is_finite() || !max_v.is_finite() {
        return Vec::new();
    }
    if (max_v - min_v).abs() < 1e-12 {
        return vec![DualHistBin {
            start: round4(min_v),
            end: round4(max_v),
            baseline_pct: if a.is_empty() { 0.0 } else { 100.0 },
            candidate_pct: if b.is_empty() { 0.0 } else { 100.0 },
        }];
    }

    let nb = bins.max(1);
    let width = (max_v - min_v) / nb as f64;
    let mut ca = vec![0usize; nb];
    let mut cb = vec![0usize; nb];
    for &v in a {
        let idx = (((v - min_v) / width).floor() as usize).min(nb - 1);
        ca[idx] += 1;
    }
    for &v in b {
        let idx = (((v - min_v) / width).floor() as usize).min(nb - 1);
        cb[idx] += 1;
    }
    let na = a.len().max(1) as f64;
    let n_b = b.len().max(1) as f64;
    (0..nb)
        .map(|i| DualHistBin {
            start: round4(min_v + i as f64 * width),
            end: round4(min_v + (i + 1) as f64 * width),
            baseline_pct: round2((ca[i] as f64 / na) * 100.0),
            candidate_pct: round2((cb[i] as f64 / n_b) * 100.0),
        })
        .collect()
}

fn compute_categorical_drift(
    baseline: &TableData,
    base_idx: usize,
    candidate: &TableData,
    cand_idx: usize,
) -> CategoricalDrift {
    let (b_freq, b_total) = value_frequencies(baseline, base_idx);
    let (c_freq, c_total) = value_frequencies(candidate, cand_idx);

    let mut all_keys: HashSet<&String> = HashSet::new();
    all_keys.extend(b_freq.keys());
    all_keys.extend(c_freq.keys());

    let mut tvd_sum = 0.0_f64;
    let mut new_categories = Vec::new();
    let mut disappeared_categories = Vec::new();
    let mut shifts = Vec::new();

    for k in all_keys {
        let bc = b_freq.get(k).copied().unwrap_or(0);
        let cc = c_freq.get(k).copied().unwrap_or(0);
        let bp = if b_total == 0 {
            0.0
        } else {
            bc as f64 / b_total as f64
        };
        let cp = if c_total == 0 {
            0.0
        } else {
            cc as f64 / c_total as f64
        };
        tvd_sum += (bp - cp).abs();
        if bc == 0 && cc > 0 {
            new_categories.push(k.clone());
        } else if cc == 0 && bc > 0 {
            disappeared_categories.push(k.clone());
        }
        shifts.push(CategoryShift {
            value: k.clone(),
            baseline_pct: round2(bp * 100.0),
            candidate_pct: round2(cp * 100.0),
            delta_pct: round2((cp - bp) * 100.0),
        });
    }

    new_categories.sort();
    disappeared_categories.sort();
    shifts.sort_by(|a, b| {
        b.delta_pct
            .abs()
            .partial_cmp(&a.delta_pct.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.value.cmp(&b.value))
    });

    CategoricalDrift {
        tvd: round4(0.5 * tvd_sum),
        new_categories: new_categories.into_iter().take(8).collect(),
        disappeared_categories: disappeared_categories.into_iter().take(8).collect(),
        top_shifts: shifts.into_iter().take(8).collect(),
    }
}

fn value_frequencies(table: &TableData, col_idx: usize) -> (HashMap<String, usize>, usize) {
    let mut freq = HashMap::new();
    let mut total = 0usize;
    for row in &table.rows {
        if let Some(s) = row.get(col_idx).and_then(|c| c.as_key_string()) {
            *freq.entry(s).or_insert(0) += 1;
            total += 1;
        }
    }
    (freq, total)
}

fn compute_key_diff(
    baseline: &TableData,
    candidate: &TableData,
    keys: &[String],
) -> Result<KeyDiffSummary> {
    let b_key_idx = resolve_indices(baseline, keys, "baseline")?;
    let c_key_idx = resolve_indices(candidate, keys, "candidate")?;

    let (b_rows, b_dups) = index_by_key(baseline, &b_key_idx);
    let (c_rows, c_dups) = index_by_key(candidate, &c_key_idx);

    let shared_cols: Vec<(String, usize, usize)> = baseline
        .columns
        .iter()
        .enumerate()
        .filter_map(|(bi, name)| {
            candidate
                .columns
                .iter()
                .position(|c| c == name)
                .map(|ci| (name.clone(), bi, ci))
        })
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged_rows = 0usize;
    let mut changed_rows = 0usize;
    let mut changed_columns: BTreeMap<String, usize> = BTreeMap::new();
    let mut cell_diff_samples = Vec::new();

    for k in c_rows.keys() {
        if !b_rows.contains_key(k) {
            added.push(k.clone());
        }
    }
    for (k, b_row) in &b_rows {
        let Some(c_row) = c_rows.get(k) else {
            removed.push(k.clone());
            continue;
        };
        let mut row_changed = false;
        for (col_name, bi, ci) in &shared_cols {
            let bv = b_row
                .get(*bi)
                .map(|v| v.display_compact())
                .unwrap_or_else(|| "NULL".to_string());
            let cv = c_row
                .get(*ci)
                .map(|v| v.display_compact())
                .unwrap_or_else(|| "NULL".to_string());
            if bv != cv {
                row_changed = true;
                *changed_columns.entry(col_name.clone()).or_insert(0) += 1;
                if cell_diff_samples.len() < 8 {
                    cell_diff_samples.push(CellDiffSample {
                        key: k.clone(),
                        column: col_name.clone(),
                        baseline: bv,
                        candidate: cv,
                    });
                }
            }
        }
        if row_changed {
            changed_rows += 1;
        } else {
            unchanged_rows += 1;
        }
    }

    added.sort();
    removed.sort();

    Ok(KeyDiffSummary {
        keys: keys.to_vec(),
        baseline_unique_keys: b_rows.len(),
        candidate_unique_keys: c_rows.len(),
        baseline_duplicate_keys: b_dups,
        candidate_duplicate_keys: c_dups,
        added_keys_count: added.len(),
        removed_keys_count: removed.len(),
        unchanged_rows,
        changed_rows,
        added_key_samples: added.into_iter().take(5).collect(),
        removed_key_samples: removed.into_iter().take(5).collect(),
        changed_columns,
        cell_diff_samples,
    })
}

fn resolve_indices(table: &TableData, keys: &[String], side: &str) -> Result<Vec<usize>> {
    let mut out = Vec::with_capacity(keys.len());
    for k in keys {
        let pos = table
            .columns
            .iter()
            .position(|c| c == k)
            .or_else(|| table.columns.iter().position(|c| c.eq_ignore_ascii_case(k)));
        match pos {
            Some(i) => out.push(i),
            None => {
                return Err(StatkeelError::config(
                    format!(
                        "`--key` column `{k}` not found in {side} `{}` (available: {})",
                        table.name,
                        table.columns.join(", ")
                    ),
                    "Pass a column present in both baseline and candidate.",
                ));
            }
        }
    }
    Ok(out)
}

fn index_by_key<'a>(
    table: &'a TableData,
    key_indices: &[usize],
) -> (BTreeMap<String, &'a Vec<CellValue>>, usize) {
    let mut map: BTreeMap<String, &'a Vec<CellValue>> = BTreeMap::new();
    let mut dups = 0usize;
    for row in &table.rows {
        let parts: Vec<String> = key_indices
            .iter()
            .map(|&idx| {
                row.get(idx)
                    .map(|v| v.display_compact())
                    .unwrap_or_else(|| "NULL".to_string())
            })
            .collect();
        let key = parts.join(" | ");
        if let std::collections::btree_map::Entry::Vacant(e) = map.entry(key) {
            e.insert(row);
        } else {
            dups += 1;
        }
    }
    (map, dups)
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

// Keep DatasetProfile imported cleanly for doc/semantic cohesion.
#[allow(dead_code)]
fn _profile_ref(_: &DatasetProfile) {}
