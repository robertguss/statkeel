use crate::audit::{AuditReport, FindingSeverity};
use crate::join::JoinReport;
use crate::profile::{AlertSeverity, ColumnProfile, DatasetProfile, HistogramBin};

const SHARED_CSS: &str = r#"
:root {
  --bg: #0f1117;
  --surface: #171a23;
  --surface-2: #1f2430;
  --border: #2c3344;
  --text: #e8ecf5;
  --muted: #9aa4b8;
  --accent: #38bdf8;
  --green: #34d399;
  --amber: #fbbf24;
  --red: #f87171;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --sans: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
[data-theme="light"] {
  --bg: #f6f8fb;
  --surface: #ffffff;
  --surface-2: #f1f5f9;
  --border: #dce3ee;
  --text: #0f172a;
  --muted: #475569;
  --accent: #0284c7;
  --green: #059669;
  --amber: #d97706;
  --red: #dc2626;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 28px 20px 64px;
  font-family: var(--sans); background: var(--bg); color: var(--text);
  line-height: 1.5;
}
.wrap { max-width: 1120px; margin: 0 auto; }
header {
  display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
  gap: 12px; padding-bottom: 18px; border-bottom: 1px solid var(--border); margin-bottom: 22px;
}
h1 { margin: 0; font-size: 1.5rem; letter-spacing: -0.02em; }
h2 { margin: 28px 0 12px; font-size: 1.1rem; letter-spacing: -0.01em; }
.meta { color: var(--muted); font-size: 0.875rem; }
.btn {
  background: var(--surface-2); color: var(--text); border: 1px solid var(--border);
  border-radius: 8px; padding: 6px 12px; cursor: pointer; font-size: 0.82rem;
}
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 22px; }
.kpi {
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px;
}
.kpi .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
.kpi .val { font-size: 1.45rem; font-weight: 700; margin-top: 4px; font-variant-numeric: tabular-nums; }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.73rem;
  font-weight: 600; font-family: var(--mono); vertical-align: middle;
}
.b-high, .b-fail { background: rgba(248,113,113,0.16); color: var(--red); border: 1px solid rgba(248,113,113,0.35); }
.b-med, .b-warn { background: rgba(251,191,36,0.16); color: var(--amber); border: 1px solid rgba(251,191,36,0.35); }
.b-info, .b-low, .b-pass { background: rgba(52,211,153,0.16); color: var(--green); border: 1px solid rgba(52,211,153,0.35); }
.b-type { background: rgba(56,189,248,0.14); color: var(--accent); border: 1px solid rgba(56,189,248,0.3); }
.card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
  padding: 16px 18px; margin-bottom: 14px;
}
.alert-row {
  display: flex; gap: 10px; align-items: flex-start; padding: 9px 0;
  border-bottom: 1px solid var(--border); font-size: 0.9rem;
}
.alert-row:last-child { border-bottom: none; }
.hint { color: var(--muted); font-size: 0.82rem; margin-top: 2px; }
.search {
  width: 100%; max-width: 360px; padding: 8px 12px; border-radius: 8px;
  border: 1px solid var(--border); background: var(--surface); color: var(--text);
  margin-bottom: 14px; font-size: 0.9rem;
}
.col-head { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 10px; }
.col-name { font-family: var(--mono); font-size: 1rem; font-weight: 700; }
.col-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 760px) { .col-grid { grid-template-columns: 1fr; } }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; font-family: var(--mono); }
.bar-track { width: 100%; height: 8px; background: var(--surface-2); border-radius: 4px; overflow: hidden; }
.bar-fill { height: 100%; background: var(--accent); border-radius: 4px; }
code, pre { font-family: var(--mono); font-size: 0.82rem; }
pre { background: var(--surface-2); padding: 12px; border-radius: 8px; overflow-x: auto; border: 1px solid var(--border); }
.footer { margin-top: 36px; text-align: center; color: var(--muted); font-size: 0.8rem; }
"#;

const THEME_JS: &str = r#"
<script>
function toggleTheme() {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
}
function filterCols(q) {
  const needle = q.toLowerCase();
  document.querySelectorAll('.col-card').forEach(el => {
    el.style.display = el.dataset.col.includes(needle) ? '' : 'none';
  });
}
</script>
"#;

pub fn render_profile_html(p: &DatasetProfile) -> String {
    let mut body = String::new();
    body.push_str(&format!(
        "<header><div><h1>⚓ statkeel Profile — {}</h1><div class=\"meta\">Source: {} · {}{}</div></div><button class=\"btn\" onclick=\"toggleTheme()\">Toggle Light/Dark</button></header>",
        esc(&p.dataset),
        esc(&p.source_kind),
        if p.sampled { "Sampled view" } else { "Full scan" },
        if p.candidate_keys.is_empty() {
            String::new()
        } else {
            format!(" · Candidate keys: {}", esc(&p.candidate_keys.join(", ")))
        }
    ));

    body.push_str("<div class=\"kpis\">");
    body.push_str(&kpi("Rows", &fmt_int(p.row_count)));
    body.push_str(&kpi("Columns", &fmt_int(p.column_count)));
    body.push_str(&kpi("Missing Cells", &format!("{:.2}%", p.missing_pct)));
    body.push_str(&kpi(
        "Duplicate Rows",
        &format!("{} ({:.1}%)", p.duplicate_row_count, p.duplicate_row_pct),
    ));
    body.push_str(&kpi("Alerts", &fmt_int(p.alerts.len())));
    body.push_str("</div>");

    // Alerts section
    body.push_str("<h2>Quality &amp; Join-Safety Alerts</h2><div class=\"card\">");
    if p.alerts.is_empty() {
        body.push_str("<span class=\"badge b-pass\">CLEAN</span> No quality alerts triggered.");
    } else {
        for a in &p.alerts {
            let cls = match a.severity {
                AlertSeverity::High => "b-high",
                AlertSeverity::Medium => "b-med",
                AlertSeverity::Info => "b-info",
            };
            body.push_str(&format!(
                "<div class=\"alert-row\"><span class=\"badge {cls}\">{}</span><div><strong>{}</strong><div class=\"hint\">Fix: {}</div></div></div>",
                esc(&a.code),
                esc(&a.message),
                esc(&a.fix_hint)
            ));
        }
    }
    body.push_str("</div>");

    // Columns section
    body.push_str("<h2>Column Profiles</h2>");
    body.push_str("<input class=\"search\" type=\"search\" placeholder=\"Filter columns by name or type...\" oninput=\"filterCols(this.value)\" />");
    for col in &p.columns {
        body.push_str(&render_column_card(col));
    }

    // Correlations
    if !p.correlations.is_empty() {
        body.push_str("<h2>Numeric Correlations (Pearson r)</h2><div class=\"card\"><table><thead><tr><th>Column A</th><th>Column B</th><th class=\"num\">Pearson r</th><th>Strength</th></tr></thead><tbody>");
        for c in p.correlations.iter().take(20) {
            let pct_w = (c.pearson_r.abs() * 100.0).min(100.0);
            let color = if c.pearson_r >= 0.0 {
                "var(--accent)"
            } else {
                "var(--amber)"
            };
            body.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td class=\"num\">{:+.4}</td><td><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{pct_w:.1}%;background:{color}\"></div></div></td></tr>",
                esc(&c.col_a),
                esc(&c.col_b),
                c.pearson_r
            ));
        }
        body.push_str("</tbody></table></div>");
    }

    wrap_html(&format!("statkeel Profile — {}", p.dataset), &body)
}

fn render_column_card(c: &ColumnProfile) -> String {
    let mut badges = format!(
        "<span class=\"badge b-type\">{}</span>",
        esc(&c.inferred_type)
    );
    if c.is_unique && c.null_count == 0 {
        badges.push_str(" <span class=\"badge b-pass\">UNIQUE KEY</span>");
    } else if c.unique_pct >= 90.0 && !c.is_unique && c.non_null_count >= 10 {
        badges.push_str(" <span class=\"badge b-high\">NEAR-UNIQUE FANOUT RISK</span>");
    }
    for pii in &c.pii_flags {
        badges.push_str(&format!(
            " <span class=\"badge b-med\">PII:{}</span>",
            esc(pii)
        ));
    }

    let mut left_tbl = String::from("<table><tbody>");
    left_tbl.push_str(&kv_row("Non-null", &fmt_int(c.non_null_count)));
    left_tbl.push_str(&kv_row(
        "Missing",
        &format!("{} ({:.2}%)", c.null_count, c.null_pct),
    ));
    left_tbl.push_str(&kv_row(
        "Distinct",
        &format!("{} ({:.2}%)", c.distinct_count, c.unique_pct),
    ));
    if let Some(num) = &c.numeric {
        left_tbl.push_str(&kv_row("Min / Max", &format!("{} / {}", num.min, num.max)));
        left_tbl.push_str(&kv_row(
            "Mean ± Std",
            &format!("{} ± {}", num.mean, num.std_dev),
        ));
        left_tbl.push_str(&kv_row(
            "P5 / P25 / Median / P75 / P95",
            &format!(
                "{} / {} / {} / {} / {}",
                num.p5, num.p25, num.median, num.p75, num.p95
            ),
        ));
        left_tbl.push_str(&kv_row(
            "Zeros / Outliers",
            &format!(
                "{} ({:.1}%) / {} ({:.1}%)",
                num.zeros_count, num.zeros_pct, num.outlier_count, num.outlier_pct
            ),
        ));
    } else if let Some(st) = &c.string {
        left_tbl.push_str(&kv_row(
            "Length (min / mean / max)",
            &format!("{} / {} / {}", st.min_len, st.mean_len, st.max_len),
        ));
        if st.whitespace_padded_count > 0 {
            left_tbl.push_str(&kv_row(
                "Whitespace-padded",
                &st.whitespace_padded_count.to_string(),
            ));
        }
        if st.leading_zero_numeric_count > 0 {
            left_tbl.push_str(&kv_row(
                "Leading-zero numeric IDs",
                &st.leading_zero_numeric_count.to_string(),
            ));
        }
    }
    left_tbl.push_str("</tbody></table>");

    let right_viz = if let Some(num) = &c.numeric {
        render_histogram_svg(&num.histogram)
    } else {
        let mut tv = String::from(
            "<table><thead><tr><th>Top Value</th><th class=\"num\">Count</th><th class=\"num\">%</th></tr></thead><tbody>",
        );
        for v in c.top_values.iter().take(6) {
            tv.push_str(&format!(
                "<tr><td><code>{}</code><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{:.1}%\"></div></div></td><td class=\"num\">{}</td><td class=\"num\">{:.1}%</td></tr>",
                esc(&v.value),
                v.pct.min(100.0),
                v.count,
                v.pct
            ));
        }
        tv.push_str("</tbody></table>");
        tv
    };

    format!(
        "<div class=\"card col-card\" data-col=\"{} {}\"><div class=\"col-head\"><span class=\"col-name\">{}</span><div>{badges}</div></div><div class=\"col-grid\"><div>{left_tbl}</div><div>{right_viz}</div></div></div>",
        esc(&c.name.to_ascii_lowercase()),
        esc(&c.inferred_type.to_ascii_lowercase()),
        esc(&c.name)
    )
}

fn render_histogram_svg(bins: &[HistogramBin]) -> String {
    if bins.is_empty() {
        return String::new();
    }
    let max_c = bins.iter().map(|b| b.count).max().unwrap_or(1).max(1) as f64;
    let w = 440.0;
    let h = 140.0;
    let pad_b = 24.0;
    let chart_h = h - pad_b - 8.0;
    let bw = (w - 16.0) / bins.len() as f64;

    let mut rects = String::new();
    for (i, b) in bins.iter().enumerate() {
        let bh = (b.count as f64 / max_c) * chart_h;
        let x = 8.0 + i as f64 * bw;
        let y = 8.0 + (chart_h - bh);
        let rw = (bw - 3.0).max(2.0);
        rects.push_str(&format!(
            "<rect x=\"{x:.1}\" y=\"{y:.1}\" width=\"{rw:.1}\" height=\"{bh:.1}\" rx=\"2\" fill=\"var(--accent)\"><title>[{}, {}]: {} rows</title></rect>",
            b.start, b.end, b.count
        ));
    }
    let lo = bins.first().map(|b| b.start).unwrap_or(0.0);
    let hi = bins.last().map(|b| b.end).unwrap_or(0.0);
    format!(
        "<svg viewBox=\"0 0 {w} {h}\" width=\"100%\" height=\"{h}\" role=\"img\" aria-label=\"Histogram\">{rects}<text x=\"8\" y=\"{}\" fill=\"var(--muted)\" font-size=\"10\" font-family=\"monospace\">{lo}</text><text x=\"{}\" y=\"{}\" text-anchor=\"end\" fill=\"var(--muted)\" font-size=\"10\" font-family=\"monospace\">{hi}</text></svg>",
        h - 6.0,
        w - 8.0,
        h - 6.0
    )
}

pub fn render_join_html(r: &JoinReport) -> String {
    let badge_cls = match r.risk_level.as_str() {
        "high" => "b-high",
        "medium" => "b-med",
        _ => "b-pass",
    };
    let mut body = format!(
        "<header><div><h1>⚓ statkeel Join Health — {} ⋈ {}</h1><div class=\"meta\">Cardinality: <span class=\"badge {badge_cls}\">{}</span> · Risk: <span class=\"badge {badge_cls}\">{}</span></div></div><button class=\"btn\" onclick=\"toggleTheme()\">Toggle Light/Dark</button></header>",
        esc(&r.left.name),
        esc(&r.right.name),
        esc(&r.cardinality),
        esc(&r.risk_level.to_uppercase())
    );

    body.push_str("<div class=\"kpis\">");
    body.push_str(&kpi(
        "Left Coverage",
        &format!("{:.1}%", r.left.matched_pct),
    ));
    body.push_str(&kpi(
        "Right Coverage",
        &format!("{:.1}%", r.right.matched_pct),
    ));
    body.push_str(&kpi(
        "LEFT JOIN Fan-Out",
        &format!("{:.3}x ({} rows)", r.left_fanout_ratio, r.left_join_rows),
    ));
    body.push_str(&kpi("INNER JOIN Rows", &fmt_int(r.inner_join_rows)));
    body.push_str("</div>");

    if !r.warnings.is_empty() || !r.failures.is_empty() {
        body.push_str("<h2>Warnings &amp; Threshold Failures</h2><div class=\"card\">");
        for f in &r.failures {
            body.push_str(&format!(
                "<div class=\"alert-row\"><span class=\"badge b-fail\">FAIL</span><div>{}</div></div>",
                esc(f)
            ));
        }
        for w in &r.warnings {
            body.push_str(&format!(
                "<div class=\"alert-row\"><span class=\"badge b-med\">WARN</span><div>{}</div></div>",
                esc(w)
            ));
        }
        body.push_str("</div>");
    }

    if !r.normalization_hints.is_empty() {
        body.push_str("<h2>Auto-Diagnosed Key Fixes</h2><div class=\"card\"><table><thead><tr><th>Transform</th><th class=\"num\">Match Lift</th><th class=\"num\">New Coverage</th><th>SQL Fix</th></tr></thead><tbody>");
        for h in &r.normalization_hints {
            body.push_str(&format!(
                "<tr><td><code>{}</code></td><td class=\"num\">+{:.1}%</td><td class=\"num\">{:.1}%</td><td><code>{}</code></td></tr>",
                esc(&h.transform),
                h.lift_pct,
                h.matched_left_pct_after,
                esc(&h.sql_hint)
            ));
        }
        body.push_str("</tbody></table></div>");
    }

    body.push_str("<div class=\"col-grid\">");
    for (title, side) in [("Left Side", &r.left), ("Right Side", &r.right)] {
        let mut c = format!(
            "<div class=\"card\"><h3>{title}: {} ({})</h3><table><tbody>",
            esc(&side.name),
            esc(&side.keys.join(", "))
        );
        c.push_str(&kv_row("Total Rows", &fmt_int(side.total_rows)));
        c.push_str(&kv_row("Distinct Keys", &fmt_int(side.distinct_keys)));
        c.push_str(&kv_row(
            "Duplicate Keys / Max Rows",
            &format!("{} (max {}x)", side.duplicate_keys, side.max_rows_per_key),
        ));
        c.push_str(&kv_row(
            "Null Keys",
            &format!("{} ({:.1}%)", side.null_keys, side.null_pct),
        ));
        c.push_str(&kv_row(
            "Matched / Orphans",
            &format!(
                "{} ({:.1}%) / {}",
                side.matched_rows, side.matched_pct, side.orphan_rows
            ),
        ));
        c.push_str("</tbody></table>");
        if !side.unmatched_samples.is_empty() {
            c.push_str(&format!(
                "<div class=\"hint\" style=\"margin-top:10px\">Unmatched samples: <code>{}</code></div>",
                esc(&side.unmatched_samples.join(", "))
            ));
        }
        c.push_str("</div>");
        body.push_str(&c);
    }
    body.push_str("</div>");

    wrap_html(
        &format!("statkeel Join — {} ⋈ {}", r.left.name, r.right.name),
        &body,
    )
}

pub fn render_audit_html(r: &AuditReport) -> String {
    let v_cls = match r.verdict.as_str() {
        "FAIL" => "b-fail",
        "WARN" => "b-warn",
        _ => "b-pass",
    };
    let mut body = format!(
        "<header><div><h1>⚓ statkeel Query Trust Receipt</h1><div class=\"meta\">Verdict: <span class=\"badge {v_cls}\">{}</span> · Mode: {}</div></div><button class=\"btn\" onclick=\"toggleTheme()\">Toggle Light/Dark</button></header>",
        esc(&r.verdict),
        esc(&r.mode)
    );

    body.push_str("<div class=\"kpis\">");
    body.push_str(&kpi("Verdict", &r.verdict));
    body.push_str(&kpi(
        "Final Rows",
        &r.final_row_count
            .map(|v| v.to_string())
            .unwrap_or_else(|| "static".to_string()),
    ));
    body.push_str(&kpi("High Findings", &r.high_count.to_string()));
    body.push_str(&kpi("Warnings", &r.medium_count.to_string()));
    body.push_str("</div>");

    if !r.waterfall.is_empty() {
        let max_rows = r
            .waterfall
            .iter()
            .map(|w| w.row_count)
            .max()
            .unwrap_or(1)
            .max(1) as f64;
        body.push_str("<h2>Live Row-Count Waterfall</h2><div class=\"card\"><table><thead><tr><th>Stage</th><th class=\"num\">Rows</th><th class=\"num\">Delta</th><th class=\"num\">Ratio</th><th>Volume</th><th>Note</th></tr></thead><tbody>");
        for s in &r.waterfall {
            let pct_w = (s.row_count as f64 / max_rows * 100.0).min(100.0);
            let delta_s = s
                .delta
                .map(|d| format!("{d:+}"))
                .unwrap_or_else(|| "—".to_string());
            let ratio_s = s
                .ratio_vs_prev
                .map(|v| format!("{v:.3}x"))
                .unwrap_or_else(|| "—".to_string());
            body.push_str(&format!(
                "<tr><td><code>{}</code></td><td class=\"num\">{}</td><td class=\"num\">{delta_s}</td><td class=\"num\">{ratio_s}</td><td style=\"width:180px\"><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{pct_w:.1}%\"></div></div></td><td>{}</td></tr>",
                esc(&s.stage),
                s.row_count,
                esc(s.note.as_deref().unwrap_or(""))
            ));
        }
        body.push_str("</tbody></table></div>");
    }

    body.push_str("<h2>Findings &amp; Fixes</h2><div class=\"card\">");
    if r.findings.is_empty() {
        body.push_str(
            "<span class=\"badge b-pass\">PASS</span> No semantic or live data hazards detected.",
        );
    } else {
        for f in &r.findings {
            let cls = match f.severity {
                FindingSeverity::High => "b-high",
                FindingSeverity::Medium => "b-med",
                FindingSeverity::Info => "b-info",
            };
            body.push_str(&format!(
                "<div class=\"alert-row\"><span class=\"badge {cls}\">{}</span><div><strong>{}</strong><div class=\"hint\">Fix: {}</div></div></div>",
                esc(&f.code),
                esc(&f.message),
                esc(&f.fix_hint)
            ));
        }
    }
    body.push_str("</div>");

    if let Some(sc) = &r.spot_check
        && !sc.rows.is_empty()
    {
        body.push_str("<h2>Spot-Check Sample Rows</h2><div class=\"card\" style=\"overflow-x:auto\"><table><thead><tr>");
        for c in &sc.columns {
            body.push_str(&format!("<th>{}</th>", esc(c)));
        }
        body.push_str("</tr></thead><tbody>");
        for row in &sc.rows {
            body.push_str("<tr>");
            for v in row {
                let s = match v {
                    serde_json::Value::Null => "NULL".to_string(),
                    serde_json::Value::String(st) => st.clone(),
                    other => other.to_string(),
                };
                body.push_str(&format!("<td><code>{}</code></td>", esc(&s)));
            }
            body.push_str("</tr>");
        }
        body.push_str("</tbody></table></div>");
    }

    wrap_html("statkeel Query Trust Receipt", &body)
}

fn wrap_html(title: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"en\" data-theme=\"dark\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><title>{}</title><style>{SHARED_CSS}</style></head><body><div class=\"wrap\">{body}<div class=\"footer\">Generated offline by <strong>statkeel</strong> · Keel Data Stack</div></div>{THEME_JS}</body></html>",
        esc(title)
    )
}

fn kpi(label: &str, val: &str) -> String {
    format!(
        "<div class=\"kpi\"><div class=\"label\">{}</div><div class=\"val\">{}</div></div>",
        esc(label),
        esc(val)
    )
}

fn kv_row(k: &str, v: &str) -> String {
    format!(
        "<tr><th>{}</th><td class=\"num\">{}</td></tr>",
        esc(k),
        esc(v)
    )
}

fn fmt_int(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
