use assert_cmd::Command;
use predicates::prelude::*;
use rusqlite::Connection;
use tempfile::TempDir;

fn statkeel() -> Command {
    Command::new(env!("CARGO_BIN_EXE_statkeel"))
}

#[test]
fn profile_csv_detects_alerts_pii_near_unique_and_renders_html() {
    let dir = TempDir::new().unwrap();
    let csv_path = dir.path().join("pseudonyms.csv");
    let html_path = dir.path().join("report.html");

    // 12 rows where sis_user_id has 1 duplicate (91.7% unique -> NEAR_UNIQUE_KEY!),
    // plus emails (PII), plus leading-zero mix, plus numeric score.
    let csv_body = "\
user_id,sis_user_id,email,score
1,001001,alice@wts.edu,92
2,001002,bob@wts.edu,88
3,001003,carol@wts.edu,95
4,001004,dave@wts.edu,74
5,001005,eve@wts.edu,81
6,001006,frank@wts.edu,90
7,001007,grace@wts.edu,85
8,001008,heidi@wts.edu,91
9,001009,ivan@wts.edu,78
10,001010,judy@wts.edu,84
11,1011,karl@wts.edu,99
12,001001,alice.alt@wts.edu,92
";
    std::fs::write(&csv_path, csv_body).unwrap();

    let out = statkeel()
        .args([
            "profile",
            csv_path.to_str().unwrap(),
            "--format",
            "json",
            "--html",
            html_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["row_count"], 12);
    assert_eq!(v["column_count"], 4);

    let alert_codes: Vec<&str> = v["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["code"].as_str().unwrap())
        .collect();
    assert!(
        alert_codes.contains(&"NEAR_UNIQUE_KEY"),
        "expected NEAR_UNIQUE_KEY in {alert_codes:?}"
    );
    assert!(
        alert_codes.contains(&"PII_DETECTED"),
        "expected PII_DETECTED in {alert_codes:?}"
    );
    assert!(
        alert_codes.contains(&"MIXED_LEADING_ZEROS"),
        "expected MIXED_LEADING_ZEROS in {alert_codes:?}"
    );

    let html = std::fs::read_to_string(&html_path).unwrap();
    assert!(html.contains("<svg"));
    assert!(html.contains("NEAR_UNIQUE_KEY"));
    assert!(html.contains("statkeel Profile"));
}

#[test]
fn profile_to_contract_emits_valid_toml_and_odcs() {
    let dir = TempDir::new().unwrap();
    let jsonl_path = dir.path().join("students.jsonl");
    std::fs::write(
        &jsonl_path,
        "{\"student_id\":1,\"gpa\":3.8,\"status\":\"active\"}\n\
         {\"student_id\":2,\"gpa\":3.5,\"status\":\"active\"}\n\
         {\"student_id\":3,\"gpa\":3.9,\"status\":\"graduated\"}\n",
    )
    .unwrap();

    statkeel()
        .args([
            "profile",
            jsonl_path.to_str().unwrap(),
            "--to-contract",
            "toml",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("[columns.\"student_id\"]"))
        .stdout(predicate::str::contains("unique = true"));

    statkeel()
        .args([
            "profile",
            jsonl_path.to_str().unwrap(),
            "--to-contract",
            "odcs",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("apiVersion: v3.2.0"))
        .stdout(predicate::str::contains("kind: DataContract"));
}

#[test]
fn join_detects_fanout_and_leading_zero_normalization_fix() {
    let dir = TempDir::new().unwrap();
    let populi_csv = dir.path().join("populi_students.csv");
    let canvas_csv = dir.path().join("canvas_pseudonyms.csv");
    let html_path = dir.path().join("join.html");

    // Populi uses plain IDs "1001".."1004"; Canvas uses zero-padded IDs "001001".."001004" + duplicate!
    std::fs::write(
        &populi_csv,
        "person_id,name\n1001,Alice\n1002,Bob\n1003,Carol\n1004,Dave\n",
    )
    .unwrap();
    std::fs::write(
        &canvas_csv,
        "sis_user_id,login\n001001,alice1\n001001,alice2\n001002,bob\n001003,carol\n009999,ghost\n",
    )
    .unwrap();

    let out = statkeel()
        .args([
            "join",
            populi_csv.to_str().unwrap(),
            canvas_csv.to_str().unwrap(),
            "--left-key",
            "person_id",
            "--right-key",
            "sis_user_id",
            "--format",
            "json",
            "--html",
            html_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["cardinality"], "1:N");
    assert_eq!(v["left"]["matched_rows"], 0);
    let hints = v["normalization_hints"].as_array().unwrap();
    assert!(
        hints.iter().any(|h| h["transform"] == "strip_leading_zeros"
            && h["matched_left_pct_after"].as_f64().unwrap() >= 75.0),
        "expected strip_leading_zeros hint in {hints:?}"
    );
    assert!(html_path.exists());

    // Threshold enforcement should exit 1 when --min-left-coverage 50 is violated.
    statkeel()
        .args([
            "join",
            populi_csv.to_str().unwrap(),
            canvas_csv.to_str().unwrap(),
            "--left-key",
            "person_id",
            "--right-key",
            "sis_user_id",
            "--min-left-coverage",
            "50",
            "--format",
            "agent",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("status: FAIL"));
}

#[test]
fn audit_sqlite_catches_fanout_demoted_left_join_domain_rules_and_passes_when_fixed() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("seminary.db");
    let rules_path = dir.path().join("rules.toml");
    let html_path = dir.path().join("audit.html");

    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "
        CREATE TABLE populi_students (person_id TEXT PRIMARY KEY, name TEXT, credits INT);
        INSERT INTO populi_students VALUES
          ('1001', 'Alice', 12),
          ('1002', 'Bob', 9),
          ('1003', 'Carol', 15),
          ('1004', 'Dave', 6);

        CREATE TABLE canvas_pseudonyms (id INT PRIMARY KEY, sis_user_id TEXT, user_id INT, workflow_state TEXT);
        INSERT INTO canvas_pseudonyms VALUES
          (1, '1001', 101, 'active'),
          (2, '1001', 101, 'deleted'),
          (3, '1002', 102, 'active'),
          (4, '1003', 103, 'active');

        CREATE TABLE canvas_enrollments (id INT PRIMARY KEY, user_id INT, workflow_state TEXT, type TEXT);
        INSERT INTO canvas_enrollments VALUES
          (10, 101, 'active', 'StudentEnrollment'),
          (11, 102, 'deleted', 'StudentEnrollment'),
          (12, 103, 'active', 'TeacherEnrollment');
        ",
    )
    .unwrap();
    drop(conn);

    std::fs::write(
        &rules_path,
        r#"
[[table_rules]]
table = "canvas_enrollments"
required_filters = ["workflow_state", "type"]
severity = "high"
reason = "Enrollments include deleted rows and Teacher/Test Student roles."
fix_hint = "Filter workflow_state = 'active' AND type = 'StudentEnrollment'"
"#,
    )
    .unwrap();

    // 1) BAD AI QUERY: fans out on canvas_pseudonyms (1001 has 2 rows), demotes LEFT JOIN in WHERE,
    //    AND forgets workflow_state/type domain rule on canvas_enrollments!
    let bad_sql = "\
        SELECT s.person_id, s.name, s.credits, e.id AS enrollment_id \
        FROM populi_students s \
        LEFT JOIN canvas_pseudonyms p ON s.person_id = p.sis_user_id \
        LEFT JOIN canvas_enrollments e ON p.user_id = e.user_id \
        WHERE p.workflow_state = 'active'";

    let bad_out = statkeel()
        .args([
            "audit",
            "--query",
            bad_sql,
            "--db",
            &format!("sqlite://{}", db_path.display()),
            "--rules",
            rules_path.to_str().unwrap(),
            "--format",
            "json",
            "--html",
            html_path.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&bad_out).unwrap();
    assert_eq!(v["verdict"], "FAIL");
    let codes: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(
        codes.contains(&"S001_DEMOTED_LEFT_JOIN"),
        "expected S001 in {codes:?}"
    );
    assert!(
        codes.contains(&"S006_DOMAIN_RULE_MISSING_FILTER"),
        "expected S006 in {codes:?}"
    );
    assert!(
        codes.contains(&"L001_LIVE_JOIN_FANOUT"),
        "expected L001 fan-out in {codes:?}"
    );
    assert!(!v["waterfall"].as_array().unwrap().is_empty());
    assert!(html_path.exists());

    // 2) FIXED QUERY: deduplicates pseudonyms in CTE, filters enrollments cleanly inside CTE,
    //    preserves all 4 Populi students with 1.000x fanout!
    let good_sql = "\
        WITH active_pseudonyms AS ( \
            SELECT sis_user_id, MIN(user_id) AS user_id \
            FROM canvas_pseudonyms \
            WHERE workflow_state = 'active' \
            GROUP BY sis_user_id \
        ), \
        active_student_enrollments AS ( \
            SELECT user_id, COUNT(*) AS active_courses \
            FROM canvas_enrollments \
            WHERE workflow_state = 'active' AND type = 'StudentEnrollment' \
            GROUP BY user_id \
        ) \
        SELECT s.person_id, s.name, s.credits, COALESCE(e.active_courses, 0) AS active_courses \
        FROM populi_students s \
        LEFT JOIN active_pseudonyms p ON s.person_id = p.sis_user_id \
        LEFT JOIN active_student_enrollments e ON p.user_id = e.user_id";

    let good_out = statkeel()
        .args([
            "audit",
            "--query",
            good_sql,
            "--db",
            &format!("sqlite://{}", db_path.display()),
            "--rules",
            rules_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let vg: serde_json::Value = serde_json::from_slice(&good_out).unwrap();
    assert_eq!(vg["verdict"], "PASS");
    assert_eq!(vg["final_row_count"], 4);
    assert_eq!(vg["spot_check"]["rows"].as_array().unwrap().len(), 3);
}

#[test]
fn audit_rejects_non_select_statements() {
    statkeel()
        .args([
            "audit",
            "--query",
            "DELETE FROM populi_students WHERE person_id = '1001'",
            "--format",
            "json",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("E_UNSAFE_SQL"));
}

#[test]
fn skill_prints_and_installs() {
    let dir = TempDir::new().unwrap();
    statkeel()
        .args(["skill"])
        .assert()
        .success()
        .stdout(predicate::str::contains("name: statkeel"));

    statkeel()
        .args(["skill", "--install", dir.path().to_str().unwrap()])
        .assert()
        .success();

    assert!(dir.path().join("statkeel/SKILL.md").exists());
}
