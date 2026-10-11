"""Tests for security log analysis and investigation metrics."""

import pandas as pd
import pytest

from src.log_analysis import (
    OUTPUT_COLUMNS,
    analyze_logs,
    calculate_investigation_metrics,
    detect_repeated_failures,
    detect_sensitive_activity,
    detect_success_after_failures,
    load_logs,
    save_timeline,
)


@pytest.fixture
def sample_csv(tmp_path):
    """Create a temporary security log CSV."""

    path = tmp_path / "sample_security_logs.csv"

    path.write_text(
        "Timestamp,User,Event,Source IP,Result\n"
        "09:00,buyer01,Login,10.0.0.12,Success\n"
        "09:02,buyer01,Login,203.0.113.25,Failure\n"
        "09:03,buyer01,Login,203.0.113.25,Failure\n"
        "09:04,buyer01,Login,203.0.113.25,Success\n"
        "09:07,buyer01,Supplier record viewed,203.0.113.25,Success\n"
        "09:10,buyer01,Bank details modified,203.0.113.25,Success\n",
        encoding="utf-8",
    )

    return path


@pytest.fixture
def sample_logs(sample_csv):
    """Return validated security logs."""

    return load_logs(sample_csv)


# =========================================================
# DATA LOADING TESTS
# =========================================================

def test_load_logs_reads_six_records(sample_logs):
    assert len(sample_logs) == 6


def test_load_logs_sorts_timestamps(sample_logs):
    assert sample_logs["Timestamp"].is_monotonic_increasing


def test_load_logs_normalizes_results(sample_logs):
    assert set(sample_logs["Result"]) == {
        "Success",
        "Failure",
    }


def test_load_logs_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_logs(tmp_path / "missing.csv")


def test_load_logs_rejects_missing_columns(tmp_path):
    path = tmp_path / "invalid.csv"

    path.write_text(
        "Timestamp,User,Event\n"
        "09:00,buyer01,Login\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Missing required columns"):
        load_logs(path)


def test_load_logs_rejects_invalid_ip(tmp_path):
    path = tmp_path / "invalid_ip.csv"

    path.write_text(
        "Timestamp,User,Event,Source IP,Result\n"
        "09:00,buyer01,Login,invalid-ip,Success\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid IP addresses"):
        load_logs(path)


def test_load_logs_rejects_invalid_timestamp(tmp_path):
    path = tmp_path / "invalid_timestamp.csv"

    path.write_text(
        "Timestamp,User,Event,Source IP,Result\n"
        "not-a-time,buyer01,Login,10.0.0.12,Success\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid timestamp"):
        load_logs(path)


# =========================================================
# INVESTIGATION METRICS TESTS
# =========================================================

def test_investigation_start_is_0900(sample_logs):
    metrics = calculate_investigation_metrics(sample_logs)

    assert metrics["investigation_start"].strftime("%H:%M") == "09:00"


def test_investigation_end_is_0910(sample_logs):
    metrics = calculate_investigation_metrics(sample_logs)

    assert metrics["investigation_end"].strftime("%H:%M") == "09:10"


def test_investigation_duration_is_ten_minutes(sample_logs):
    metrics = calculate_investigation_metrics(sample_logs)

    assert metrics["duration_minutes"] == 10


def test_investigation_duration_matches_timedelta(sample_logs):
    metrics = calculate_investigation_metrics(sample_logs)

    expected_duration = (
        metrics["investigation_end"]
        - metrics["investigation_start"]
    )

    assert metrics["investigation_duration"] == expected_duration


def test_investigation_metrics_count_records(sample_logs):
    metrics = calculate_investigation_metrics(sample_logs)

    assert metrics["records_analyzed"] == 6


def test_investigation_metrics_reject_empty_dataframe():
    logs = pd.DataFrame(
        columns=[
            "Timestamp",
            "User",
            "Event",
            "Source IP",
            "Result",
        ]
    )

    with pytest.raises(ValueError, match="empty logs"):
        calculate_investigation_metrics(logs)


# =========================================================
# DETECTION RULE TESTS
# =========================================================

def test_detect_repeated_failures(sample_logs):
    findings = detect_repeated_failures(sample_logs)

    assert len(findings) == 1

    assert findings[0]["Severity"] == "Medium"

    assert (
        findings[0]["Detection Rule"]
        == "Repeated Failed Logins"
    )


def test_repeated_failures_reject_invalid_threshold(sample_logs):
    with pytest.raises(ValueError, match="threshold"):
        detect_repeated_failures(sample_logs, threshold=0)


def test_detect_success_after_failures(sample_logs):
    findings = detect_success_after_failures(sample_logs)

    assert len(findings) == 1

    assert findings[0]["Severity"] == "High"

    assert findings[0]["Timestamp"].strftime("%H:%M") == "09:04"


def test_success_after_failures_reject_invalid_window(sample_logs):
    with pytest.raises(ValueError, match="window_minutes"):
        detect_success_after_failures(
            sample_logs,
            window_minutes=0,
        )


def test_detect_sensitive_activity(sample_logs):
    suspicious_logins = detect_success_after_failures(sample_logs)

    findings = detect_sensitive_activity(
        sample_logs,
        suspicious_logins,
    )

    assert len(findings) == 1

    assert findings[0]["Event"] == "Bank details modified"

    assert findings[0]["Severity"] == "Critical"


# =========================================================
# INTEGRATION AND REPORT TESTS
# =========================================================

def test_analysis_generates_three_findings(sample_logs):
    timeline = analyze_logs(sample_logs)

    assert len(timeline) == 3

    assert list(timeline.columns) == OUTPUT_COLUMNS


def test_analysis_returns_empty_timeline_without_findings():
    logs = pd.DataFrame(
        [
            {
                "Timestamp": pd.Timestamp(
                    "2000-01-01T09:00:00Z"
                ),
                "User": "buyer01",
                "Event": "Login",
                "Source IP": "10.0.0.12",
                "Result": "Success",
            }
        ]
    )

    timeline = analyze_logs(logs)

    assert timeline.empty


def test_save_timeline_creates_csv(sample_logs, tmp_path):
    timeline = analyze_logs(sample_logs)

    output_path = tmp_path / "reports" / "incident_timeline.csv"

    saved_path = save_timeline(timeline, output_path)

    assert saved_path.exists()

    saved_report = pd.read_csv(saved_path)

    assert len(saved_report) == 3