"""Security log analysis and investigation timeline generation."""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
from typing import Any

import pandas as pd


# =========================================================
# PROJECT CONFIGURATION
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_INPUT = PROJECT_ROOT / "data" / "sample_security_logs.csv"

DEFAULT_OUTPUT = PROJECT_ROOT / "reports" / "incident_timeline.csv"

REQUIRED_COLUMNS = {
    "Timestamp",
    "User",
    "Event",
    "Source IP",
    "Result",
}

OUTPUT_COLUMNS = [
    "Timestamp",
    "User",
    "Event",
    "Source IP",
    "Result",
    "Severity",
    "Detection Rule",
    "Investigation Recommendation",
]

SUCCESS_RESULTS = {"success", "successful"}

FAILURE_RESULTS = {"failure", "failed", "denied"}

SENSITIVE_EVENTS = {
    "bank details modified",
    "supplier bank details modified",
    "payment details modified",
    "privileged access granted",
    "password changed",
    "security settings changed",
    "mfa disabled",
    "multi-factor authentication disabled",
}

DEFAULT_THRESHOLD = 2

DEFAULT_WINDOW_MINUTES = 15

# Reference date used when timestamps contain times only.
REFERENCE_DATE = "2000-01-01"


# =========================================================
# TIMESTAMP PARSING
# =========================================================

def parse_timestamp(value: str, row_number: int) -> pd.Timestamp:
    """Parse a timestamp with or without a calendar date."""

    value = value.strip()

    # Handle time-only timestamps such as 09:00 or 09:00:30.
    for time_format in ("%H:%M", "%H:%M:%S"):
        try:
            parsed_time = pd.to_datetime(
                value,
                format=time_format,
                errors="raise",
            )

            return pd.Timestamp(
                year=2000,
                month=1,
                day=1,
                hour=parsed_time.hour,
                minute=parsed_time.minute,
                second=parsed_time.second,
                tz="UTC",
            )

        except ValueError:
            continue

    # Handle complete timestamps, including ISO 8601 timestamps.
    try:
        timestamp = pd.Timestamp(value)

        if pd.isna(timestamp):
            raise ValueError("Timestamp is missing.")

        if timestamp.tzinfo is None:
            timestamp = timestamp.tz_localize("UTC")
        else:
            timestamp = timestamp.tz_convert("UTC")

        return timestamp

    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError(
            f"Invalid timestamp on CSV row {row_number}: {value!r}"
        ) from exc


# =========================================================
# DATA INGESTION AND VALIDATION
# =========================================================

def load_logs(file_path: str | Path = DEFAULT_INPUT) -> pd.DataFrame:
    """Load and validate security logs from a CSV file."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Security log file not found: {path}"
        )

    try:
        logs = pd.read_csv(
            path,
            dtype=str,
            keep_default_na=False,
        )

    except (
        OSError,
        UnicodeError,
        pd.errors.ParserError,
    ) as exc:
        raise ValueError(
            f"Unable to read security log CSV: {path}"
        ) from exc

    if logs.empty:
        raise ValueError(
            "The security log file contains no records."
        )

    missing_columns = REQUIRED_COLUMNS - set(logs.columns)

    if missing_columns:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(sorted(missing_columns))
        )

    logs = logs.copy()

    # Validate required fields.
    for column in REQUIRED_COLUMNS:
        logs[column] = logs[column].astype(str).str.strip()

        if logs[column].eq("").any():
            raise ValueError(
                f"Column '{column}' contains empty values."
            )

    # Parse timestamps consistently.
    logs["Timestamp"] = pd.to_datetime(
        [
            parse_timestamp(value, row_number)
            for row_number, value in enumerate(
                logs["Timestamp"],
                start=2,
            )
        ],
        utc=True,
    )

    # Validate and normalize event results.
    normalized_results = logs["Result"].str.casefold()

    valid_results = SUCCESS_RESULTS | FAILURE_RESULTS

    invalid_results = ~normalized_results.isin(valid_results)

    if invalid_results.any():
        invalid_values = sorted(
            logs.loc[invalid_results, "Result"].unique().tolist()
        )

        raise ValueError(
            f"Unsupported results: {invalid_values}. "
            "Use Success, Failure, or Denied."
        )

    logs["Result"] = normalized_results.map(
        lambda result: (
            "Success"
            if result in SUCCESS_RESULTS
            else "Failure"
        )
    )

    # Validate source IP addresses.
    invalid_ips = []

    for index, address in logs["Source IP"].items():
        try:
            ipaddress.ip_address(address)

        except ValueError:
            invalid_ips.append(index + 2)

    if invalid_ips:
        raise ValueError(
            f"Invalid IP addresses on CSV rows: {invalid_ips}"
        )

    # Sort records chronologically.
    logs = logs.sort_values(
        "Timestamp",
        kind="stable",
    ).reset_index(drop=True)

    return logs


# =========================================================
# INVESTIGATION METRICS
# =========================================================

def calculate_investigation_metrics(
    logs: pd.DataFrame,
) -> dict[str, Any]:
    """
    Calculate the investigation start, end, and duration.

    This implements the same calculation as the Jupyter Notebook.
    """

    if logs.empty:
        raise ValueError(
            "Cannot calculate investigation metrics from empty logs."
        )

    investigation_start = logs["Timestamp"].min()

    investigation_end = logs["Timestamp"].max()

    investigation_duration = (
        investigation_end - investigation_start
    )

    duration_minutes = (
        investigation_duration.total_seconds() / 60
    )

    return {
        "investigation_start": investigation_start,
        "investigation_end": investigation_end,
        "investigation_duration": investigation_duration,
        "duration_minutes": duration_minutes,
        "records_analyzed": len(logs),
    }


def print_investigation_metrics(
    metrics: dict[str, Any],
) -> None:
    """Print investigation metrics in a readable format."""

    start = metrics["investigation_start"]

    end = metrics["investigation_end"]

    duration = metrics["investigation_duration"]

    print("\nINVESTIGATION SUMMARY")
    print("=" * 60)

    print(f"Investigation start: {start:%H:%M:%S}")

    print(f"Investigation end:   {end:%H:%M:%S}")

    print(
        "Investigation duration: "
        f"{duration.total_seconds() / 60:.0f} minutes"
    )

    print(
        f"Records analyzed: {metrics['records_analyzed']}"
    )


# =========================================================
# SECURITY FINDING CONSTRUCTION
# =========================================================

def make_finding(
    log: pd.Series,
    severity: str,
    detection_rule: str,
    recommendation: str,
) -> dict[str, Any]:
    """Create a standardized security finding."""

    return {
        "Timestamp": log["Timestamp"],
        "User": log["User"],
        "Event": log["Event"],
        "Source IP": log["Source IP"],
        "Result": log["Result"],
        "Severity": severity,
        "Detection Rule": detection_rule,
        "Investigation Recommendation": recommendation,
    }


# =========================================================
# DETECTION RULE 1
# REPEATED FAILED LOGINS
# =========================================================

def detect_repeated_failures(
    logs: pd.DataFrame,
    threshold: int = DEFAULT_THRESHOLD,
) -> list[dict[str, Any]]:
    """Detect repeated failed logins from the same user and IP."""

    if threshold < 1:
        raise ValueError(
            "threshold must be at least 1."
        )

    findings = []

    failed_logins = logs[
        logs["Event"].str.casefold().eq("login")
        & logs["Result"].eq("Failure")
    ]

    grouped = failed_logins.groupby(
        ["User", "Source IP"],
        sort=False,
    )

    for _, group in grouped:
        group = group.sort_values(
            "Timestamp",
            kind="stable",
        )

        if len(group) < threshold:
            continue

        triggering_log = group.iloc[threshold - 1]

        findings.append(
            make_finding(
                triggering_log,
                severity="Medium",
                detection_rule="Repeated Failed Logins",
                recommendation=(
                    "Review authentication records, verify the "
                    "user's identity, and investigate the source IP."
                ),
            )
        )

    return findings


# =========================================================
# DETECTION RULE 2
# SUCCESS AFTER REPEATED FAILURES
# =========================================================

def detect_success_after_failures(
    logs: pd.DataFrame,
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> list[dict[str, Any]]:
    """Detect successful logins following repeated failures."""

    if threshold < 1:
        raise ValueError(
            "threshold must be at least 1."
        )

    if window_minutes <= 0:
        raise ValueError(
            "window_minutes must be greater than zero."
        )

    window = pd.Timedelta(minutes=window_minutes)

    findings = []

    login_logs = logs[
        logs["Event"].str.casefold().eq("login")
    ].sort_values(
        "Timestamp",
        kind="stable",
    )

    grouped = login_logs.groupby(
        ["User", "Source IP"],
        sort=False,
    )

    for _, group in grouped:
        failures = []

        for _, log in group.iterrows():
            timestamp = log["Timestamp"]

            failures = [
                failure_time
                for failure_time in failures
                if timestamp - failure_time <= window
            ]

            if log["Result"] == "Failure":
                failures.append(timestamp)
                continue

            if len(failures) >= threshold:
                findings.append(
                    make_finding(
                        log,
                        severity="High",
                        detection_rule=(
                            "Successful Login After Repeated Failures"
                        ),
                        recommendation=(
                            "Verify whether the successful login was "
                            "authorized. Review MFA records, session "
                            "activity, and account access history."
                        ),
                    )
                )

            failures = []

    return findings


# =========================================================
# DETECTION RULE 3
# SENSITIVE ACTIVITY AFTER SUSPICIOUS AUTHENTICATION
# =========================================================

def detect_sensitive_activity(
    logs: pd.DataFrame,
    suspicious_logins: list[dict[str, Any]],
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> list[dict[str, Any]]:
    """Detect sensitive actions following suspicious logins."""

    if window_minutes <= 0:
        raise ValueError(
            "window_minutes must be greater than zero."
        )

    window = pd.Timedelta(minutes=window_minutes)

    findings = []

    suspicious_successes = [
        finding
        for finding in suspicious_logins
        if finding["Detection Rule"]
        == "Successful Login After Repeated Failures"
    ]

    sensitive_logs = logs[
        logs["Event"].str.casefold().isin(SENSITIVE_EVENTS)
        & logs["Result"].eq("Success")
    ]

    for _, log in sensitive_logs.iterrows():
        for login in suspicious_successes:
            if (
                log["User"] != login["User"]
                or log["Source IP"] != login["Source IP"]
            ):
                continue

            elapsed = log["Timestamp"] - login["Timestamp"]

            if pd.Timedelta(0) <= elapsed <= window:
                findings.append(
                    make_finding(
                        log,
                        severity="Critical",
                        detection_rule=(
                            "Sensitive Activity After Suspicious Login"
                        ),
                        recommendation=(
                            "Verify the sensitive change with the "
                            "authorized account owner. Preserve audit "
                            "records and follow incident response "
                            "procedures."
                        ),
                    )
                )

                break

    return findings


# =========================================================
# SECURITY ANALYSIS PIPELINE
# =========================================================

def analyze_logs(
    logs: pd.DataFrame,
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> pd.DataFrame:
    """Analyze logs and return a chronological incident timeline."""

    findings = detect_repeated_failures(
        logs,
        threshold=threshold,
    )

    suspicious_logins = detect_success_after_failures(
        logs,
        threshold=threshold,
        window_minutes=window_minutes,
    )

    findings.extend(suspicious_logins)

    findings.extend(
        detect_sensitive_activity(
            logs,
            suspicious_logins=suspicious_logins,
            window_minutes=window_minutes,
        )
    )

    if not findings:
        return pd.DataFrame(columns=OUTPUT_COLUMNS)

    timeline = pd.DataFrame(
        findings,
        columns=OUTPUT_COLUMNS,
    )

    severity_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
    }

    timeline["_severity_order"] = timeline["Severity"].map(
        severity_order
    )

    timeline = timeline.sort_values(
        ["Timestamp", "_severity_order"],
        kind="stable",
    )

    return (
        timeline.drop(columns="_severity_order")
        .reset_index(drop=True)
    )


# =========================================================
# REPORT GENERATION
# =========================================================

def save_timeline(
    timeline: pd.DataFrame,
    output_path: str | Path = DEFAULT_OUTPUT,
) -> Path:
    """Save the incident timeline to CSV."""

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    timeline.to_csv(
        path,
        index=False,
        date_format="%Y-%m-%dT%H:%M:%SZ",
    )

    return path


# =========================================================
# MAIN EXECUTION
# =========================================================

def run_analysis(
    input_path: str | Path = DEFAULT_INPUT,
    output_path: str | Path = DEFAULT_OUTPUT,
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> pd.DataFrame:
    """Run the complete security log analysis pipeline."""

    # Step 1: Load security logs.
    logs = load_logs(input_path)

    # Step 2: Calculate investigation metrics.
    metrics = calculate_investigation_metrics(logs)

    # Step 3: Print investigation metrics.
    print_investigation_metrics(metrics)

    # Step 4: Analyze security events.
    timeline = analyze_logs(
        logs,
        threshold=threshold,
        window_minutes=window_minutes,
    )

    # Step 5: Save the incident timeline.
    saved_path = save_timeline(
        timeline,
        output_path,
    )

    # Step 6: Display analysis results.
    print("\nSECURITY ANALYSIS RESULTS")
    print("=" * 60)

    print(f"Findings detected: {len(timeline)}")

    print(f"Report saved to: {saved_path.resolve()}")

    if timeline.empty:
        print("\nNo findings matched the configured rules.")

    else:
        print("\nFindings by severity:")

        for severity in [
            "Critical",
            "High",
            "Medium",
            "Low",
        ]:
            count = int(
                timeline["Severity"].eq(severity).sum()
            )

            if count:
                print(f"  {severity}: {count}")

        print("\nIncident timeline:")

        print(
            timeline[
                [
                    "Timestamp",
                    "User",
                    "Event",
                    "Source IP",
                    "Severity",
                    "Detection Rule",
                ]
            ].to_string(index=False)
        )

    return timeline


def main() -> None:
    """Parse command-line arguments and run the analysis."""

    parser = argparse.ArgumentParser(
        description="Analyze security logs and investigation duration."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Input security log CSV.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output incident timeline CSV.",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help="Failed-login threshold. Default: 2.",
    )

    parser.add_argument(
        "--window-minutes",
        type=int,
        default=DEFAULT_WINDOW_MINUTES,
        help="Detection window in minutes. Default: 15.",
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1.")

    if args.window_minutes <= 0:
        parser.error("--window-minutes must be greater than zero.")

    run_analysis(
        input_path=args.input,
        output_path=args.output,
        threshold=args.threshold,
        window_minutes=args.window_minutes,
    )


if __name__ == "__main__":
    main()