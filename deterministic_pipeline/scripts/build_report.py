import json
import math
import os
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.artifacts import atomic_write_text
from lib.config import (
    get_event_context,
    get_main_identifier,
    load_pipeline_config,
    missing_session_id_allowed_tables,
    missing_main_identifier_allowed_tables,
    output_dir,
    quality_check_enabled,
    same_second_allowed_tables,
    same_second_strict_tables,
)


METRICS_JSON = "quality_metrics.json"
DRILLDOWNS_JSON = "quality_drilldowns.json"
STABLE_REPORT_TXT = "quality_report.txt"


def pct_to_str(value) -> str:
    if value is None:
        return ""

    try:
        if math.isnan(float(value)):
            return ""
        return f"{float(value) * 100:.2f}%"
    except Exception:
        return ""


def load_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def threshold(config: dict, name: str, default: float = 0.01) -> float:
    thresholds = config.get("thresholds", {})
    return float(thresholds.get(name, default))


def skip_missing(config: dict, table: str, check_name: str) -> bool:
    context = get_event_context(config, table)
    accepted_names = {check_name}
    if any(context.get(name) is True for name in accepted_names):
        return True
    if (
        check_name == "skip_main_identifier_check"
        and table in missing_main_identifier_allowed_tables(config)
    ):
        return True
    if (
        check_name == "skip_session_id_check"
        and table in missing_session_id_allowed_tables(config)
    ):
        return True
    return False


def classify_result(config: dict, result: dict) -> dict:
    table = result.get("table")
    confirmed = []
    expected = []
    investigate = []

    if result.get("status") == "error":
        confirmed.append(f"{table}: scan_error={result.get('error')}")
        return {
            "table": table,
            "confirmed": confirmed,
            "expected": expected,
            "investigate": investigate,
        }

    if result.get("status") != "checked":
        return {
            "table": table,
            "confirmed": [],
            "expected": [f"{table}: skipped ({result.get('reason')})"],
            "investigate": [],
        }

    rows_total = int(result.get("rows_total") or 0)
    if rows_total == 0:
        confirmed.append(f"CRITICAL {table}: no rows in selected period")

    duplicate_pct = result.get("duplicate_pct")
    if duplicate_pct is not None and duplicate_pct >= threshold(config, "duplicate_pct"):
        confirmed.append(
            f"{table}: duplicate_pct={pct_to_str(duplicate_pct)}, duplicate_rows={result.get('duplicate_rows')}"
        )

    replicated_pct = result.get("replicated_pct")
    if replicated_pct is not None and replicated_pct >= threshold(config, "replicated_pct"):
        confirmed.append(
            f"{table}: replicated_pct={pct_to_str(replicated_pct)}, replicated_rows={result.get('replicated_rows')}"
        )

    delta = result.get("delta_vs_lookback_expected")
    expected_rows = result.get("expected_rows_from_lookback")
    rows_in_range = result.get("rows_in_range")
    min_expected_rows = threshold(
        config, "suspicious_volume_min_expected_rows", 10.0
    )
    new_activity_min_rows = threshold(config, "new_activity_min_rows", 100.0)
    if (
        expected_rows is not None
        and expected_rows >= min_expected_rows
        and delta is not None
    ):
        if delta >= threshold(config, "suspicious_high_delta_pct", 0.2):
            investigate.append(
                f"{table}: suspicious_high delta_vs_lookback_expected={pct_to_str(delta)}, "
                f"rows_in_range={rows_in_range}, expected_rows={expected_rows}"
            )
    elif (
        rows_in_range is not None
        and rows_in_range >= new_activity_min_rows
        and (expected_rows is None or expected_rows < min_expected_rows)
    ):
        investigate.append(
            f"{table}: new_activity rows_in_range={rows_in_range}, "
            f"expected_rows={expected_rows or 0}"
        )
        if delta <= -threshold(config, "suspicious_low_delta_pct", 0.2):
            investigate.append(
                f"{table}: suspicious_low delta_vs_lookback_expected={pct_to_str(delta)}, "
                f"rows_in_range={rows_in_range}, expected_rows={expected_rows}"
            )

    if quality_check_enabled(config, "future_event_time", True):
        future_rows = int(result.get("future_event_time_rows") or 0)
        if future_rows > 0:
            confirmed.append(
                f"{table}: future_event_time_rows={future_rows}, "
                f"max_future_event_time="
                f"{result.get('max_future_event_time', result.get('max_event_time'))}"
            )
    elif result.get("future_event_time_check") == "disabled":
        expected.append(f"{table}: future_event_time check disabled by config")

    identifier_checks = [
        ("missing_adid_pct", "missing_adid_rows", "skip_adid_check"),
        (
            "missing_main_identifier_pct",
            "missing_main_identifier_rows",
            "skip_main_identifier_check",
        ),
        ("missing_session_id_pct", "missing_session_id_rows", "skip_session_id_check"),
        ("missing_event_key_pct", "missing_event_key_rows", "skip_event_key_check"),
    ]

    for pct_col, row_col, skip_col in identifier_checks:
        value = result.get(pct_col)
        if value is None or value < threshold(config, pct_col):
            continue

        display_pct_col = (
            f"missing_{get_main_identifier(config)}_pct"
            if pct_col == "missing_main_identifier_pct"
            else pct_col
        )

        if skip_missing(config, table, skip_col):
            expected.append(
                f"{table}: {display_pct_col}={pct_to_str(value)} allowed by config"
            )
        else:
            confirmed.append(
                f"{table}: {display_pct_col}={pct_to_str(value)}, rows={result.get(row_col)}"
            )

    allowed = same_second_allowed_tables(config)
    strict = same_second_strict_tables(config)
    burst_pct = result.get("same_second_burst_pct")

    if burst_pct is not None and burst_pct >= threshold(config, "same_second_burst_pct"):
        if table in allowed and table not in strict:
            expected.append(
                f"{table}: same_second_burst_pct={pct_to_str(burst_pct)} allowed by event group"
            )
        else:
            investigate.append(
                f"{table}: same_second_burst_pct={pct_to_str(burst_pct)}, rows={result.get('same_second_burst_rows')}"
            )

    return {
        "table": table,
        "confirmed": confirmed,
        "expected": expected,
        "investigate": investigate,
    }


def summarize_csv(path_value: str) -> str:
    if not path_value:
        return "not generated"

    path = Path(path_value)
    if not path.exists():
        return f"{path_value} (missing)"

    try:
        rows = len(pd.read_csv(path))
    except pd.errors.EmptyDataError:
        rows = 0
    except Exception:
        rows = "unknown"

    return f"{path_value} ({rows} rows)"


def summarize_parameter_problems(metrics: dict, column_preview: int = 12) -> list[str]:
    detailed = []
    unpopulated_by_table: dict[str, list[str]] = {}
    for result in metrics.get("parameter_results", []):
        table = str(result.get("event_table"))
        parameter = str(result.get("parameter"))
        if result.get("status") == "error":
            detailed.append(f"{table}.*: error={result.get('error')}")
            continue
        if result.get("status") != "problem":
            continue

        problems = set(str(result.get("problem") or "").split(","))
        if "unpopulated_column" in problems:
            unpopulated_by_table.setdefault(table, []).append(parameter)
            problems.remove("unpopulated_column")

        for problem in sorted(problem for problem in problems if problem):
            detailed.append(
                f"{table}.{parameter}: {problem}; current_missing="
                f"{pct_to_str(result.get('missing_pct'))}; lookback_presence="
                f"{pct_to_str(result.get('lookback_presence_pct'))}; "
                f"expected_present={result.get('expected_present_rows')}"
            )

    grouped = []
    for table, parameters in sorted(unpopulated_by_table.items()):
        ordered = sorted(parameters)
        preview = ", ".join(ordered[:column_preview])
        remainder = len(ordered) - column_preview
        suffix = f" (+{remainder} more)" if remainder > 0 else ""
        grouped.append(
            f"{table}: {len(ordered)} columns unpopulated in the current and "
            f"lookback windows: {preview}{suffix}"
        )
    return detailed + grouped


def build_report(config: dict, metrics: dict, drilldowns: dict | None) -> str:
    confirmed = []
    expected = []
    investigate = []

    for result in metrics.get("results", []):
        classified = classify_result(config, result)
        confirmed.extend(classified["confirmed"])
        expected.extend(classified["expected"])
        investigate.extend(classified["investigate"])

    parameter_problems = summarize_parameter_problems(metrics)

    event_tables_discovered = metrics.get(
        "event_tables_discovered", metrics.get("event_tables_checked")
    )
    event_tables_checked = metrics.get("event_tables_checked")
    event_tables_not_scanned = metrics.get("event_tables_not_scanned") or []
    non_storage_event_objects = metrics.get("non_storage_event_objects_skipped") or []
    if event_tables_not_scanned:
        confirmed.append(
            "Coverage incomplete: "
            f"checked {event_tables_checked}/{event_tables_discovered} event tables; "
            f"not scanned: {', '.join(event_tables_not_scanned)}"
        )

    if not confirmed:
        confirmed.append("No confirmed deterministic problems found.")
    if not expected:
        expected.append("No findings explicitly allowed by configured event context.")
    if not investigate:
        investigate.append("No deterministic investigation-only patterns found.")

    drilldown_lines = []
    if drilldowns:
        drilldown_lines = [
            f"- Duplicate samples: {summarize_csv(drilldowns.get('duplicate_samples'))}",
            f"- Same-second samples: {summarize_csv(drilldowns.get('same_second_samples'))}",
            f"- Future-time samples: {summarize_csv(drilldowns.get('future_time_samples'))}",
            f"- Drilldown errors: {summarize_csv(drilldowns.get('errors'))}",
        ]
    else:
        drilldown_lines = ["- Drilldowns were not generated."]

    definitions = config.get("quality_definitions", {})
    definition_lines = [
        f"- {name}: {definition.get('definition')}"
        for name, definition in definitions.items()
    ]
    date_range = metrics.get("date_range") or {}
    date_range_description = (
        date_range.get("description")
        or f"last {metrics.get('period_days')} days"
    )
    lookback = metrics.get("lookback") or {}
    lookback_description = lookback.get("description") or "30-day historical baseline"

    lines = [
        "Deterministic DB Quality Report",
        f"Generated at: {datetime.now()}",
        f"Database: {metrics.get('database')}",
        f"Main identifier: {metrics.get('main_identifier') or get_main_identifier(config)}",
        f"Date range: {date_range_description}",
        f"Historical lookback: {lookback_description}",
        f"Event tables checked: {event_tables_checked}/{event_tables_discovered}",
        f"Coverage complete: {not event_tables_not_scanned}",
        f"Non-storage event objects inventoried but not scanned: {len(non_storage_event_objects)}",
        "",
        "Definitions",
        *definition_lines,
        "",
        "1. Confirmed Problems",
        *[f"- {line}" for line in confirmed],
        "",
        "2. Parameter Problems",
        *[f"- {line}" for line in (parameter_problems or ["No parameter problems found."])],
        f"- Full event findings: {metrics.get('event_quality_csv', 'quality_metrics JSON')}",
        f"- Full parameter findings: {metrics.get('parameter_quality_csv', 'quality_metrics JSON')}",
        "",
        "3. Explicitly Expected by Configured Event Context",
        *[f"- {line}" for line in expected],
        "",
        "4. Needs More Investigation",
        *[f"- {line}" for line in investigate],
        "",
        "5. Drilldown Artifacts",
        *drilldown_lines,
    ]

    return "\n".join(lines)


def main():
    config = load_pipeline_config()
    reports_dir = output_dir()
    timestamp = os.getenv("DQ_RUN_ID") or datetime.now().strftime("%Y%m%d_%H%M%S")

    run_id = os.getenv("DQ_RUN_ID")
    metrics_path = (
        reports_dir / f"quality_metrics_{run_id}.json"
        if run_id
        else reports_dir / METRICS_JSON
    )
    drilldowns_path = (
        reports_dir / f"quality_drilldowns_{run_id}.json"
        if run_id
        else reports_dir / DRILLDOWNS_JSON
    )
    metrics = load_json(metrics_path)
    drilldowns = load_json(drilldowns_path) if drilldowns_path.exists() else None

    report = build_report(config, metrics, drilldowns)

    report_path = reports_dir / f"quality_report_{timestamp}.txt"
    stable_report_path = reports_dir / STABLE_REPORT_TXT
    atomic_write_text(report_path, report)
    atomic_write_text(stable_report_path, report)

    print(report)
    print(f"\nSaved report: {report_path}")
    print(f"Saved stable report: {stable_report_path}")


if __name__ == "__main__":
    main()
