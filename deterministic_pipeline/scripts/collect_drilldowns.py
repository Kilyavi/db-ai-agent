import json
import os
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.clickhouse import query_df
from lib.artifacts import atomic_write_dataframe_csv, atomic_write_text
from lib.config import (
    date_range_sql_condition,
    get_database,
    get_date_range,
    get_main_identifier,
    load_pipeline_config,
    output_dir,
)
from lib.sql import qident, sql_literal


METRICS_JSON = "quality_metrics.json"
STABLE_MANIFEST_JSON = "quality_drilldowns.json"


def load_metrics(reports_dir: Path) -> dict:
    run_id = os.getenv("DQ_RUN_ID")
    path = (
        reports_dir / f"quality_metrics_{run_id}.json"
        if run_id
        else reports_dir / METRICS_JSON
    )
    if not path.exists():
        raise FileNotFoundError(f"No metrics file found: {path}. Run collect_metrics.py first.")
    return json.loads(path.read_text(encoding="utf-8"))


def has_columns(result: dict, *columns: str) -> bool:
    present = set(result.get("columns_present", []))
    return all(column in present for column in columns)


def candidate_tables(metrics: dict, max_tables: int) -> list[dict]:
    candidates = []

    for result in metrics.get("results", []):
        if result.get("status") != "checked":
            continue

        rows_total = max(int(result.get("rows_total") or 0), 1)
        duplicate_rows = int(result.get("duplicate_rows") or 0)
        burst_rows = (
            int(result.get("same_second_burst_rows") or 0)
            if result.get("same_second_burst_check") == "checked"
            else 0
        )
        future_rows = int(result.get("future_event_time_rows") or 0)
        score = max(duplicate_rows, burst_rows, future_rows) / rows_total

        if score > 0:
            candidates.append((score, result))

    return [item for _, item in sorted(candidates, key=lambda pair: pair[0], reverse=True)[:max_tables]]


def save_df(df: pd.DataFrame, path: Path) -> str:
    atomic_write_dataframe_csv(df, path)
    return str(path)


def optional_norm(columns: set[str], column: str) -> str:
    if column in columns:
        return f"nullIf(ifNull(toString({column}), ''), '')"
    return "NULL"


def date_range_event_filter(config: dict, column_name: str) -> str:
    return date_range_sql_condition(get_date_range(config), column_name)


def duplicate_samples(config: dict, result: dict, limit: int) -> pd.DataFrame:
    database = get_database(config)
    table = result["table"]
    table_ref = f"{qident(database)}.{qident(table)}"
    columns = set(result.get("columns_present", []))
    main_identifier = get_main_identifier(config)
    main_identifier_expr = optional_norm(columns, main_identifier)

    return query_df(f"""
        SELECT
            '{table}' AS event_table,
            event_date,
            nullIf(ifNull(toString(adid), ''), '') AS adid,
            nullIf(ifNull(toString(event_key), ''), '') AS event_key,
            count() AS rows_same_event_key_adid_time,
            uniqExact({main_identifier_expr}) AS unique_main_identifiers
        FROM {table_ref}
        WHERE {date_range_event_filter(config, "event_date")}
          AND adid IS NOT NULL
          AND trim(BOTH ' ' FROM toString(adid)) != ''
          AND lower(toString(adid)) != 'null'
          AND event_key IS NOT NULL
          AND trim(BOTH ' ' FROM toString(event_key)) != ''
          AND lower(toString(event_key)) != 'null'
        GROUP BY
            event_date,
            adid,
            event_key
        HAVING rows_same_event_key_adid_time > 1
        ORDER BY rows_same_event_key_adid_time DESC
        LIMIT {int(limit)}
    """, config)


def same_second_samples(config: dict, table: str, limit: int) -> pd.DataFrame:
    database = get_database(config)
    table_ref = f"{qident(database)}.{qident(table)}"
    threshold = int(
        config.get("quality_definitions", {})
        .get("same_second_burst", {})
        .get("default_unique_event_key_threshold", 3)
    )

    return query_df(f"""
        SELECT
            '{table}' AS event_table,
            event_date,
            nullIf(ifNull(toString(adid), ''), '') AS adid,
            count() AS rows_same_second,
            uniqExact(nullIf(ifNull(toString(event_key), ''), '')) AS unique_event_keys
        FROM {table_ref}
        WHERE {date_range_event_filter(config, "event_date")}
          AND adid IS NOT NULL
          AND trim(BOTH ' ' FROM toString(adid)) != ''
          AND lower(toString(adid)) != 'null'
          AND event_key IS NOT NULL
          AND trim(BOTH ' ' FROM toString(event_key)) != ''
          AND lower(toString(event_key)) != 'null'
        GROUP BY
            event_date,
            adid
        HAVING unique_event_keys > {threshold}
        ORDER BY rows_same_second DESC
        LIMIT {int(limit)}
    """, config)


def future_time_samples(config: dict, table: str, limit: int) -> pd.DataFrame:
    database = get_database(config)
    table_ref = f"{qident(database)}.{qident(table)}"
    tolerance = int(
        config.get("quality_definitions", {})
        .get("future_event_time", {})
        .get("future_tolerance_minutes", 10)
    )

    return query_df(f"""
        SELECT
            '{table}' AS event_table,
            event_date,
            now() AS checked_at
        FROM {table_ref}
        WHERE event_date > now() + INTERVAL {tolerance} MINUTE
        ORDER BY event_date DESC
        LIMIT {int(limit)}
    """, config)


def main():
    config = load_pipeline_config()
    reports_dir = output_dir()
    timestamp = os.getenv("DQ_RUN_ID") or datetime.now().strftime("%Y%m%d_%H%M%S")

    metrics = load_metrics(reports_dir)
    max_tables = int(config.get("drilldown", {}).get("max_tables", 20))
    max_rows = int(config.get("drilldown", {}).get("max_rows_per_table", 50))
    tables = candidate_tables(metrics, max_tables)

    duplicate_parts = []
    same_second_parts = []
    future_parts = []
    errors = []

    print("Collecting deterministic drilldowns...")
    print(f"Candidate tables: {len(tables)}")

    for result in tables:
        table = result["table"]
        print(f"Drilling into {table}...")

        try:
            if int(result.get("duplicate_rows") or 0) > 0 and has_columns(result, "adid", "event_key"):
                duplicate_parts.append(duplicate_samples(config, result, max_rows))

            if (
                result.get("same_second_burst_check") == "checked"
                and int(result.get("same_second_burst_rows") or 0) > 0
                and has_columns(result, "adid", "event_key")
            ):
                same_second_parts.append(same_second_samples(config, table, max_rows))

            if int(result.get("future_event_time_rows") or 0) > 0:
                future_parts.append(future_time_samples(config, table, max_rows))

        except Exception as e:
            errors.append({
                "event_table": table,
                "error": str(e),
            })

    duplicate_df = pd.concat(duplicate_parts, ignore_index=True) if duplicate_parts else pd.DataFrame()
    same_second_df = pd.concat(same_second_parts, ignore_index=True) if same_second_parts else pd.DataFrame()
    future_df = pd.concat(future_parts, ignore_index=True) if future_parts else pd.DataFrame()
    error_df = pd.DataFrame(errors)

    duplicate_path = reports_dir / f"duplicate_samples_{timestamp}.csv"
    same_second_path = reports_dir / f"same_second_samples_{timestamp}.csv"
    future_path = reports_dir / f"future_time_samples_{timestamp}.csv"
    errors_path = reports_dir / f"drilldown_errors_{timestamp}.csv"

    manifest = {
        "script": "collect_drilldowns",
        "created_at": str(datetime.now()),
        "duplicate_samples": save_df(duplicate_df, duplicate_path),
        "same_second_samples": save_df(same_second_df, same_second_path),
        "future_time_samples": save_df(future_df, future_path),
        "errors": save_df(error_df, errors_path),
    }

    manifest_path = reports_dir / f"quality_drilldowns_{timestamp}.json"
    stable_manifest_path = reports_dir / STABLE_MANIFEST_JSON
    text = json.dumps(manifest, indent=2, ensure_ascii=False)
    atomic_write_text(manifest_path, text)
    atomic_write_text(stable_manifest_path, text)

    print(f"Saved drilldown manifest: {manifest_path}")
    print(f"Saved stable drilldown manifest: {stable_manifest_path}")

    if errors:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
