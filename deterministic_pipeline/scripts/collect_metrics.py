import fnmatch
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.clickhouse import query_df
from lib.artifacts import atomic_write_dataframe_csv, atomic_write_text
from lib.config import (
    date_range_sql_condition,
    date_range_sql_interval,
    filter_blacklisted,
    get_database,
    get_date_range,
    get_date_range_description,
    get_identifier_aliases,
    get_lookback_range,
    get_main_identifier,
    get_table_prefixes,
    load_pipeline_config,
    historical_lookback_sql_condition,
    lookback_comparison_window_count,
    missing_session_id_allowed_tables,
    missing_main_identifier_allowed_tables,
    output_dir,
    quality_check_enabled,
    same_second_allowed_tables,
    same_second_strict_tables,
)
from lib.sql import pct, qident, sql_literal


STABLE_METRICS_JSON = "quality_metrics.json"
STABLE_INVENTORY_CSV = "table_inventory.csv"
STABLE_EVENT_QUALITY_CSV = "event_quality.csv"
STABLE_PARAMETER_QUALITY_CSV = "parameter_quality.csv"
NON_STORAGE_EVENT_ENGINES = {
    "Dictionary",
    "LiveView",
    "MaterializedView",
    "View",
    "WindowView",
}


def max_event_tables(config: dict) -> int:
    raw_value = (
        os.getenv("DQ_MAX_EVENT_TABLES")
        or config.get("collection", {}).get("max_event_tables")
        or config.get("db_problem_scan", {}).get("scan_max_event_tables")
        or 200
    )
    value = int(raw_value)
    if value <= 0:
        raise ValueError("max event tables must be greater than zero")
    return value


def collection_workers(config: dict) -> int:
    raw_value = (
        os.getenv("DQ_WORKERS")
        or config.get("collection", {}).get("workers")
        or 4
    )
    value = int(raw_value)
    if value <= 0:
        raise ValueError("collection workers must be greater than zero")
    return value


def is_event_storage_table(item: dict) -> bool:
    return bool(item.get("has_event_date")) and item.get("engine") not in (
        NON_STORAGE_EVENT_ENGINES
    )


def first_value(df, column: str, default=None):
    if df.empty or column not in df.columns:
        return default
    return df.iloc[0][column]


def normalize_columns(value) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return []


def discover_inventory(config: dict) -> list[dict]:
    database = get_database(config)
    prefixes = get_table_prefixes(config)
    max_tables = int(config.get("collection", {}).get("max_inventory_tables", 200))

    prefix_conditions = " OR ".join(
        f"startsWith(c.table, {sql_literal(prefix)})"
        for prefix in prefixes
    )
    if not prefix_conditions:
        prefix_conditions = "1"

    df = query_df(f"""
        SELECT
            table,
            engine,
            estimated_rows,
            column_count,
            columns
        FROM
        (
            SELECT
                c.table AS table,
                any(t.engine) AS engine,
                ifNull(any(p.estimated_rows), 0) AS estimated_rows,
                count() AS column_count,
                groupUniqArray(c.name) AS columns
            FROM system.columns AS c
            INNER JOIN system.tables AS t
                ON c.database = t.database
               AND c.table = t.name
            LEFT JOIN
            (
                SELECT
                    database,
                    table,
                    sum(rows) AS estimated_rows
                FROM system.parts
                WHERE active
                  AND database = {sql_literal(database)}
                GROUP BY
                    database,
                    table
            ) AS p
                ON c.database = p.database
               AND c.table = p.table
            WHERE c.database = {sql_literal(database)}
              AND ({prefix_conditions})
            GROUP BY c.table
        )
        ORDER BY estimated_rows DESC, table
        LIMIT {max_tables}
    """, config)

    inventory = []
    identifier_aliases = {
        "adid": get_identifier_aliases(config, "adid"),
        "main_identifier": get_identifier_aliases(config, "user_id"),
        "session_id": get_identifier_aliases(config, "session_id"),
        "event_key": get_identifier_aliases(config, "event_key"),
    }
    allowed_tables = set(filter_blacklisted(df["table"].astype(str).tolist(), config))

    for row in df.to_dict("records"):
        table = str(row["table"])
        if table not in allowed_tables:
            continue

        columns = normalize_columns(row.get("columns", []))
        inventory.append({
            "table": table,
            "engine": str(row.get("engine", "")),
            "estimated_rows": int(row.get("estimated_rows", 0) or 0),
            "column_count": int(row.get("column_count", 0) or 0),
            "has_event_date": "event_date" in columns,
            "has_event_key": any(alias in columns for alias in identifier_aliases["event_key"]),
            "has_adid": any(alias in columns for alias in identifier_aliases["adid"]),
            "has_main_identifier": any(
                alias in columns
                for alias in identifier_aliases["main_identifier"]
            ),
            "has_session_id": any(alias in columns for alias in identifier_aliases["session_id"]),
            "columns": columns,
        })

    return inventory


def norm_value_expr(column: str) -> str:
    identifier = qident(column)
    return f"""
        if(
            {identifier} IS NULL
            OR trim(BOTH ' ' FROM toString({identifier})) = ''
            OR toString({identifier}) = '00000000-0000-0000-0000-000000000000'
            OR lower(toString({identifier})) = 'null',
            NULL,
            toString({identifier})
        )
    """.strip()


def norm_expr(
    columns: set[str],
    column: str,
    aliases: list[str] | None = None,
) -> str:
    present = [alias for alias in (aliases or [column]) if alias in columns]
    if not present:
        return f"NULL AS {column}_norm"
    values = [norm_value_expr(alias) for alias in present]
    value_expr = values[0] if len(values) == 1 else f"coalesce({', '.join(values)})"
    return f"{value_expr} AS {column}_norm"


def date_range_time_filter(config: dict, column_name: str) -> str:
    return date_range_sql_condition(get_date_range(config), column_name)


def lookback_history_condition(config: dict, column_name: str) -> str:
    date_range = get_date_range(config)
    lookback = get_lookback_range(config)
    return historical_lookback_sql_condition(
        date_range,
        lookback,
        column_name,
    )


def lookback_scope_condition(config: dict, column_name: str) -> str:
    date_range = get_date_range(config)
    lookback = get_lookback_range(config)
    if date_range.get("mode") == "fixed":
        start = f"{date_range['start_date']} 00:00:00"
        end = f"{date_range['end_date_exclusive']} 00:00:00"
        return (
            f"{column_name} >= toDateTime({sql_literal(start)}) "
            f"- {date_range_sql_interval(lookback)} "
            f"AND {column_name} < toDateTime({sql_literal(end)})"
        )
    return (
        f"{column_name} >= now() - {date_range_sql_interval(date_range)} "
        f"- {date_range_sql_interval(lookback)} "
        f"AND {column_name} < now()"
    )


def scan_table(config: dict, table: str, columns: list[str]) -> dict:
    database = get_database(config)
    date_range = get_date_range(config)
    lookback = get_lookback_range(config)
    if (
        date_range.get("mode") == "rolling"
        and lookback["duration_seconds"] <= date_range["duration_seconds"]
    ):
        raise ValueError("lookback must be longer than the rolling date_range")
    columns_set = set(columns)
    identifier_aliases = {
        "adid": get_identifier_aliases(config, "adid"),
        "main_identifier": get_identifier_aliases(config, "user_id"),
        "session_id": get_identifier_aliases(config, "session_id"),
        "event_key": get_identifier_aliases(config, "event_key"),
    }

    if "event_date" not in columns_set:
        return {
            "table": table,
            "status": "skipped",
            "reason": "No event_date column",
        }

    future_tolerance = int(
        config.get("quality_definitions", {})
        .get("future_event_time", {})
        .get("future_tolerance_minutes", 10)
    )
    future_event_time_enabled = quality_check_enabled(config, "future_event_time", True)
    same_second_threshold = int(
        config.get("quality_definitions", {})
        .get("same_second_burst", {})
        .get("default_unique_event_key_threshold", 3)
    )

    allowed_same_second = same_second_allowed_tables(config)
    strict_same_second = same_second_strict_tables(config)
    allowed_missing_main_identifier = missing_main_identifier_allowed_tables(config)
    allowed_missing_session_id = missing_session_id_allowed_tables(config)

    table_ref = f"{qident(database)}.{qident(table)}"

    base_from = f"""
        FROM
        (
            SELECT
                event_date AS event_time,
                {norm_expr(columns_set, "adid", identifier_aliases["adid"])},
                {norm_expr(
                    columns_set,
                    "main_identifier",
                    identifier_aliases["main_identifier"],
                )},
                {norm_expr(columns_set, "session_id", identifier_aliases["session_id"])},
                {norm_expr(columns_set, "event_key", identifier_aliases["event_key"])}
            FROM {table_ref}
            WHERE {date_range_time_filter(config, "event_date")}
        )
        WHERE event_time IS NOT NULL
    """

    main_df = query_df(f"""
        SELECT
            count() AS rows_total,
            countIf(event_time >= today()
                    AND event_time < today() + 1) AS rows_today,
            countIf(event_time >= today() - 1
                    AND event_time < today()) AS rows_yesterday,
            min(event_time) AS min_event_time,
            max(event_time) AS max_event_time,
            countIf(adid_norm IS NULL) AS missing_adid_rows,
            countIf(main_identifier_norm IS NULL) AS missing_main_identifier_rows,
            countIf(session_id_norm IS NULL) AS missing_session_id_rows,
            countIf(event_key_norm IS NULL) AS missing_event_key_rows
        {base_from}
    """, config)

    if future_event_time_enabled:
        future_df = query_df(f"""
            SELECT
                count() AS future_event_time_rows,
                max(event_date) AS max_future_event_time
            FROM {table_ref}
            WHERE event_date > now() + INTERVAL {future_tolerance} MINUTE
        """, config)
    else:
        future_df = pd.DataFrame([{
            "future_event_time_rows": 0,
            "max_future_event_time": None,
        }])

    volume_df = query_df(f"""
        SELECT count() AS lookback_rows
        FROM {table_ref}
        WHERE {lookback_history_condition(config, "event_date")}
    """, config)

    rows_total = int(first_value(main_df, "rows_total", 0) or 0)
    lookback_rows = int(first_value(volume_df, "lookback_rows", 0) or 0)
    comparison_windows = lookback_comparison_window_count(date_range, lookback)
    expected_rows = (
        lookback_rows / comparison_windows
        if comparison_windows > 0
        else None
    )
    delta_vs_lookback_expected = (
        (rows_total - expected_rows) / expected_rows
        if expected_rows and expected_rows > 0
        else None
    )
    duplicate_rows = 0
    replicated_rows = 0
    same_second_burst_rows = 0

    if (
        any(alias in columns_set for alias in identifier_aliases["event_key"])
        and any(alias in columns_set for alias in identifier_aliases["adid"])
    ):
        anomaly_df = query_df(f"""
            SELECT
                ifNull(sum(group_rows - 1), 0) AS duplicate_rows,
                ifNull(count() - uniqExact(event_key_norm), 0) AS replicated_rows,
                ifNull(
                    sumIf(
                        rows_in_second,
                        key_rank = 1 AND unique_event_keys > {same_second_threshold}
                    ),
                    0
                ) AS same_second_burst_rows
            FROM
            (
                SELECT
                    event_time,
                    adid_norm,
                    event_key_norm,
                    group_rows,
                    sum(group_rows) OVER (
                        PARTITION BY event_time, adid_norm
                    ) AS rows_in_second,
                    count() OVER (
                        PARTITION BY event_time, adid_norm
                    ) AS unique_event_keys,
                    row_number() OVER (
                        PARTITION BY event_time, adid_norm
                        ORDER BY event_key_norm
                    ) AS key_rank
                FROM
                (
                    SELECT
                        event_time,
                        adid_norm,
                        event_key_norm,
                        count() AS group_rows
                    {base_from}
                      AND adid_norm IS NOT NULL
                      AND event_key_norm IS NOT NULL
                    GROUP BY
                        event_time,
                        adid_norm,
                        event_key_norm
                )
            )
        """, config)
        duplicate_rows = int(first_value(anomaly_df, "duplicate_rows", 0) or 0)
        replicated_rows = int(first_value(anomaly_df, "replicated_rows", 0) or 0)
        same_second_burst_rows = int(
            first_value(anomaly_df, "same_second_burst_rows", 0) or 0
        )

    if table in allowed_same_second and table not in strict_same_second:
        same_second_burst_check = "allowed_group"
    else:
        same_second_burst_check = "checked"

    missing_main_identifier_check = (
        "allowed_group" if table in allowed_missing_main_identifier else "checked"
    )
    missing_session_id_check = (
        "allowed_group" if table in allowed_missing_session_id else "checked"
    )

    return {
        "table": table,
        "status": "checked",
        "date_range": date_range,
        "lookback": lookback,
        "period_days": date_range.get("days_back"),
        "period_hours": date_range.get("hours_back"),
        "rows_total": rows_total,
        "rows_in_range": rows_total,
        "rows_today": int(first_value(main_df, "rows_today", 0) or 0),
        "rows_yesterday": rows_total,
        "lookback_rows": lookback_rows,
        "expected_rows_from_lookback": expected_rows,
        "delta_vs_lookback_expected": delta_vs_lookback_expected,
        "median_prev_days": expected_rows,
        "delta_yesterday_vs_median": delta_vs_lookback_expected,
        "min_event_time": str(first_value(main_df, "min_event_time")) if first_value(main_df, "min_event_time") is not None else None,
        "max_event_time": str(first_value(main_df, "max_event_time")) if first_value(main_df, "max_event_time") is not None else None,
        "future_event_time_check": "checked" if future_event_time_enabled else "disabled",
        "future_event_time_rows": int(
            first_value(future_df, "future_event_time_rows", 0) or 0
        ),
        "max_future_event_time": (
            str(first_value(future_df, "max_future_event_time"))
            if first_value(future_df, "max_future_event_time") is not None
            else None
        ),
        "duplicate_rows": duplicate_rows,
        "duplicate_pct": pct(duplicate_rows, rows_total),
        "replicated_rows": replicated_rows,
        "replicated_pct": pct(replicated_rows, rows_total),
        "same_second_burst_rows": same_second_burst_rows,
        "same_second_burst_pct": pct(same_second_burst_rows, rows_total),
        "same_second_burst_check": same_second_burst_check,
        "missing_adid_rows": int(first_value(main_df, "missing_adid_rows", 0) or 0),
        "missing_adid_pct": pct(int(first_value(main_df, "missing_adid_rows", 0) or 0), rows_total),
        "main_identifier": get_main_identifier(config),
        "missing_main_identifier_rows": int(
            first_value(main_df, "missing_main_identifier_rows", 0) or 0
        ),
        "missing_main_identifier_pct": pct(
            int(first_value(main_df, "missing_main_identifier_rows", 0) or 0),
            rows_total,
        ),
        "missing_main_identifier_check": missing_main_identifier_check,
        "missing_session_id_rows": int(first_value(main_df, "missing_session_id_rows", 0) or 0),
        "missing_session_id_pct": pct(int(first_value(main_df, "missing_session_id_rows", 0) or 0), rows_total),
        "missing_session_id_check": missing_session_id_check,
        "missing_event_key_rows": int(first_value(main_df, "missing_event_key_rows", 0) or 0),
        "missing_event_key_pct": pct(int(first_value(main_df, "missing_event_key_rows", 0) or 0), rows_total),
        "identifier_columns": {
            identifier: [alias for alias in aliases if alias in columns_set]
            for identifier, aliases in identifier_aliases.items()
        },
        "columns_present": sorted(columns),
    }


def json_values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        values = list(value)
    elif hasattr(value, "tolist"):
        values = value.tolist()
    else:
        values = [value]
    return [str(item) for item in values]


def scan_parameters(config: dict, table: str, columns: list[str]) -> list[dict]:
    parameter_config = config.get("parameter_quality", {})
    auto = parameter_config.get("auto_discovery", {})
    exclude_columns = set(auto.get("exclude_columns", [])) | {
        "event_date",
        "event_key",
        "adid",
        get_main_identifier(config),
        "session_id",
        "session_uuid",
        "sessions_uuid",
    }
    exclude_patterns = auto.get("exclude_patterns", ["*_json", "*_jsonb"])
    parameters = [
        column
        for column in sorted(set(columns))
        if column not in exclude_columns
        and not any(fnmatch.fnmatchcase(column, pattern) for pattern in exclude_patterns)
    ][:int(parameter_config.get("max_parameters_per_table", 200))]
    if not parameters:
        return []

    measurement_condition = date_range_time_filter(config, "event_time")
    history_condition = lookback_history_condition(config, "event_time")
    top_limit = int(parameter_config.get("defaults", {}).get("top_values_limit", 10))
    value_selects = []
    metric_selects = [
        f"countIf({measurement_condition}) AS rows_checked",
        f"countIf({history_condition}) AS lookback_rows_checked",
    ]
    for index, parameter in enumerate(parameters):
        alias = qident(f"parameter_{index}")
        value_selects.append(f"{norm_value_expr(parameter)} AS {alias}")
        metric_selects.extend([
            f"countIf(({measurement_condition}) AND {alias} IS NULL) AS missing_{index}",
            f"topKIf({top_limit})(ifNull({alias}, '<MISSING>'), "
            f"{measurement_condition}) AS observed_{index}",
            f"countIf(({history_condition}) AND {alias} IS NULL) "
            f"AS lookback_missing_{index}",
            f"topKIf({top_limit})(ifNull({alias}, '<MISSING>'), "
            f"{history_condition}) AS lookback_observed_{index}",
        ])

    database = get_database(config)
    df = query_df(f"""
        SELECT {', '.join(metric_selects)}
        FROM
        (
            SELECT
                event_date AS event_time,
                {', '.join(value_selects)}
            FROM {qident(database)}.{qident(table)}
            WHERE {lookback_scope_condition(config, 'event_date')}
        )
    """, config)
    row = df.iloc[0] if not df.empty else {}
    rows_checked = int(row.get("rows_checked", 0) or 0)
    lookback_rows_checked = int(row.get("lookback_rows_checked", 0) or 0)
    required_presence = float(auto.get("required_min_presence_pct", 0.95))
    flag_unpopulated = bool(auto.get("flag_unpopulated", True))
    default_missing = float(
        parameter_config.get("defaults", {}).get("max_missing_pct", 0.0)
    )
    results = []
    for index, parameter in enumerate(parameters):
        missing_rows = int(row.get(f"missing_{index}", 0) or 0)
        lookback_missing_rows = int(row.get(f"lookback_missing_{index}", 0) or 0)
        missing_pct = pct(missing_rows, rows_checked)
        lookback_missing_pct = pct(lookback_missing_rows, lookback_rows_checked)
        lookback_presence_pct = (
            1.0 - lookback_missing_pct
            if lookback_missing_pct is not None
            else None
        )
        inferred_required = bool(
            lookback_presence_pct is not None
            and lookback_presence_pct >= required_presence
        )
        max_missing_pct = float(
            config.get("thresholds", {}).get(
                f"missing_{parameter}_pct",
                default_missing,
            )
        )
        problems = []
        if flag_unpopulated and lookback_missing_pct == 1.0:
            if missing_pct is not None and missing_pct < 1.0:
                problems.append("newly_populated")
            else:
                problems.append("unpopulated_column")
        elif (
            inferred_required
            and missing_pct is not None
            and missing_pct > max_missing_pct
        ):
            problems.append("missing_values")
        results.append({
            "event_table": table,
            "parameter": parameter,
            "status": "problem" if problems else "ok",
            "date_range_description": get_date_range(config)["description"],
            "lookback_description": get_lookback_range(config)["description"],
            "rows_checked": rows_checked,
            "missing_rows": missing_rows,
            "missing_pct": missing_pct,
            "observed_values": json_values(row.get(f"observed_{index}")),
            "lookback_rows_checked": lookback_rows_checked,
            "lookback_missing_rows": lookback_missing_rows,
            "lookback_presence_pct": lookback_presence_pct,
            "lookback_observed_values": json_values(
                row.get(f"lookback_observed_{index}")
            ),
            "expected_present_rows": (
                rows_checked * lookback_presence_pct
                if lookback_presence_pct is not None
                else None
            ),
            "inferred_required": inferred_required,
            "problem": ",".join(problems),
        })
    return results


def write_inventory(path: Path, inventory: list[dict]) -> None:
    df = pd.DataFrame(inventory)
    if not df.empty and "columns" in df.columns:
        df["columns"] = df["columns"].apply(lambda value: ", ".join(value))
    atomic_write_dataframe_csv(df, path)


def scan_event_table(config: dict, item: dict) -> tuple[dict, list[dict]]:
    table = item["table"]
    try:
        event_result = scan_table(config, table, item["columns"])
    except Exception as error:
        event_result = {
            "table": table,
            "status": "error",
            "error": str(error),
        }

    try:
        parameter_results = scan_parameters(config, table, item["columns"])
    except Exception as error:
        parameter_results = [{
            "event_table": table,
            "parameter": "*",
            "status": "error",
            "error": str(error),
        }]
    return event_result, parameter_results


def main():
    config = load_pipeline_config()
    reports_dir = output_dir()
    timestamp = os.getenv("DQ_RUN_ID") or datetime.now().strftime("%Y%m%d_%H%M%S")

    print("Collecting deterministic DB metrics...")
    print(f"Database: {get_database(config)}")
    print(f"Date range: {get_date_range_description(config)}")

    inventory = discover_inventory(config)
    discovered_event_tables = [item for item in inventory if is_event_storage_table(item)]
    non_storage_event_objects = [
        item["table"]
        for item in inventory
        if item.get("has_event_date") and not is_event_storage_table(item)
    ]
    table_limit = max_event_tables(config)
    event_tables = discovered_event_tables[:table_limit]
    event_tables_not_scanned = [
        item["table"] for item in discovered_event_tables[table_limit:]
    ]
    print(
        "Event-table coverage: "
        f"{len(event_tables)}/{len(discovered_event_tables)} "
        f"(configured limit: {table_limit})"
    )
    if event_tables_not_scanned:
        print(
            "WARNING: coverage is incomplete; not scanned: "
            + ", ".join(event_tables_not_scanned)
        )

    worker_count = min(collection_workers(config), max(len(event_tables), 1))
    print(f"Collection workers: {worker_count}")
    if worker_count > 1:
        os.environ.setdefault("DB_AGENT_SPINNER", "0")

    event_results_by_table = {}
    parameter_results_by_table = {}
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(scan_event_table, config, item): item["table"]
            for item in event_tables
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            table = futures[future]
            event_result, table_parameter_results = future.result()
            event_results_by_table[table] = event_result
            parameter_results_by_table[table] = table_parameter_results
            print(f"Completed {table} ({completed}/{len(event_tables)})")

    results = [event_results_by_table[item["table"]] for item in event_tables]
    parameter_results = [
        result
        for item in event_tables
        for result in parameter_results_by_table[item["table"]]
    ]

    inventory_path = reports_dir / f"table_inventory_{timestamp}.csv"
    metrics_path = reports_dir / f"quality_metrics_{timestamp}.json"
    event_quality_path = reports_dir / f"event_quality_{timestamp}.csv"
    parameter_quality_path = reports_dir / f"parameter_quality_{timestamp}.csv"
    stable_inventory_path = reports_dir / STABLE_INVENTORY_CSV
    stable_metrics_path = reports_dir / STABLE_METRICS_JSON
    stable_event_quality_path = reports_dir / STABLE_EVENT_QUALITY_CSV
    stable_parameter_quality_path = reports_dir / STABLE_PARAMETER_QUALITY_CSV

    write_inventory(inventory_path, inventory)
    write_inventory(stable_inventory_path, inventory)
    atomic_write_dataframe_csv(pd.DataFrame(results), event_quality_path)
    atomic_write_dataframe_csv(pd.DataFrame(results), stable_event_quality_path)
    atomic_write_dataframe_csv(
        pd.DataFrame(parameter_results), parameter_quality_path
    )
    atomic_write_dataframe_csv(
        pd.DataFrame(parameter_results), stable_parameter_quality_path
    )

    artifact = {
        "script": "collect_metrics",
        "created_at": str(datetime.now()),
        "database": get_database(config),
        "main_identifier": get_main_identifier(config),
        "date_range": get_date_range(config),
        "lookback": get_lookback_range(config),
        "period_days": get_date_range(config).get("days_back"),
        "period_hours": get_date_range(config).get("hours_back"),
        "tables_discovered": len(inventory),
        "event_tables_discovered": len(discovered_event_tables),
        "event_tables_checked": len(event_tables),
        "event_tables_not_scanned": event_tables_not_scanned,
        "non_storage_event_objects_skipped": non_storage_event_objects,
        "coverage_complete": not event_tables_not_scanned,
        "collection_workers": worker_count,
        "event_quality_csv": str(event_quality_path),
        "parameter_quality_csv": str(parameter_quality_path),
        "results": results,
        "parameter_results": parameter_results,
    }

    text = json.dumps(artifact, indent=2, ensure_ascii=False)
    atomic_write_text(metrics_path, text)
    atomic_write_text(stable_metrics_path, text)

    print(f"Saved metrics: {metrics_path}")
    print(f"Saved stable metrics: {stable_metrics_path}")
    print(f"Saved inventory: {inventory_path}")
    print(f"Saved event quality CSV: {event_quality_path}")
    print(f"Saved parameter quality CSV: {parameter_quality_path}")

    if event_tables_not_scanned or any(
        result.get("status") == "error"
        for result in [*results, *parameter_results]
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
