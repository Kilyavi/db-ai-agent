import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from quality_config import (
    date_range_sql_condition,
    filter_blacklisted_tables,
    get_database,
    get_date_range,
    get_identifier_aliases,
    get_lookback_range,
    get_main_identifier,
    get_missing_session_id_allowed_tables,
    get_missing_main_identifier_allowed_tables,
    MEASUREMENT_TIME_COLUMN_CANDIDATES,
    measurement_time_column,
    get_same_second_allowed_tables,
    get_same_second_strict_tables,
    get_table_blacklist,
    get_table_prefixes,
    is_quality_check_enabled,
    load_rules as load_config_rules,
)
from readonly_clickhouse import query_df


REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

STABLE_OUTPUT_JSON = REPORT_DIR / "database_quality_scan.json"


DEFAULT_DB = os.getenv("CH_DATABASE", "analytics")
DEFAULT_DAYS_BACK = int(os.getenv("QUALITY_DAYS_BACK", "7"))
DEFAULT_TABLE_NAME_PREFIXES = ["event_"]
DEFAULT_MAX_TABLES = int(os.getenv("DB_SCAN_MAX_TABLES", "200"))
DEFAULT_SCAN_MAX_EVENT_TABLES = int(os.getenv("DB_SCAN_MAX_EVENT_TABLES", "20"))

DEFAULT_PRIORITY_EVENT_TABLES = [
    "event_first_open",
    "event_login",
    "event_session_start",
    "event_purchase",
    "event_click",
    "event_reward",
]

DEFAULT_SKIP_MISSING_MAIN_IDENTIFIER_TABLES = [
    "event_first_open",
]

DEFAULT_SKIP_MISSING_SESSION_ID_TABLES = [
    "event_first_open",
]


def qident(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def normalized_identifier_expr(column: str, alias: str) -> str:
    return f"{normalized_identifier_value_expr(column)} AS {alias}"


def normalized_identifier_value_expr(column: str) -> str:
    zero_uuid = "00000000-0000-0000-0000-000000000000"
    column_ref = qident(column)
    return f"""
        if(
            {column_ref} IS NULL
            OR trim(BOTH ' ' FROM toString({column_ref})) = ''
            OR toString({column_ref}) = '{zero_uuid}'
            OR lower(toString({column_ref})) = 'null',
            NULL,
            toString({column_ref})
        )
    """.strip()


def normalized_identifier_alias_expr(
    columns: set[str],
    aliases: list[str],
    result_alias: str,
) -> tuple[str, list[str]]:
    present = [column for column in aliases if column in columns]
    if not present:
        return f"NULL AS {result_alias}", []
    values = [normalized_identifier_value_expr(column) for column in present]
    value_expr = values[0] if len(values) == 1 else f"coalesce({', '.join(values)})"
    return f"{value_expr} AS {result_alias}", present


def load_rules() -> dict:
    return load_config_rules()


def as_list(value: Any, default: list[str] | None = None) -> list[str] | None:
    if value is None:
        return default

    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return default


def get_database_scan_config() -> dict:
    rules = load_rules()
    db_scan_rules = rules.get("db_problem_scan", {})

    database = get_database(rules)
    date_range = get_date_range(
        rules,
        days_candidates=[db_scan_rules.get("days_back") or DEFAULT_DAYS_BACK],
    )
    days_back = date_range.get("days_back")
    lookback = get_lookback_range(rules)

    table_blacklist = get_table_blacklist(rules)

    explicit_tables = as_list(
        os.getenv("QUALITY_EVENT_TABLES")
        or db_scan_rules.get("event_tables")
        or rules.get("event_tables")
    )
    if explicit_tables:
        explicit_tables = filter_blacklisted_tables(explicit_tables, table_blacklist)

    table_name_prefixes = (
        os.getenv("DB_SCAN_TABLE_PREFIXES")
        and as_list(os.getenv("DB_SCAN_TABLE_PREFIXES"))
    ) or get_table_prefixes(rules)

    skip_missing_main_identifier_tables = set(
        as_list(
            db_scan_rules.get("skip_missing_main_identifier_tables")
            or rules.get("skip_missing_main_identifier_tables"),
            DEFAULT_SKIP_MISSING_MAIN_IDENTIFIER_TABLES,
        )
        or []
    )
    skip_missing_session_id_tables = set(
        as_list(
            db_scan_rules.get("skip_missing_session_id_tables")
            or rules.get("skip_missing_session_id_tables"),
            DEFAULT_SKIP_MISSING_SESSION_ID_TABLES,
        )
        or []
    )

    skip_missing_main_identifier_tables.update(get_missing_main_identifier_allowed_tables(rules))
    skip_missing_session_id_tables.update(get_missing_session_id_allowed_tables(rules))

    priority_event_tables = as_list(
        db_scan_rules.get("priority_event_tables")
        or rules.get("priority_event_tables"),
        DEFAULT_PRIORITY_EVENT_TABLES,
    )

    max_tables = int(
        os.getenv("DB_SCAN_MAX_TABLES")
        or db_scan_rules.get("max_tables")
        or DEFAULT_MAX_TABLES
    )

    scan_max_event_tables = int(
        os.getenv("DB_SCAN_MAX_EVENT_TABLES")
        or db_scan_rules.get("scan_max_event_tables")
        or DEFAULT_SCAN_MAX_EVENT_TABLES
    )

    future_tolerance_minutes = int(
        rules.get("quality_definitions", {})
        .get("future_event_time", {})
        .get("future_tolerance_minutes", 10)
    )
    same_second_unique_event_key_threshold = int(
        rules.get("quality_definitions", {})
        .get("same_second_burst", {})
        .get("default_unique_event_key_threshold", 3)
    )

    return {
        "database": database,
        "date_range": date_range,
        "lookback": lookback,
        "days_back": days_back,
        "explicit_tables": explicit_tables,
        "table_name_prefixes": (
            table_name_prefixes
            if table_name_prefixes is not None
            else DEFAULT_TABLE_NAME_PREFIXES
        ),
        "skip_missing_main_identifier_tables": set(
            filter_blacklisted_tables(list(skip_missing_main_identifier_tables), table_blacklist)
        ),
        "skip_missing_session_id_tables": set(filter_blacklisted_tables(list(skip_missing_session_id_tables), table_blacklist)),
        "priority_event_tables": filter_blacklisted_tables(priority_event_tables or DEFAULT_PRIORITY_EVENT_TABLES, table_blacklist),
        "same_second_allowed_tables": get_same_second_allowed_tables(rules),
        "same_second_strict_tables": get_same_second_strict_tables(rules),
        "future_event_time_enabled": is_quality_check_enabled(
            rules,
            "future_event_time",
            True,
        ),
        "future_tolerance_minutes": future_tolerance_minutes,
        "same_second_unique_event_key_threshold": same_second_unique_event_key_threshold,
        "max_tables": max_tables,
        "scan_max_event_tables": scan_max_event_tables,
        "table_blacklist": table_blacklist,
        "identifier_aliases": {
            name: get_identifier_aliases(name, rules)
            for name in ["adid", "user_id", "session_id", "event_key"]
        },
        "main_identifier": get_main_identifier(rules),
    }


def coerce_columns(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return []


def normalize_inventory_record(row: dict) -> dict:
    columns = coerce_columns(row.get("columns", []))
    raw_column_types = row.get("column_types", [])
    column_types = {
        str(item[0]): str(item[1])
        for item in raw_column_types
        if isinstance(item, (list, tuple)) and len(item) >= 2
    }
    if not column_types and "event_date" in columns:
        column_types["event_date"] = "DateTime"
    main_identifier_columns = [
        column
        for column in get_identifier_aliases("user_id")
        if column in columns
    ]
    session_columns = [
        column
        for column in get_identifier_aliases("session_id")
        if column in columns
    ]

    return {
        "table": str(row.get("table", "")),
        "engine": str(row.get("engine", "")),
        "column_count": int(row.get("column_count", 0) or 0),
        "estimated_rows": int(row.get("estimated_rows", 0) or 0),
        "has_event_date": "event_date" in columns,
        "measurement_time_column": measurement_time_column(column_types),
        "column_types": column_types,
        "has_adid": "adid" in columns,
        "has_main_identifier": bool(main_identifier_columns),
        "main_identifier_columns": main_identifier_columns,
        "has_session_id": bool(session_columns),
        "session_id_columns": session_columns,
        "has_event_key": "event_key" in columns,
        "columns": columns,
    }


def discover_table_inventory(
    database: str,
    table_name_prefixes: list[str],
    max_tables: int,
) -> list[dict]:
    prefix_conditions = " OR ".join(
        f"startsWith(c.table, {sql_literal(prefix)})"
        for prefix in table_name_prefixes
    )

    if not prefix_conditions:
        prefix_conditions = "1"

    df = query_df(f"""
        SELECT
            table,
            engine,
            estimated_rows,
            column_count,
            columns,
            column_types
        FROM
        (
            SELECT
                c.table AS table,
                any(t.engine) AS engine,
                ifNull(any(p.estimated_rows), 0) AS estimated_rows,
                count() AS column_count,
                groupUniqArray(c.name) AS columns,
                groupUniqArray(tuple(c.name, c.type)) AS column_types
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
        LIMIT {int(max_tables)}
    """)

    return [
        normalize_inventory_record(row)
        for row in df.to_dict("records")
    ]


def select_event_tables(
    inventory: list[dict],
    explicit_tables: list[str] | None,
    priority_event_tables: list[str],
    scan_max_event_tables: int,
) -> tuple[list[str], str, list[str]]:
    if explicit_tables:
        return explicit_tables, "configured", []

    candidates = [
        item
        for item in inventory
        if (
            item.get("measurement_time_column")
            or item.get("has_event_date")
        )
        and item.get("engine") != "MaterializedView"
    ]

    by_table = {
        item["table"]: item
        for item in candidates
    }

    selected = []
    selected_set = set()

    for table in priority_event_tables:
        if table not in by_table or table in selected_set:
            continue
        selected.append(table)
        selected_set.add(table)

    remaining = [
        item
        for item in candidates
        if item["table"] not in selected_set
    ]
    remaining = sorted(
        remaining,
        key=lambda item: (-item["estimated_rows"], item["table"]),
    )

    for item in remaining:
        selected.append(item["table"])

    limited = selected[:scan_max_event_tables]
    not_scanned = selected[scan_max_event_tables:]

    return limited, "discovered", not_scanned


def get_columns(database: str, table: str) -> set[str]:
    df = query_df(f"""
        DESCRIBE TABLE {qident(database)}.{qident(table)}
    """)

    if "name" not in df.columns:
        raise RuntimeError(f"Cannot read columns for {database}.{table}")

    return set(df["name"].astype(str).tolist())


def first_value(df, column: str, default=None):
    if df.empty or column not in df.columns:
        return default
    return df.iloc[0][column]


def pct(value: int, total: int):
    if total == 0:
        return None
    return round(value / total, 6)


def date_range_time_filter(date_range: dict, column_name: str) -> str:
    return date_range_sql_condition(date_range, column_name)


def scan_table(
    database: str,
    table: str,
    date_range: dict,
    days_back: int | None,
    skip_missing_main_identifier_tables: set[str],
    skip_missing_session_id_tables: set[str],
    same_second_allowed_tables: set[str],
    same_second_strict_tables: set[str],
    future_event_time_enabled: bool,
    future_tolerance_minutes: int,
    same_second_unique_event_key_threshold: int,
    columns: set[str] | None = None,
    identifier_aliases: dict[str, list[str]] | None = None,
    time_column: str | None = None,
) -> dict:
    columns = columns or get_columns(database, table)
    identifier_aliases = identifier_aliases or {
        name: get_identifier_aliases(name)
        for name in ["adid", "user_id", "session_id", "event_key"]
    }

    time_column = time_column or ("event_date" if "event_date" in columns else None)
    if time_column is None or time_column not in columns:
        return {
            "table": table,
            "status": "skipped",
            "reason": "No supported DateTime measurement column",
            "columns_present": sorted(columns),
        }
    if time_column not in MEASUREMENT_TIME_COLUMN_CANDIDATES:
        raise ValueError(f"Unsupported measurement time column: {time_column!r}")
    time_ref = time_column

    adid_expr, adid_columns = normalized_identifier_alias_expr(
        columns, identifier_aliases["adid"], "adid_norm"
    )
    main_identifier_expr, main_identifier_columns = normalized_identifier_alias_expr(
        columns, identifier_aliases["user_id"], "main_identifier_norm"
    )
    session_id_expr, session_id_columns = normalized_identifier_alias_expr(
        columns, identifier_aliases["session_id"], "session_id_norm"
    )
    event_key_expr, event_key_columns = normalized_identifier_alias_expr(
        columns, identifier_aliases["event_key"], "event_key_norm"
    )
    has_adid = bool(adid_columns)
    has_main_identifier = bool(main_identifier_columns)
    has_session_id = bool(session_id_columns)
    has_event_key = bool(event_key_columns)

    base_from = f"""
        FROM
        (
            SELECT
                {time_ref} AS event_time,
                {adid_expr},
                {main_identifier_expr},
                {session_id_expr},
                {event_key_expr}
            FROM {qident(database)}.{qident(table)}
            WHERE {date_range_time_filter(date_range, time_ref)}
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
    """)

    if future_event_time_enabled:
        future_df = query_df(f"""
            SELECT
                count() AS future_event_time_rows,
                max({time_ref}) AS max_future_event_time
            FROM {qident(database)}.{qident(table)}
            WHERE {time_ref} > now()
                + INTERVAL {int(future_tolerance_minutes)} MINUTE
        """)
        future_event_time_rows = int(
            first_value(future_df, "future_event_time_rows", 0) or 0
        )
        raw_max_future_event_time = first_value(
            future_df, "max_future_event_time"
        )
        max_future_event_time = (
            str(raw_max_future_event_time)
            if raw_max_future_event_time is not None
            else None
        )
    else:
        future_event_time_rows = 0
        max_future_event_time = None

    rows_total = int(first_value(main_df, "rows_total", 0) or 0)

    missing_adid_rows = int(first_value(main_df, "missing_adid_rows", 0) or 0)
    missing_main_identifier_rows = int(
        first_value(main_df, "missing_main_identifier_rows", 0) or 0
    )
    missing_session_id_rows = int(first_value(main_df, "missing_session_id_rows", 0) or 0)
    missing_event_key_rows = int(first_value(main_df, "missing_event_key_rows", 0) or 0)

    duplicate_rows = 0
    same_second_burst_rows = 0

    if has_event_key and has_adid:
        anomaly_df = query_df(f"""
            SELECT
                ifNull(sum(group_rows - 1), 0) AS duplicate_rows,
                ifNull(
                    sumIf(
                        rows_in_second,
                        key_rank = 1
                        AND unique_event_keys > {int(same_second_unique_event_key_threshold)}
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
        """)
        duplicate_rows = int(first_value(anomaly_df, "duplicate_rows", 0) or 0)
        same_second_burst_rows = int(
            first_value(anomaly_df, "same_second_burst_rows", 0) or 0
        )

    if table in skip_missing_main_identifier_tables:
        missing_main_identifier_check = "skipped"
        missing_main_identifier_rows_for_score = 0
    else:
        missing_main_identifier_check = "checked"
        missing_main_identifier_rows_for_score = missing_main_identifier_rows

    if table in skip_missing_session_id_tables:
        missing_session_id_check = "skipped"
        missing_session_id_rows_for_score = 0
    else:
        missing_session_id_check = "checked"
        missing_session_id_rows_for_score = missing_session_id_rows

    if table in same_second_allowed_tables and table not in same_second_strict_tables:
        same_second_burst_check = "allowed_group"
        same_second_burst_rows_for_score = 0
    else:
        same_second_burst_check = "checked"
        same_second_burst_rows_for_score = same_second_burst_rows

    problem_signal_rows = (
        future_event_time_rows
        + duplicate_rows
        + missing_adid_rows
        + missing_main_identifier_rows_for_score
        + missing_session_id_rows_for_score
        + missing_event_key_rows
        + same_second_burst_rows_for_score
    )

    problems = []
    schema_warnings = []

    if rows_total == 0:
        problems.append("No rows in selected period")

    if not has_adid:
        schema_warnings.append("Missing adid column")

    if not has_event_key:
        schema_warnings.append("Missing event_key column")

    if not has_main_identifier and table not in skip_missing_main_identifier_tables:
        schema_warnings.append(
            "Missing main identifier column "
            f"(accepted: {', '.join(identifier_aliases['user_id'])})"
        )

    if not has_session_id and table not in skip_missing_session_id_tables:
        schema_warnings.append(
            "Missing session identifier column "
            f"(accepted: {', '.join(identifier_aliases['session_id'])})"
        )

    if duplicate_rows > 0:
        problems.append("Duplicate event_time + adid + event_key rows found")

    if same_second_burst_rows_for_score > 0:
        problems.append("Same-second event bursts found")

    if future_event_time_rows > 0:
        problems.append(f"Future {time_column} rows found")

    if missing_adid_rows > 0:
        problems.append("Missing adid rows found")

    if missing_main_identifier_rows_for_score > 0:
        problems.append(
            f"Missing {identifier_aliases['user_id'][0]} rows found"
        )

    if missing_session_id_rows_for_score > 0:
        problems.append("Missing session_id rows found")

    if missing_event_key_rows > 0:
        problems.append("Missing event_key rows found")

    return {
        "table": table,
        "status": "ok" if not problems and not schema_warnings else "problem",
        "date_range": date_range,
        "measurement_time_column": time_column,
        "period_days": date_range.get("days_back"),
        "period_hours": date_range.get("hours_back"),

        "rows_total": rows_total,
        "rows_today": int(first_value(main_df, "rows_today", 0) or 0),
        "rows_yesterday": int(first_value(main_df, "rows_yesterday", 0) or 0),
        "min_event_time": str(first_value(main_df, "min_event_time")) if first_value(main_df, "min_event_time") is not None else None,
        "max_event_time": str(first_value(main_df, "max_event_time")) if first_value(main_df, "max_event_time") is not None else None,

        "duplicate_rows": duplicate_rows,
        "duplicate_pct": pct(duplicate_rows, rows_total),

        "same_second_burst_rows": same_second_burst_rows,
        "same_second_burst_pct": pct(same_second_burst_rows, rows_total),
        "same_second_burst_check": same_second_burst_check,
        "problem_signal_rows": problem_signal_rows,
        "problem_signal_pct": pct(problem_signal_rows, rows_total),

        "future_event_time_rows": future_event_time_rows,
        "max_future_event_time": max_future_event_time,
        "missing_adid_rows": missing_adid_rows,
        "missing_main_identifier_rows": missing_main_identifier_rows,
        "missing_main_identifier_check": missing_main_identifier_check,
        "missing_session_id_rows": missing_session_id_rows,
        "missing_session_id_check": missing_session_id_check,
        "missing_event_key_rows": missing_event_key_rows,

        "columns_expected": {
            "adid": has_adid,
            "main_identifier": has_main_identifier,
            "session_id": has_session_id,
            "event_key": has_event_key,
        },
        "identifier_sources": {
            "adid": adid_columns,
            "user_id": main_identifier_columns,
            "session_id": session_id_columns,
            "event_key": event_key_columns,
        },
        "main_identifier": identifier_aliases["user_id"][0],
        "schema_warnings": schema_warnings,
        "problems": problems,
    }


def write_inventory_csv(path: Path, inventory: list[dict]) -> None:
    if not inventory:
        path.write_text("", encoding="utf-8")
        return

    import pandas as pd

    df = pd.DataFrame(inventory)
    if "columns" in df.columns:
        df["columns"] = df["columns"].apply(lambda value: ", ".join(value))
    if "column_types" in df.columns:
        df["column_types"] = df["column_types"].apply(
            lambda value: json.dumps(value, ensure_ascii=False)
        )
    df.to_csv(path, index=False, encoding="utf-8-sig")


def main():
    started_at = datetime.now()
    timestamp = os.getenv("QUALITY_RUN_ID") or started_at.strftime("%Y%m%d_%H%M%S")
    config = get_database_scan_config()

    database = config["database"]
    date_range = config["date_range"]
    lookback = config["lookback"]
    days_back = config["days_back"]
    explicit_tables = config["explicit_tables"]
    table_name_prefixes = config["table_name_prefixes"]
    skip_missing_main_identifier_tables = config["skip_missing_main_identifier_tables"]
    skip_missing_session_id_tables = config["skip_missing_session_id_tables"]
    priority_event_tables = config["priority_event_tables"]
    same_second_allowed_tables = config["same_second_allowed_tables"]
    same_second_strict_tables = config["same_second_strict_tables"]
    future_event_time_enabled = config["future_event_time_enabled"]
    future_tolerance_minutes = config["future_tolerance_minutes"]
    same_second_unique_event_key_threshold = config[
        "same_second_unique_event_key_threshold"
    ]
    max_tables = config["max_tables"]
    scan_max_event_tables = config["scan_max_event_tables"]
    table_blacklist = config["table_blacklist"]
    identifier_aliases = config["identifier_aliases"]

    print(f"DB problem scan started at: {started_at}")
    print(f"Database: {database}")
    print(f"Date range: {date_range['description']}")
    print(f"Historical lookback: {lookback['description']}")
    print(f"Discovery prefixes: {', '.join(table_name_prefixes)}")

    inventory = discover_table_inventory(
        database=database,
        table_name_prefixes=table_name_prefixes,
        max_tables=max_tables,
    )
    blacklisted_inventory_tables = [
        item["table"]
        for item in inventory
        if item["table"] not in filter_blacklisted_tables([item["table"]], table_blacklist)
    ]
    inventory = [
        item
        for item in inventory
        if item["table"] not in blacklisted_inventory_tables
    ]

    inventory_by_table = {
        item["table"]: item
        for item in inventory
    }

    discovered_event_tables = [
        item["table"]
        for item in inventory
        if item.get("measurement_time_column")
        and item.get("engine") != "MaterializedView"
    ]

    event_tables, table_source, event_tables_not_scanned = select_event_tables(
        inventory=inventory,
        explicit_tables=explicit_tables,
        priority_event_tables=priority_event_tables,
        scan_max_event_tables=scan_max_event_tables,
    )

    print(f"Inventory tables found: {len(inventory)}")
    print(f"Event tables discovered: {len(discovered_event_tables)}")
    print(f"Event tables to scan: {len(event_tables)} ({table_source})")
    if event_tables_not_scanned:
        print(f"Event tables not deep-scanned this run: {len(event_tables_not_scanned)}")

    results = []

    for table in event_tables:
        print(f"Scanning DB table: {database}.{table}")

        try:
            inventory_item = inventory_by_table.get(table)
            columns = set(inventory_item["columns"]) if inventory_item else None
            result = scan_table(
                database=database,
                table=table,
                date_range=date_range,
                days_back=days_back,
                skip_missing_main_identifier_tables=skip_missing_main_identifier_tables,
                skip_missing_session_id_tables=skip_missing_session_id_tables,
                same_second_allowed_tables=same_second_allowed_tables,
                same_second_strict_tables=same_second_strict_tables,
                future_event_time_enabled=future_event_time_enabled,
                future_tolerance_minutes=future_tolerance_minutes,
                same_second_unique_event_key_threshold=same_second_unique_event_key_threshold,
                columns=columns,
                identifier_aliases=identifier_aliases,
                time_column=(
                    inventory_item.get("measurement_time_column")
                    if inventory_item
                    else None
                ),
            )
        except Exception as e:
            result = {
                "table": table,
                "status": "error",
                "error": str(e),
            }

        results.append(result)

    problem_tables = [
        r for r in results
        if r.get("status") in ("problem", "error")
    ]

    skipped_inventory_tables = [
        item["table"]
        for item in inventory
        if not item.get("measurement_time_column")
    ]

    inventory_path = REPORT_DIR / f"db_inventory_{timestamp}.csv"
    write_inventory_csv(inventory_path, inventory)

    report = {
        "agent": "database_quality_scanner",
        "started_at": str(started_at),
        "finished_at": str(datetime.now()),
        "database": database,
        "date_range": date_range,
        "lookback": lookback,
        "period_days": date_range.get("days_back"),
        "period_hours": date_range.get("hours_back"),
        "table_source": table_source,
        "table_name_prefixes": table_name_prefixes,
        "table_blacklist": table_blacklist,
        "same_second_allowed_tables": sorted(same_second_allowed_tables),
        "same_second_strict_tables": sorted(same_second_strict_tables),
        "missing_main_identifier_allowed_tables": sorted(skip_missing_main_identifier_tables),
        "missing_session_id_allowed_tables": sorted(skip_missing_session_id_tables),
        "future_event_time_enabled": future_event_time_enabled,
        "blacklisted_inventory_tables": blacklisted_inventory_tables,
        "scan_max_event_tables": scan_max_event_tables,
        "inventory_path": str(inventory_path),
        "inventory_tables_found": len(inventory),
        "event_tables_discovered_count": len(discovered_event_tables),
        "event_tables_not_scanned": event_tables_not_scanned,
        "inventory_tables_without_event_date": skipped_inventory_tables,
        "inventory_tables_without_supported_time": skipped_inventory_tables,
        "tables_checked": len(results),
        "problem_tables_count": len(problem_tables),
        "results": results,
    }

    timestamped_output_json = REPORT_DIR / f"database_quality_scan_{timestamp}.json"
    report_text = json.dumps(report, indent=2, ensure_ascii=False)

    STABLE_OUTPUT_JSON.write_text(report_text, encoding="utf-8")
    timestamped_output_json.write_text(report_text, encoding="utf-8")

    print("\n" + "=" * 80)
    print("DB problem scan finished")
    print(f"Inventory tables found: {len(inventory)}")
    print(f"Event tables discovered: {len(discovered_event_tables)}")
    print(f"Event tables not deep-scanned this run: {len(event_tables_not_scanned)}")
    print(f"Tables checked: {len(results)}")
    print(f"Problem tables: {len(problem_tables)}")
    print(f"Saved inventory: {inventory_path}")
    print(f"Saved stable report: {STABLE_OUTPUT_JSON}")
    print(f"Saved timestamped report: {timestamped_output_json}")
    print("=" * 80)

    if any(result.get("status") == "error" for result in results):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
