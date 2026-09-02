import json
import os
from datetime import datetime

import pandas as pd

from quality_config import (
    date_range_sql_condition,
    filter_blacklisted_tables,
    get_database,
    get_date_range,
    get_identifier_aliases,
    get_lookback_range,
    get_main_identifier,
    get_present_identifier_columns,
    historical_lookback_sql_condition,
    lookback_comparison_window_count,
    MEASUREMENT_TIME_COLUMN_CANDIDATES,
    get_missing_session_id_allowed_tables,
    get_missing_main_identifier_allowed_tables,
    get_same_second_allowed_tables,
    get_same_second_strict_tables,
    get_table_prefixes,
    load_rules as load_config_rules,
)
from readonly_clickhouse import query_df


DATABASE = get_database()
REPORT_DIR = "reports"
DEFAULT_RULES = {
    "event_context": {},
    "table_name_prefixes": ["event_"],
    "thresholds": {
        "missing_adid_pct": 0.01,
        "missing_main_identifier_pct": 0.01,
        "missing_session_id_pct": 0.01,
        "duplicate_pct": 0.01,
        "replicated_pct": 0.01,
        "same_second_burst_pct": 0.01,
        "suspicious_high_delta_pct": 0.2,
        "suspicious_low_delta_pct": 0.2,
    },
}


def load_rules() -> dict:
    rules = load_config_rules()

    if not rules:
        print("No quality configuration found. Using defaults.")
        return DEFAULT_RULES

    merged = dict(rules)
    merged["event_context"] = rules.get("event_context", {})
    merged["table_name_prefixes"] = (
        rules.get("db_problem_scan", {}).get("table_name_prefixes")
        or rules.get("table_name_prefixes")
        or DEFAULT_RULES["table_name_prefixes"]
    )
    configured_thresholds = dict(rules.get("thresholds", {}))
    if (
        "missing_main_identifier_pct" not in configured_thresholds
        and "missing_main_identifier_pct" in configured_thresholds
    ):
        configured_thresholds["missing_main_identifier_pct"] = configured_thresholds[
            "missing_main_identifier_pct"
        ]
    merged["thresholds"] = {
        **DEFAULT_RULES["thresholds"],
        **configured_thresholds,
    }
    merged["classification_rules"] = rules.get("classification_rules", {})

    return merged


RULES = load_rules()
EVENT_CONTEXT = RULES["event_context"]
THRESHOLDS = RULES["thresholds"]
TABLE_NAME_PREFIXES = get_table_prefixes(RULES)
SAME_SECOND_ALLOWED_TABLES = get_same_second_allowed_tables(RULES)
SAME_SECOND_STRICT_TABLES = get_same_second_strict_tables(RULES)
MISSING_MAIN_IDENTIFIER_ALLOWED_TABLES = get_missing_main_identifier_allowed_tables(RULES)
MISSING_SESSION_ID_ALLOWED_TABLES = get_missing_session_id_allowed_tables(RULES)
SESSION_ID_ALIASES = get_identifier_aliases("session_id", RULES)
MAIN_IDENTIFIER = get_main_identifier(RULES)
MAIN_IDENTIFIER_ALIASES = get_identifier_aliases("user_id", RULES)
DATE_RANGE = get_date_range(RULES)
LOOKBACK = get_lookback_range(RULES)
if (
    DATE_RANGE.get("mode") == "rolling"
    and LOOKBACK["duration_seconds"] <= DATE_RANGE["duration_seconds"]
):
    raise ValueError("lookback must be longer than the rolling date_range")
MAX_EVENT_TABLES = int(
    os.getenv("QUALITY_MAX_EVENT_TABLES")
    or RULES.get("db_problem_scan", {}).get("scan_max_event_tables")
    or 200
)
SAME_SECOND_UNIQUE_EVENT_KEY_THRESHOLD = int(
    RULES.get("quality_definitions", {})
    .get("same_second_burst", {})
    .get("default_unique_event_key_threshold", 3)
)
_EVENT_TABLE_TIME_COLUMNS: dict[str, str] = {}


def qident(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def selected_period_condition(column_name: str) -> str:
    return date_range_sql_condition(DATE_RANGE, column_name)


def selected_period_description() -> str:
    return DATE_RANGE["description"]


def lookback_history_condition(column_name: str) -> str:
    return historical_lookback_sql_condition(
        DATE_RANGE,
        LOOKBACK,
        column_name,
    )


def lookback_history_window_count() -> float:
    return lookback_comparison_window_count(DATE_RANGE, LOOKBACK)


def validate_table_name(table_name: str) -> None:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
    if not table_name or any(ch not in allowed for ch in table_name):
        raise ValueError(f"Unsafe table name: {table_name}")


def null_uint64() -> str:
    return "CAST(NULL, 'Nullable(UInt64)')"


def get_event_rules(table_name: str) -> dict:
    table_rules = dict(EVENT_CONTEXT.get(table_name, {}))

    if (
        table_name in SAME_SECOND_ALLOWED_TABLES
        and table_name not in SAME_SECOND_STRICT_TABLES
    ):
        table_rules.setdefault("skip_suspicious_same_second_check", True)

    if table_name in MISSING_MAIN_IDENTIFIER_ALLOWED_TABLES:
        table_rules.setdefault("skip_main_identifier_check", True)

    if table_name in MISSING_SESSION_ID_ALLOWED_TABLES:
        table_rules.setdefault("skip_session_id_check", True)

    return table_rules


def get_event_tables() -> list[str]:
    mapping = get_event_table_time_columns()
    _EVENT_TABLE_TIME_COLUMNS.clear()
    _EVENT_TABLE_TIME_COLUMNS.update(mapping)
    return list(mapping)


def get_event_table_time_columns() -> dict[str, str]:
    prefix_conditions = " OR ".join(
        f"startsWith(c.table, {sql_literal(prefix)})"
        for prefix in TABLE_NAME_PREFIXES
    )

    if not prefix_conditions:
        prefix_conditions = "1"

    sql = f"""
        SELECT
            c.table AS event_table,
            c.name AS time_column,
            ifNull(any(p.estimated_rows), 0) AS estimated_rows
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
              AND database = {sql_literal(DATABASE)}
            GROUP BY
                database,
                table
        ) AS p
            ON c.database = p.database
           AND c.table = p.table
        WHERE c.database = {sql_literal(DATABASE)}
          AND c.name IN ({
              ", ".join(sql_literal(column) for column in MEASUREMENT_TIME_COLUMN_CANDIDATES)
          })
          AND (
              startsWith(c.type, 'DateTime')
              OR startsWith(c.type, 'Nullable(DateTime')
          )
          AND t.engine != 'MaterializedView'
          AND ({prefix_conditions})
        GROUP BY c.table, c.name
        ORDER BY
            estimated_rows DESC,
            c.table,
            indexOf(
                [{", ".join(sql_literal(column) for column in MEASUREMENT_TIME_COLUMN_CANDIDATES)}],
                c.name
            )
        LIMIT {MAX_EVENT_TABLES * len(MEASUREMENT_TIME_COLUMN_CANDIDATES)}
    """

    df = query_df(sql)
    if "event_table" not in df.columns:
        return {}
    allowed = set(filter_blacklisted_tables(df["event_table"].tolist()))
    result = {}
    for _, row in df.iterrows():
        table = str(row["event_table"])
        if table in allowed and table not in result:
            result[table] = str(row["time_column"])
            if len(result) >= MAX_EVENT_TABLES:
                break
    return result


def get_columns(table_name: str) -> set[str]:
    validate_table_name(table_name)

    df = query_df(f"""
        SELECT name
        FROM system.columns
        WHERE database = {sql_literal(DATABASE)}
          AND table = {sql_literal(table_name)}
    """)

    if "name" not in df.columns:
        return set()

    return set(df["name"].tolist())


def build_step_exception_condition(table_rules: dict, check_name: str) -> str | None:
    step_exceptions = table_rules.get("step_exceptions", {})
    accepted_names = {check_name}
    if check_name == "skip_main_identifier_check":
        accepted_names.add("skip_main_identifier_check")

    skipped_steps = [
        step
        for step, step_rules in step_exceptions.items()
        if any(step_rules.get(name) is True for name in accepted_names)
    ]

    if not skipped_steps:
        return None

    quoted_steps = ", ".join(f"'{step}'" for step in skipped_steps)

    return f"step NOT IN ({quoted_steps})"


def missing_expr(
    columns: set[str],
    column: str | list[str],
    table_rules: dict | None = None,
    check_name: str | None = None,
) -> str:
    candidates = [column] if isinstance(column, str) else column
    present_columns = [candidate for candidate in candidates if candidate in columns]
    if not present_columns:
        return null_uint64()

    extra_condition = None

    if table_rules and check_name and "step" in columns:
        extra_condition = build_step_exception_condition(table_rules, check_name)

    per_column_conditions = []
    for physical_column in present_columns:
        column_ref = qident(physical_column)
        per_column_conditions.append(f"""(
            {column_ref} IS NULL
            OR trim(BOTH ' ' FROM toString({column_ref})) = ''
            OR toString({column_ref}) = '00000000-0000-0000-0000-000000000000'
            OR lower(toString({column_ref})) = 'null'
        )""")
    base_missing_condition = "(" + " AND ".join(per_column_conditions) + ")"

    if extra_condition:
        return f"""
            countIf(
                {extra_condition}
                AND {base_missing_condition}
            )
        """

    return f"""
        countIf({base_missing_condition})
    """


def quality_check_table(
    table_name: str,
    time_column: str = "event_date",
) -> pd.DataFrame:
    validate_table_name(table_name)

    columns = get_columns(table_name)
    table_rules = get_event_rules(table_name)
    table_ref = f"{qident(DATABASE)}.{qident(table_name)}"
    time_ref = qident(time_column)

    has_event_key = "event_key" in columns
    has_adid = "adid" in columns

    if table_rules.get("skip_adid_check") is True:
        missing_adid_sql = null_uint64()
    else:
        missing_adid_sql = missing_expr(
            columns=columns,
            column="adid",
            table_rules=table_rules,
            check_name="skip_adid_check",
        )

    skip_main_identifier_check = (
        table_rules.get("skip_main_identifier_check") is True
        or table_rules.get("skip_main_identifier_check") is True
    )
    if skip_main_identifier_check:
        missing_main_identifier_sql = null_uint64()
    else:
        missing_main_identifier_sql = missing_expr(
            columns=columns,
            column=MAIN_IDENTIFIER_ALIASES,
            table_rules=table_rules,
            check_name="skip_main_identifier_check",
        )

    if table_rules.get("skip_session_id_check") is True:
        missing_session_sql = null_uint64()
    else:
        missing_session_sql = missing_expr(
            columns=columns,
            column=SESSION_ID_ALIASES,
            table_rules=table_rules,
            check_name="skip_session_id_check",
        )

    if has_event_key and has_adid:
        burst_expression = (
            f"sumIf(rows_in_second, key_rank = 1 AND unique_event_keys > "
            f"{SAME_SECOND_UNIQUE_EVENT_KEY_THRESHOLD})"
            if table_rules.get("skip_suspicious_same_second_check") is not True
            else "CAST(NULL, 'Nullable(UInt64)')"
        )
        anomaly_sql = f"""
            SELECT
                ifNull(sum(group_rows - 1), 0) AS duplicate_rows,
                ifNull(count() - uniqExact(event_key_norm), 0) AS replicated_rows,
                {burst_expression} AS same_second_burst_rows
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
                        {time_ref} AS event_time,
                        toString(adid) AS adid_norm,
                        toString(event_key) AS event_key_norm,
                        count() AS group_rows
                    FROM {table_ref}
                    WHERE {selected_period_condition(time_ref)}
                      AND adid IS NOT NULL
                      AND trim(BOTH ' ' FROM toString(adid)) != ''
                      AND lower(toString(adid)) != 'null'
                      AND event_key IS NOT NULL
                      AND trim(BOTH ' ' FROM toString(event_key)) != ''
                      AND lower(toString(event_key)) != 'null'
                    GROUP BY
                        event_time,
                        adid_norm,
                        event_key_norm
                )
            )
        """
    else:
        anomaly_sql = """
            SELECT
                CAST(NULL, 'Nullable(UInt64)') AS duplicate_rows,
                CAST(NULL, 'Nullable(UInt64)') AS replicated_rows,
                CAST(NULL, 'Nullable(UInt64)') AS same_second_burst_rows
        """

    volume_sql = f"""
        SELECT count() AS lookback_rows
        FROM {table_ref}
        WHERE {lookback_history_condition(time_ref)}
    """

    base_sql = f"""
        SELECT
            '{table_name}' AS event_table,
            count() AS rows_in_range,
            {missing_adid_sql} AS missing_adid_rows,
            {missing_main_identifier_sql} AS missing_main_identifier_rows,
            {missing_session_sql} AS missing_session_id_rows
        FROM {table_ref}
        WHERE {selected_period_condition(time_ref)}
    """

    base_df = query_df(base_sql)
    anomaly_df = query_df(anomaly_sql)
    volume_df = query_df(volume_sql)

    result = pd.concat(
        [
            base_df.reset_index(drop=True),
            anomaly_df.reset_index(drop=True),
            volume_df.reset_index(drop=True),
        ],
        axis=1,
    )

    numeric_cols = [
        "rows_in_range",
        "missing_adid_rows",
        "missing_main_identifier_rows",
        "missing_session_id_rows",
        "duplicate_rows",
        "replicated_rows",
        "same_second_burst_rows",
        "lookback_rows",
    ]

    for col in numeric_cols:
        if col in result.columns:
            result[col] = pd.to_numeric(result[col], errors="coerce")

    result["date_range_mode"] = DATE_RANGE["mode"]
    result["date_range_description"] = DATE_RANGE["description"]
    result["measurement_period"] = selected_period_description()
    result["measurement_time_column"] = time_column
    result["lookback_description"] = LOOKBACK["description"]
    result["session_id_columns"] = ",".join(
        get_present_identifier_columns(columns, "session_id", RULES)
    )
    result["main_identifier"] = MAIN_IDENTIFIER
    result["main_identifier_columns"] = ",".join(
        get_present_identifier_columns(columns, "user_id", RULES)
    )

    if "rows_in_range" not in result.columns:
        result["rows_in_range"] = result.get("rows_yesterday")
    rows = result.loc[0, "rows_in_range"]
    result["rows_yesterday"] = result["rows_in_range"]  # Compatibility column.

    if rows and rows > 0:
        result["missing_adid_pct"] = result["missing_adid_rows"] / rows
        result["missing_main_identifier_pct"] = (
            result["missing_main_identifier_rows"] / rows
        )
        result["missing_session_id_pct"] = result["missing_session_id_rows"] / rows
        result["duplicate_pct"] = result["duplicate_rows"] / rows
        result["replicated_pct"] = result["replicated_rows"] / rows
        result["same_second_burst_pct"] = result["same_second_burst_rows"] / rows
    else:
        result["missing_adid_pct"] = None
        result["missing_main_identifier_pct"] = None
        result["missing_session_id_pct"] = None
        result["duplicate_pct"] = None
        result["replicated_pct"] = None
        result["same_second_burst_pct"] = None

    if "lookback_rows" in result.columns:
        lookback_rows = result.loc[0, "lookback_rows"]
        expected_rows = (
            float(lookback_rows) / lookback_history_window_count()
            if pd.notna(lookback_rows)
            else None
        )
    else:
        expected_rows = result.loc[0, "median_prev_days"]

    result["expected_rows_from_lookback"] = expected_rows
    result["median_prev_days"] = expected_rows  # Compatibility column.
    result["rows_yesterday_for_volume"] = rows  # Compatibility column.
    if pd.notna(expected_rows) and expected_rows > 0:
        delta = (rows - expected_rows) / expected_rows
    else:
        delta = None
    result["delta_vs_lookback_expected"] = delta
    result["delta_yesterday_vs_median"] = delta  # Compatibility column.

    return result


def classify(row) -> str:
    checks = [
        ("missing_adid_high", "missing_adid_pct"),
        ("missing_main_identifier_high", "missing_main_identifier_pct"),
        ("missing_session_id_high", "missing_session_id_pct"),
        ("duplicate_high", "duplicate_pct"),
        ("replicated_high", "replicated_pct"),
        ("same_second_burst_high", "same_second_burst_pct"),
    ]

    flags = []

    if row.get("rows_in_range", row.get("rows_yesterday")) == 0:
        flags.append("no_rows_in_range")

    for flag_name, col_name in checks:
        value = row.get(col_name)
        threshold = THRESHOLDS.get(col_name, 0.01)

        if pd.notna(value) and value >= threshold:
            flags.append(flag_name)

    delta = row.get("delta_vs_lookback_expected", row.get("delta_yesterday_vs_median"))
    expected_rows = row.get("expected_rows_from_lookback", row.get("median_prev_days"))
    high_threshold = THRESHOLDS.get("suspicious_high_delta_pct", 0.2)
    low_threshold = THRESHOLDS.get("suspicious_low_delta_pct", 0.2)

    if pd.notna(expected_rows) and expected_rows > 0 and pd.notna(delta):
        if delta >= high_threshold:
            flags.append("suspicious_high")
        if delta <= -low_threshold:
            flags.append("suspicious_low")

    return ", ".join(flags) if flags else "ok"


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)

    tables = get_event_tables()
    table_time_columns = {
        table: _EVENT_TABLE_TIME_COLUMNS.get(table, "event_date")
        for table in tables
    }
    print(f"Found event tables: {len(tables)}")
    print(f"Configured date range: {DATE_RANGE['description']}")
    print(f"Measurement period: {selected_period_description()}")
    print(f"Historical lookback: {LOOKBACK['description']}")

    results = []

    for table, time_column in table_time_columns.items():
        print(f"Checking {table} using {time_column}...")
        try:
            results.append(quality_check_table(table, time_column))
        except Exception as e:
            results.append(pd.DataFrame([{
                "event_table": table,
                "error": str(e),
            }]))

    if results:
        final_df = pd.concat(results, ignore_index=True)
    else:
        final_df = pd.DataFrame(
            columns=[
                "event_table",
                "rows_in_range",
                "status",
                "error",
                "date_range_mode",
                "date_range_description",
                "measurement_period",
            ]
        )

    if "error" not in final_df.columns:
        final_df["error"] = None

    final_df["status"] = final_df.apply(
        lambda row: "error" if pd.notna(row.get("error")) else classify(row),
        axis=1,
    )

    timestamp = os.getenv("QUALITY_RUN_ID") or datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORT_DIR, f"event_quality_{timestamp}.csv")
    final_df.to_csv(path, index=False, encoding="utf-8-sig")

    problem_df = final_df[final_df["status"] != "ok"].copy()

    print("\n=== Event quality problems ===")
    if problem_df.empty:
        print("No problems found.")
    else:
        cols = [
            "event_table",
            "status",
            "rows_yesterday",
            "missing_adid_pct",
            "missing_main_identifier_pct",
            "missing_session_id_pct",
            "duplicate_pct",
            "replicated_pct",
            "same_second_burst_pct",
            "median_prev_days",
            "delta_yesterday_vs_median",
            "error",
        ]

        existing_cols = [col for col in cols if col in problem_df.columns]
        print(problem_df[existing_cols].to_string(index=False))

    print(f"\nSaved report: {path}")

    if final_df["error"].notna().any():
        raise SystemExit(2)


if __name__ == "__main__":
    main()
