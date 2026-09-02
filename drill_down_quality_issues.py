import glob
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
    get_main_identifier,
    get_missing_session_id_allowed_tables,
    get_missing_main_identifier_allowed_tables,
    load_rules as load_config_rules,
)
from readonly_clickhouse import query_df


DATABASE = get_database()
DATE_RANGE = get_date_range()
REPORT_DIR = "reports"
FALLBACK_TABLES = [
    "event_first_open",
    "event_login",
    "event_session_start",
    "event_purchase",
    "event_click",
    "event_reward",
]
SESSION_ID_ALIASES = get_identifier_aliases("session_id")
MAIN_IDENTIFIER = get_main_identifier()
MAIN_IDENTIFIER_ALIASES = get_identifier_aliases("user_id")


def load_rules() -> dict:
    return load_config_rules()


def latest_file(pattern: str) -> str | None:
    files = glob.glob(pattern)
    if not files:
        return None
    run_id = os.getenv("QUALITY_RUN_ID")
    if run_id:
        run_files = [path for path in files if run_id in os.path.basename(path)]
        return max(run_files, key=os.path.getmtime) if run_files else None
    return max(files, key=os.path.getmtime)


def unique_keep_order(values: list[str]) -> list[str]:
    seen = set()
    result = []

    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)

    return result


def qident(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def selected_period_condition(column_name: str) -> str:
    return date_range_sql_condition(DATE_RANGE, column_name)


def get_tables_from_latest_quality() -> tuple[list[str], str | None]:
    path = latest_file(os.path.join(REPORT_DIR, "event_quality_*.csv"))
    if path is None:
        return [], None

    df = pd.read_csv(path)
    if "event_table" not in df.columns or "status" not in df.columns:
        return [], path

    problem_df = df[
        (df["status"].notna())
        & (df["status"] != "ok")
        & (~df["status"].isin(["no_rows_in_range", "no_rows_yesterday"]))
    ].copy()

    if problem_df.empty:
        return [], path

    tables = unique_keep_order(problem_df["event_table"].astype(str).tolist())
    return filter_blacklisted_tables(tables), path


def get_drilldown_config() -> dict:
    rules = load_rules()
    drilldown_rules = rules.get("drilldown", {})

    configured_tables = drilldown_rules.get("tables") or rules.get("drilldown_tables")
    max_tables = int(
        os.getenv("DRILLDOWN_MAX_TABLES")
        or drilldown_rules.get("max_tables")
        or 20
    )
    print_limit = int(
        os.getenv("DRILLDOWN_PRINT_LIMIT")
        or drilldown_rules.get("print_limit")
        or 20
    )

    if configured_tables:
        if isinstance(configured_tables, str):
            tables = [
                table.strip()
                for table in configured_tables.split(",")
                if table.strip()
            ]
        else:
            tables = [str(table).strip() for table in configured_tables if str(table).strip()]
        table_source = "configured"
        quality_source = None
    else:
        tables, quality_source = get_tables_from_latest_quality()
        table_source = "latest_quality_report"

    if not tables and quality_source is None:
        tables = filter_blacklisted_tables(FALLBACK_TABLES)
        table_source = "fallback"

    default_missing_tables = sorted(
        get_missing_main_identifier_allowed_tables(rules)
        | get_missing_session_id_allowed_tables(rules)
    ) or ["event_first_open"]

    missing_id_tables = drilldown_rules.get("missing_id_tables") or default_missing_tables

    if isinstance(missing_id_tables, str):
        missing_id_tables = [
            table.strip()
            for table in missing_id_tables.split(",")
            if table.strip()
        ]

    return {
        "tables": filter_blacklisted_tables(unique_keep_order(tables))[:max_tables],
        "missing_id_tables": filter_blacklisted_tables(unique_keep_order([str(table) for table in missing_id_tables])),
        "table_source": table_source,
        "quality_source": quality_source,
        "print_limit": print_limit,
    }


def validate_table_name(table_name: str) -> None:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
    if not table_name or any(ch not in allowed for ch in table_name):
        raise ValueError(f"Unsafe table name: {table_name}")


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


def optional_dim(columns: set[str], column: str) -> str:
    if column in columns:
        return f"ifNull(nullIf(toString({column}), ''), 'NULL') AS {column}"
    return f"'NO_COLUMN' AS {column}"


def normalized_identifier_value(column: str) -> str:
    column_ref = qident(column)
    return f"""if(
        {column_ref} IS NULL
        OR trim(BOTH ' ' FROM toString({column_ref})) = ''
        OR toString({column_ref}) = '00000000-0000-0000-0000-000000000000'
        OR lower(toString({column_ref})) = 'null',
        NULL,
        toString({column_ref})
    )"""


def logical_identifier_select(columns: set[str], aliases: list[str]) -> tuple[str, list[str]]:
    present = [alias for alias in aliases if alias in columns]
    if not present:
        return "NULL", []
    values = [normalized_identifier_value(alias) for alias in present]
    return (
        values[0] if len(values) == 1 else f"coalesce({', '.join(values)})",
        present,
    )


def missing_by_step_type(table_name: str, columns: set[str] | None = None) -> pd.DataFrame:
    validate_table_name(table_name)
    columns = columns or get_columns(table_name)
    table_ref = f"{qident(DATABASE)}.{qident(table_name)}"

    step_expr = optional_dim(columns, "step")
    type_expr = optional_dim(columns, "type")
    main_identifier_select_expr, main_identifier_columns = logical_identifier_select(
        columns, MAIN_IDENTIFIER_ALIASES
    )
    session_select_expr, session_columns = logical_identifier_select(
        columns, SESSION_ID_ALIASES
    )

    main_identifier_expr = "0"
    session_expr = "0"

    if main_identifier_columns:
        main_identifier_expr = """
            countIf(
                main_identifier IS NULL
                OR trim(BOTH ' ' FROM toString(main_identifier)) = ''
                OR toString(main_identifier) = '00000000-0000-0000-0000-000000000000'
                OR lower(toString(main_identifier)) = 'null'
            )
        """

    if session_columns:
        session_expr = """
            countIf(
                session_id IS NULL
                OR trim(BOTH ' ' FROM toString(session_id)) = ''
                OR toString(session_id) = '00000000-0000-0000-0000-000000000000'
                OR lower(toString(session_id)) = 'null'
            )
        """

    sql = f"""
        SELECT
            '{table_name}' AS event_table,
            step,
            type,
            count() AS rows_in_range,
            {main_identifier_expr} AS missing_main_identifier_rows,
            {session_expr} AS missing_session_id_rows,
            missing_main_identifier_rows / rows_in_range AS missing_main_identifier_pct,
            missing_session_id_rows / rows_in_range AS missing_session_id_pct
        FROM
        (
            SELECT
                {step_expr},
                {type_expr},
                {main_identifier_select_expr} AS main_identifier,
                {session_select_expr} AS session_id
            FROM {table_ref}
            WHERE {selected_period_condition("event_date")}
        )
        GROUP BY
            step,
            type
        HAVING missing_main_identifier_rows > 0
            OR missing_session_id_rows > 0
        ORDER BY rows_in_range DESC
        LIMIT 100
    """

    return query_df(sql)


def duplicate_samples(table_name: str, columns: set[str] | None = None) -> pd.DataFrame:
    validate_table_name(table_name)
    columns = columns or get_columns(table_name)
    table_ref = f"{qident(DATABASE)}.{qident(table_name)}"

    if "event_key" not in columns or "adid" not in columns:
        return pd.DataFrame()

    adid_expr = optional_dim(columns, "adid")
    main_identifier_expr = logical_identifier_select(
        columns,
        MAIN_IDENTIFIER_ALIASES,
    )[0]
    platform_expr = optional_dim(columns, "platform")
    region_expr = optional_dim(columns, "region")
    server_region_expr = optional_dim(columns, "server_region")
    step_expr = optional_dim(columns, "step")
    type_expr = optional_dim(columns, "type")

    sql = f"""
        SELECT
            '{table_name}' AS event_table,
            event_date,
            adid,
            event_key,
            count() AS rows_same_event_key_adid_time,
            uniqExact(adid) AS unique_adids,
            uniqExact(main_identifier) AS unique_main_identifiers,
            groupUniqArray(adid) AS adids,
            anyHeavy(platform) AS most_common_platform,
            anyHeavy(region) AS most_common_region,
            anyHeavy(server_region) AS most_common_server_region,
            anyHeavy(step) AS most_common_step,
            anyHeavy(type) AS most_common_type
        FROM
        (
            SELECT
                event_date,
                event_key,
                {adid_expr},
                {main_identifier_expr} AS main_identifier,
                {platform_expr},
                {region_expr},
                {server_region_expr},
                {step_expr},
                {type_expr}
            FROM {table_ref}
            WHERE {selected_period_condition("event_date")}
              AND adid IS NOT NULL
              AND trim(BOTH ' ' FROM toString(adid)) != ''
              AND lower(toString(adid)) != 'null'
              AND event_key IS NOT NULL
              AND trim(BOTH ' ' FROM toString(event_key)) != ''
              AND lower(toString(event_key)) != 'null'
        )
        GROUP BY
            event_date,
            adid,
            event_key
        HAVING rows_same_event_key_adid_time > 1
        ORDER BY rows_same_event_key_adid_time DESC
        LIMIT 50
    """

    return query_df(sql)


def suspicious_samples(table_name: str, columns: set[str] | None = None) -> pd.DataFrame:
    validate_table_name(table_name)
    columns = columns or get_columns(table_name)
    table_ref = f"{qident(DATABASE)}.{qident(table_name)}"

    if "event_key" not in columns or "adid" not in columns:
        return pd.DataFrame()

    platform_expr = optional_dim(columns, "platform")
    region_expr = optional_dim(columns, "region")
    server_region_expr = optional_dim(columns, "server_region")
    step_expr = optional_dim(columns, "step")
    type_expr = optional_dim(columns, "type")

    sql = f"""
        SELECT
            '{table_name}' AS event_table,
            event_date,
            adid,
            count() AS rows_same_second,
            uniqExact(event_key) AS unique_event_keys,
            anyHeavy(platform) AS most_common_platform,
            anyHeavy(region) AS most_common_region,
            anyHeavy(server_region) AS most_common_server_region,
            groupUniqArray(step) AS steps,
            groupUniqArray(type) AS types
        FROM
        (
            SELECT
                event_date,
                adid,
                event_key,
                {platform_expr},
                {region_expr},
                {server_region_expr},
                {step_expr},
                {type_expr}
            FROM {table_ref}
            WHERE {selected_period_condition("event_date")}
              AND adid IS NOT NULL
              AND trim(BOTH ' ' FROM toString(adid)) != ''
              AND lower(toString(adid)) != 'null'
              AND event_key IS NOT NULL
              AND trim(BOTH ' ' FROM toString(event_key)) != ''
              AND lower(toString(event_key)) != 'null'
        )
        GROUP BY
            event_date,
            adid
        HAVING unique_event_keys > 3
        ORDER BY rows_same_second DESC
        LIMIT 50
    """

    return query_df(sql)


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)

    config = get_drilldown_config()
    tables = config["tables"]
    missing_id_tables = config["missing_id_tables"]
    print_limit = config["print_limit"]

    duplicate_parts = []
    suspicious_parts = []
    missing_parts = []
    error_parts = []

    print("Running drilldown...")
    print(f"Table source: {config['table_source']}")
    if config["quality_source"]:
        print(f"Quality source: {config['quality_source']}")
    print(f"Tables: {len(tables)}")

    for table in tables:
        print(f"Checking {table}...")

        try:
            columns = get_columns(table)

            if "event_date" not in columns:
                print(f"Skipping {table}: no event_date column.")
                continue

            dup_df = duplicate_samples(table, columns)
            if not dup_df.empty:
                duplicate_parts.append(dup_df)

            susp_df = suspicious_samples(table, columns)
            if not susp_df.empty:
                suspicious_parts.append(susp_df)

        except Exception as e:
            error_parts.append(pd.DataFrame([{
                "event_table": table,
                "error": str(e),
            }]))

    for table in missing_id_tables:
        print(f"\nChecking missing IDs for {table}...")

        try:
            columns = get_columns(table)

            if "event_date" not in columns:
                print(f"Skipping {table}: no event_date column.")
                continue

            missing_df = missing_by_step_type(table, columns)
            if not missing_df.empty:
                missing_parts.append(missing_df)

        except Exception as e:
            error_parts.append(pd.DataFrame([{
                "event_table": table,
                "check": "missing_ids",
                "error": str(e),
            }]))

    duplicate_df = pd.concat(duplicate_parts, ignore_index=True) if duplicate_parts else pd.DataFrame()
    suspicious_df = pd.concat(suspicious_parts, ignore_index=True) if suspicious_parts else pd.DataFrame()
    missing_df = pd.concat(missing_parts, ignore_index=True) if missing_parts else pd.DataFrame()
    error_df = pd.concat(error_parts, ignore_index=True) if error_parts else pd.DataFrame()

    timestamp = os.getenv("QUALITY_RUN_ID") or datetime.now().strftime("%Y%m%d_%H%M%S")

    duplicate_path = os.path.join(REPORT_DIR, f"quality_duplicate_samples_{timestamp}.csv")
    suspicious_path = os.path.join(REPORT_DIR, f"quality_suspicious_samples_{timestamp}.csv")
    missing_path = os.path.join(REPORT_DIR, f"quality_missing_ids_{timestamp}.csv")
    error_path = os.path.join(REPORT_DIR, f"quality_drilldown_errors_{timestamp}.csv")

    duplicate_df.to_csv(duplicate_path, index=False, encoding="utf-8-sig")
    suspicious_df.to_csv(suspicious_path, index=False, encoding="utf-8-sig")
    missing_df.to_csv(missing_path, index=False, encoding="utf-8-sig")
    error_df.to_csv(error_path, index=False, encoding="utf-8-sig")

    print("\n=== Duplicate samples ===")
    if duplicate_df.empty:
        print("No duplicates found.")
    else:
        print(duplicate_df.head(print_limit).to_string(index=False))

    print("\n=== Suspicious same-second bursts ===")
    if suspicious_df.empty:
        print("No suspicious bursts found.")
    else:
        print(suspicious_df.head(print_limit).to_string(index=False))

    print("\n=== Missing IDs by step/type ===")
    if missing_df.empty:
        print(f"No missing {MAIN_IDENTIFIER}/session_id found.")
    else:
        print(missing_df.to_string(index=False))

    if not error_df.empty:
        print("\n=== Drilldown errors ===")
        print(error_df.to_string(index=False))

    print(f"\nSaved duplicate samples: {duplicate_path}")
    print(f"Saved suspicious samples: {suspicious_path}")
    print(f"Saved missing IDs: {missing_path}")
    print(f"Saved drilldown errors: {error_path}")

    if not error_df.empty:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
