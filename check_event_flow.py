import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from check_parameter_quality import canonical_parameter_name, profile_schema_json
from quality_config import (
    date_range_sql_condition,
    get_active_profile,
    get_database,
    get_date_range,
    get_identifier_aliases,
    get_main_identifier,
    get_table_blacklist,
    is_parameter_missing_allowed,
    is_table_blacklisted,
    load_rules,
)
from readonly_clickhouse import query_df


PROJECT_DIR = Path(__file__).resolve().parent
REPORT_DIR = PROJECT_DIR / "reports"
PROFILE_SCHEMA_DIR = PROJECT_DIR / "config" / "profile_schemas"
RAW_PROFILE_TECHNICAL_PARAMETERS = {
    "device_hash",
    "event_date",
    "gps_adid",
    "idfa",
    "idfv",
    "ip_address",
    "oaid",
}


def qident(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def sql_literal(value: Any) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def latest_file(pattern: str) -> Path | None:
    files = list(REPORT_DIR.glob(pattern))
    if not files:
        return None
    run_id = os.getenv("QUALITY_RUN_ID")
    if run_id:
        matching = [path for path in files if run_id in path.name]
        return max(matching, key=lambda path: path.stat().st_mtime) if matching else None
    return max(files, key=lambda path: path.stat().st_mtime)


def read_csv_or_empty(path: Path | None) -> pd.DataFrame:
    if path is None:
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def filter_blacklisted_event_rows(
    frame: pd.DataFrame,
    patterns: list[str],
) -> pd.DataFrame:
    if frame.empty or "event_table" not in frame.columns:
        return frame
    keep = ~frame["event_table"].astype(str).map(
        lambda table: is_table_blacklisted(table, patterns)
    )
    return frame.loc[keep].reset_index(drop=True)


def table_columns(database: str, table: str) -> set[str]:
    frame = query_df(f"""
        SELECT name
        FROM system.columns
        WHERE database = {sql_literal(database)}
          AND table = {sql_literal(table)}
    """)
    if "name" not in frame.columns:
        return set()
    return set(frame["name"].astype(str))


def raw_type_expression(columns: set[str], *, include_legacy_event: bool) -> str:
    candidates = []
    if "type" in columns:
        candidates.append("nullIf(type, '')")
    candidates.append(
        "nullIf(if(isValidJSON(payload), JSONExtractString(payload, 'type'), ''), '')"
    )
    if include_legacy_event:
        candidates.append(
            "nullIf(if(isValidJSON(payload), "
            "JSONExtractString(payload, 'event', 'name'), ''), '')"
        )
    candidates.append("''")
    return f"coalesce({', '.join(candidates)})"


def normalized_event_expression(columns: set[str], *, include_legacy_event: bool) -> str:
    raw_type = raw_type_expression(columns, include_legacy_event=include_legacy_event)
    return f"replaceRegexpOne({raw_type}, '^.*\\\\.', '')"


def collect_source_events(
    database: str,
    table: str,
    columns: set[str],
    date_range: dict,
) -> pd.DataFrame:
    if not {"event_time", "payload"}.issubset(columns):
        raise RuntimeError(
            f"{database}.{table} must contain event_time and payload; found {sorted(columns)}"
        )
    event_expr = normalized_event_expression(columns, include_legacy_event=False)
    raw_type_expr = raw_type_expression(columns, include_legacy_event=False)
    mode_expr = "mode" if "mode" in columns else "''"
    return query_df(f"""
        SELECT
            if(event_table = '', '__UNKNOWN__', event_table) AS event_table,
            any(raw_type) AS source_type,
            groupUniqArrayIf(mode, mode != '') AS modes,
            count() AS raw_rows,
            countIf(NOT isValidJSON(payload)) AS invalid_json_rows,
            countIf(
                isValidJSON(payload)
                AND JSONExtractRaw(payload, 'params') IN ('', 'null')
            ) AS missing_params_object_rows
        FROM
        (
            SELECT
                payload,
                {mode_expr} AS mode,
                {raw_type_expr} AS raw_type,
                {event_expr} AS event_table
            FROM {qident(database)}.{qident(table)}
            WHERE {date_range_sql_condition(date_range, 'event_time')}
        )
        GROUP BY event_table
        ORDER BY raw_rows DESC, event_table
    """)


def collect_dlq_events(
    database: str,
    table: str,
    columns: set[str],
    date_range: dict,
) -> pd.DataFrame:
    if not columns:
        return pd.DataFrame(
            columns=[
                "event_table",
                "dlq_source_table",
                "source_event_name",
                "dlq_shape",
                "dlq_rows",
                "modes",
                "event_parameters_rows",
                "validation_errors",
                "rejected_at_min",
                "rejected_at_max",
            ]
        )
    if not {"event_time", "payload"}.issubset(columns):
        raise RuntimeError(
            f"{database}.{table} must contain event_time and payload; found {sorted(columns)}"
        )
    event_expr = normalized_event_expression(columns, include_legacy_event=True)
    mode_expr = "mode" if "mode" in columns else "''"
    return query_df(f"""
        SELECT
            if(event_table = '', '__UNKNOWN__', event_table) AS event_table,
            {sql_literal(table)} AS dlq_source_table,
            anyIf(source_event_name, source_event_name != '') AS source_event_name,
            dlq_shape,
            groupUniqArrayIf(mode, mode != '') AS modes,
            countIf(has_event_parameters) AS event_parameters_rows,
            arrayDistinct(arrayFlatten(groupArray(validation_errors))) AS validation_errors,
            minIf(rejected_at, rejected_at != '') AS rejected_at_min,
            maxIf(rejected_at, rejected_at != '') AS rejected_at_max,
            count() AS dlq_rows
        FROM
        (
            SELECT
                {event_expr} AS event_table,
                if(
                    isValidJSON(payload),
                    JSONExtractString(payload, 'event', 'name'),
                    ''
                ) AS source_event_name,
                {mode_expr} AS mode,
                isValidJSON(payload)
                    AND JSONHas(payload, 'event', 'parameters') AS has_event_parameters,
                if(
                    isValidJSON(payload),
                    JSONExtract(payload, 'validationErrors', 'Array(String)'),
                    CAST([], 'Array(String)')
                ) AS validation_errors,
                if(
                    isValidJSON(payload),
                    JSONExtractString(payload, 'rejectedAt'),
                    ''
                ) AS rejected_at,
                multiIf(
                    NOT isValidJSON(payload), 'invalid_json',
                    JSONHas(payload, 'event'), 'legacy_event_envelope',
                    JSONHas(payload, 'type') AND JSONHas(payload, 'params'),
                        'standard_type_params',
                    'unknown_json_shape'
                ) AS dlq_shape
            FROM {qident(database)}.{qident(table)}
            WHERE {date_range_sql_condition(date_range, 'event_time')}
        )
        GROUP BY event_table, dlq_shape
        ORDER BY dlq_rows DESC, event_table, dlq_shape
    """)


def int_value(value: Any) -> int:
    number = pd.to_numeric(value, errors="coerce")
    return 0 if pd.isna(number) else int(number)


def flow_severity(flags: list[str]) -> str:
    if any(flag.startswith("critical_") for flag in flags):
        return "critical"
    if any(flag.startswith("low_") for flag in flags):
        return "low"
    if any(flag.startswith("investigate_") for flag in flags):
        return "investigate"
    return "ok"


def build_flow_results(
    quality_df: pd.DataFrame,
    source_df: pd.DataFrame,
    dlq_df: pd.DataFrame,
    source_comparison_excluded_tables: set[str] | None = None,
) -> list[dict]:
    source_comparison_excluded_tables = source_comparison_excluded_tables or set()
    target_rows = {}
    if {"event_table", "status"}.issubset(quality_df.columns):
        for _, row in quality_df.iterrows():
            target_rows[str(row["event_table"])] = int_value(
                row.get("rows_in_range", row.get("rows_yesterday"))
            )

    source_rows = {
        str(row["event_table"]): int_value(row.get("raw_rows"))
        for _, row in source_df.iterrows()
    }
    dlq_rows = {}
    dlq_shapes = {}
    dlq_source_tables = {}
    for _, row in dlq_df.iterrows():
        table = str(row["event_table"])
        dlq_rows[table] = dlq_rows.get(table, 0) + int_value(row.get("dlq_rows"))
        dlq_shapes.setdefault(table, set()).add(str(row.get("dlq_shape", "unknown")))
        source_table = str(row.get("dlq_source_table", "") or "")
        if source_table:
            dlq_source_tables.setdefault(table, set()).add(source_table)

    results = []
    for table in sorted(set(target_rows) | set(source_rows) | set(dlq_rows)):
        target_exists = table in target_rows
        parsed_rows = target_rows.get(table, 0)
        raw_rows = source_rows.get(table, 0)
        rejected_rows = dlq_rows.get(table, 0)
        comparison_excluded = table in source_comparison_excluded_tables
        flags = []

        if target_exists and parsed_rows == 0:
            if comparison_excluded:
                flags.append("investigate_source_comparison_not_applicable")
            elif raw_rows > 0:
                flags.append("low_raw_seen_but_parsed_missing")
            elif rejected_rows > 0:
                flags.append("critical_dlq_seen_but_parsed_missing")
            else:
                flags.append("critical_event_not_received")
        if (
            not target_exists
            and raw_rows > 0
            and table != "__UNKNOWN__"
            and not comparison_excluded
        ):
            flags.append("low_missing_parsed_table")
        if rejected_rows > 0:
            flags.append("critical_dlq_rows")
        if target_exists and raw_rows > parsed_rows and parsed_rows > 0:
            flags.append("investigate_raw_to_parsed_count_gap")
        if (
            target_exists
            and parsed_rows > 0
            and raw_rows == 0
            and not comparison_excluded
        ):
            flags.append("investigate_parsed_without_source_window_rows")
        if table == "__UNKNOWN__" and raw_rows > 0:
            flags.append("critical_source_type_missing")

        results.append({
            "event_table": table,
            "target_table_exists": target_exists,
            "raw_rows": raw_rows,
            "parsed_rows": parsed_rows if target_exists else None,
            "dlq_rows": rejected_rows,
            "dlq_shapes": sorted(dlq_shapes.get(table, set())),
            "dlq_source_tables": sorted(dlq_source_tables.get(table, set())),
            "source_comparison_excluded": comparison_excluded,
            "status": flags or ["ok"],
            "severity": flow_severity(flags),
        })
    return results


def load_profile_schema(profile_name: str) -> dict:
    path = PROFILE_SCHEMA_DIR / f"{profile_name}.json"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_profile_schema(profile_name: str, profile_schema: dict) -> None:
    path = PROFILE_SCHEMA_DIR / f"{profile_name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary_path.write_text(
            profile_schema_json(profile_schema),
            encoding="utf-8",
        )
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def raw_parameter_spec(raw_examples: Any) -> list[Any]:
    values = raw_examples if isinstance(raw_examples, (list, tuple)) else []
    decoded = []
    for raw_value in values:
        try:
            value = json.loads(str(raw_value))
        except (TypeError, ValueError, json.JSONDecodeError):
            value = str(raw_value)
        if value is None or value == "":
            continue
        decoded.append(value)

    value_types = {type(value) for value in decoded}
    if value_types and value_types <= {bool}:
        parameter_type = "UInt8"
    elif value_types and value_types <= {int}:
        parameter_type = "Int64"
    elif value_types and value_types <= {int, float}:
        parameter_type = "Float64"
    else:
        parameter_type = "String"

    examples = []
    for value in decoded:
        example = (
            value
            if isinstance(value, str)
            else json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        )
        if example not in examples:
            examples.append(example)
        if len(examples) >= 5:
            break
    return [parameter_type, examples, "normal"]


def collect_source_profile_parameters(
    database: str,
    raw_table: str,
    raw_columns: set[str],
    date_range: dict,
    event_tables: list[str],
) -> pd.DataFrame:
    if not event_tables:
        return pd.DataFrame(columns=["event_table", "parameter", "raw_examples"])
    event_expr = normalized_event_expression(
        raw_columns,
        include_legacy_event=False,
    )
    event_literals = ", ".join(sql_literal(table) for table in event_tables)
    return query_df(f"""
        SELECT
            event_table,
            parameter,
            groupUniqArray(5)(raw_value) AS raw_examples
        FROM
        (
            SELECT
                {event_expr} AS event_table,
                parameter_item.1 AS parameter,
                parameter_item.2 AS raw_value
            FROM {qident(database)}.{qident(raw_table)}
            ARRAY JOIN JSONExtractKeysAndValuesRaw(
                JSONExtractRaw(payload, 'params')
            ) AS parameter_item
            WHERE {date_range_sql_condition(date_range, 'event_time')}
              AND isValidJSON(payload)
        )
        WHERE event_table IN ({event_literals})
          AND parameter != ''
        GROUP BY event_table, parameter
        ORDER BY event_table, parameter
    """)


def raw_profile_event_additions(
    profile_schema: dict,
    source_df: pd.DataFrame,
    source_parameter_df: pd.DataFrame,
    raw_table: str,
) -> dict[str, dict]:
    events = profile_schema.get("events", {})
    if not isinstance(events, dict) or source_df.empty:
        return {}
    inherited_parameters = {
        canonical_parameter_name(str(parameter))
        for section in ("system_parameters", "common_parameters")
        for parameter in profile_schema.get(section, {})
    }
    source_events = sorted({
        str(event_table)
        for event_table in source_df.get("event_table", pd.Series(dtype=str))
        if str(event_table) and str(event_table) != "__UNKNOWN__"
    })
    missing_events = [event for event in source_events if event not in events]
    additions = {}
    for event_table in missing_events:
        parameters = {}
        if not source_parameter_df.empty:
            event_rows = source_parameter_df[
                source_parameter_df["event_table"].astype(str) == event_table
            ]
            for _, row in event_rows.sort_values("parameter").iterrows():
                parameter = str(row.get("parameter", ""))
                canonical = canonical_parameter_name(parameter)
                if (
                    not parameter
                    or canonical in inherited_parameters
                    or parameter in RAW_PROFILE_TECHNICAL_PARAMETERS
                ):
                    continue
                parameters[parameter] = raw_parameter_spec(row.get("raw_examples"))
        additions[event_table] = {
            "parameters": parameters,
            "required": False,
            "discovered_from": raw_table,
        }
    return additions


def parameter_scope(profile_schema: dict, table: str, parameter: str) -> str:
    if parameter in profile_schema.get("system_parameters", {}):
        return "system"
    if parameter in profile_schema.get("common_parameters", {}):
        return "common"
    event = profile_schema.get("events", {}).get(table, {})
    if parameter in event.get("parameters", {}):
        return "event"
    return "configured_or_discovered"


def source_parameter_aliases(parameter: str, rules: dict) -> list[str]:
    if parameter == "event_name":
        return ["type"]
    if parameter in {"session_id", "session_uuid", "sessions_uuid"}:
        return get_identifier_aliases("session_id", rules)
    main_identifier = get_main_identifier(rules)
    if parameter in {main_identifier, "user_id"}:
        return get_identifier_aliases("user_id", rules)
    return [parameter]


def parameter_problem_pairs(
    parameter_df: pd.DataFrame,
    profile_schema: dict,
    max_checks: int,
    rules: dict | None = None,
) -> list[dict]:
    required = {"event_table", "parameter", "status"}
    if parameter_df.empty or not required.issubset(parameter_df.columns):
        return []
    problems = parameter_df[parameter_df["status"].isin(["problem", "error"])].copy()
    if problems.empty:
        return []
    problem_text = problems.get("problem", pd.Series("", index=problems.index)).astype(str)
    missing_pct = pd.to_numeric(
        problems.get("missing_pct", pd.Series(0, index=problems.index)),
        errors="coerce",
    ).fillna(0)
    problems = problems[
        problem_text.str.contains("missing|unpopulated", case=False, regex=True)
        | (missing_pct > 0)
    ].copy()
    priority_rank = problems.get(
        "report_priority", pd.Series("normal", index=problems.index)
    ).astype(str).str.lower().map(
        {"extreme": 0, "critical": 0, "high": 1, "normal": 2, "low": 3}
    ).fillna(2)
    problems["_priority_rank"] = priority_rank
    problems = problems.sort_values(
        ["_priority_rank", "event_table", "parameter"], kind="stable"
    )

    pairs = []
    seen = set()
    for _, row in problems.iterrows():
        table = str(row.get("event_table", ""))
        parameter = str(row.get("parameter", ""))
        if not table or not parameter or parameter == "*" or (table, parameter) in seen:
            continue
        if rules is not None and is_parameter_missing_allowed(
            table,
            parameter,
            rules,
        ):
            continue
        seen.add((table, parameter))
        numeric_missing_pct = pd.to_numeric(row.get("missing_pct"), errors="coerce")
        target_problem = str(row.get("problem", ""))
        if pd.isna(numeric_missing_pct) and any(
            problem in target_problem
            for problem in ("missing_column", "unpopulated_column")
        ):
            numeric_missing_pct = 1.0
        pairs.append({
            "event_table": table,
            "parameter": parameter,
            "scope": parameter_scope(profile_schema, table, parameter),
            "target_missing_pct": (
                None
                if pd.isna(numeric_missing_pct)
                else float(numeric_missing_pct)
            ),
            "target_problem": target_problem,
            "report_priority": str(row.get("report_priority", "normal")),
        })
        if len(pairs) >= max_checks:
            break
    return pairs


def collect_source_parameter_evidence(
    database: str,
    raw_table: str,
    raw_columns: set[str],
    date_range: dict,
    pairs: list[dict],
    rules: dict,
    source_df: pd.DataFrame,
    source_comparison_excluded_tables: set[str] | None = None,
) -> list[dict]:
    if not pairs:
        return []
    source_comparison_excluded_tables = source_comparison_excluded_tables or set()
    event_expr = normalized_event_expression(raw_columns, include_legacy_event=False)
    alias_to_parameter = {}
    all_aliases = set()
    for pair in pairs:
        aliases = source_parameter_aliases(pair["parameter"], rules)
        for alias in aliases:
            all_aliases.add(alias)
            alias_to_parameter.setdefault(alias, pair["parameter"])
    alias_literals = ", ".join(sql_literal(alias) for alias in sorted(all_aliases))
    event_literals = ", ".join(
        sql_literal(table) for table in sorted({pair["event_table"] for pair in pairs})
    )
    canonical_parts = []
    for alias, parameter in sorted(alias_to_parameter.items()):
        canonical_parts.extend([
            f"parameter_key = {sql_literal(alias)}",
            sql_literal(parameter),
        ])
    canonical_expr = f"multiIf({', '.join(canonical_parts)}, parameter_key)"
    evidence_df = query_df(f"""
        SELECT
            event_table,
            parameter,
            count() AS raw_present_rows
        FROM
        (
            SELECT
                event_table,
                arrayJoin(
                    arrayDistinct(
                        arrayMap(
                            parameter_item -> {canonical_expr.replace('parameter_key', 'parameter_item.1')},
                            arrayFilter(
                                parameter_item -> parameter_item.1 IN ({alias_literals})
                                    AND parameter_item.2 NOT IN ('', 'null', '\"\"'),
                                parameter_items
                            )
                        )
                    )
                ) AS parameter
            FROM
            (
                SELECT
                    {event_expr} AS event_table,
                    if(
                        isValidJSON(payload),
                        JSONExtractKeysAndValuesRaw(JSONExtractRaw(payload, 'params')),
                        CAST([], 'Array(Tuple(String, String))')
                    ) AS parameter_items
                FROM {qident(database)}.{qident(raw_table)}
                WHERE {date_range_sql_condition(date_range, 'event_time')}
            )
            WHERE event_table IN ({event_literals})
        )
        GROUP BY event_table, parameter
    """)
    evidence = {
        (str(row["event_table"]), str(row["parameter"])): row
        for _, row in evidence_df.iterrows()
    }
    source_rows = {
        str(row["event_table"]): int_value(row.get("raw_rows"))
        for _, row in source_df.iterrows()
    }

    results = []
    for pair in pairs:
        row = evidence.get((pair["event_table"], pair["parameter"]), {})
        raw_rows = source_rows.get(pair["event_table"], 0)
        present_rows = (
            raw_rows
            if pair["parameter"] == "event_name"
            else int_value(row.get("raw_present_rows"))
        )
        if raw_rows:
            present_rows = min(present_rows, raw_rows)
        # Source totals and parameter evidence are separate read-only queries. New
        # rows can arrive between them in a rolling window, so cap the ratio at the
        # only valid maximum instead of reporting impossible values above 100%.
        raw_presence_pct = min(present_rows / raw_rows, 1.0) if raw_rows else None
        target_missing_pct = pair["target_missing_pct"]
        if pair["event_table"] in source_comparison_excluded_tables:
            diagnosis = "source_comparison_not_applicable"
            status = "investigate_source_comparison_not_applicable"
            severity = "investigate"
        elif raw_rows == 0:
            diagnosis = "no_source_rows_for_parameter_check"
            status = "investigate_no_source_rows_for_parameter_check"
            severity = "investigate"
        elif raw_presence_pct >= 0.99 and (target_missing_pct or 0) > 0:
            diagnosis = "likely_parser_or_column_mapping_issue"
            status = "low_target_parameter_missing_but_raw_present"
            severity = "low"
        elif raw_presence_pct < 0.99:
            diagnosis = "source_payload_parameter_missing"
            status = "critical_parameter_missing_in_raw_and_target"
            severity = "critical"
        else:
            diagnosis = "source_parameter_present"
            status = "ok"
            severity = "ok"
        results.append({
            **pair,
            "source_aliases": source_parameter_aliases(pair["parameter"], rules),
            "raw_rows": raw_rows,
            "raw_present_rows": present_rows,
            "raw_presence_pct": raw_presence_pct,
            "diagnosis": diagnosis,
            "status": status,
            "severity": severity,
        })
    return results


def json_records(frame: pd.DataFrame) -> list[dict]:
    if frame.empty:
        return []
    return json.loads(frame.to_json(orient="records", date_format="iso"))


def configured_table_list(
    config: dict,
    plural_key: str,
    singular_key: str,
    default: str,
) -> list[str]:
    raw = config.get(plural_key)
    if isinstance(raw, str):
        values = [part.strip() for part in raw.split(",") if part.strip()]
    elif isinstance(raw, (list, tuple, set)):
        values = [str(item).strip() for item in raw if str(item).strip()]
    else:
        value = str(config.get(singular_key) or default).strip()
        values = [value] if value else []
    return list(dict.fromkeys(values))


def main() -> None:
    REPORT_DIR.mkdir(exist_ok=True)
    rules = load_rules()
    profile_name, _ = get_active_profile(rules)
    database = get_database(rules)
    date_range = get_date_range(rules)
    config = rules.get("source_flow", {})
    raw_table = str(config.get("raw_table", "source_events"))
    dlq_tables = configured_table_list(
        config,
        "dlq_tables",
        "dlq_table",
        "source_events_dlq",
    )
    source_comparison_excluded_tables = set(
        configured_table_list(
            config,
            "source_comparison_excluded_tables",
            "source_comparison_excluded_table",
            "",
        )
    )
    max_parameter_checks = max(1, int(config.get("max_parameter_checks", 100)))

    quality_path = latest_file("event_quality_*.csv")
    parameter_path = latest_file("parameter_quality_*.csv")
    if quality_path is None:
        raise FileNotFoundError("No event_quality_*.csv found for source-flow comparison")

    quality_df = read_csv_or_empty(quality_path)
    parameter_df = read_csv_or_empty(parameter_path)
    table_blacklist = get_table_blacklist(rules)
    quality_df = filter_blacklisted_event_rows(quality_df, table_blacklist)
    parameter_df = filter_blacklisted_event_rows(parameter_df, table_blacklist)
    raw_columns = table_columns(database, raw_table)
    dlq_columns_by_table = {
        table: table_columns(database, table)
        for table in dlq_tables
    }
    if not raw_columns:
        raise RuntimeError(f"Source table {database}.{raw_table} was not found")

    print(f"Checking source flow: {database}.{raw_table} -> parsed event tables")
    for dlq_table in dlq_tables:
        print(f"Checking failure path: {database}.{dlq_table}")
    print(f"Measurement period: {date_range['description']}")

    source_df = collect_source_events(
        database, raw_table, raw_columns, date_range
    )
    source_df = filter_blacklisted_event_rows(source_df, table_blacklist)
    dlq_frames = [
        collect_dlq_events(
            database,
            dlq_table,
            dlq_columns_by_table[dlq_table],
            date_range,
        )
        for dlq_table in dlq_tables
    ]
    dlq_df = (
        pd.concat(dlq_frames, ignore_index=True)
        if dlq_frames
        else pd.DataFrame()
    )
    dlq_df = filter_blacklisted_event_rows(dlq_df, table_blacklist)
    flow_results = build_flow_results(
        quality_df,
        source_df,
        dlq_df,
        source_comparison_excluded_tables,
    )

    profile_schema = load_profile_schema(profile_name)
    profile_schema_events_added = []
    if profile_schema:
        known_events = profile_schema.get("events", {})
        raw_only_events = sorted({
            str(event_table)
            for event_table in source_df.get("event_table", pd.Series(dtype=str))
            if str(event_table)
            and str(event_table) != "__UNKNOWN__"
            and str(event_table) not in known_events
        })
        source_parameter_df = collect_source_profile_parameters(
            database,
            raw_table,
            raw_columns,
            date_range,
            raw_only_events,
        )
        additions = raw_profile_event_additions(
            profile_schema,
            source_df,
            source_parameter_df,
            raw_table,
        )
        if additions:
            profile_schema["events"].update(additions)
            save_profile_schema(profile_name, profile_schema)
            profile_schema_events_added = sorted(additions)
            print(
                "Profile schema appended raw-only events: "
                + ", ".join(profile_schema_events_added)
            )
    pairs = parameter_problem_pairs(
        parameter_df,
        profile_schema,
        max_parameter_checks,
        rules,
    )
    parameter_results = collect_source_parameter_evidence(
        database,
        raw_table,
        raw_columns,
        date_range,
        pairs,
        rules,
        source_df,
        source_comparison_excluded_tables,
    )

    critical = [
        item
        for item in flow_results
        if any(flag.startswith("critical_") for flag in item["status"])
    ]
    low = [
        item
        for item in flow_results
        if item["severity"] == "low"
    ]
    parameter_source_missing = [
        item
        for item in parameter_results
        if item["diagnosis"] == "source_payload_parameter_missing"
    ]
    parser_parameter_issues = [
        item
        for item in parameter_results
        if item["diagnosis"] == "likely_parser_or_column_mapping_issue"
    ]
    critical_parameter_issues = [
        item
        for item in parameter_results
        if item["severity"] == "critical"
    ]
    low_parameter_issues = [
        item
        for item in parameter_results
        if item["severity"] == "low"
    ]
    missing_dlq_tables = [
        table
        for table, columns in dlq_columns_by_table.items()
        if not columns
    ]
    artifact = {
        "agent": "event_source_flow_checker",
        "generated_at": datetime.now().isoformat(),
        "profile": profile_name,
        "database": database,
        "date_range": date_range,
        "source_table": f"{database}.{raw_table}",
        "dlq_tables": [
            f"{database}.{table}"
            for table in dlq_tables
            if dlq_columns_by_table[table]
        ],
        "missing_dlq_tables": missing_dlq_tables,
        "source_comparison_excluded_tables": sorted(
            source_comparison_excluded_tables
        ),
        "quality_report": str(quality_path),
        "parameter_report": str(parameter_path) if parameter_path else None,
        "summary": {
            "source_event_types": int(len(source_df)),
            "dlq_rows": int(pd.to_numeric(dlq_df.get("dlq_rows"), errors="coerce").fillna(0).sum())
            if not dlq_df.empty
            else 0,
            "critical_event_flows": len(critical),
            "low_event_flows": len(low),
            "parameter_checks": len(parameter_results),
            "source_parameter_missing": len(parameter_source_missing),
            "likely_parser_parameter_issues": len(parser_parameter_issues),
            "critical_parameter_issues": len(critical_parameter_issues),
            "low_parameter_issues": len(low_parameter_issues),
            "missing_dlq_tables": len(missing_dlq_tables),
            "profile_schema_events_added": len(profile_schema_events_added),
        },
        "flow_results": flow_results,
        "parameter_results": parameter_results,
        "raw_event_summary": json_records(source_df),
        "dlq_summary": json_records(dlq_df),
        "profile_schema_events_added": profile_schema_events_added,
    }

    timestamp = os.getenv("QUALITY_RUN_ID") or datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = REPORT_DIR / f"event_flow_{timestamp}.json"
    stable_path = REPORT_DIR / "event_flow_latest.json"
    text = json.dumps(artifact, indent=2, ensure_ascii=False)
    output_path.write_text(text, encoding="utf-8")
    stable_path.write_text(text, encoding="utf-8")

    print("\n=== Critical event-flow findings ===")
    if critical:
        for item in critical[:100]:
            print(
                f"{item['event_table']}: {','.join(item['status'])}; "
                f"raw={item['raw_rows']}, parsed={item['parsed_rows']}, "
                f"dlq={item['dlq_rows']}"
            )
    else:
        print("No critical event-flow findings.")
    print("\n=== Low event-flow findings ===")
    if low:
        for item in low[:100]:
            print(
                f"{item['event_table']}: {','.join(item['status'])}; "
                f"raw={item['raw_rows']}, parsed={item['parsed_rows']}, "
                f"dlq={item['dlq_rows']}"
            )
    else:
        print("No low event-flow findings.")
    print(f"\nSaved event-flow evidence: {output_path}")


if __name__ == "__main__":
    main()
