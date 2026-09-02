import fnmatch
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from quality_config import (
    date_range_sql_condition,
    date_range_sql_interval,
    filter_blacklisted_tables,
    get_active_profile,
    get_database,
    get_date_range,
    get_lookback_range,
    historical_lookback_sql_condition,
    is_parameter_missing_allowed,
    measurement_time_column,
    MEASUREMENT_TIME_COLUMN_CANDIDATES,
    get_main_identifier,
    get_table_prefixes,
    load_rules,
)
from readonly_clickhouse import query_df


REPORT_DIR = Path("reports")
PROJECT_ROOT = Path(__file__).resolve().parent
MAIN_IDENTIFIER = get_main_identifier()
# Each parameter expands into several measurement and lookback expressions.
# Bound wide-table statements below ClickHouse's default 256 KiB max_query_size.
PARAMETER_QUERY_BATCH_SIZE = 20
DEFAULT_INVALID_VALUES = ["n/a", "na", "unknown", "undefined", "none", "-", "null"]
DEFAULT_AUTO_EXCLUDE_COLUMNS = [
    *MEASUREMENT_TIME_COLUMN_CANDIDATES,
    "event_key",
    "adid",
    MAIN_IDENTIFIER,
    "session_id",
    "session_uuid",
    "sessions_uuid",
    "device_hash",
    "updated_at",
    "meta_data",
    "meta_data_jsonb",
    "server_supported_versions",
]
DEFAULT_AUTO_EXCLUDE_PATTERNS = ["*_json", "*_jsonb"]
DEFAULT_PROFILE_SCHEMA_DIR = Path("config/profile_schemas")
DEFAULT_COMMON_PARAMETER_MIN_EVENTS = 3
DEFAULT_SYSTEM_PARAMETERS = [
    "event_key",
    "event_name",
    "adid",
    MAIN_IDENTIFIER,
    "session_id",
    "character_id",
    "client_version",
    "platform",
    "region",
    "server",
    "server_region",
    "server_version",
    "tz_offset",
]
DEFAULT_SYSTEM_ALIASES = {
    "session_id": ["session_id", "session_uuid", "sessions_uuid"],
}
DEFAULT_PARAMETER_PRIORITIES = {
    "adid": "extreme",
    MAIN_IDENTIFIER: "extreme",
    "session_id": "extreme",
    "event_key": "extreme",
    "event_name": "high",
    "server_region": "high",
    "platform": "high",
    "step": "high",
    "value": "high",
    "type": "high",
    "tz_offset": "low",
}
DEFAULT_PARAMETER_EXAMPLES = {
    "adid": ["4bcdd67e-0bbc-4ca8-b7a5-4ba29e28c30a"],
    MAIN_IDENTIFIER: ["4bcdd67e-0bbc-4ca8-b7a5-4ba29e28c30a"],
    "session_id": ["4bcdd67e-0bbc-4ca8-b7a5-4ba29e28c30a"],
    "event_key": ["4bcdd67e-0bbc-4ca8-b7a5-4ba29e28c30a"],
    "platform": ["ios"],
    "tz_offset": ["180"],
}


def qident(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def sql_literal(value: Any) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def as_list(value: Any, default: list[str] | None = None) -> list[str]:
    if value is None:
        return list(default or [])
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return list(default or [])


def parameter_thresholds(raw_thresholds: Any, prefix: str) -> dict[str, float]:
    if not isinstance(raw_thresholds, dict):
        return {}
    result = {}
    suffix = "_pct"
    for key, value in raw_thresholds.items():
        key = str(key)
        if not key.startswith(prefix) or not key.endswith(suffix):
            continue
        parameter = key[len(prefix):-len(suffix)]
        if not parameter:
            continue
        threshold = float(value)
        if threshold < 0 or threshold > 1:
            raise ValueError(f"thresholds.{key} must be between 0 and 1")
        result[parameter] = threshold
    return result


def parameter_config(rules: dict | None = None) -> dict:
    rules = rules or load_rules()
    raw = rules.get("parameter_quality", {})
    date_range = get_date_range(rules)
    lookback = get_lookback_range(rules, raw)
    if (
        date_range.get("mode") == "rolling"
        and lookback["duration_seconds"] <= date_range["duration_seconds"]
    ):
        raise ValueError("lookback must be longer than the rolling date_range")

    defaults = raw.get("defaults", {})
    auto_discovery = raw.get("auto_discovery", {})
    profile_schema = rules.get("profile_schema", {})
    thresholds = rules.get("thresholds", {})
    profile_schema_directory = Path(
        os.getenv(
            "PROFILE_SCHEMA_DIR",
            profile_schema.get("directory", DEFAULT_PROFILE_SCHEMA_DIR),
        )
    )
    if not profile_schema_directory.is_absolute():
        profile_schema_directory = PROJECT_ROOT / profile_schema_directory
    return {
        "enabled": bool(raw.get("enabled", True)),
        "date_range": date_range,
        "lookback": lookback,
        "global_parameters": raw.get("global_parameters", {}),
        "tables": raw.get("tables", {}),
        "default_invalid_values": as_list(
            defaults.get("invalid_values"), DEFAULT_INVALID_VALUES
        ),
        "default_max_missing_pct": float(defaults.get("max_missing_pct", 0.0)),
        "default_max_invalid_pct": float(defaults.get("max_invalid_pct", 0.0)),
        "parameter_missing_thresholds": parameter_thresholds(
            thresholds,
            "missing_",
        ),
        "parameter_invalid_thresholds": parameter_thresholds(
            thresholds,
            "invalid_",
        ),
        "top_values_limit": max(1, int(defaults.get("top_values_limit", 10))),
        "auto_discovery": {
            "enabled": bool(auto_discovery.get("enabled", True)),
            "exclude_columns": as_list(
                auto_discovery.get("exclude_columns"),
                DEFAULT_AUTO_EXCLUDE_COLUMNS,
            ),
            "exclude_patterns": as_list(
                auto_discovery.get("exclude_patterns"),
                DEFAULT_AUTO_EXCLUDE_PATTERNS,
            ),
            "default_rule": {
                "required_value": "auto",
                **auto_discovery.get("default_rule", {}),
            },
            "required_min_presence_pct": float(
                auto_discovery.get("required_min_presence_pct", 0.95)
            ),
            "flag_unpopulated": bool(auto_discovery.get("flag_unpopulated", True)),
        },
        "profile_schema": {
            "enabled": bool(profile_schema.get("enabled", True)),
            "directory": profile_schema_directory,
            "create_if_missing": bool(profile_schema.get("create_if_missing", True)),
            "common_parameter_min_events": max(
                2,
                int(
                    profile_schema.get(
                        "common_parameter_min_events",
                        DEFAULT_COMMON_PARAMETER_MIN_EVENTS,
                    )
                ),
            ),
        },
    }


def profile_schema_path(profile_name: str, config: dict) -> Path:
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", profile_name).strip("._")
    if not safe_name:
        raise ValueError(f"Cannot create profile schema path for {profile_name!r}")
    return config["profile_schema"]["directory"] / f"{safe_name}.json"


def load_profile_schema(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or not isinstance(payload.get("events", {}), dict):
        raise ValueError(f"Invalid profile schema: {path}")
    return payload


def parameter_aliases(parameter: str) -> list[str]:
    return DEFAULT_SYSTEM_ALIASES.get(parameter, [parameter])


def canonical_parameter_name(parameter: str) -> str:
    for canonical, aliases in DEFAULT_SYSTEM_ALIASES.items():
        if parameter in aliases:
            return canonical
    return parameter


def decode_parameter_spec(
    raw_spec: Any,
    *,
    require_column: bool,
    required_value: Any,
) -> dict:
    if isinstance(raw_spec, (list, tuple)) and len(raw_spec) >= 3:
        parameter_type, examples, priority = raw_spec[:3]
        options = raw_spec[3] if len(raw_spec) >= 4 and isinstance(raw_spec[3], dict) else {}
        rule = dict(options)
        rule["type"] = parameter_type
        rule["examples"] = examples if isinstance(examples, list) else [examples]
        rule["report_priority"] = priority
    elif isinstance(raw_spec, dict):
        rule = dict(raw_spec)
        if "required_column" in rule:
            rule["require_column"] = bool(rule.pop("required_column"))
    else:
        return {}

    rule.setdefault("require_column", require_column)
    rule.setdefault("required_value", required_value)
    rule["_profile_schema"] = True
    rule["_report_priority"] = str(rule.get("report_priority", "normal"))
    return rule


def profile_parameter_spec(
    profile_schema: dict,
    table: str,
    parameter: str,
) -> Any:
    event = profile_schema.get("events", {}).get(table, {})
    event_parameters = event.get("parameters", {}) if isinstance(event, dict) else {}
    if isinstance(event_parameters, dict) and parameter in event_parameters:
        return event_parameters[parameter]
    for section in ("system_parameters", "common_parameters"):
        parameters = profile_schema.get(section, {})
        if isinstance(parameters, dict) and parameter in parameters:
            return parameters[parameter]
    return None


def parameter_spec_priority(raw_spec: Any) -> str:
    if isinstance(raw_spec, (list, tuple)) and len(raw_spec) >= 3:
        return str(raw_spec[2])
    if isinstance(raw_spec, dict):
        return str(raw_spec.get("report_priority", "normal"))
    return "normal"


def profile_parameters(
    profile_schema: dict,
    table: str,
    columns: set[str] | None = None,
) -> dict[str, dict]:
    configured_events = profile_schema.get("events", {})
    event = configured_events.get(table, {})
    event_parameters = event.get("parameters", {}) if isinstance(event, dict) else {}
    columns = set(columns or set())

    # Backward-compatible reader for create-once v1 files.
    if int(profile_schema.get("schema_version", 1)) < 2:
        result = {}
        for name, raw_rule in event_parameters.items():
            if raw_rule is None:
                result[str(name)] = {"_profile_schema_ignore": True}
                continue
            rule = decode_parameter_spec(
                raw_rule,
                require_column=True,
                required_value="auto",
            )
            if rule:
                result[str(name)] = rule
        return result

    result = {}
    exceptions = {
        canonical_parameter_name(str(name))
        for name in event.get("system_parameter_exceptions", [])
    }
    if table not in configured_events:
        exceptions.update(
            canonical_parameter_name(str(name))
            for name in profile_schema.get("system_parameters", {})
            if not any(
                alias in columns
                for alias in parameter_aliases(
                    canonical_parameter_name(str(name))
                )
            )
        )
    for name, raw_spec in profile_schema.get("system_parameters", {}).items():
        canonical_name = canonical_parameter_name(str(name))
        if canonical_name in exceptions:
            continue
        rule = decode_parameter_spec(
            raw_spec,
            require_column=True,
            required_value=True,
        )
        if not rule:
            continue
        aliases = parameter_aliases(canonical_name)
        if aliases != [canonical_name]:
            rule.setdefault("aliases", aliases)
        if canonical_name not in result or str(name) == canonical_name:
            result[canonical_name] = rule

    for name, raw_spec in profile_schema.get("common_parameters", {}).items():
        aliases = parameter_aliases(str(name))
        if columns and not any(alias in columns for alias in aliases):
            continue
        rule = decode_parameter_spec(
            raw_spec,
            require_column=False,
            required_value="auto",
        )
        if not rule:
            continue
        if aliases != [name]:
            rule.setdefault("aliases", aliases)
        result[str(name)] = rule

    if isinstance(event_parameters, dict):
        for name, raw_spec in event_parameters.items():
            if raw_spec is None:
                result[str(name)] = {"_profile_schema_ignore": True}
                continue
            rule = decode_parameter_spec(
                raw_spec,
                require_column=True,
                required_value="auto",
            )
            if rule:
                result[str(name)] = {**result.get(str(name), {}), **rule}
    return result


def observed_examples(value: Any, limit: int = 5) -> list[str]:
    try:
        values = json.loads(value) if isinstance(value, str) else list(value or [])
    except (TypeError, ValueError, json.JSONDecodeError):
        values = []
    return [str(item) for item in values if str(item) != "<MISSING>"][:limit]


def most_common_type(
    parameter: str,
    table_schemas: dict[str, dict[str, str]],
) -> str:
    types = Counter()
    aliases = parameter_aliases(parameter)
    for table in sorted(table_schemas):
        schema = table_schemas[table]
        for alias in aliases:
            if alias in schema:
                types[schema[alias]] += 1
                break
    return types.most_common(1)[0][0] if types else ""


def parameter_examples(
    parameter: str,
    results_by_table: dict[str, dict[str, dict]],
) -> list[str]:
    aliases = parameter_aliases(parameter)
    examples = []
    for table in sorted(results_by_table):
        for alias in aliases:
            result = results_by_table[table].get(alias)
            if not result:
                continue
            for example in observed_examples(
                result.get("lookback_observed_values")
                or result.get("observed_values"),
                limit=5,
            ):
                if example not in examples:
                    examples.append(example)
                if len(examples) >= 5:
                    return examples
    return examples or list(DEFAULT_PARAMETER_EXAMPLES.get(parameter, []))


def parameter_spec(
    parameter: str,
    parameter_type: str,
    examples: list[str],
) -> list[Any]:
    return [
        parameter_type,
        examples[:5],
        DEFAULT_PARAMETER_PRIORITIES.get(parameter, "normal"),
    ]


def profile_generation_system_rules(columns: set[str]) -> dict[str, dict]:
    rules = {}
    for name in DEFAULT_SYSTEM_PARAMETERS:
        aliases = parameter_aliases(name)
        if not any(alias in columns for alias in aliases):
            continue
        rule = {
            "require_column": False,
            "required_value": "auto",
            "_profile_schema": True,
            "_report_priority": DEFAULT_PARAMETER_PRIORITIES.get(name, "normal"),
        }
        if aliases != [name]:
            rule["aliases"] = aliases
        rules[name] = rule
    return rules


def build_profile_schema(
    profile_name: str,
    database: str,
    table_schemas: dict[str, dict[str, str]],
    results: list[dict],
    config: dict,
) -> dict:
    results_by_table: dict[str, dict[str, dict]] = {}
    for result in results:
        parameter = str(result.get("parameter", ""))
        if parameter and parameter != "*":
            results_by_table.setdefault(str(result.get("event_table")), {})[parameter] = result

    system_names = [
        name
        for name in DEFAULT_SYSTEM_PARAMETERS
        if any(
            any(alias in schema for alias in parameter_aliases(name))
            for schema in table_schemas.values()
        )
    ]
    occurrences = Counter()
    for table_results in results_by_table.values():
        occurrences.update(table_results.keys())
    common_names = sorted(
        name
        for name, count in occurrences.items()
        if count >= config["profile_schema"]["common_parameter_min_events"]
        and name not in system_names
    )

    system_parameters = {
        name: parameter_spec(
            name,
            most_common_type(name, table_schemas),
            parameter_examples(name, results_by_table),
        )
        for name in system_names
    }
    common_parameters = {
        name: parameter_spec(
            name,
            most_common_type(name, table_schemas),
            parameter_examples(name, results_by_table),
        )
        for name in common_names
    }

    events = {}
    for table in sorted(table_schemas):
        schema = table_schemas[table]
        exceptions = [
            name
            for name in system_names
            if not any(alias in schema for alias in parameter_aliases(name))
        ]
        special_parameters = {}
        for parameter, result in sorted(results_by_table.get(table, {}).items()):
            if parameter in system_names or parameter in common_names:
                continue
            special_parameters[parameter] = parameter_spec(
                parameter,
                schema.get(parameter, ""),
                observed_examples(
                    result.get("lookback_observed_values")
                    or result.get("observed_values"),
                    limit=5,
                ),
            )
        event = {"parameters": special_parameters}
        if exceptions:
            event["system_parameter_exceptions"] = exceptions
        events[table] = event

    return {
        "schema_version": 3,
        "profile_name": profile_name,
        "database": database,
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "generation_mode": "create_once_then_manual",
        "parameter_format": ["type", "examples_up_to_5", "priority"],
        "priority_order": ["extreme", "high", "normal", "low"],
        "notes": "Generated only when absent. Edit values in place; later runs never overwrite this file.",
        "system_parameters": system_parameters,
        "common_parameters": common_parameters,
        "events": events,
    }


def profile_schema_json(payload: dict) -> str:
    inline_values: dict[str, str] = {}
    marker_index = 0

    def inline_parameter_map(parameters: Any) -> Any:
        nonlocal marker_index
        if not isinstance(parameters, dict):
            return parameters
        result = {}
        for name, value in parameters.items():
            if isinstance(value, list) and len(value) >= 3:
                marker = f"__INLINE_PROFILE_PARAMETER_{marker_index}__"
                marker_index += 1
                inline_values[marker] = json.dumps(value, ensure_ascii=False)
                result[name] = marker
            else:
                result[name] = value
        return result

    compact_payload = dict(payload)
    compact_payload["system_parameters"] = inline_parameter_map(
        payload.get("system_parameters", {})
    )
    compact_payload["common_parameters"] = inline_parameter_map(
        payload.get("common_parameters", {})
    )
    compact_events = {}
    for table, event in payload.get("events", {}).items():
        compact_event = dict(event)
        compact_event["parameters"] = inline_parameter_map(event.get("parameters", {}))
        compact_events[table] = compact_event
    compact_payload["events"] = compact_events

    text = json.dumps(compact_payload, ensure_ascii=False, indent=2)
    for marker, inline_json in inline_values.items():
        text = text.replace(json.dumps(marker), inline_json)
    return text + "\n"


def create_profile_schema_once(path: Path, payload: dict) -> bool:
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(profile_schema_json(payload))
    except FileExistsError:
        return False
    return True


def missing_profile_schema_tables(
    discovered_tables: set[str],
    table_schemas: dict[str, dict[str, str]],
) -> list[str]:
    return sorted(discovered_tables - set(table_schemas))


def missing_profile_event_result(table: str, event: Any) -> dict | None:
    if isinstance(event, dict) and event.get("required", True) is False:
        return None
    return {
        "event_table": table,
        "parameter": "*",
        "status": "problem",
        "problem": "missing_event",
        "profile_schema_parameter": True,
        "report_priority": "high",
    }


def date_range_condition(date_range: dict, column: str = "event_date") -> str:
    if not date_range.get("mode"):
        return "1"
    return date_range_sql_condition(date_range, qident(column))


def baseline_range_condition(
    date_range: dict,
    lookback: dict,
    column: str = "event_date",
) -> str:
    column_ref = qident(column)
    if date_range.get("mode") == "fixed":
        start = f"{date_range['start_date']} 00:00:00"
        end = f"{date_range['end_date_exclusive']} 00:00:00"
        return (
            f"{column_ref} >= toDateTime({sql_literal(start)}) "
            f"- {date_range_sql_interval(lookback)} "
            f"AND {column_ref} < toDateTime({sql_literal(end)})"
        )
    return (
        f"{column_ref} >= now() - {date_range_sql_interval(date_range)} "
        f"- {date_range_sql_interval(lookback)} "
        f"AND {column_ref} < now()"
    )


def historical_lookback_condition(
    date_range: dict,
    lookback: dict,
    column: str = "event_date",
) -> str:
    if not date_range.get("mode"):
        return "1"
    return historical_lookback_sql_condition(
        date_range,
        lookback,
        qident(column),
    )


def discover_tables(database: str, prefixes: list[str]) -> list[str]:
    prefix_condition = " OR ".join(
        f"startsWith(table, {sql_literal(prefix)})" for prefix in prefixes
    ) or "1"
    df = query_df(f"""
        SELECT DISTINCT c.table AS table
        FROM system.columns AS c
        INNER JOIN system.tables AS t
            ON c.database = t.database
           AND c.table = t.name
        WHERE c.database = {sql_literal(database)}
          AND c.name IN ({
              ", ".join(sql_literal(column) for column in MEASUREMENT_TIME_COLUMN_CANDIDATES)
          })
          AND (
              startsWith(c.type, 'DateTime')
              OR startsWith(c.type, 'Nullable(DateTime')
          )
          AND t.engine != 'MaterializedView'
          AND ({prefix_condition})
        ORDER BY table
    """)
    if "table" not in df.columns:
        return []
    return filter_blacklisted_tables(df["table"].astype(str).tolist())


def discover_materialized_views(database: str, prefixes: list[str]) -> set[str]:
    prefix_condition = " OR ".join(
        f"startsWith(name, {sql_literal(prefix)})" for prefix in prefixes
    ) or "1"
    df = query_df(f"""
        SELECT name AS table
        FROM system.tables
        WHERE database = {sql_literal(database)}
          AND engine = 'MaterializedView'
          AND ({prefix_condition})
        ORDER BY table
    """)
    if "table" not in df.columns:
        return set()
    return set(df["table"].astype(str))


def get_table_schema(database: str, table: str) -> dict[str, str]:
    df = query_df(f"DESCRIBE TABLE {qident(database)}.{qident(table)}")
    if "name" not in df.columns:
        raise RuntimeError(f"Cannot read columns for {database}.{table}")
    if "type" not in df.columns:
        return {str(name): "" for name in df["name"].tolist()}
    return {
        str(row["name"]): str(row["type"])
        for _, row in df[["name", "type"]].iterrows()
    }


def get_columns(database: str, table: str) -> set[str]:
    return set(get_table_schema(database, table))


def normalized_value(column: str) -> str:
    column_ref = qident(column)
    return f"""if(
        {column_ref} IS NULL
        OR trim(BOTH ' ' FROM toString({column_ref})) = ''
        OR toString({column_ref}) = '00000000-0000-0000-0000-000000000000'
        OR lower(toString({column_ref})) = 'null',
        NULL,
        toString({column_ref})
    )"""


def parameter_value_expression(
    columns: set[str],
    aliases: list[str],
    rule: dict | None = None,
    default_invalid_values: list[str] | None = None,
) -> tuple[str, list[str]]:
    present = [alias for alias in aliases if alias in columns]
    if not present:
        return "NULL", []
    values = [normalized_value(alias) for alias in present]
    if len(values) == 1:
        return values[0], present

    rule = rule or {}
    valid_values = []
    for value in values:
        invalid_condition = invalid_value_condition(
            rule,
            default_invalid_values or [],
            value_ref=value,
        )
        valid_values.append(
            f"if(({value}) IS NOT NULL AND NOT ({invalid_condition}), {value}, NULL)"
        )

    # Prefer any valid alias. If every populated alias is invalid, retain the
    # first populated value so the normal invalid-value metric still flags it.
    fallback = f"coalesce({', '.join(values)})"
    return f"coalesce({', '.join([*valid_values, fallback])})", present


def invalid_value_condition(
    rule: dict,
    default_invalid_values: list[str],
    value_ref: str = "parameter_value",
) -> str:
    conditions = []
    invalid_values = as_list(rule.get("invalid_values"), default_invalid_values)
    if invalid_values:
        literals = ", ".join(sql_literal(value.lower()) for value in invalid_values)
        conditions.append(f"lower({value_ref}) IN ({literals})")

    allowed_values = as_list(rule.get("allowed_values"))
    if allowed_values:
        literals = ", ".join(sql_literal(value.lower()) for value in allowed_values)
        conditions.append(f"lower({value_ref}) NOT IN ({literals})")

    allowed_pattern = rule.get("allowed_pattern")
    if allowed_pattern:
        conditions.append(
            f"NOT match({value_ref}, {sql_literal(allowed_pattern)})"
        )

    if rule.get("min_value") is not None:
        minimum = float(rule["min_value"])
        conditions.append(
            f"(toFloat64OrNull({value_ref}) IS NULL "
            f"OR toFloat64OrNull({value_ref}) < {minimum})"
        )
    if rule.get("max_value") is not None:
        maximum = float(rule["max_value"])
        conditions.append(
            f"(toFloat64OrNull({value_ref}) IS NULL "
            f"OR toFloat64OrNull({value_ref}) > {maximum})"
        )

    return " OR ".join(f"({condition})" for condition in conditions) or "0"


def is_auto_excluded(parameter: str, auto_config: dict) -> bool:
    if parameter in set(auto_config["exclude_columns"]):
        return True
    return any(
        fnmatch.fnmatchcase(parameter, pattern)
        for pattern in auto_config["exclude_patterns"]
    )


def rules_for_table(
    config: dict,
    table: str,
    columns: set[str] | None = None,
    contract_parameters: dict[str, dict] | None = None,
    project_rules: dict | None = None,
) -> dict[str, dict]:
    auto_config = config["auto_discovery"]
    combined = {}
    if auto_config["enabled"]:
        combined.update({
            column: dict(auto_config["default_rule"])
            for column in sorted(columns or set())
            if not is_auto_excluded(column, auto_config)
        })

    combined.update({
        name: dict(rule)
        for name, rule in config["global_parameters"].items()
        if isinstance(rule, dict)
    })
    table_config = config["tables"].get(table, {})
    for parameter in as_list(table_config.get("exclude_parameters")):
        combined.pop(parameter, None)
    table_parameters = table_config.get("parameters", table_config)
    if isinstance(table_parameters, dict):
        for name, rule in table_parameters.items():
            if isinstance(rule, dict):
                combined[name] = {**combined.get(name, {}), **rule}
    for name, rule in (contract_parameters or {}).items():
        if rule.get("_profile_schema_ignore") is True:
            combined.pop(name, None)
            continue
        combined[name] = {**combined.get(name, {}), **rule}
    missing_thresholds = config.get("parameter_missing_thresholds", {})
    invalid_thresholds = config.get("parameter_invalid_thresholds", {})
    for name, rule in combined.items():
        if name in missing_thresholds:
            rule.setdefault("max_missing_pct", missing_thresholds[name])
        if name in invalid_thresholds:
            rule.setdefault("max_invalid_pct", invalid_thresholds[name])
        if (
            project_rules is not None
            and is_parameter_missing_allowed(table, name, project_rules)
        ):
            rule["max_missing_pct"] = 1.0
            rule["_missing_allowed_by_config"] = True
    return combined


def json_array(value: Any) -> str:
    if value is None:
        values = []
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    elif hasattr(value, "tolist"):
        values = value.tolist()
    else:
        values = [value]
    return json.dumps([str(item) for item in values], ensure_ascii=False)


def _check_parameter_batch(
    database: str,
    table: str,
    parameter_rules: dict[str, dict],
    columns: set[str],
    config: dict,
    time_column: str = "event_date",
) -> list[dict]:
    lookback = config.get("lookback") or config["date_range"]
    results_by_parameter = {}
    prepared = []
    value_selects = []
    measurement_condition = date_range_condition(
        config["date_range"],
        "__event_time",
    )
    lookback_condition = historical_lookback_condition(
        config["date_range"],
        lookback,
        "__event_time",
    )
    metric_selects = [
        f"countIf({measurement_condition}) AS rows_checked",
        f"countIf({lookback_condition}) AS lookback_rows_checked",
    ]
    top_limit = int(config["top_values_limit"])

    for index, (parameter, rule) in enumerate(parameter_rules.items()):
        aliases = as_list(rule.get("aliases"), [parameter])
        value_expr, source_columns = parameter_value_expression(
            columns,
            aliases,
            rule,
            config["default_invalid_values"],
        )
        require_column = bool(rule.get("require_column", False))
        required_value = rule.get("required_value", "auto")
        base = {
            "event_table": table,
            "parameter": parameter,
            "source_columns": ",".join(source_columns),
            "date_range_description": config["date_range"]["description"],
            "lookback_description": lookback["description"],
            "measurement_time_column": time_column,
            "require_column": require_column,
            "required_value": required_value,
            "profile_schema_parameter": bool(rule.get("_profile_schema", False)),
            "report_priority": str(rule.get("_report_priority", "normal")),
            "missing_allowed_by_config": bool(
                rule.get("_missing_allowed_by_config", False)
            ),
        }

        if not source_columns:
            results_by_parameter[parameter] = {
                **base,
                "status": "problem" if require_column else "skipped",
                "rows_checked": 0,
                "missing_rows": None,
                "missing_pct": None,
                "invalid_rows": None,
                "invalid_pct": None,
                "observed_values": "[]",
                "lookback_rows_checked": None,
                "lookback_missing_rows": None,
                "lookback_missing_pct": None,
                "lookback_presence_pct": None,
                "lookback_invalid_rows": None,
                "lookback_invalid_pct": None,
                "lookback_observed_values": "[]",
                "expected_present_rows": None,
                "presence_delta_pct": None,
                "inferred_required": False,
                "problem": "missing_column" if require_column else "column_not_present",
            }
            continue

        value_alias = f"parameter_{index}"
        missing_alias = f"missing_{index}"
        invalid_alias = f"invalid_{index}"
        observed_alias = f"observed_{index}"
        lookback_missing_alias = f"lookback_missing_{index}"
        lookback_invalid_alias = f"lookback_invalid_{index}"
        lookback_observed_alias = f"lookback_observed_{index}"
        value_ref = qident(value_alias)
        invalid_condition = invalid_value_condition(
            rule,
            config["default_invalid_values"],
            value_ref=value_ref,
        )
        value_selects.append(f"{value_expr} AS {value_ref}")
        metric_selects.extend([
            f"countIf(({measurement_condition}) AND {value_ref} IS NULL) "
            f"AS {qident(missing_alias)}",
            f"countIf(({measurement_condition}) AND {value_ref} IS NOT NULL "
            f"AND ({invalid_condition})) "
            f"AS {qident(invalid_alias)}",
            f"topKIf({top_limit})(ifNull({value_ref}, '<MISSING>'), "
            f"{measurement_condition}) "
            f"AS {qident(observed_alias)}",
            f"countIf(({lookback_condition}) AND {value_ref} IS NULL) "
            f"AS {qident(lookback_missing_alias)}",
            f"countIf(({lookback_condition}) AND {value_ref} IS NOT NULL "
            f"AND ({invalid_condition})) "
            f"AS {qident(lookback_invalid_alias)}",
            f"topKIf({top_limit})(ifNull({value_ref}, '<MISSING>'), "
            f"{lookback_condition}) "
            f"AS {qident(lookback_observed_alias)}",
        ])
        prepared.append({
            "parameter": parameter,
            "rule": rule,
            "base": base,
            "missing_alias": missing_alias,
            "invalid_alias": invalid_alias,
            "observed_alias": observed_alias,
            "lookback_missing_alias": lookback_missing_alias,
            "lookback_invalid_alias": lookback_invalid_alias,
            "lookback_observed_alias": lookback_observed_alias,
        })

    row = {}
    if prepared:
        df = query_df(f"""
            SELECT
                {', '.join(metric_selects)}
            FROM
            (
                SELECT
                    {qident(time_column)} AS {qident('__event_time')},
                    {', '.join(value_selects)}
                FROM {qident(database)}.{qident(table)}
                WHERE {
                    baseline_range_condition(
                        config['date_range'],
                        lookback,
                        time_column,
                    )
                }
            )
        """)
        row = df.iloc[0] if not df.empty else {}

    rows_checked = int(row.get("rows_checked", 0) or 0)
    lookback_rows_checked = int(
        row.get("lookback_rows_checked", rows_checked) or 0
    )
    for item in prepared:
        rule = item["rule"]
        base = item["base"]
        missing_rows = int(row.get(item["missing_alias"], 0) or 0)
        invalid_rows = int(row.get(item["invalid_alias"], 0) or 0)
        missing_pct = missing_rows / rows_checked if rows_checked else None
        invalid_pct = invalid_rows / rows_checked if rows_checked else None
        lookback_missing_rows = int(
            row.get(item["lookback_missing_alias"], missing_rows) or 0
        )
        lookback_invalid_rows = int(
            row.get(item["lookback_invalid_alias"], invalid_rows) or 0
        )
        lookback_missing_pct = (
            lookback_missing_rows / lookback_rows_checked
            if lookback_rows_checked
            else None
        )
        lookback_presence_pct = (
            1.0 - lookback_missing_pct
            if lookback_missing_pct is not None
            else None
        )
        lookback_invalid_pct = (
            lookback_invalid_rows / lookback_rows_checked
            if lookback_rows_checked
            else None
        )
        present_rows = rows_checked - missing_rows
        expected_present_rows = (
            rows_checked * lookback_presence_pct
            if lookback_presence_pct is not None
            else None
        )
        presence_delta_pct = (
            (present_rows - expected_present_rows) / expected_present_rows
            if expected_present_rows
            else None
        )
        max_missing_pct = float(
            rule.get("max_missing_pct", config["default_max_missing_pct"])
        )
        max_invalid_pct = float(
            rule.get("max_invalid_pct", config["default_max_invalid_pct"])
        )
        problems = []
        required_mode = str(base["required_value"]).strip().lower()
        auto_required = required_mode == "auto"
        inferred_required = False
        if auto_required and lookback_missing_pct is not None:
            inferred_required = (
                lookback_missing_pct < 1.0
                and lookback_presence_pct
                >= config["auto_discovery"]["required_min_presence_pct"]
            )
            if (
                lookback_missing_pct == 1.0
                and config["auto_discovery"]["flag_unpopulated"]
            ):
                problems.append("unpopulated_column")
            elif (
                inferred_required
                and missing_pct is not None
                and missing_pct > max_missing_pct
            ):
                problems.append("missing_values")
        elif bool(base["required_value"]) and missing_pct is not None:
            inferred_required = True
            if missing_pct > max_missing_pct:
                problems.append("missing_values")
        if invalid_pct is not None and invalid_pct > max_invalid_pct:
            problems.append("invalid_values")

        results_by_parameter[item["parameter"]] = {
            **base,
            "status": "problem" if problems else "ok",
            "rows_checked": rows_checked,
            "missing_rows": missing_rows,
            "missing_pct": missing_pct,
            "invalid_rows": invalid_rows,
            "invalid_pct": invalid_pct,
            "observed_values": json_array(row.get(item["observed_alias"])),
            "lookback_rows_checked": lookback_rows_checked,
            "lookback_missing_rows": lookback_missing_rows,
            "lookback_missing_pct": lookback_missing_pct,
            "lookback_presence_pct": lookback_presence_pct,
            "lookback_invalid_rows": lookback_invalid_rows,
            "lookback_invalid_pct": lookback_invalid_pct,
            "lookback_observed_values": json_array(
                row.get(
                    item["lookback_observed_alias"],
                    row.get(item["observed_alias"]),
                )
            ),
            "expected_present_rows": expected_present_rows,
            "presence_delta_pct": presence_delta_pct,
            "inferred_required": inferred_required,
            "problem": ",".join(problems),
        }

    return [results_by_parameter[parameter] for parameter in parameter_rules]


def check_parameters(
    database: str,
    table: str,
    parameter_rules: dict[str, dict],
    columns: set[str],
    config: dict,
    time_column: str = "event_date",
) -> list[dict]:
    items = list(parameter_rules.items())
    results = []
    for offset in range(0, len(items), PARAMETER_QUERY_BATCH_SIZE):
        batch = dict(items[offset : offset + PARAMETER_QUERY_BATCH_SIZE])
        results.extend(
            _check_parameter_batch(
                database,
                table,
                batch,
                columns,
                config,
                time_column,
            )
        )
    return results


def check_parameter(
    database: str,
    table: str,
    parameter: str,
    rule: dict,
    columns: set[str],
    config: dict,
) -> dict:
    return check_parameters(
        database,
        table,
        {parameter: rule},
        columns,
        config,
    )[0]


def print_problem_summary(frame: pd.DataFrame, limit: int = 100) -> None:
    problems = frame[frame["status"].isin(["problem", "error"])]
    print("\n=== Parameter quality problems ===")
    if problems.empty:
        print("No problems found.")
        return

    display_columns = [
        "event_table",
        "parameter",
        "status",
        "problem",
        "rows_checked",
        "missing_pct",
        "invalid_pct",
        "lookback_presence_pct",
        "expected_present_rows",
    ]
    display_columns = [column for column in display_columns if column in problems]
    text = problems[display_columns].head(limit).to_string(index=False)
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    safe_text = text.encode(encoding, errors="replace").decode(encoding)
    print(safe_text)
    if len(problems) > limit:
        print(f"... {len(problems) - limit} additional problems are in the CSV report.")


def main() -> None:
    REPORT_DIR.mkdir(exist_ok=True)
    rules = load_rules()
    config = parameter_config(rules)
    profile_name, _ = get_active_profile(rules)
    database = get_database(rules)
    timestamp = os.getenv("QUALITY_RUN_ID") or datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"parameter_quality_{timestamp}.csv"
    schema_path = profile_schema_path(profile_name, config)
    profile_schema = (
        load_profile_schema(schema_path)
        if config["profile_schema"]["enabled"]
        else {}
    )

    if profile_schema:
        schema_profile = profile_schema.get("profile_name")
        schema_database = profile_schema.get("database")
        if schema_profile and schema_profile != profile_name:
            raise ValueError(
                f"Profile schema {schema_path} belongs to {schema_profile!r}, "
                f"not active profile {profile_name!r}"
            )
        if schema_database and schema_database != database:
            raise ValueError(
                f"Profile schema {schema_path} targets {schema_database!r}, "
                f"not active database {database!r}"
            )

    if not config["enabled"]:
        pd.DataFrame(columns=["event_table", "parameter", "status"]).to_csv(
            path, index=False, encoding="utf-8-sig"
        )
        print(f"Parameter quality checks disabled. Saved empty report: {path}")
        return

    tables = discover_tables(database, get_table_prefixes(rules))
    materialized_views = discover_materialized_views(
        database,
        get_table_prefixes(rules),
    )
    discovered_tables = set(tables)
    configured_tables = filter_blacklisted_tables(list(config["tables"]))
    for table in configured_tables:
        if table not in tables:
            tables.append(table)
    contract_tables = [
        table
        for table in filter_blacklisted_tables(list(profile_schema.get("events", {})))
        if table not in materialized_views
    ]
    for table in contract_tables:
        if table not in tables:
            tables.append(table)

    print(f"Parameter quality date range: {config['date_range']['description']}")
    print(f"Parameter historical lookback: {config['lookback']['description']}")
    print(
        "Parameter selection: automatic schema discovery "
        f"({'enabled' if config['auto_discovery']['enabled'] else 'disabled'})"
    )
    if profile_schema:
        print(f"Profile schema: loaded {schema_path} (manual edits preserved)")
    elif config["profile_schema"]["enabled"]:
        print(f"Profile schema: will create once at {schema_path}")
    results = []
    table_schemas: dict[str, dict[str, str]] = {}
    for table in tables:
        try:
            contract_event = profile_schema.get("events", {}).get(table, {})
            if table not in discovered_tables:
                missing_event = missing_profile_event_result(table, contract_event)
                if missing_event is not None:
                    results.append(missing_event)
                continue

            table_schema = get_table_schema(database, table)
            table_schemas[table] = table_schema
            columns = set(table_schema)
            time_column = measurement_time_column(table_schema)
            if time_column is None:
                raise RuntimeError(
                    f"{database}.{table} has no supported DateTime measurement column"
                )
            if profile_schema:
                contract_parameters = profile_parameters(
                    profile_schema,
                    table,
                    columns,
                )
            elif config["profile_schema"]["enabled"]:
                contract_parameters = profile_generation_system_rules(columns)
            else:
                contract_parameters = {}
            table_rules = rules_for_table(
                config,
                table,
                columns,
                contract_parameters=contract_parameters,
                project_rules=rules,
            )
            if not table_rules:
                continue
            print(
                f"Checking {len(table_rules)} auto-discovered parameters for {table}: "
                f"{', '.join(table_rules)}"
            )
            results.extend(
                check_parameters(
                    database,
                    table,
                    table_rules,
                    columns,
                    config,
                    time_column,
                )
            )
        except Exception as exc:
            results.append({
                "event_table": table,
                "parameter": "*",
                "status": "error",
                "problem": str(exc),
            })

    generated_schema = {}
    missing_schema_tables = missing_profile_schema_tables(
        discovered_tables,
        table_schemas,
    )
    if (
        config["profile_schema"]["enabled"]
        and config["profile_schema"]["create_if_missing"]
        and not profile_schema
    ):
        if missing_schema_tables:
            print(
                "Profile schema not created because schema discovery was incomplete: "
                + ", ".join(missing_schema_tables)
            )
        else:
            generated_schema = build_profile_schema(
                profile_name,
                database,
                table_schemas,
                results,
                config,
            )
            if create_profile_schema_once(schema_path, generated_schema):
                print(f"Profile schema created once: {schema_path}")
            else:
                generated_schema = load_profile_schema(schema_path)
                print(f"Profile schema already exists; preserved: {schema_path}")

    active_schema = profile_schema or generated_schema
    if active_schema:
        for result in results:
            raw_spec = profile_parameter_spec(
                active_schema,
                str(result.get("event_table", "")),
                str(result.get("parameter", "")),
            )
            if raw_spec is not None:
                result["profile_schema_parameter"] = True
                result["report_priority"] = parameter_spec_priority(raw_spec)

    frame = pd.DataFrame(results)
    if frame.empty:
        frame = pd.DataFrame(columns=["event_table", "parameter", "status"])
    frame.to_csv(path, index=False, encoding="utf-8-sig")

    print_problem_summary(frame)
    print(f"\nSaved report: {path}")

    if (frame["status"] == "error").any():
        raise SystemExit(2)


if __name__ == "__main__":
    main()
