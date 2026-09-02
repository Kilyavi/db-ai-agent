import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv

from quality_config import (
    date_range_sql_condition,
    filter_blacklisted_tables,
    get_date_range,
    get_event_group_names,
    get_identifier_aliases,
    get_main_identifier,
    get_present_identifier_columns,
    get_llm_config,
    get_profile_context,
    get_table_blacklist,
    is_table_blacklisted,
    load_rules,
)
from console_status import Spinner
from readonly_clickhouse import query_df, validate_readonly_sql


REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

STABLE_OUTPUT_JSON = REPORT_DIR / "database_investigation.json"
STABLE_OUTPUT_TXT = REPORT_DIR / "database_investigation.txt"

SESSION_ID_ALIASES = get_identifier_aliases("session_id")
MAIN_IDENTIFIER = get_main_identifier()
MAIN_IDENTIFIER_ALIASES = get_identifier_aliases("user_id")

INTERESTING_COLUMNS = [
    "event_time",
    "event_date",
    "payload",
    "mode",
    "adid",
    *MAIN_IDENTIFIER_ALIASES,
    *SESSION_ID_ALIASES,
    "event_key",
    "step",
    "type",
    "platform",
    "region",
    "server_region",
    "client_version",
    "app_version",
    "version",
    "build",
]

ALLOWED_SYSTEM_TABLES = {
    "system.columns",
    "system.tables",
    "system.parts",
}

MOJIBAKE_MARKERS = ("\u00e2", "\u00c2", "\u00c3")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def qident(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def load_source_flow_evidence() -> dict:
    run_id = os.getenv("QUALITY_RUN_ID")
    candidates = (
        list(REPORT_DIR.glob(f"event_flow_{run_id}.json"))
        if run_id
        else []
    )
    if not candidates:
        candidates = list(REPORT_DIR.glob("event_flow_*.json"))
    candidates = [path for path in candidates if path.name != "event_flow_latest.json"]
    if not candidates:
        return {"status": "not_available"}
    path = max(candidates, key=lambda item: item.stat().st_mtime)
    with path.open("r", encoding="utf-8") as handle:
        artifact = json.load(handle)
    critical = [
        item
        for item in artifact.get("flow_results", [])
        if any(str(flag).startswith("critical_") for flag in item.get("status", []))
    ]
    low = [
        item
        for item in artifact.get("flow_results", [])
        if str(item.get("severity")) == "low"
        or any(str(flag).startswith("low_") for flag in item.get("status", []))
    ]
    parameter_findings = [
        item
        for item in artifact.get("parameter_results", [])
        if item.get("diagnosis")
        in {"source_payload_parameter_missing", "likely_parser_or_column_mapping_issue"}
    ]
    raw_event_types = [
        {
            "event_table": item.get("event_table"),
            "source_type": item.get("source_type"),
            "raw_rows": item.get("raw_rows"),
        }
        for item in artifact.get("raw_event_summary", [])
        if item.get("event_table") and item.get("source_type")
    ]
    return {
        "status": "available",
        "path": str(path),
        "summary": artifact.get("summary", {}),
        "critical_event_flows": critical[:30],
        "low_event_flows": low[:30],
        "parameter_source_comparisons": parameter_findings[:30],
        "raw_event_types": raw_event_types[:80],
        "dlq_summary": artifact.get("dlq_summary", [])[:20],
    }


def compact_source_flow_evidence_for_prompt(evidence: dict) -> dict:
    """Keep planner evidence bounded to fields that can change query design."""
    flow_fields = {
        "event_table",
        "target_table_exists",
        "raw_rows",
        "parsed_rows",
        "dlq_rows",
        "dlq_shapes",
        "dlq_source_tables",
        "status",
        "severity",
    }
    parameter_fields = {
        "event_table",
        "parameter",
        "scope",
        "target_missing_pct",
        "source_aliases",
        "raw_rows",
        "raw_present_rows",
        "raw_presence_pct",
        "diagnosis",
        "status",
        "severity",
    }

    def select_fields(items: list[dict], allowed: set[str], limit: int) -> list[dict]:
        return [
            {key: item.get(key) for key in allowed if key in item}
            for item in items[:limit]
        ]

    return {
        "status": evidence.get("status"),
        "summary": evidence.get("summary", {}),
        "critical_event_flows": select_fields(
            evidence.get("critical_event_flows", []), flow_fields, 15
        ),
        "low_event_flows": select_fields(
            evidence.get("low_event_flows", []), flow_fields, 15
        ),
        "parameter_source_comparisons": select_fields(
            evidence.get("parameter_source_comparisons", []), parameter_fields, 12
        ),
        "raw_event_types": evidence.get("raw_event_types", [])[:80],
        "dlq_summary": evidence.get("dlq_summary", [])[:20],
    }


def relevant_inventory_for_planner(
    inventory: list[dict],
    config: dict,
    evidence: dict,
) -> list[dict]:
    """Avoid sending unrelated table schemas to an evidence-guided planner."""
    if evidence.get("status") != "available":
        return inventory

    mandatory_tables = list(config.get("mandatory_inventory_tables", []))
    relevant_tables = set(mandatory_tables[:1])
    relevant_tables.update(
        str(item.get("dlq_source_table"))
        for item in evidence.get("dlq_summary", [])
        if item.get("dlq_source_table") and int(item.get("dlq_rows") or 0) > 0
    )
    for key in ("critical_event_flows", "low_event_flows"):
        relevant_tables.update(
            str(item.get("event_table"))
            for item in evidence.get(key, [])
            if item.get("event_table")
            and (
                int(item.get("raw_rows") or 0) > 0
                or int(item.get("dlq_rows") or 0) > 0
            )
        )
    relevant_tables.update(
        str(item.get("event_table"))
        for item in evidence.get("parameter_source_comparisons", [])
        if item.get("event_table")
    )
    return [item for item in inventory if item.get("table") in relevant_tables]


def as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def configured_source_tables(rules: dict) -> list[str]:
    source_flow = rules.get("source_flow", {})
    configured_dlqs = source_flow.get("dlq_tables")
    if isinstance(configured_dlqs, str):
        dlq_tables = [
            table.strip()
            for table in configured_dlqs.split(",")
            if table.strip()
        ]
    elif isinstance(configured_dlqs, (list, tuple, set)):
        dlq_tables = [
            str(table).strip()
            for table in configured_dlqs
            if str(table).strip()
        ]
    else:
        dlq_tables = [
            str(source_flow.get("dlq_table") or "source_events_dlq").strip()
        ]
    tables = [
        str(source_flow.get("raw_table") or "source_events").strip(),
        *dlq_tables,
    ]
    return list(dict.fromkeys(table for table in tables if table))


def get_investigation_config() -> dict:
    rules = load_rules()
    ai_rules = rules.get("ai_db_agent", {})
    profile_context = get_profile_context(rules)
    date_range = get_date_range(
        rules,
        env_prefix="AI_AGENT",
        days_env_var="AI_AGENT_DAYS_BACK",
        days_candidates=[ai_rules.get("days_back")],
    )

    return {
        "rules": rules,
        "profile": profile_context,
        "database": profile_context["database"],
        "table_name_prefixes": profile_context["table_name_prefixes"],
        "table_blacklist": profile_context["table_blacklist"],
        "mandatory_inventory_tables": configured_source_tables(rules),
        "date_range": date_range,
        "duration_hours": date_range["duration_seconds"] / 3600,
        "max_inventory_tables": as_int(
            os.getenv("AI_AGENT_MAX_INVENTORY_TABLES")
            or ai_rules.get("max_inventory_tables"),
            80,
        ),
        "max_iterations": as_int(
            os.getenv("AI_AGENT_MAX_ITERATIONS")
            or ai_rules.get("max_iterations"),
            2,
        ),
        "max_queries_per_iteration": as_int(
            os.getenv("AI_AGENT_MAX_QUERIES_PER_ITERATION")
            or ai_rules.get("max_queries_per_iteration"),
            3,
        ),
        "planning_max_tokens": as_int(
            os.getenv("AI_AGENT_PLANNING_MAX_TOKENS")
            or ai_rules.get("planning_max_tokens"),
            2000,
        ),
        "result_preview_rows": as_int(
            os.getenv("AI_AGENT_RESULT_PREVIEW_ROWS")
            or ai_rules.get("result_preview_rows"),
            12,
        ),
        "source_flow_evidence": load_source_flow_evidence(),
    }


def date_range_prompt_instruction(date_range: dict) -> str:
    return (
        "Use the physical timestamp column shown by the inventory. "
        "For raw source and DLQ tables such as source_events, source_events_dlq, and "
        "partner_events_dlq, the timestamp column is event_time, "
        "so use exactly: "
        f"{date_range_sql_condition(date_range, 'event_time')}. "
        "For parsed event tables that expose event_date, use exactly: "
        f"{date_range_sql_condition(date_range, 'event_date')}. "
        "Never use event_date for a raw source or DLQ table."
    )


def repair_text(value: Any) -> str:
    text = str(value or "")
    if not any(marker in text for marker in MOJIBAKE_MARKERS):
        return text

    try:
        repaired = text.encode("cp1252", errors="strict").decode("utf-8", errors="strict")
    except UnicodeError:
        try:
            repaired = text.encode("cp1252", errors="ignore").decode("utf-8", errors="ignore")
        except Exception:
            return text

    if len(repaired.strip()) < max(1, int(len(text.strip()) * 0.7)):
        return text

    return repaired


def ask_model(
    messages: list[dict],
    max_tokens: int | None = None,
    temperature: float = 0.1,
    llm_config: dict | None = None,
) -> str:
    load_dotenv()

    llm_config = llm_config or get_llm_config("AI_AGENT")
    base_url = llm_config["base_url"]
    model = llm_config["model"]
    api_key = llm_config["api_key"]

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens or llm_config["max_tokens"],
    }

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    request = urllib.request.Request(
        url=f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with Spinner(f"LLM request running: {model}"):
            with urllib.request.urlopen(request, timeout=240) as response:
                result = json.loads(response.read().decode("utf-8"))

        choice = result["choices"][0]
        content = choice.get("message", {}).get("content", "").strip()

        if not content:
            reasoning_len = len(choice.get("message", {}).get("reasoning_content", "") or "")
            raise RuntimeError(
                "model returned no final content "
                f"(finish_reason={choice.get('finish_reason')}, reasoning_chars={reasoning_len})"
            )

        return repair_text(content)

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"model HTTP error {e.code}: {body[:1000]}") from e


def discover_inventory(config: dict) -> list[dict]:
    database = config["database"]
    prefixes = config["table_name_prefixes"]
    max_tables = config["max_inventory_tables"]
    mandatory_tables = config.get("mandatory_inventory_tables", [])

    prefix_conditions = " OR ".join(
        f"startsWith(c.table, {sql_literal(prefix)})"
        for prefix in prefixes
    )
    if not prefix_conditions:
        prefix_conditions = "1"

    mandatory_literals = ", ".join(
        sql_literal(table) for table in mandatory_tables
    )
    mandatory_condition = (
        f"c.table IN ({mandatory_literals})" if mandatory_literals else "0"
    )
    mandatory_order = (
        f"table IN ({mandatory_literals})" if mandatory_literals else "0"
    )
    inventory_limit = int(max_tables) + len(mandatory_tables)

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
              AND (({prefix_conditions}) OR {mandatory_condition})
            GROUP BY c.table
        )
        ORDER BY {mandatory_order} DESC, estimated_rows DESC, table
        LIMIT {inventory_limit}
    """)

    inventory = []
    blacklist = config["table_blacklist"]

    for row in df.to_dict("records"):
        table = str(row["table"])
        if is_table_blacklisted(table, blacklist):
            continue

        columns = [str(column) for column in row.get("columns", [])]
        interesting = [column for column in INTERESTING_COLUMNS if column in columns]
        session_id_columns = get_present_identifier_columns(
            columns, "session_id", config["rules"]
        )
        main_identifier_columns = get_present_identifier_columns(
            columns, "user_id", config["rules"]
        )

        inventory.append({
            "table": table,
            "engine": str(row.get("engine", "")),
            "estimated_rows": int(row.get("estimated_rows", 0) or 0),
            "column_count": int(row.get("column_count", 0) or 0),
            "interesting_columns": interesting,
            "has_event_time": "event_time" in columns,
            "has_event_date": "event_date" in columns,
            "has_event_key": "event_key" in columns,
            "has_adid": "adid" in columns,
            "has_main_identifier": bool(main_identifier_columns),
            "main_identifier": get_main_identifier(config["rules"]),
            "main_identifier_columns": main_identifier_columns,
            "has_session_id": bool(session_id_columns),
            "session_id_columns": session_id_columns,
            "event_groups": get_event_group_names(table, config["rules"]),
            "columns": columns,
        })

    return inventory


def inventory_for_prompt(inventory: list[dict]) -> str:
    lines = []

    for item in inventory:
        flags = []
        for key in [
            "event_time",
            "event_date",
            "event_key",
            "adid",
            "main_identifier",
            "session_id",
        ]:
            if item.get(f"has_{key}"):
                flags.append(
                    item["main_identifier"]
                    if key == "main_identifier"
                    else key
                )

        groups = ",".join(item["event_groups"]) if item["event_groups"] else "none"
        columns = ",".join(item["interesting_columns"]) or "no common event columns"

        lines.append(
            f"- {item['table']}: rows~{item['estimated_rows']}, "
            f"groups={groups}, cols={columns}, key_flags={','.join(flags)}"
        )

    return "\n".join(lines)


def extract_json_object(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text, flags=re.IGNORECASE).strip()
        text = re.sub(r"```$", "", text).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        return json.loads(text[start:end + 1])


def table_lookup(inventory: list[dict]) -> dict[str, dict]:
    return {item["table"]: item for item in inventory}


def normalize_identifier(identifier: str) -> str:
    identifier = identifier.strip().strip(",")
    identifier = identifier.replace("`", "").replace('"', "")
    return identifier


def referenced_tables(sql: str) -> list[str]:
    normalized = re.sub(r"\s+", " ", sql)
    # SQL-standard trim syntax contains a FROM token that separates the trim
    # character from its value. Mask that separator before scanning real table
    # references so `toString(...)` is not mistaken for a table name.
    normalized = re.sub(
        r"\btrim\s*\(\s*(?:both|leading|trailing)\s+"
        r"(?:'(?:''|[^'])*'\s+)?from\s+",
        "trim(",
        normalized,
        flags=re.IGNORECASE,
    )
    refs = []

    for match in re.finditer(r"\b(?:from|join)\s+([`\"A-Za-z0-9_.]+)", normalized, re.IGNORECASE):
        ref = normalize_identifier(match.group(1))
        if ref and not ref.startswith("("):
            refs.append(ref)

    return refs


def cte_aliases(sql: str) -> set[str]:
    text = sql.strip()
    match = re.match(r"with\s+(?:recursive\s+)?", text, re.IGNORECASE)
    if not match:
        return set()

    aliases: set[str] = set()
    position = match.end()

    while position < len(text):
        alias_match = re.match(
            r"\s*([A-Za-z_][A-Za-z0-9_]*)\s+as\s*\(",
            text[position:],
            re.IGNORECASE,
        )
        if not alias_match:
            break

        aliases.add(alias_match.group(1))
        position += alias_match.end()
        depth = 1
        quote = None

        while position < len(text) and depth:
            char = text[position]
            if quote:
                if char == quote:
                    if position + 1 < len(text) and text[position + 1] == quote:
                        position += 2
                        continue
                    quote = None
            elif char in {"'", '"', "`"}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            position += 1

        if depth:
            break

        comma_match = re.match(r"\s*,", text[position:])
        if not comma_match:
            break
        position += comma_match.end()

    return aliases


def mask_nonempty_sql_string_literals(sql: str) -> str:
    """Hide literal contents while preserving empty strings for safety checks."""
    return re.sub(
        r"'(?:''|[^'])*'",
        lambda match: "''" if match.group(0) == "''" else " " * len(match.group(0)),
        sql,
    )


def normalize_clickhouse_boolean_syntax(sql: str) -> str:
    """Convert unary ! to ClickHouse NOT without touching quotes or !=."""
    output = []
    quote = None
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote is not None:
            output.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            output.append(char)
        elif char == "!" and (index + 1 >= len(sql) or sql[index + 1] != "="):
            output.append("NOT ")
        else:
            output.append(char)
        index += 1
    return "".join(output)


def normalize_sql_line_continuations(sql: str) -> str:
    """Normalize model-emitted line escapes outside SQL string literals."""
    output = []
    quote = None
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote is not None:
            output.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            output.append(char)
            index += 1
            continue
        if char == "\\" and index + 1 < len(sql):
            escaped = sql[index + 1]
            if escaped in {"\r", "\n"}:
                index += 1
                continue
            if escaped in {"r", "n", "t"}:
                output.append("\n" if escaped in {"r", "n"} else " ")
                index += 2
                continue
        output.append(char)
        index += 1
    return "".join(output)


def normalize_raw_payload_path_syntax(sql: str) -> str:
    """Convert model-style payload.params access to ClickHouse JSON extraction."""
    output = []
    quote = None
    index = 0
    pattern = re.compile(
        r"payload\s*\.\s*params(?![A-Za-z0-9_])",
        flags=re.IGNORECASE,
    )
    while index < len(sql):
        char = sql[index]
        if quote is not None:
            output.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            output.append(char)
            index += 1
            continue
        match = pattern.match(sql, index)
        if match:
            output.append("JSONExtractRaw(payload, 'params')")
            index = match.end()
            continue
        output.append(char)
        index += 1
    return "".join(output)


def normalize_raw_payload_session_to_string(sql: str) -> str:
    """Read canonical raw session aliases from payload.params instead of columns."""
    normalized = sql
    for identifier in SESSION_ID_ALIASES:
        pattern = re.compile(
            rf"\btoString\s*\(\s*`?{re.escape(identifier)}`?\s*\)",
            flags=re.IGNORECASE,
        )
        replacement = (
            "toString(JSONExtractString(JSONExtractRaw(payload, 'params'), "
            f"'{identifier}'))"
        )
        normalized = pattern.sub(replacement, normalized)
    return normalized


def normalize_jsonhas_string_comparisons(sql: str) -> str:
    """Use string extraction when a model compares a JSON path with text."""
    pattern = re.compile(
        r"\bJSONHas\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*,\s*"
        r"((?:'(?:''|[^'])*'\s*,\s*)*'(?:''|[^'])*')\s*\)"
        r"\s*=\s*('(?:''|[^'])*')",
        flags=re.IGNORECASE,
    )
    return pattern.sub(
        lambda match: (
            f"JSONExtractString({match.group(1)}, {match.group(2)}) "
            f"= {match.group(3)}"
        ),
        sql,
    )


def normalize_dlq_rejected_at_datetime(sql: str) -> str:
    """Parse ISO-8601 rejectedAt values, including milliseconds and Z."""
    pattern = re.compile(
        r"\btoDateTime\s*\(\s*JSONExtractString\(\s*payload\s*,\s*"
        r"'rejectedAt'\s*\)\s*\)",
        flags=re.IGNORECASE,
    )
    return pattern.sub(
        "parseDateTime64BestEffortOrNull("
        "JSONExtractString(payload, 'rejectedAt'))",
        sql,
    )


def normalize_dlq_validation_errors_array_size(sql: str) -> str:
    """Use a typed ClickHouse array before measuring validationErrors length."""
    pattern = re.compile(
        r"\barraySize\s*\(\s*JSONExtractRaw\s*\(\s*payload\s*,\s*"
        r"'validationErrors'\s*\)\s*\)",
        flags=re.IGNORECASE,
    )
    return pattern.sub(
        "length(JSONExtract(payload, 'validationErrors', 'Array(String)'))",
        sql,
    )


def normalize_dlq_type_identifier(sql: str) -> str:
    """Replace a missing DLQ type column with its legacy-envelope event name."""
    replacement = (
        "replaceRegexpOne("
        "JSONExtractString(payload, 'event', 'name'), '^.*\\\\.', '')"
    )
    output = []
    quote = None
    index = 0
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])type(?![A-Za-z0-9_])",
        flags=re.IGNORECASE,
    )
    while index < len(sql):
        char = sql[index]
        if quote is not None:
            output.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            output.append(char)
            index += 1
            continue
        match = pattern.match(sql, index)
        if match:
            output.append(replacement)
            index = match.end()
            continue
        output.append(char)
        index += 1
    return "".join(output)


def normalize_legacy_dlq_parameter_paths(sql: str) -> str:
    """Map payload.params to payload.event.parameters for a known legacy DLQ."""
    return re.sub(
        r"(\bJSON[A-Za-z0-9_]*\s*\(\s*payload\s*,\s*)'params'",
        r"\1'event', 'parameters'",
        sql,
        flags=re.IGNORECASE,
    )


def normalize_truncated_measurement_timestamp(sql: str, config: dict) -> str:
    """Restore one missing final character only for configured window literals."""
    date_range = config.get("date_range")
    if not date_range:
        return sql

    required = date_range_sql_condition(date_range, "event_time")
    expected_literals = re.findall(r"'((?:''|[^'])*)'", required)
    normalized = sql
    for expected in set(expected_literals):
        if len(expected) < 2:
            continue
        truncated_literal = f"'{expected[:-1]}'"
        expected_literal = f"'{expected}'"
        normalized = normalized.replace(truncated_literal, expected_literal)
    return normalized


def normalized_sql_fragment(value: str) -> str:
    """Normalize harmless formatting differences for SQL guardrail comparisons."""
    return re.sub(r"\s+", " ", str(value or "")).strip().rstrip(";").casefold()


class MediumPrioritySqlProblem(ValueError):
    """A non-executable AI SQL problem that must remain visible in reports."""

    def __init__(self, code: str, message: str, invalid_value: str | None = None):
        super().__init__(message)
        self.code = code
        self.invalid_value = invalid_value


def validate_datetime_literals(sql: str) -> None:
    """Flag impossible literal timestamps before ClickHouse can coerce them."""
    for raw_value in re.findall(
        r"\btoDateTime(?:64)?\s*\(\s*'((?:''|[^'])*)'",
        sql,
        flags=re.IGNORECASE,
    ):
        value = raw_value.replace("''", "'")
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise MediumPrioritySqlProblem(
                "invalid_datetime_literal",
                (
                    f"AI SQL contains an impossible datetime literal: {value!r}; "
                    "the query was not executed."
                ),
                invalid_value=value,
            ) from exc


def validate_balanced_parentheses(sql: str) -> None:
    """Reject malformed model SQL before sending it to ClickHouse."""
    depth = 0
    quote = None
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote is not None:
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("AI SQL has unbalanced parentheses")
        index += 1

    if depth != 0:
        raise ValueError("AI SQL has unbalanced parentheses")


def validate_measurement_window(
    sql: str,
    config: dict,
    referenced_inventory: list[dict],
) -> None:
    """Require the exact frozen pipeline window for every event timestamp used."""
    date_range = config.get("date_range")
    if not date_range:
        return

    inventory_by_table = {
        str(item.get("table")): item
        for item in referenced_inventory
        if item.get("table")
    }
    for scope in direct_select_scopes(sql) or [sql]:
        scope_inventory = [
            inventory_by_table[table]
            for table in referenced_table_names(scope)
            if table in inventory_by_table
        ]
        required_columns = set()
        for item in scope_inventory:
            columns = set(item.get("columns", []))
            if "event_time" in columns:
                required_columns.add("event_time")
            elif "event_date" in columns:
                required_columns.add("event_date")

        scope_normalized = normalized_sql_fragment(scope)
        for column in sorted(required_columns):
            required = date_range_sql_condition(date_range, column)
            if normalized_sql_fragment(required) not in scope_normalized:
                raise ValueError(
                    "AI SQL must use the exact configured "
                    f"{column} predicate in every SELECT scope: {required}"
                )


def referenced_table_names(sql: str) -> set[str]:
    return {reference.split(".")[-1] for reference in referenced_tables(sql)}


def direct_select_scopes(sql: str) -> list[str]:
    """Return SELECT scopes with nested SELECT bodies masked out."""
    masked_sql = mask_nonempty_sql_string_literals(sql)
    depth_at = [0] * (len(masked_sql) + 1)
    depth = 0
    for index, char in enumerate(masked_sql):
        depth_at[index] = depth
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
    depth_at[len(masked_sql)] = depth

    select_matches = list(re.finditer(r"\bselect\b", masked_sql, re.IGNORECASE))
    union_matches = list(
        re.finditer(r"\bunion(?:\s+all)?\b", masked_sql, re.IGNORECASE)
    )
    intervals = []
    for match in select_matches:
        start = match.start()
        select_depth = depth_at[start]
        end = len(sql)
        for union_match in union_matches:
            if (
                union_match.start() > start
                and depth_at[union_match.start()] == select_depth
            ):
                end = union_match.start()
                break
        for index in range(match.end(), end):
            if depth_at[index] < select_depth:
                end = index
                break
        intervals.append((start, end, select_depth))

    scopes = []
    for start, end, select_depth in intervals:
        scope = list(sql[start:end])
        for child_start, child_end, child_depth in intervals:
            if child_start <= start or child_start >= end or child_depth <= select_depth:
                continue
            relative_start = child_start - start
            relative_end = min(child_end, end) - start
            scope[relative_start:relative_end] = " " * (
                relative_end - relative_start
            )
        scopes.append("".join(scope))
    return scopes


def sql_references_column_on_table(
    sql: str,
    table: str,
    column: str,
    inventory_by_table: dict[str, dict],
) -> bool:
    """Return whether a SELECT scope resolves a physical column to one table."""
    quoted_table = re.escape(table)
    quoted_column = re.escape(column)
    reserved_aliases = {
        "where", "prewhere", "join", "inner", "left", "right", "full",
        "cross", "on", "using", "group", "order", "limit", "union", "settings",
    }

    for scope in direct_select_scopes(sql):
        scope_tables = referenced_table_names(scope)
        if table not in scope_tables:
            continue
        identifier_scan = mask_nonempty_sql_string_literals(scope)
        aliases = {table}
        table_reference = re.compile(
            rf"\b(?:from|join)\s+(?:[`\"]?[A-Za-z0-9_]+[`\"]?\.)?"
            rf"[`\"]?{quoted_table}[`\"]?"
            r"(?:\s+(?:as\s+)?([A-Za-z_][A-Za-z0-9_]*))?",
            re.IGNORECASE,
        )
        for match in table_reference.finditer(identifier_scan):
            alias = str(match.group(1) or "")
            if alias and alias.casefold() not in reserved_aliases:
                aliases.add(alias)

        for alias in aliases:
            if re.search(
                rf"(?<![A-Za-z0-9_])`?{re.escape(alias)}`?\s*\.\s*"
                rf"`?{quoted_column}`?(?![A-Za-z0-9_])",
                identifier_scan,
                re.IGNORECASE,
            ):
                return True

        unqualified_scan = re.sub(
            rf"(?<![A-Za-z0-9_])`?[A-Za-z_][A-Za-z0-9_]*`?\s*\.\s*"
            rf"`?{quoted_column}`?(?![A-Za-z0-9_])",
            " ",
            identifier_scan,
            flags=re.IGNORECASE,
        )
        if not re.search(
            rf"(?<![A-Za-z0-9_])`?{quoted_column}`?(?![A-Za-z0-9_])",
            unqualified_scan,
            re.IGNORECASE,
        ):
            continue

        column_owners = {
            referenced_table
            for referenced_table in scope_tables
            if column in set(
                inventory_by_table.get(referenced_table, {}).get("columns", [])
            )
        }
        if not column_owners or column_owners == {table}:
            return True
    return False


def all_zero_scalar_metrics(df: pd.DataFrame) -> bool:
    """Return true only for a one-row result made entirely of numeric zeroes."""
    if len(df) != 1 or len(df.columns) == 0:
        return False

    numeric_values = []
    for value in df.iloc[0].tolist():
        if pd.isna(value):
            return False
        try:
            numeric_values.append(float(value))
        except (TypeError, ValueError):
            return False
    return bool(numeric_values) and all(value == 0 for value in numeric_values)


def duplicate_investigation_reason(
    investigation: dict,
    successful_ids: set[str],
    executed_sql: set[str],
) -> str | None:
    investigation_id = str(investigation.get("id") or "unnamed_investigation")
    if investigation_id.casefold() in successful_ids:
        return f"investigation id {investigation_id!r} already succeeded"

    sql_fingerprint = normalized_sql_fragment(investigation.get("sql") or "")
    if sql_fingerprint and sql_fingerprint in executed_sql:
        return "the same normalized SQL was already executed"
    return None


def validate_ai_sql(sql: str, config: dict, inventory: list[dict]) -> str:
    sql = normalize_truncated_measurement_timestamp(
        normalize_sql_line_continuations(sql),
        config,
    )
    safe_sql = validate_readonly_sql(
        normalize_clickhouse_boolean_syntax(
            normalize_dlq_validation_errors_array_size(
                normalize_dlq_rejected_at_datetime(
                    normalize_jsonhas_string_comparisons(
                        normalize_raw_payload_path_syntax(sql)
                    )
                )
            )
        )
    )
    validate_balanced_parentheses(safe_sql)
    validate_datetime_literals(safe_sql)
    identifier_scan_sql = mask_nonempty_sql_string_literals(safe_sql)

    select_clauses = re.findall(
        r"\bselect\b(.*?)(?=\bfrom\b)",
        safe_sql,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if any(re.search(r"(^|,)\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?\*", clause) for clause in select_clauses):
        raise ValueError(
            "AI SQL must select explicit columns or aggregates, not wildcard projections."
        )

    database = config["database"]
    inventory_by_table = table_lookup(inventory)
    allowed_tables = set(inventory_by_table)
    allowed_ctes = cte_aliases(safe_sql)
    blacklist = config["table_blacklist"]
    referenced_inventory = []

    for ref in referenced_tables(safe_sql):
        parts = ref.split(".")

        if len(parts) == 2:
            ref_db, ref_table = parts
            full_ref = f"{ref_db}.{ref_table}"

            if full_ref in ALLOWED_SYSTEM_TABLES:
                continue

            if ref_db == "system":
                raise ValueError(f"AI SQL references unsupported system table: {full_ref}")

            if ref_db != database:
                raise ValueError(f"AI SQL references database outside active profile: {ref_db}")

            table = ref_table
        else:
            table = parts[-1]

        if table in allowed_ctes:
            continue

        if table not in allowed_tables:
            raise ValueError(f"AI SQL references table outside allowed inventory: {table}")

        if is_table_blacklisted(table, blacklist):
            raise ValueError(f"AI SQL references blacklisted table: {table}")

        referenced_inventory.append(inventory_by_table[table])

    validate_measurement_window(safe_sql, config, referenced_inventory)

    raw_table = next(
        iter(config.get("mandatory_inventory_tables", ["source_events"])),
        "source_events",
    )
    if any(item.get("table") == raw_table for item in referenced_inventory):
        known_source_types = {
            str(item.get("source_type"))
            for item in config.get("source_flow_evidence", {}).get("raw_event_types", [])
            if item.get("source_type")
        }
        compared_types = set(re.findall(
            r"(?<![A-Za-z0-9_])type\s*=\s*'((?:''|[^'])*)'",
            safe_sql,
            flags=re.IGNORECASE,
        ))
        unknown_types = sorted(compared_types - known_source_types)
        if known_source_types and unknown_types:
            raise ValueError(
                "AI SQL filters source_events with unknown source type(s) "
                f"{unknown_types}; use an exact source_type from deterministic evidence"
            )

    mandatory_tables = config.get("mandatory_inventory_tables", [])
    dlq_tables = set(mandatory_tables[1:] or ["source_events_dlq"])
    source_flow_evidence = config.get("source_flow_evidence", {})
    populated_dlq_tables = {
        str(item.get("dlq_source_table"))
        for item in source_flow_evidence.get("dlq_summary", [])
        if item.get("dlq_source_table") and int(item.get("dlq_rows") or 0) > 0
    }
    queried_empty_dlqs = sorted(
        item.get("table")
        for item in referenced_inventory
        if source_flow_evidence.get("status") == "available"
        and item.get("table") in dlq_tables
        and item.get("table") not in populated_dlq_tables
    )
    if queried_empty_dlqs:
        raise ValueError(
            "AI SQL queries DLQ table(s) with zero rows in deterministic evidence: "
            f"{queried_empty_dlqs}"
        )
    legacy_dlq_tables = {
        str(item.get("dlq_source_table"))
        for item in source_flow_evidence.get("dlq_summary", [])
        if item.get("dlq_shape") == "legacy_event_envelope"
        and item.get("dlq_source_table")
    }
    references_legacy_dlq = any(
        item.get("table") in legacy_dlq_tables
        for item in referenced_inventory
    )
    uses_params_path = re.search(
        r"\bJSON[A-Za-z0-9_]*\s*\(\s*payload\s*,\s*'params'",
        safe_sql,
        flags=re.IGNORECASE,
    )
    if references_legacy_dlq and uses_params_path:
        if referenced_inventory and all(
            item.get("table") in legacy_dlq_tables
            for item in referenced_inventory
        ):
            safe_sql = normalize_legacy_dlq_parameter_paths(safe_sql)
            identifier_scan_sql = mask_nonempty_sql_string_literals(safe_sql)
        else:
            raise ValueError(
                "AI SQL uses ambiguous payload.params with a legacy DLQ; query "
                "the legacy DLQ separately with payload.event.parameters"
            )
    if (
        len(referenced_inventory) == 1
        and referenced_inventory[0].get("table") in dlq_tables
        and "type" not in set(referenced_inventory[0].get("columns", []))
        and re.search(
            r"(?<![A-Za-z0-9_])type(?![A-Za-z0-9_])",
            identifier_scan_sql,
            re.IGNORECASE,
        )
    ):
        safe_sql = normalize_dlq_type_identifier(safe_sql)
        identifier_scan_sql = mask_nonempty_sql_string_literals(safe_sql)

    raw_inventory = next(
        (
            item
            for item in referenced_inventory
            if item.get("table") == raw_table
        ),
        None,
    )
    if (
        len(referenced_inventory) == 1
        and raw_inventory is not None
        and "payload" in set(raw_inventory.get("columns", []))
        and not set(SESSION_ID_ALIASES).intersection(raw_inventory.get("columns", []))
    ):
        safe_sql = normalize_raw_payload_session_to_string(safe_sql)
        identifier_scan_sql = mask_nonempty_sql_string_literals(safe_sql)

    for dlq_inventory in (
        item
        for item in referenced_inventory
        if item.get("table") in dlq_tables
    ):
        if (
            "type" not in set(dlq_inventory.get("columns", []))
            and sql_references_column_on_table(
                safe_sql,
                str(dlq_inventory.get("table")),
                "type",
                inventory_by_table,
            )
        ):
            table = str(dlq_inventory.get("table"))
            raise ValueError(
                f"AI SQL references physical column 'type' on {table}, but the "
                "live inventory requires deriving the event name from payload"
            )

    physical_identifier_names = set(MAIN_IDENTIFIER_ALIASES + SESSION_ID_ALIASES)
    for identifier in physical_identifier_names:
        identifier_pattern = rf"(?<![A-Za-z0-9_])`?{re.escape(identifier)}`?(?![A-Za-z0-9_])"
        if not re.search(identifier_pattern, identifier_scan_sql, flags=re.IGNORECASE):
            continue

        if referenced_inventory and all(
            identifier not in set(item.get("columns", []))
            for item in referenced_inventory
        ):
            available = sorted({
                column
                for item in referenced_inventory
                for column in item.get("columns", [])
                if column in physical_identifier_names
            })
            raise ValueError(
                f"AI SQL references identifier column {identifier!r}, but the referenced "
                f"tables expose {available or 'no configured identifier aliases'}"
            )

        empty_string_comparison = rf"(?:{identifier_pattern}\s*(?:=|!=|<>)\s*''|''\s*(?:=|!=|<>)\s*{identifier_pattern})"
        if re.search(empty_string_comparison, identifier_scan_sql, flags=re.IGNORECASE):
            raise ValueError(
                f"AI SQL must not compare identifier {identifier!r} directly with an empty "
                "string; use IS NULL or normalize with toString/trim first"
            )

    return safe_sql


def records_preview(df: pd.DataFrame, max_rows: int) -> list[dict]:
    preview = df.head(max_rows).copy()

    for column in preview.columns:
        preview[column] = preview[column].apply(
            lambda value: None if pd.isna(value) else str(value)
        )

    return preview.to_dict("records")


def observation_brief(observations: list[dict]) -> str:
    if not observations:
        return "No previous observations."

    lines = []
    for obs in observations[-8:]:
        if obs["status"] != "ok":
            reason = (
                obs.get("rejection_reason")
                or obs.get("error")
                or obs.get("reason")
                or "unspecified model SQL failure"
            )
            lines.append(
                f"- {obs['id']}: {obs['status']}; not evidence; reason={reason}; "
                "retry only with corrected, smaller, read-only SQL if still useful."
            )
            continue

        lines.append(
            f"- {obs['id']}: rows_returned={obs['rows_returned']}, columns={','.join(obs['columns'])}, "
            f"sample={json.dumps(obs['preview'][:3], ensure_ascii=False)}"
        )

    return "\n".join(lines)


def build_planning_messages(config: dict, inventory: list[dict], observations: list[dict], iteration: int) -> list[dict]:
    profile = config["profile"]
    compact_evidence = compact_source_flow_evidence_for_prompt(
        config["source_flow_evidence"]
    )
    planner_inventory = relevant_inventory_for_planner(
        inventory,
        config,
        compact_evidence,
    )
    system = """
You are an autonomous read-only ClickHouse data-quality investigator.
Your job is to investigate unresolved questions from deterministic source-flow evidence.
Prioritize source_events -> parsed event table gaps, missing payload parameters, and
the configured DLQ tables (including source_events_dlq and partner_events_dlq). Do not
repeat a deterministic count unless a drilldown can distinguish
an upstream sender problem, parser/mapping problem, or DLQ payload-shape problem.
Return final answers only. No hidden reasoning, no prose outside JSON.
Every query must be read-only SELECT/WITH/DESCRIBE/EXPLAIN and return a small result set.
Prefer aggregate counts, percentages, grouped top-N, or explicit LIMIT.
Do not use SELECT *.
The validator requires the exact configured measurement predicate shown below;
never rewrite its timestamp, start, end, or interval arithmetic. Every SELECT
branch and scalar subquery that reads a timestamped table must include that
table's exact predicate; an outer query predicate does not cover a subquery.
Avoid broad UNION queries across many large tables.
Prefer one table per query. If UNION ALL is necessary, every branch must return
the same number of explicitly named columns in the same order and compatible types.
Use only physical column names listed for each table. Session identifiers vary by
table (for example session_id or session_uuid); never assume one alias exists.
If a raw source or DLQ inventory lists payload but no physical session identifier,
never reference session_id, session_uuid, or sessions_uuid as a column. Inspect the
configured JSON path instead. Do not substitute a similarly named raw_* table for
one of the configured raw transport tables.
Never compare identifier columns directly with an empty string because identifiers
may be UUID or another non-String type. Count missing identifiers with this shape,
substituting the physical column name:
countIf(nullIf(trimBoth(toString(session_id)), '') IS NULL).
Use exactly one countIf for that metric; never nest countIf inside countIf.
countIf is already an aggregate, so never wrap it in sum, count, or another
aggregate function.
For an aggregate-only SELECT, omit GROUP BY. Never use GROUP BY 1 when the first
selected expression is an aggregate.
For raw source/DLQ tables, payload-shape labels such as dlq_shape are derived
values, not physical columns unless the inventory explicitly lists them. Inspect
payload with isValidJSON, JSONHas, JSONExtractString, and JSONExtractRaw.
For a legacy DLQ missing-session metric, use one countIf whose condition checks
all configured aliases, for example:
countIf(
  nullIf(JSONExtractString(JSONExtractRaw(payload, 'event', 'parameters'), 'session_id'), '') IS NULL
  AND nullIf(JSONExtractString(JSONExtractRaw(payload, 'event', 'parameters'), 'session_uuid'), '') IS NULL
  AND nullIf(JSONExtractString(JSONExtractRaw(payload, 'event', 'parameters'), 'sessions_uuid'), '') IS NULL
) AS missing_session_ids.
For validationErrors, use the typed array expression
length(JSONExtract(payload, 'validationErrors', 'Array(String)')) > 0.
Never use arraySize or apply an array function directly to JSONExtractRaw.
When source_events exposes a physical type column, filter it directly instead of
inventing payload.event_type or filtering payload.event.name. Normalize namespaced
types with replaceRegexpOne(type, '^.*\\.', '') when needed. Raw event parameter
keys are inside the JSON object at payload.params, but payload itself is a physical
String column. Never write payload.params as SQL identifier access. Use
JSONHas(payload, 'params', 'session_id') for presence, or
JSONExtractString(JSONExtractRaw(payload, 'params'), 'session_id') for a value.
For a source_events missing-session metric when no physical session column exists, use:
countIf(nullIf(JSONExtractString(JSONExtractRaw(payload, 'params'), 'session_id'), '') IS NULL).
Never test JSONHas(payload, 'session_id') or another parameter at the payload root.
Use the exact source_type supplied in deterministic raw_event_types when filtering
source_events. Never invent a namespace, shorten the value, or run an event-specific
aggregate without an event-type predicate. A critical_event_flow with raw_rows=0
and no source_type is already deterministic evidence of sender absence, not a
query target. Do not query source_events for that event_table name. If no exact
source_type mapping exists in raw_event_types, skip that event-specific query.
For a legacy DLQ envelope, the event name is commonly
JSONExtractString(payload, 'event', 'name'); use it only when JSONHas(payload, 'event').
The name is namespaced (for example namespace.event_player_ping), so compare the exact
source_event_name from deterministic dlq_summary or normalize it with
replaceRegexpOne(JSONExtractString(payload, 'event', 'name'), '^.*\\.', '').
Legacy DLQ parameters are under payload.event.parameters, not payload.params.
The rejection reason is the Array(String) at payload.validationErrors, and the
rejection timestamp string is payload.rejectedAt. For the supplied player-ping
shape, "unknown event" is rejection evidence; legacy_event_envelope is only a
shape label and does not mean invalid JSON.
The configured DLQ inventories may have no physical type column. Never select,
filter, or GROUP BY a missing DLQ type column; derive an event name from payload.
The label legacy_event_envelope does not by itself mean the JSON is malformed.
Do not query a DLQ table that is absent from deterministic dlq_summary; zero DLQ
rows are already known and cannot establish payload quality. Every raw/DLQ
payload-quality aggregate must include count() AS total_rows. If total_rows is
zero, conclude only that the window has no rows, never that payload quality is good.
If deterministic evidence says a parsed table is missing and it is absent from the
inventory, do not query or join that missing table; investigate only existing raw/DLQ tables.
ClickHouse uses NOT for boolean negation. Never use unary !; it is only valid as
part of the != operator.
For ClickHouse, do not place aggregate functions in WHERE; use HAVING or a subquery.
Do not repeat a successful investigation or the same table/hypothesis in a later
iteration. Repeat a failed or rejected investigation only when the SQL is materially safer.
Rows from different users sharing one event_time are a same-second burst, not
duplicates. Call rows duplicates only when the grouping includes an identity key
such as event_key or the relevant user/session identifier.
Never mutate, delete, create, optimize, or alter raw data.
Respect table blacklist and event groups.
""".strip()

    user = f"""
Active profile:
{json.dumps(profile, ensure_ascii=False, separators=(',', ':'))}

Investigation window: {config['date_range']['description']}.
{date_range_prompt_instruction(config['date_range'])}
Use database: {config['database']}.
Never query blacklisted tables: {profile['table_blacklist']}.
Configured raw source and DLQ tables in scope:
{config.get('mandatory_inventory_tables', [])}.
For raw transport evidence, query only those configured tables. In particular,
do not substitute partner_events for partner_events_dlq.

Event group meaning:
- same_second_allowed: same timestamp bursts may be expected; look for duplicates, future dates, missing IDs, or extreme outliers instead.
- same_second_strict: same timestamp bursts are more suspicious and deserve checks.

Available table inventory:
{inventory_for_prompt(planner_inventory)}

Deterministic source-flow evidence (treat counts as facts and investigate their cause):
{json.dumps(compact_evidence, ensure_ascii=False, separators=(',', ':'))}

Previous observations:
{observation_brief(observations)}

Iteration {iteration}: propose up to {config['max_queries_per_iteration']} useful SQL investigations.

Return valid JSON only:
{{
  "investigations": [
    {{
      "id": "short_snake_case_id",
      "hypothesis": "what unknown problem this checks",
      "tables": ["table_name"],
      "sql": "SELECT ..."
    }}
  ]
}}
""".strip()

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def execute_investigation(investigation: dict, config: dict, inventory: list[dict]) -> dict:
    investigation_id = str(investigation.get("id") or "unnamed_investigation")
    sql = str(investigation.get("sql") or "").strip()

    base = {
        "id": investigation_id,
        "hypothesis": investigation.get("hypothesis"),
        "tables": investigation.get("tables", []),
        "sql": sql,
    }

    try:
        safe_sql = validate_ai_sql(sql, config, inventory)
    except MediumPrioritySqlProblem as e:
        return {
            **base,
            "status": "problem",
            "priority": "medium",
            "problem_code": e.code,
            "invalid_value": e.invalid_value,
            "reason": str(e),
        }
    except Exception as e:
        return {
            **base,
            "status": "rejected",
            "rejection_reason": str(e),
        }

    try:
        df = query_df(safe_sql)
    except Exception as e:
        return {
            **base,
            "status": "error",
            "error": str(e),
        }

    columns = [str(column) for column in df.columns]
    raw_transport_tables = set(config.get("mandatory_inventory_tables", []))
    queries_raw_transport = bool(
        referenced_table_names(safe_sql) & raw_transport_tables
    )
    if queries_raw_transport and all_zero_scalar_metrics(df):
        normalized_columns = {column.casefold() for column in columns}
        if normalized_columns & {"total_rows", "row_count", "rows"}:
            return {
                **base,
                "sql": safe_sql,
                "status": "no_data",
                "reason": (
                    "The configured window contains no source rows; payload "
                    "quality was not evaluated."
                ),
                "rows_returned": int(len(df)),
                "columns": columns,
                "preview": records_preview(df, config["result_preview_rows"]),
            }
        return {
            **base,
            "sql": safe_sql,
            "status": "inconclusive",
            "reason": (
                "All raw/DLQ aggregate metrics are zero without an explicit "
                "total_rows count, so empty input cannot be distinguished from "
                "the measured condition."
            ),
            "rows_returned": int(len(df)),
            "columns": columns,
            "preview": records_preview(df, config["result_preview_rows"]),
        }

    return {
        **base,
        "sql": safe_sql,
        "status": "ok",
        "rows_returned": int(len(df)),
        "columns": columns,
        "preview": records_preview(df, config["result_preview_rows"]),
    }


def failed_observation_notes(observations: list[dict]) -> list[dict]:
    notes = []
    for obs in observations:
        if obs.get("status") == "ok":
            continue
        notes.append(
            {
                "id": str(obs.get("id") or "unnamed"),
                "status": str(obs.get("status") or "unknown"),
                "tables": obs.get("tables", []),
            }
        )
    return notes


def build_final_messages(config: dict, inventory: list[dict], observations: list[dict]) -> list[dict]:
    successful_observations = [obs for obs in observations if obs.get("status") == "ok"]

    system = """
You are a senior data-quality investigator.
Use only successful executed observations as data-quality evidence.
Deterministic source-flow evidence is also confirmed evidence and must be summarized first.
Missing parsed events are critical only when the same measurement window also has zero
matching source_events rows. When matching source_events rows exist but parsed rows are zero,
classify the parsing/delivery gap as low. A target parameter missing while it is present
in source_events is low; a parameter missing in both target and source_events is critical.
DLQ rows remain critical failure-path evidence
even when their payload does not expose an explicit error message.
Failed and rejected attempts are intentionally not provided. Do not infer or mention
investigations that are absent from the successful-observation evidence.
Separate confirmed findings from hypotheses.
Do not invent causes. If you mention possible metric impact or pipeline behavior, label it as hypothesis.
Keep all recommendations read-only.
Return a concise final report.
""".strip()

    user = f"""
Active profile:
{json.dumps(config['profile'], ensure_ascii=False)}

Event groups were provided:
- same_second_allowed: {config['profile']['same_second_allowed_tables']}
- same_second_strict: {config['profile']['same_second_strict_tables']}
Do not say event group rules were not provided.
Never describe a same_second_strict table as allowed or expected unless an explicit
event_context exception supports that exact finding.

Successful AI investigations (evidence only):
{json.dumps(successful_observations, ensure_ascii=False, indent=2)}

Deterministic source_events -> parsed tables and configured DLQ evidence:
{json.dumps(config['source_flow_evidence'], ensure_ascii=False, indent=2)}

Output format:
1. Critical missing-event, parsing, and DLQ findings
2. Low raw-to-parsed delivery gaps
3. Parameter origin findings (source payload vs parser/table)
4. Other AI-led findings supported by successful observations
5. Explicitly expected only when configured event_context supports it
""".strip()

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def execution_note_text(observations: list[dict]) -> str:
    notes = failed_observation_notes(observations)
    if not notes:
        return ""
    counts: dict[str, int] = {}
    for note in notes:
        status = note["status"]
        counts[status] = counts.get(status, 0) + 1
    summary = ", ".join(
        f"{count} {status}" for status, count in sorted(counts.items())
    )
    attempt_word = "attempt" if len(notes) == 1 else "attempts"
    verb = "was" if len(notes) == 1 else "were"
    pronoun = "it" if len(notes) == 1 else "they"
    evidence_verb = "is" if len(notes) == 1 else "are"
    return (
        "Execution notes\n"
        f"- {summary} AI {attempt_word} {verb} omitted because "
        f"{pronoun} {evidence_verb} not evidence."
    )


def observation_status_counts(observations: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for observation in observations:
        status = str(observation.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def render_investigation_report(config: dict, observations: list[dict]) -> str:
    """Render executed evidence without asking a model to reinterpret it."""
    counts = observation_status_counts(observations)
    status_summary = (
        ", ".join(f"{status}={count}" for status, count in counts.items())
        if counts
        else "none"
    )
    lines = [
        "# AI investigation execution summary",
        "",
        f"Measurement window: {config['date_range']['description']}",
        f"Observation statuses: {status_summary}",
        "",
        "Only observations marked `ok` are evidence. AI query problems are reported "
        "separately and are not database findings. Deterministic event-flow and DLQ "
        "artifacts remain authoritative for severity.",
    ]

    successful = [item for item in observations if item.get("status") == "ok"]
    if successful:
        lines.extend(["", "## Successful observations"])
        for item in successful:
            preview = json.dumps(item.get("preview", [])[:3], ensure_ascii=False)
            lines.append(
                f"- `{item.get('id', 'unnamed')}`: tables={item.get('tables', [])}; "
                f"rows_returned={item.get('rows_returned', 0)}; preview={preview}"
            )
    else:
        lines.extend(["", "No successful AI observations were produced."])

    problems = [item for item in observations if item.get("status") == "problem"]
    if problems:
        lines.extend(["", "## AI query problems"])
        for item in problems:
            priority = str(item.get("priority") or "medium").upper()
            code = item.get("problem_code") or "query_problem"
            reason = item.get("reason") or "query was not executed"
            lines.append(
                f"- {priority} `{item.get('id', 'unnamed')}`: "
                f"code={code}; reason={reason}"
            )

    excluded = [
        item
        for item in observations
        if item.get("status") not in {"ok", "problem"}
    ]
    if excluded:
        lines.extend(["", "## Excluded from evidence"])
        for item in excluded:
            reason = (
                item.get("rejection_reason")
                or item.get("error")
                or item.get("reason")
                or "not evidence"
            )
            lines.append(
                f"- `{item.get('id', 'unnamed')}`: "
                f"status={item.get('status')}; reason={reason}"
            )

    return "\n".join(lines)


def observations_are_degraded(observations: list[dict]) -> bool:
    return any(
        item.get("status") in {"problem", "rejected", "error", "inconclusive"}
        for item in observations
    )


def sanitize_readonly_report(text: str) -> str:
    text = repair_text(text)
    replacements = {
        "implementing deduplication logic": "adding read-only BI-level deduplication checks",
        "implement deduplication logic": "add read-only BI-level deduplication checks",
        "Implement deduplication logic": "Add read-only BI-level deduplication checks",
        "ensuring that the source system enforces uniqueness": "validating whether the source system enforces uniqueness",
        "Review the ETL/ELT pipeline": "Run read-only diagnostics against ETL/ELT output",
        "review the ETL/ELT pipeline": "run read-only diagnostics against ETL/ELT output",
        "root cause": "pattern",
        "Root Cause": "Pattern",
        "mutate raw data": "monitor raw data",
        "delete records": "flag records",
        "quarantine records": "flag records",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return text


def main():
    started_at = datetime.now()
    timestamp = os.getenv("QUALITY_RUN_ID") or started_at.strftime("%Y%m%d_%H%M%S")
    load_dotenv()
    config = get_investigation_config()
    llm_config = get_llm_config("AI_AGENT")

    print(f"Database investigation started at: {started_at}")
    print(f"Profile: {config['profile']['profile_name']}")
    print(f"Database: {config['database']}")
    print(f"LLM model: {llm_config['model']}")
    print(f"LLM max tokens: {llm_config['max_tokens']}")
    print(f"Date range: {config['date_range']['description']}")
    print(f"Prefixes: {', '.join(config['table_name_prefixes']) or '(all)'}")
    print(f"Blacklist patterns: {config['table_blacklist'] or 'none'}")

    inventory = discover_inventory(config)
    inventory_tables = filter_blacklisted_tables(
        [item["table"] for item in inventory],
        get_table_blacklist(config["rules"]),
    )

    print(f"Inventory tables available to AI: {len(inventory_tables)}")

    observations = []
    plans = []
    successful_investigation_ids: set[str] = set()
    executed_sql_fingerprints: set[str] = set()

    for iteration in range(1, config["max_iterations"] + 1):
        print(f"\nAI planning iteration {iteration}...")

        messages = build_planning_messages(config, inventory, observations, iteration)

        try:
            plan_text = ask_model(
                messages,
                max_tokens=config["planning_max_tokens"],
                temperature=0.0,
                llm_config=llm_config,
            )
            plan = extract_json_object(plan_text)
        except Exception as e:
            observations.append({
                "id": f"planning_iteration_{iteration}",
                "status": "error",
                "error": f"AI planning failed: {e}",
            })
            print(f"AI planning failed: {e}")
            break

        investigations = plan.get("investigations", [])
        if not investigations:
            print("AI returned no investigations.")
            break

        investigations = investigations[:config["max_queries_per_iteration"]]
        plans.append({
            "iteration": iteration,
            "raw_plan": plan,
        })

        for investigation in investigations:
            print(f"Executing AI investigation: {investigation.get('id')}")
            duplicate_reason = duplicate_investigation_reason(
                investigation,
                successful_investigation_ids,
                executed_sql_fingerprints,
            )
            if duplicate_reason:
                observation = {
                    "id": str(investigation.get("id") or "unnamed_investigation"),
                    "hypothesis": investigation.get("hypothesis"),
                    "tables": investigation.get("tables", []),
                    "sql": str(investigation.get("sql") or "").strip(),
                    "status": "skipped_duplicate",
                    "reason": duplicate_reason,
                }
                observations.append(observation)
                print(" - skipped_duplicate")
                continue

            observation = execute_investigation(investigation, config, inventory)
            observations.append(observation)
            sql_fingerprint = normalized_sql_fragment(investigation.get("sql") or "")
            if sql_fingerprint:
                executed_sql_fingerprints.add(sql_fingerprint)
            if observation.get("status") == "ok":
                successful_investigation_ids.add(
                    str(observation.get("id") or "unnamed_investigation").casefold()
                )
            print(f" - {observation['status']}")

    print("\nWriting deterministic investigation summary...")
    final_report = render_investigation_report(config, observations)

    final_report = sanitize_readonly_report(final_report)

    finished_at = datetime.now()

    artifact = {
        "agent": "database_investigator",
        "started_at": str(started_at),
        "finished_at": str(finished_at),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "profile": config["profile"],
        "date_range": config["date_range"],
        "duration_hours": config["duration_hours"],
        "inventory_tables": inventory,
        "plans": plans,
        "observation_summary": observation_status_counts(observations),
        "observations": observations,
        "final_report": final_report,
    }

    timestamped_json = REPORT_DIR / f"database_investigation_{timestamp}.json"
    timestamped_txt = REPORT_DIR / f"database_investigation_{timestamp}.txt"

    artifact_text = json.dumps(artifact, indent=2, ensure_ascii=False)
    STABLE_OUTPUT_JSON.write_text(artifact_text, encoding="utf-8")
    timestamped_json.write_text(artifact_text, encoding="utf-8")
    STABLE_OUTPUT_TXT.write_text(final_report, encoding="utf-8")
    timestamped_txt.write_text(final_report, encoding="utf-8")

    print("\n=== Database investigation report ===")
    print(final_report)
    print(f"\nSaved stable JSON: {STABLE_OUTPUT_JSON}")
    print(f"Saved timestamped JSON: {timestamped_json}")
    print(f"Saved stable report: {STABLE_OUTPUT_TXT}")
    print(f"Saved timestamped report: {timestamped_txt}")

    if observations_are_degraded(observations) or not any(
        observation.get("status") == "ok" for observation in observations
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
