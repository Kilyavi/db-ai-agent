import fnmatch
import json
import os
import re
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_DIR = Path(os.getenv("AGENT_CONFIG_DIR", PROJECT_ROOT / "config"))
SYSTEM_CONFIG_PATH = Path(os.getenv("SYSTEM_AGENT_CONFIG_PATH", CONFIG_DIR / "system_agent_config.json"))
PERSONAL_CONFIG_PATH = Path(os.getenv("PERSONAL_CONFIG_PATH", CONFIG_DIR / "personal_config.json"))
PERSONAL_AGENT_CONFIG_PATH = Path(os.getenv("PERSONAL_AGENT_CONFIG_PATH", CONFIG_DIR / "personal_agent_config.json"))
DEFAULT_PROFILE_NAME = "clickhouse.analytics"
DEFAULT_DATABASE = "analytics"
DEFAULT_TABLE_PREFIXES = ["event_"]
DEFAULT_MAIN_IDENTIFIER = "user_id"
DEFAULT_LLM_BASE_URL = "http://localhost:1234/v1"
DEFAULT_LLM_MODEL = "active"
DEFAULT_LLM_MAX_TOKENS = 12000
AUTO_MODEL_VALUES = {"", "auto", "active", "loaded", "lmstudio-active", "local-model-name"}
DEFAULT_IDENTIFIER_ALIASES = {
    "adid": ["adid"],
    "user_id": ["user_id"],
    "session_id": ["session_id", "session_uuid", "sessions_uuid"],
    "event_key": ["event_key"],
}
MEASUREMENT_TIME_COLUMN_CANDIDATES = (
    "event_date",
    "created_at",
    "date",
    "startdate",
    "loaded_at",
)


def load_json_file(path: Path) -> dict:
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)

    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value

    return merged


def load_shared_agent_config() -> dict:
    rules = {}

    for path in [
        SYSTEM_CONFIG_PATH,
        PERSONAL_AGENT_CONFIG_PATH,
    ]:
        rules = deep_merge(rules, load_json_file(path))

    return rules


def load_rules() -> dict:
    return load_shared_agent_config()


def load_personal_config() -> dict:
    return load_json_file(PERSONAL_CONFIG_PATH)


def as_list(value: Any, default: list[str] | None = None) -> list[str] | None:
    if value is None:
        return default

    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return default


def as_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def get_positive_int(candidates: list[Any], field_name: str, default: int) -> int:
    for candidate in candidates:
        text = as_optional_text(candidate)
        if text is None:
            continue
        try:
            number = int(text)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be a positive integer, got {text!r}") from exc
        if number <= 0:
            raise ValueError(f"{field_name} must be a positive integer, got {text!r}")
        return number
    return default


def is_auto_model(value: Any) -> bool:
    text = as_optional_text(value)
    return text is None or text.lower() in AUTO_MODEL_VALUES


def request_lmstudio_json(
    url: str,
    api_key: str | None = None,
    timeout: float = 5.0,
) -> dict | None:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    request = urllib.request.Request(url=url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (
        OSError,
        UnicodeDecodeError,
        urllib.error.HTTPError,
        urllib.error.URLError,
        json.JSONDecodeError,
    ):
        return None

    if isinstance(payload, dict):
        return payload
    return None


def get_lmstudio_native_models_url(base_url: str) -> str:
    clean_url = base_url.rstrip("/")
    if clean_url.endswith("/v1"):
        clean_url = clean_url[:-3]
    return f"{clean_url}/api/v0/models"


def collect_lmstudio_model_ids(data: Any, loaded_only: bool = False) -> list[str]:
    if not isinstance(data, list):
        return []

    models: list[str] = []
    seen: set[str] = set()
    for item in data:
        if isinstance(item, dict):
            if loaded_only and item.get("state") != "loaded":
                continue
            model_type = as_optional_text(item.get("type"))
            if model_type and model_type not in {"llm", "vlm"}:
                continue
            model_id = as_optional_text(item.get("id") or item.get("name"))
        else:
            model_id = as_optional_text(item)
        if model_id and model_id not in seen:
            models.append(model_id)
            seen.add(model_id)
    return models


def get_loaded_lmstudio_models(
    base_url: str,
    api_key: str | None = None,
    timeout: float = 5.0,
) -> list[str]:
    native_payload = request_lmstudio_json(
        get_lmstudio_native_models_url(base_url),
        api_key,
        timeout,
    )
    if native_payload is not None:
        return collect_lmstudio_model_ids(native_payload.get("data"), loaded_only=True)

    openai_payload = request_lmstudio_json(
        f"{base_url.rstrip('/')}/models",
        api_key,
        timeout,
    )
    if openai_payload is None:
        return []
    return collect_lmstudio_model_ids(openai_payload.get("data"))


def choose_lmstudio_model(configured_model: Any, loaded_models: list[str] | None) -> str:
    configured = as_optional_text(configured_model)
    available = [model for model in (loaded_models or []) if as_optional_text(model)]

    if available:
        oss_models = [model for model in available if "oss" in model.lower()]
        if oss_models:
            return oss_models[0]
        if configured and not is_auto_model(configured) and configured in available:
            return configured
        return available[0]

    if configured and not is_auto_model(configured):
        return configured
    return DEFAULT_LLM_MODEL


def get_active_profile(rules: dict | None = None) -> tuple[str, dict]:
    rules = rules or load_rules()
    profiles = rules.get("database_profiles", {})
    profile_name = (
        os.getenv("DQ_PROFILE")
        or os.getenv("DB_AGENT_PROFILE")
        or os.getenv("QUALITY_DB_PROFILE")
        or rules.get("active_database_profile")
        or DEFAULT_PROFILE_NAME
    )

    profile = profiles.get(profile_name, {}).copy()

    if not profile:
        profile = {
            "kind": "clickhouse",
            "database": rules.get("database") or DEFAULT_DATABASE,
            "table_name_prefixes": rules.get("table_name_prefixes") or DEFAULT_TABLE_PREFIXES,
        }

    return profile_name, profile


def get_database(rules: dict | None = None) -> str:
    rules = rules or load_rules()
    _, profile = get_active_profile(rules)

    return (
        os.getenv("DQ_DATABASE")
        or os.getenv("DB_AGENT_DATABASE")
        or profile.get("database")
        or os.getenv("CH_DATABASE")
        or rules.get("database")
        or DEFAULT_DATABASE
    )


def get_main_identifier(rules: dict | None = None) -> str:
    """Return the physical main-identifier column for the active profile."""
    rules = rules or load_rules()
    _, profile = get_active_profile(rules)
    identifier = str(
        os.getenv("DQ_MAIN_IDENTIFIER")
        or os.getenv("DB_AGENT_MAIN_IDENTIFIER")
        or os.getenv("QUALITY_MAIN_IDENTIFIER")
        or profile.get("main_identifier")
        or rules.get("main_identifier")
        or DEFAULT_MAIN_IDENTIFIER
    ).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier):
        raise ValueError(f"Invalid main_identifier: {identifier!r}")
    return identifier


def get_date_range_days(
    rules: dict | None = None,
    env_var: str | None = None,
    days_candidates: list[Any] | None = None,
) -> int:
    rules = rules or load_rules()
    date_range = rules.get("date_range", {})
    date_range_config = date_range if isinstance(date_range, dict) else {}
    scalar_days = None
    if date_range is not None and not isinstance(date_range, dict):
        scalar_range = parse_date_range_scalar(date_range)
        if (
            scalar_range["mode"] == "rolling"
            and scalar_range["interval_unit"] == "day"
        ):
            scalar_days = scalar_range["days_back"]

    return get_positive_int(
        [
            os.getenv(env_var) if env_var else None,
            os.getenv("QUALITY_DAYS_BACK"),
            scalar_days,
            date_range_config.get("days_back"),
            date_range_config.get("default_days_back"),
            *(days_candidates or []),
            rules.get("days_back"),
        ],
        "date_range.days_back",
        7,
    )


def parse_config_date(value: Any, field_name: str) -> date | None:
    text = as_optional_text(value)
    if text is None:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DD, got {text!r}") from exc


def rolling_date_range(value: int, unit: str = "day") -> dict:
    amount = int(value)
    normalized_unit = str(unit).strip().lower().rstrip("s")
    if amount <= 0:
        raise ValueError(f"date_range amount must be positive, got {value!r}")
    if normalized_unit not in {"day", "hour"}:
        raise ValueError(f"Unsupported rolling date_range unit: {unit!r}")

    display_unit = normalized_unit if amount == 1 else f"{normalized_unit}s"
    duration_seconds = amount * (86400 if normalized_unit == "day" else 3600)
    return {
        "mode": "rolling",
        "interval_value": amount,
        "interval_unit": normalized_unit,
        "days_back": amount if normalized_unit == "day" else None,
        "hours_back": amount if normalized_unit == "hour" else amount * 24,
        "duration_seconds": duration_seconds,
        "start_date": None,
        "end_date": None,
        "end_date_exclusive": None,
        "description": f"last {amount} {display_unit}",
    }


def fixed_date_range(start_date: date, end_date: date) -> dict:
    if start_date > end_date:
        raise ValueError("date_range.start_date must be on or before date_range.end_date")
    end_exclusive = end_date + timedelta(days=1)
    days = (end_date - start_date).days + 1
    return {
        "mode": "fixed",
        "interval_value": days,
        "interval_unit": "day",
        "days_back": days,
        "hours_back": days * 24,
        "duration_seconds": days * 86400,
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "end_date_exclusive": end_exclusive.isoformat(),
        "description": f"from {start_date.isoformat()} to {end_date.isoformat()}",
    }


def parse_date_range_scalar(value: Any) -> dict:
    examples = "'1 hour', '7 days', or '2026-02-01 to 2026-05-05'"

    if isinstance(value, bool):
        raise ValueError(f"date_range must look like {examples}")

    if isinstance(value, int):
        if value <= 0:
            raise ValueError(f"date_range days must be positive, got {value!r}")
        return rolling_date_range(value)

    text = as_optional_text(value)
    if text is None:
        raise ValueError(f"date_range must look like {examples}")

    rolling_match = re.fullmatch(
        r"(?:last\s+)?(\d+)\s*(h|hours?|d|days?)?",
        text,
        flags=re.IGNORECASE,
    )
    if rolling_match:
        amount = int(rolling_match.group(1))
        raw_unit = (rolling_match.group(2) or "day").lower()
        unit = "hour" if raw_unit.startswith("h") else "day"
        if amount <= 0:
            raise ValueError(f"date_range amount must be positive, got {text!r}")
        return rolling_date_range(amount, unit)

    fixed_match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2})(?:\s+to\s+|\s*\.\.\s*)(\d{4}-\d{2}-\d{2})",
        text,
        flags=re.IGNORECASE,
    )
    if fixed_match:
        start_date = parse_config_date(fixed_match.group(1), "date_range.start_date")
        end_date = parse_config_date(fixed_match.group(2), "date_range.end_date")
        return fixed_date_range(start_date, end_date)

    raise ValueError(f"date_range must look like {examples}, got {text!r}")


def get_date_range(
    rules: dict | None = None,
    env_prefix: str | None = None,
    days_env_var: str | None = None,
    days_candidates: list[Any] | None = None,
) -> dict:
    rules = rules or load_rules()
    date_range = rules.get("date_range", {})
    date_range_config = date_range if isinstance(date_range, dict) else {}
    days_env_var = days_env_var or "QUALITY_DAYS_BACK"

    prefix_start = None
    prefix_end = None
    if env_prefix:
        prefix_start = (
            as_optional_text(os.getenv(f"{env_prefix}_START_DATE"))
            or as_optional_text(os.getenv(f"{env_prefix}_FROM_DATE"))
        )
        prefix_end = (
            as_optional_text(os.getenv(f"{env_prefix}_END_DATE"))
            or as_optional_text(os.getenv(f"{env_prefix}_TO_DATE"))
        )

    if prefix_start is not None or prefix_end is not None:
        start_candidate = prefix_start
        end_candidate = prefix_end
    else:
        start_candidate = (
            as_optional_text(os.getenv("QUALITY_START_DATE"))
            or as_optional_text(os.getenv("QUALITY_FROM_DATE"))
        )
        end_candidate = (
            as_optional_text(os.getenv("QUALITY_END_DATE"))
            or as_optional_text(os.getenv("QUALITY_TO_DATE"))
        )

    start_date = parse_config_date(
        start_candidate
        or date_range_config.get("start_date")
        or date_range_config.get("from_date")
        or date_range_config.get("from"),
        "date_range.start_date",
    )
    end_date = parse_config_date(
        end_candidate
        or date_range_config.get("end_date")
        or date_range_config.get("to_date")
        or date_range_config.get("to"),
        "date_range.end_date",
    )

    if bool(start_date) != bool(end_date):
        raise ValueError(
            "Both date_range.start_date/date_range.from_date and "
            "date_range.end_date/date_range.to_date must be provided for a fixed date range"
        )
    if start_date and end_date:
        return fixed_date_range(start_date, end_date)

    scalar_range = None
    if not isinstance(date_range, dict) and date_range is not None:
        scalar_range = parse_date_range_scalar(date_range)
        if scalar_range["mode"] == "fixed":
            return scalar_range

    days_override = (
        as_optional_text(os.getenv(days_env_var))
        or (
            as_optional_text(os.getenv("QUALITY_DAYS_BACK"))
            if days_env_var != "QUALITY_DAYS_BACK"
            else None
        )
    )
    if days_override is not None:
        return rolling_date_range(
            get_positive_int([days_override], "date_range.days_back", 7)
        )

    if scalar_range is not None:
        return scalar_range

    hours_back = date_range_config.get("hours_back")
    if hours_back is not None:
        return rolling_date_range(
            get_positive_int([hours_back], "date_range.hours_back", 1),
            "hour",
        )

    return rolling_date_range(get_date_range_days(rules, days_env_var, days_candidates))


def get_lookback_range(
    rules: dict | None = None,
    section: dict | None = None,
    default: str = "30 days",
) -> dict:
    """Return the rolling historical baseline independently of date_range."""
    rules = rules or load_rules()
    section = section or {}
    raw = (
        section.get("lookback")
        or section.get("date_range")  # Former parameter-quality override.
        or rules.get("lookback")
        or default
    )

    if isinstance(raw, dict):
        if raw.get("hours_back") is not None:
            result = rolling_date_range(
                get_positive_int(
                    [raw.get("hours_back")],
                    "lookback.hours_back",
                    1,
                ),
                "hour",
            )
        else:
            result = rolling_date_range(
                get_positive_int(
                    [raw.get("days_back"), raw.get("default_days_back")],
                    "lookback.days_back",
                    30,
                )
            )
    else:
        result = parse_date_range_scalar(raw)

    if result["mode"] != "rolling":
        raise ValueError("lookback must be a rolling hour/day range, not a fixed range")
    return result


def date_range_sql_interval(date_range: dict) -> str:
    if date_range.get("mode") != "rolling":
        raise ValueError("SQL interval is available only for rolling date ranges")
    value = int(date_range.get("interval_value") or date_range.get("days_back") or 1)
    unit = str(date_range.get("interval_unit") or "day").upper()
    if unit not in {"DAY", "HOUR"}:
        raise ValueError(f"Unsupported date range SQL unit: {unit!r}")
    return f"INTERVAL {value} {unit}"


def sql_string_literal(value: Any) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def rolling_reference_time_sql() -> str:
    raw = str(os.getenv("QUALITY_REFERENCE_TIME") or "").strip()
    if not raw:
        return "now()"
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            "QUALITY_REFERENCE_TIME must be an ISO timestamp"
        ) from exc
    if parsed.tzinfo is None:
        return (
            f"toDateTime("
            f"{sql_string_literal(parsed.strftime('%Y-%m-%d %H:%M:%S'))})"
        )
    return (
        "parseDateTime64BestEffort("
        f"{sql_string_literal(parsed.isoformat(timespec='seconds'))})"
    )


def date_range_sql_condition(date_range: dict, column_name: str) -> str:
    if date_range.get("mode") == "fixed":
        start = f"{date_range['start_date']} 00:00:00"
        end = f"{date_range['end_date_exclusive']} 00:00:00"
        return (
            f"{column_name} >= toDateTime({sql_string_literal(start)}) "
            f"AND {column_name} < toDateTime({sql_string_literal(end)})"
        )
    reference = rolling_reference_time_sql()
    return (
        f"{column_name} >= {reference} - {date_range_sql_interval(date_range)} "
        f"AND {column_name} < {reference}"
    )


def uses_daily_aligned_lookback(date_range: dict, lookback: dict) -> bool:
    """Return whether an hourly measurement should use matching prior-day slots."""
    return (
        date_range.get("mode") == "rolling"
        and str(date_range.get("interval_unit") or "").lower() == "hour"
        and 0 < int(date_range.get("duration_seconds") or 0) < 86400
        and str(lookback.get("interval_unit") or "").lower() == "day"
    )


def daily_aligned_time_slot_sql_condition(
    date_range: dict,
    column_name: str,
) -> str:
    """Match the same rolling time-of-day slot as the current hourly window."""
    duration_seconds = int(date_range["duration_seconds"])
    value_second = (
        f"dateDiff('second', toStartOfDay({column_name}), {column_name})"
    )
    reference = rolling_reference_time_sql()
    now_second = f"dateDiff('second', toStartOfDay({reference}), {reference})"
    start_second = (
        f"modulo({now_second} - {duration_seconds} + 86400, 86400)"
    )
    return (
        f"if({start_second} < {now_second}, "
        f"({value_second} >= {start_second} AND {value_second} < {now_second}), "
        f"({value_second} >= {start_second} OR {value_second} < {now_second}))"
    )


def historical_lookback_sql_condition(
    date_range: dict,
    lookback: dict,
    column_name: str,
) -> str:
    """Build the preceding historical window used for baseline comparisons."""
    if date_range.get("mode") == "fixed":
        start = f"{date_range['start_date']} 00:00:00"
        return (
            f"{column_name} >= toDateTime({sql_string_literal(start)}) "
            f"- {date_range_sql_interval(lookback)} "
            f"AND {column_name} < toDateTime({sql_string_literal(start)})"
        )

    reference = rolling_reference_time_sql()
    condition = (
        f"{column_name} >= {reference} - {date_range_sql_interval(date_range)} "
        f"- {date_range_sql_interval(lookback)} "
        f"AND {column_name} < {reference} - {date_range_sql_interval(date_range)}"
    )
    if uses_daily_aligned_lookback(date_range, lookback):
        condition += (
            " AND "
            + daily_aligned_time_slot_sql_condition(date_range, column_name)
        )
    return condition


def lookback_comparison_window_count(date_range: dict, lookback: dict) -> float:
    """Return how many measurement-sized windows contribute to the baseline."""
    if uses_daily_aligned_lookback(date_range, lookback):
        return float(int(lookback["interval_value"]))
    measurement_seconds = float(date_range["duration_seconds"])
    if measurement_seconds <= 0:
        raise ValueError("date_range duration must be positive")
    return float(lookback["duration_seconds"]) / measurement_seconds


def get_clickhouse_connection_config() -> dict:
    personal = load_personal_config()
    clickhouse = personal.get("clickhouse", {})

    return {
        "host": os.getenv("CH_HOST") or clickhouse.get("host"),
        "port": int(os.getenv("CH_PORT") or clickhouse.get("port") or 8123),
        "user": os.getenv("CH_USER") or clickhouse.get("user"),
        "password": os.getenv("CH_PASSWORD") or clickhouse.get("password"),
        "secure": os.getenv("CH_SECURE") if os.getenv("CH_SECURE") is not None else clickhouse.get("secure", False),
    }


def get_llm_config(prefix: str = "AI_AGENT") -> dict:
    shared = load_shared_agent_config()
    personal = load_personal_config()
    llm = deep_merge(shared.get("llm", {}), personal.get("llm", {}))
    base_url = (
        os.getenv(f"{prefix}_BASE_URL")
        or os.getenv("LMSTUDIO_BASE_URL")
        or llm.get("base_url")
        or DEFAULT_LLM_BASE_URL
    )
    configured_model = (
        os.getenv(f"{prefix}_MODEL") or os.getenv("LMSTUDIO_MODEL") or llm.get("model")
    )
    api_key = (
        os.getenv(f"{prefix}_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or llm.get("api_key")
    )
    max_tokens = get_positive_int(
        [
            os.getenv(f"{prefix}_MAX_TOKENS"),
            os.getenv("LMSTUDIO_MAX_TOKENS"),
            llm.get("max_tokens"),
        ],
        "llm.max_tokens",
        DEFAULT_LLM_MAX_TOKENS,
    )
    loaded_models = get_loaded_lmstudio_models(base_url, api_key)

    return {
        "base_url": base_url,
        "model": choose_lmstudio_model(configured_model, loaded_models),
        "configured_model": configured_model,
        "loaded_models": loaded_models,
        "api_key": api_key,
        "max_tokens": max_tokens,
    }


def get_table_prefixes(rules: dict | None = None) -> list[str]:
    rules = rules or load_rules()
    _, profile = get_active_profile(rules)

    env_prefixes = as_list(os.getenv("DQ_TABLE_PREFIXES"))
    if env_prefixes is not None:
        return env_prefixes

    db_scan_env_prefixes = as_list(os.getenv("DB_SCAN_TABLE_PREFIXES"))
    if db_scan_env_prefixes is not None:
        return db_scan_env_prefixes

    if "table_name_prefixes" in profile:
        profile_prefixes = as_list(profile.get("table_name_prefixes"))
        if profile_prefixes is not None:
            return profile_prefixes

    db_scan_rules = rules.get("db_problem_scan", {})
    if "table_name_prefixes" in db_scan_rules:
        db_scan_prefixes = as_list(db_scan_rules.get("table_name_prefixes"))
        if db_scan_prefixes is not None:
            return db_scan_prefixes

    if "table_name_prefixes" in rules:
        rule_prefixes = as_list(rules.get("table_name_prefixes"))
        if rule_prefixes is not None:
            return rule_prefixes

    return DEFAULT_TABLE_PREFIXES


def get_table_blacklist(rules: dict | None = None) -> list[str]:
    rules = rules or load_rules()
    _, profile = get_active_profile(rules)

    patterns = []
    for value in [
        rules.get("table_blacklist"),
        rules.get("event_blacklist"),
        profile.get("table_blacklist"),
        profile.get("event_blacklist"),
        rules.get("db_problem_scan", {}).get("table_blacklist"),
    ]:
        patterns.extend(as_list(value, []) or [])

    patterns.extend(as_list(os.getenv("DQ_TABLE_BLACKLIST"), []) or [])
    patterns.extend(as_list(os.getenv("DB_TABLE_BLACKLIST"), []) or [])

    deduped = []
    seen = set()
    for pattern in patterns:
        if pattern in seen:
            continue
        seen.add(pattern)
        deduped.append(pattern)

    return deduped


def is_table_blacklisted(table: str, patterns: list[str] | None = None) -> bool:
    patterns = patterns if patterns is not None else get_table_blacklist()
    normalized_table = str(table).casefold()

    for pattern in patterns:
        if fnmatch.fnmatchcase(normalized_table, str(pattern).casefold()):
            return True

    return False


def filter_blacklisted_tables(tables: list[str], patterns: list[str] | None = None) -> list[str]:
    patterns = patterns if patterns is not None else get_table_blacklist()
    return [table for table in tables if not is_table_blacklisted(table, patterns)]


def get_event_groups(rules: dict | None = None) -> dict:
    rules = rules or load_rules()
    return rules.get("event_groups", {})


def is_quality_check_enabled(
    rules: dict | None,
    check_name: str,
    default: bool = True,
) -> bool:
    rules = rules or load_rules()
    check_config = rules.get("quality_definitions", {}).get(check_name, {})
    if "enabled" not in check_config:
        return default
    return bool(check_config.get("enabled"))


def group_tables(group: Any) -> list[str]:
    if isinstance(group, dict):
        return as_list(group.get("tables"), []) or []
    return as_list(group, []) or []


def get_same_second_allowed_tables(rules: dict | None = None) -> set[str]:
    groups = get_event_groups(rules)
    tables = []
    for key in ["same_second_allowed", "same_time_allowed"]:
        tables.extend(group_tables(groups.get(key)))
    return set(tables)


def get_same_second_strict_tables(rules: dict | None = None) -> set[str]:
    groups = get_event_groups(rules)
    tables = []
    for key in ["same_second_strict", "same_time_strict"]:
        tables.extend(group_tables(groups.get(key)))
    return set(tables)


def get_missing_main_identifier_allowed_tables(
    rules: dict | None = None,
) -> set[str]:
    groups = get_event_groups(rules)
    tables = []
    for key in [
        "missing_main_identifier_allowed",
        "missing_main_identifier_expected",
    ]:
        tables.extend(group_tables(groups.get(key)))
    return set(tables)


def get_missing_session_id_allowed_tables(rules: dict | None = None) -> set[str]:
    groups = get_event_groups(rules)
    tables = []
    for key in ["missing_session_id_allowed", "missing_session_id_expected"]:
        tables.extend(group_tables(groups.get(key)))
    return set(tables)


def get_identifier_aliases(
    identifier: str,
    rules: dict | None = None,
) -> list[str]:
    """Return ordered physical columns for one logical system identifier."""
    rules = rules or load_rules()
    configured = (
        [get_main_identifier(rules)]
        if identifier == "user_id"
        else rules.get("quality_definitions", {})
        .get("missing_identifier", {})
        .get("aliases", {})
        .get(identifier)
    )
    aliases = as_list(configured, DEFAULT_IDENTIFIER_ALIASES.get(identifier, [identifier]))

    ordered = []
    seen = set()
    for alias in aliases or [identifier]:
        if alias in seen:
            continue
        seen.add(alias)
        ordered.append(alias)
    return ordered


def is_parameter_missing_allowed(
    table: str,
    parameter: str,
    rules: dict | None = None,
) -> bool:
    """Return whether configuration explicitly permits a missing identifier."""
    rules = load_rules() if rules is None else rules
    table_context = rules.get("event_context", {}).get(table, {})

    main_identifier_names = {
        "user_id",
        get_main_identifier(rules),
        *get_identifier_aliases("user_id", rules),
    }
    if parameter in main_identifier_names:
        return (
            table in get_missing_main_identifier_allowed_tables(rules)
            or table_context.get("skip_main_identifier_check") is True
        )

    session_identifier_names = {
        "session_id",
        *get_identifier_aliases("session_id", rules),
    }
    if parameter in session_identifier_names:
        return (
            table in get_missing_session_id_allowed_tables(rules)
            or table_context.get("skip_session_id_check") is True
        )

    return False


def get_present_identifier_columns(
    columns: set[str] | list[str],
    identifier: str,
    rules: dict | None = None,
) -> list[str]:
    available = set(columns)
    return [
        alias
        for alias in get_identifier_aliases(identifier, rules)
        if alias in available
    ]


def is_datetime_column_type(column_type: Any) -> bool:
    normalized = str(column_type or "").replace(" ", "")
    return (
        normalized.startswith("DateTime")
        or normalized.startswith("Nullable(DateTime")
        or normalized.startswith("LowCardinality(DateTime")
    )


def measurement_time_column(schema: dict[str, Any]) -> str | None:
    for column in MEASUREMENT_TIME_COLUMN_CANDIDATES:
        if column in schema and is_datetime_column_type(schema[column]):
            return column
    return None


def get_event_group_names(table: str, rules: dict | None = None) -> list[str]:
    groups = get_event_groups(rules)
    names = []

    for group_name, group_value in groups.items():
        if table in group_tables(group_value):
            names.append(group_name)

    return names


def get_profile_context(rules: dict | None = None) -> dict:
    rules = rules or load_rules()
    profile_name, profile = get_active_profile(rules)

    return {
        "profile_name": profile_name,
        "kind": profile.get("kind", "clickhouse"),
        "database": get_database(rules),
        "main_identifier": get_main_identifier(rules),
        "table_name_prefixes": get_table_prefixes(rules),
        "table_blacklist": get_table_blacklist(rules),
        "same_second_allowed_tables": sorted(get_same_second_allowed_tables(rules)),
        "same_second_strict_tables": sorted(get_same_second_strict_tables(rules)),
        "missing_main_identifier_allowed_tables": sorted(
            get_missing_main_identifier_allowed_tables(rules)
        ),
        "missing_session_id_allowed_tables": sorted(get_missing_session_id_allowed_tables(rules)),
    }
