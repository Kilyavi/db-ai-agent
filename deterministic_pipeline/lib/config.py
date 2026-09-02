import os
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
PIPELINE_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from quality_config import (  # noqa: E402
    DEFAULT_DATABASE,
    DEFAULT_PROFILE_NAME,
    DEFAULT_TABLE_PREFIXES,
    date_range_sql_condition as root_date_range_sql_condition,
    date_range_sql_interval as root_date_range_sql_interval,
    filter_blacklisted_tables,
    get_active_profile as root_get_active_profile,
    get_database as root_get_database,
    get_date_range as root_get_date_range,
    get_event_groups,
    get_identifier_aliases as root_get_identifier_aliases,
    get_main_identifier as root_get_main_identifier,
    get_lookback_range as root_get_lookback_range,
    historical_lookback_sql_condition as root_historical_lookback_sql_condition,
    lookback_comparison_window_count as root_lookback_comparison_window_count,
    get_missing_session_id_allowed_tables,
    get_missing_main_identifier_allowed_tables,
    get_same_second_allowed_tables,
    get_same_second_strict_tables,
    get_table_blacklist as root_get_table_blacklist,
    get_table_prefixes as root_get_table_prefixes,
    group_tables as root_group_tables,
    is_quality_check_enabled,
    is_table_blacklisted,
    load_personal_config as root_load_personal_config,
    load_shared_agent_config as root_load_shared_agent_config,
)


PROJECT_DIR = ROOT_DIR
DEFAULT_PREFIXES = DEFAULT_TABLE_PREFIXES


def load_pipeline_config() -> dict:
    return root_load_shared_agent_config()


def load_personal_config() -> dict:
    return root_load_personal_config()


def get_active_profile(config: dict) -> tuple[str, dict]:
    return root_get_active_profile(config)


def get_database(config: dict) -> str:
    return root_get_database(config)


def get_table_prefixes(config: dict) -> list[str]:
    return root_get_table_prefixes(config)


def get_date_range(config: dict) -> dict:
    return root_get_date_range(config, "DQ", "DQ_DAYS_BACK")


def get_days_back(config: dict) -> int:
    date_range = get_date_range(config)
    return int(date_range.get("days_back") or 1)


def get_date_range_description(config: dict) -> str:
    return get_date_range(config)["description"]


def get_lookback_range(config: dict) -> dict:
    return root_get_lookback_range(config)


def date_range_sql_condition(date_range: dict, column_name: str) -> str:
    return root_date_range_sql_condition(date_range, column_name)


def date_range_sql_interval(date_range: dict) -> str:
    return root_date_range_sql_interval(date_range)


def historical_lookback_sql_condition(
    date_range: dict,
    lookback: dict,
    column_name: str,
) -> str:
    return root_historical_lookback_sql_condition(
        date_range,
        lookback,
        column_name,
    )


def lookback_comparison_window_count(date_range: dict, lookback: dict) -> float:
    return root_lookback_comparison_window_count(date_range, lookback)


def get_table_blacklist(config: dict) -> list[str]:
    return root_get_table_blacklist(config)


def is_blacklisted(table: str, config: dict) -> bool:
    return is_table_blacklisted(table, get_table_blacklist(config))


def filter_blacklisted(tables: list[str], config: dict) -> list[str]:
    return filter_blacklisted_tables(tables, get_table_blacklist(config))


def group_tables(config: dict, group_name: str) -> set[str]:
    group = get_event_groups(config).get(group_name, {})
    return set(root_group_tables(group))


def quality_check_enabled(config: dict, check_name: str, default: bool = True) -> bool:
    return is_quality_check_enabled(config, check_name, default)


def same_second_allowed_tables(config: dict) -> set[str]:
    return get_same_second_allowed_tables(config)


def same_second_strict_tables(config: dict) -> set[str]:
    return get_same_second_strict_tables(config)


def missing_main_identifier_allowed_tables(config: dict) -> set[str]:
    return get_missing_main_identifier_allowed_tables(config)


def missing_session_id_allowed_tables(config: dict) -> set[str]:
    return get_missing_session_id_allowed_tables(config)


def get_event_context(config: dict, table: str) -> dict:
    return dict(config.get("event_context", {}).get(table, {}))


def get_identifier_aliases(config: dict, identifier: str) -> list[str]:
    return root_get_identifier_aliases(identifier, config)


def get_main_identifier(config: dict) -> str:
    return root_get_main_identifier(config)


def get_clickhouse_config() -> dict:
    personal = load_personal_config().get("clickhouse", {})
    return {
        "host": os.getenv("CH_HOST") or personal.get("host"),
        "port": int(os.getenv("CH_PORT") or personal.get("port") or 8123),
        "user": os.getenv("CH_USER") or personal.get("user"),
        "password": os.getenv("CH_PASSWORD") or personal.get("password"),
        "secure": os.getenv("CH_SECURE") if os.getenv("CH_SECURE") is not None else personal.get("secure", False),
    }


def output_dir() -> Path:
    path = PIPELINE_DIR / "reports"
    path.mkdir(exist_ok=True)
    return path
