import os
import re
import threading

import clickhouse_connect
from dotenv import load_dotenv

from lib.config import get_clickhouse_config, get_database
from lib.status import Spinner


_CLIENT_STATE = threading.local()

FORBIDDEN_SQL_PATTERNS = [
    r"\binsert\b",
    r"\bupdate\b",
    r"\bdelete\b",
    r"\bdrop\b",
    r"\btruncate\b",
    r"\bcreate\b",
    r"\balter\b",
    r"\brename\b",
    r"\battach\b",
    r"\bdetach\b",
    r"\boptimize\b",
    r"\bkill\b",
    r"\bgrant\b",
    r"\brevoke\b",
    r"\bset\b",
    r"\buse\b",
]

ALLOWED_STARTS = (
    "select",
    "with",
    "show",
    "describe",
    "desc",
    "explain",
)


def env_bool(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "y")


def normalize_sql(sql: str) -> str:
    sql = sql.strip()
    sql = re.sub(r"--.*?$", "", sql, flags=re.MULTILINE)
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    return sql.strip()


def validate_readonly_sql(sql: str) -> str:
    normalized = normalize_sql(sql)
    lowered = normalized.lower()

    if not lowered:
        raise ValueError("Empty SQL is not allowed.")

    if ";" in lowered.rstrip(";"):
        raise ValueError("Multiple SQL statements are not allowed.")

    if not lowered.startswith(ALLOWED_STARTS):
        raise ValueError("Only SELECT/WITH/SHOW/DESCRIBE/EXPLAIN queries are allowed.")

    for pattern in FORBIDDEN_SQL_PATTERNS:
        if re.search(pattern, lowered):
            raise ValueError(f"Forbidden SQL keyword detected: {pattern}")

    return normalized


def get_client(config: dict):
    client = getattr(_CLIENT_STATE, "client", None)
    if client is not None:
        return client

    load_dotenv()
    connection = get_clickhouse_config()
    secure = connection["secure"] if isinstance(connection["secure"], bool) else env_bool(connection["secure"])

    max_execution_time = int(os.getenv("CH_MAX_EXECUTION_TIME", "120"))
    client = clickhouse_connect.get_client(
        host=connection["host"],
        port=connection["port"],
        username=connection["user"],
        password=connection["password"],
        database=get_database(config),
        secure=secure,
        connect_timeout=10,
        send_receive_timeout=int(
            os.getenv("CH_SEND_RECEIVE_TIMEOUT", str(max_execution_time + 30))
        ),
    )
    _CLIENT_STATE.client = client
    return client


def query_df(sql: str, config: dict, status: str | None = None):
    safe_sql = validate_readonly_sql(sql)
    with Spinner(status or "ClickHouse query running"):
        client = get_client(config)
        return client.query_df(
            safe_sql,
            settings={
                "readonly": 1,
                "max_execution_time": int(os.getenv("CH_MAX_EXECUTION_TIME", "120")),
                "max_result_rows": int(os.getenv("CH_MAX_RESULT_ROWS", "10000")),
                "result_overflow_mode": "break",
            },
        )
