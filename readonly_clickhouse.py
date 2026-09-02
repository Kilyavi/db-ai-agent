import os
import re
from dotenv import load_dotenv
import clickhouse_connect
from console_status import Spinner
from quality_config import get_clickhouse_connection_config, get_database


_CLIENT = None
DEFAULT_MAX_EXECUTION_TIME = 120


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


def env_bool(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "y")


def normalize_sql(sql: str) -> str:
    sql = sql.strip()
    sql = re.sub(r"--.*?$", "", sql, flags=re.MULTILINE)
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    sql = sql.strip()
    return sql


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


def get_client():
    global _CLIENT

    if _CLIENT is not None:
        return _CLIENT

    load_dotenv()

    connection_config = get_clickhouse_connection_config()
    host = connection_config["host"]
    port = connection_config["port"]
    user = connection_config["user"]
    password = connection_config["password"]
    database = get_database()
    secure = (
        connection_config["secure"]
        if isinstance(connection_config["secure"], bool)
        else env_bool(connection_config["secure"])
    )

    max_execution_time = int(
        os.getenv("CH_MAX_EXECUTION_TIME", str(DEFAULT_MAX_EXECUTION_TIME))
    )
    _CLIENT = clickhouse_connect.get_client(
        host=host,
        port=port,
        username=user,
        password=password,
        database=database,
        secure=secure,
        connect_timeout=10,
        send_receive_timeout=max_execution_time + 10,
    )

    return _CLIENT


def query_df(sql: str, status: str | None = None):
    safe_sql = validate_readonly_sql(sql)
    with Spinner(status or "ClickHouse query running"):
        client = get_client()
        return client.query_df(
            safe_sql,
            settings={
                "readonly": 1,
                "max_execution_time": int(
                    os.getenv("CH_MAX_EXECUTION_TIME", str(DEFAULT_MAX_EXECUTION_TIME))
                ),
                "max_result_rows": int(os.getenv("CH_MAX_RESULT_ROWS", "10000")),
                "result_overflow_mode": "break",
            },
        )


if __name__ == "__main__":
    print("Safe runner test")

    df = query_df("""
        SELECT
            currentDatabase() AS database,
            count() AS active_tables
        FROM system.tables
        WHERE database = currentDatabase()
    """)

    print(df)

    print("\nWrite-block test")
    try:
        query_df("""
            CREATE TABLE ai_test_write
            (
                x UInt8
            )
            ENGINE = Memory
        """)
    except Exception as e:
        print("Blocked correctly:")
        print(e)
