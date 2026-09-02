def qident(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def pct(value: int | float, total: int | float):
    if not total:
        return None
    return round(float(value) / float(total), 6)
