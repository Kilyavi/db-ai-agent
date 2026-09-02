import glob
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime

import pandas as pd
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*_args, **_kwargs):
        return False

from quality_config import (
    get_llm_config,
    get_main_identifier,
    get_missing_session_id_allowed_tables,
    get_missing_main_identifier_allowed_tables,
    load_rules as load_config_rules,
)
from console_status import Spinner


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


REPORT_DIR = "reports"
MAIN_IDENTIFIER = get_main_identifier()


def read_csv_or_empty(path: str) -> pd.DataFrame:
    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def load_known_event_context() -> str:
    rules = load_config_rules()

    if not rules:
        return "Known expected event behavior: no external rules file found."

    event_context = rules.get("event_context", {})

    lines = ["Known expected event behavior from loaded config:"]

    for event_table, context in event_context.items():
        notes = context.get("notes", "")

        flags = []

        if context.get("can_trigger_before_login") is True:
            flags.append("can trigger before login")

        if context.get("skip_adid_check") is True:
            flags.append("adid check skipped")

        if context.get("skip_main_identifier_check") is True:
            flags.append(f"{MAIN_IDENTIFIER} check skipped")

        if context.get("skip_session_id_check") is True:
            flags.append("session_id check skipped")

        if context.get("skip_suspicious_same_second_check") is True:
            flags.append("same-second burst check skipped")

        flag_text = "; ".join(flags) if flags else "no table-level flags"

        lines.append(f"- {event_table}: {flag_text}. {notes}".strip())

        step_exceptions = context.get("step_exceptions", {})
        for step, step_context in step_exceptions.items():
            step_notes = step_context.get("notes", "")

            step_flags = []

            if step_context.get("skip_adid_check") is True:
                step_flags.append("adid check skipped")

            if step_context.get("skip_main_identifier_check") is True:
                step_flags.append(f"{MAIN_IDENTIFIER} check skipped")

            if step_context.get("skip_session_id_check") is True:
                step_flags.append("session_id check skipped")

            step_flag_text = "; ".join(step_flags) if step_flags else "no step-level flags"

            lines.append(
                f"  - step {step}: {step_flag_text}. {step_notes}".strip()
            )

    return "\n".join(lines)


def missing_allowed_tables() -> tuple[set[str], set[str]]:
    rules = load_config_rules()
    return (
        get_missing_main_identifier_allowed_tables(rules),
        get_missing_session_id_allowed_tables(rules),
    )


KNOWN_EVENT_CONTEXT = load_known_event_context()


def same_second_skipped_tables() -> set[str]:
    rules = load_config_rules()
    return {
        table
        for table, context in rules.get("event_context", {}).items()
        if context.get("skip_suspicious_same_second_check") is True
    }

def latest_file(pattern: str) -> str | None:
    files = glob.glob(pattern)
    if not files:
        return None
    run_id = os.getenv("QUALITY_RUN_ID")
    if run_id:
        run_files = [path for path in files if run_id in os.path.basename(path)]
        return max(run_files, key=os.path.getmtime) if run_files else None
    return max(files, key=os.path.getmtime)


def repair_text(value) -> str:
    text = str(value or "")
    if not any(ord(char) in (0x00C2, 0x00C3, 0x00E2) for char in text):
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

    return repaired if repaired.strip() else text


def compact_text(value, limit: int = 180) -> str:
    text = repair_text(value)
    text = re.sub(
        r"https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?[^\s)]*",
        "[local-url]",
        text,
        flags=re.I,
    )
    text = re.sub(
        r"\b(?:127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "[local-ip]",
        text,
    )
    text = re.sub(r"\b[A-Z]:\\Users\\[^\\\s]+", "[user-dir]", text, flags=re.I)
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    text = re.sub(
        r"(?is)(^|[\r\n;])\s*(SELECT|WITH|INSERT|UPDATE|DELETE)\b.*",
        r"\1 SQL omitted.",
        text,
    )
    text = re.sub(
        r"(?is)\b(sql|query)\s*[:=]\s*(SELECT|WITH|INSERT|UPDATE|DELETE)\b.*",
        r"\1 omitted.",
        text,
    )
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) <= limit:
        return text

    return f"{text[:limit].rstrip()}..."


def observation_id(observation: dict) -> str:
    return str(
        observation.get("id")
        or observation.get("name")
        or observation.get("hypothesis_id")
        or observation.get("plan_id")
        or "unnamed"
    )


def observation_tables(observation: dict) -> str:
    tables = observation.get("tables") or []
    if isinstance(tables, dict):
        tables = tables.values()
    elif isinstance(tables, str):
        tables = [tables]

    table_list = [str(table).strip() for table in tables if str(table).strip()]
    return ", ".join(sorted(set(table_list))) or "unknown"


def ask_lmstudio(prompt: str) -> str:
    load_dotenv()

    llm_config = get_llm_config("AI_AGENT")
    base_url = llm_config["base_url"]
    model = llm_config["model"]
    api_key = llm_config["api_key"]

    system_prompt = f"""
You are a precise senior product/data analyst for a game analytics DB.
Use only provided facts and keep the report read-only.
Separate confirmed data-quality problems from hypotheses.
Treat duplicate_high and replicated_high as confirmed findings unless expected behavior is listed.
Treat suspicious_high and suspicious_low as volume anomalies versus the configured rolling median.
Treat same_second_burst_high as an investigation item unless expected behavior is listed.
Do not call same-second bursts a problem for tables whose event_context skips that check.
Start immediately with the final report. Do not include analysis or reasoning.

{KNOWN_EVENT_CONTEXT}
""".strip()

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.0,
        "max_tokens": llm_config["max_tokens"],
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
        with Spinner(f"LLM recommendation request running: {model}"):
            with urllib.request.urlopen(request, timeout=240) as response:
                result = json.loads(response.read().decode("utf-8"))

        answer = result["choices"][0]["message"].get("content", "").strip()
        if not answer:
            choice = result["choices"][0]
            message = choice.get("message", {})
            reasoning_length = len(message.get("reasoning_content", "") or "")
            raise RuntimeError(
                "LM Studio returned no final content. "
                f"finish_reason={choice.get('finish_reason')}, "
                f"reasoning_content_chars={reasoning_length}"
            )
        if len(answer) < 50:
            raise RuntimeError(f"LM Studio returned an unexpectedly short response: {answer!r}")

        return answer

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")

        print("\n=== LM Studio HTTP error ===")
        print(f"Status: {e.code} {e.reason}")
        print("\nResponse body:")
        print(error_body[:5000])

        raise


def pct_to_str(value) -> str:
    if pd.isna(value) or str(value).lower() in ("none", "nan", "<na>", ""):
        return ""

    try:
        return f"{float(value) * 100:.2f}%"
    except Exception:
        return ""


def compact_database_quality_scan() -> tuple[str, str]:
    path = latest_file(os.path.join(REPORT_DIR, "database_quality_scan*.json"))
    if path is None:
        return "NOT_FOUND", "No database quality scan found. Run scan_database_quality.py first."

    print(f"Using database quality scan: {path}")

    with open(path, "r", encoding="utf-8") as f:
        report = json.load(f)

    results = report.get("results", [])
    problem_results = [
        item
        for item in results
        if item.get("status") in ("problem", "error")
    ]

    def score(item: dict) -> float:
        if item.get("status") == "error":
            return 999999.0

        values = [
            item.get("duplicate_pct") or 0,
            item.get("same_second_burst_pct") or 0,
            item.get("problem_signal_pct") or 0,
            abs(float(item.get("delta_vs_lookback_expected") or 0)),
        ]

        return max(float(value) for value in values)

    problem_results = sorted(problem_results, key=score, reverse=True)

    lines = [
        (
            f"DB scan: database={report.get('database')}, "
            f"date_range={report.get('date_range', {}).get('description')}, "
            f"lookback={report.get('lookback', {}).get('description')}, "
            f"table_source={report.get('table_source')}, "
            f"inventory_tables={report.get('inventory_tables_found')}, "
            f"event_tables_discovered={report.get('event_tables_discovered_count')}, "
            f"tables_checked={report.get('tables_checked')}, "
            f"problem_tables={report.get('problem_tables_count')}, "
            f"not_deep_scanned={len(report.get('event_tables_not_scanned', []))}."
        )
    ]

    for item in problem_results[:4]:
        if item.get("status") == "error":
            lines.append(f"- {item.get('table')}: scan error={item.get('error')}")
            continue

        facts = [
            f"rows={item.get('rows_total')}",
            f"duplicate={pct_to_str(item.get('duplicate_pct')) or '0%'}",
            f"same_second={pct_to_str(item.get('same_second_burst_pct')) or '0%'}",
            f"future_rows={item.get('future_event_time_rows')}",
            f"missing_{MAIN_IDENTIFIER}_rows="
            f"{item.get('missing_main_identifier_rows')}",
            f"missing_main_identifier_check="
            f"{item.get('missing_main_identifier_check')}",
        ]
        problems = "; ".join(item.get("problems", []))
        schema_warnings = "; ".join(item.get("schema_warnings", []))

        line = f"- {item.get('table')}: " + ", ".join(facts)
        if problems:
            line += f"; problems={problems}"
        if schema_warnings:
            line += f"; schema={schema_warnings}"
        lines.append(line)

    return path, "\n".join(lines)


def compact_database_investigation() -> tuple[str, str]:
    path = latest_file(os.path.join(REPORT_DIR, "database_investigation_*.json"))
    if path is None:
        return "NOT_FOUND", "No database investigation found."

    print(f"Using database investigation: {path}")

    with open(path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    observations = artifact.get("observations", [])
    ok_observations = [obs for obs in observations if obs.get("status") == "ok"]
    problem_observations = [obs for obs in observations if obs.get("status") == "problem"]
    medium_problem_observations = [
        obs
        for obs in problem_observations
        if str(obs.get("priority") or "").casefold() == "medium"
    ]
    rejected_observations = [obs for obs in observations if obs.get("status") == "rejected"]
    error_observations = [obs for obs in observations if obs.get("status") == "error"]

    lines = [
        f"Database investigation source={path}",
        (
            f"observations_ok={len(ok_observations)}, "
            f"rejected={len(rejected_observations)}, "
            f"errors={len(error_observations)}, "
            f"problems_medium={len(medium_problem_observations)}"
        ),
    ]

    if ok_observations:
        lines.append("compact_observations:")
        for observation in ok_observations[:8]:
            rows_returned = observation.get("rows_returned")
            hypothesis = compact_text(
                observation.get("hypothesis")
                or observation.get("goal")
                or observation.get("summary"),
                160,
            )
            line = (
                f"- ok {observation_id(observation)}: "
                f"tables={observation_tables(observation)}; "
                f"rows_returned={rows_returned}"
            )
            if hypothesis:
                line = f"{line}; hypothesis={hypothesis}"
            preview = observation.get("preview") or []
            if preview:
                line = (
                    f"{line}; preview="
                    f"{compact_text(json.dumps(preview[:2], ensure_ascii=False), 500)}"
                )
            lines.append(line)

    if problem_observations:
        lines.append("ai_query_problems:")
        for observation in problem_observations[:12]:
            priority = str(observation.get("priority") or "medium").upper()
            code = observation.get("problem_code") or "query_problem"
            reason = compact_text(observation.get("reason"), 260)
            line = (
                f"- {priority} {observation_id(observation)}: "
                f"code={code}; tables={observation_tables(observation)}"
            )
            if reason:
                line = f"{line}; reason={reason}"
            lines.append(line)
        lines.append(
            "AI query problems are reported as pipeline-quality issues and are not "
            "database findings; their queries were not executed."
        )

    if rejected_observations or error_observations:
        omitted = [
            f"{observation_id(observation)}:{observation.get('status')}"
            for observation in (rejected_observations + error_observations)[:12]
        ]
        lines.append(
            "execution_notes: "
            f"{len(rejected_observations)} rejected and {len(error_observations)} errored AI attempts "
            "were omitted from data-quality evidence; do not infer findings from them."
        )
        if omitted:
            lines.append("omitted_attempts=" + ", ".join(omitted))

    final_report = str(artifact.get("final_report", "") or "")
    if final_report.strip():
        lines.append(
            "AI investigation narrative omitted; structured successful "
            "observations above are the only AI-led evidence."
        )
    else:
        lines.append("final_report_chars=0.")

    return path, "\n".join(lines)


def format_finding_line(finding: dict) -> str:
    if finding.get("issue") == "error":
        return (
            f"- {finding.get('table')}: error={finding.get('value')}, "
            f"rows_in_range={finding.get('rows_in_range')}"
        )

    return (
        f"- {finding.get('table')}: issue={finding.get('issue')}, "
        f"metric={finding.get('metric')}, value={finding.get('value_percent')}, "
        f"rows_in_range={finding.get('rows_in_range')}"
    )


def compact_quality_report() -> tuple[str, str]:
    path = latest_file(os.path.join(REPORT_DIR, "event_quality_*.csv"))
    if path is None:
        raise FileNotFoundError("No event_quality_*.csv found. Run check_event_quality.py first.")

    print(f"Using quality report: {path}")

    df = read_csv_or_empty(path)
    if df.empty or not {"status", "event_table"}.issubset(df.columns):
        return path, "Quality report contains no event-table rows."

    def split_status(value) -> set[str]:
        return {
            part.strip()
            for part in str(value).split(",")
            if part.strip()
        }

    no_rows_count = int(df["status"].apply(
        lambda value: bool(
            {"no_rows_in_range", "no_rows_yesterday"} & split_status(value)
        )
    ).sum())

    problem_df = df[
        (df["status"] != "ok")
        & (~df["status"].isin(["no_rows_in_range", "no_rows_yesterday"]))
    ].copy()

    def number_or_none(value):
        if pd.isna(value) or str(value).lower() in ("none", "nan", "<na>", ""):
            return None

        try:
            return float(value)
        except Exception:
            return None

    def int_or_none(value):
        if pd.isna(value) or str(value).lower() in ("none", "nan", "<na>", ""):
            return None

        try:
            return int(value)
        except Exception:
            return None

    metric_map = {
        "missing_adid_high": {
            "metric": "missing_adid_pct",
            "column": "missing_adid_pct",
        },
        "missing_main_identifier_high": {
            "metric": "missing_main_identifier_pct",
            "column": "missing_main_identifier_pct",
        },
        "missing_session_id_high": {
            "metric": "missing_session_id_pct",
            "column": "missing_session_id_pct",
        },
        "duplicate_high": {
            "metric": "duplicate_pct",
            "column": "duplicate_pct",
        },
        "replicated_high": {
            "metric": "replicated_pct",
            "column": "replicated_pct",
        },
        "same_second_burst_high": {
            "metric": "same_second_burst_pct",
            "column": "same_second_burst_pct",
        },
        "suspicious_high": {
            "metric": "delta_vs_lookback_expected",
            "column": "delta_vs_lookback_expected",
        },
        "suspicious_low": {
            "metric": "delta_vs_lookback_expected",
            "column": "delta_vs_lookback_expected",
        },
    }

    findings = []

    for _, row in problem_df.iterrows():
        table = row.get("event_table")
        status_raw = str(row.get("status", ""))
        status_parts = split_status(status_raw)

        rows_in_range = int_or_none(
            row.get("rows_in_range", row.get("rows_yesterday"))
        )

        for issue, meta in metric_map.items():
            if issue not in status_parts:
                continue

            value = number_or_none(row.get(meta["column"]))

            findings.append({
                "table": table,
                "issue": issue,
                "metric": meta["metric"],
                "value_fraction": value,
                "value_percent": pct_to_str(row.get(meta["column"])),
                "rows_in_range": rows_in_range,
            })

        error_value = row.get("error")
        if pd.notna(error_value) and str(error_value).strip():
            findings.append({
                "table": table,
                "issue": "error",
                "metric": "error",
                "value": str(error_value),
                "rows_in_range": rows_in_range,
            })

    lines = [
        f"Quality report: no_rows_in_range_count={int(no_rows_count)}.",
        "Findings:",
    ]
    no_rows_tables = df.loc[
        df["status"].apply(
            lambda value: bool(
                {"no_rows_in_range", "no_rows_yesterday"} & split_status(value)
            )
        ),
        "event_table",
    ].astype(str).tolist()
    if no_rows_tables:
        listed = ", ".join(no_rows_tables[:30])
        suffix = "" if len(no_rows_tables) <= 30 else f", +{len(no_rows_tables) - 30} more"
        lines.append(
            f"- No parsed rows requiring source_events severity comparison: {listed}{suffix}"
        )
    lines.extend(format_finding_line(finding) for finding in findings[:16])

    return path, "\n".join(lines)


def compact_event_flow() -> tuple[str, str]:
    path = latest_file(os.path.join(REPORT_DIR, "event_flow_*.json"))
    if path is None:
        return "NOT_FOUND", "No raw-to-parsed event-flow evidence found."
    with open(path, "r", encoding="utf-8") as handle:
        artifact = json.load(handle)
    lines = [
        f"Event flow: {json.dumps(artifact.get('summary', {}), ensure_ascii=False)}"
    ]
    severity_findings = [
        item
        for item in artifact.get("flow_results", [])
        if str(item.get("severity")) in {"critical", "low"}
        or any(
            str(flag).startswith(("critical_", "low_"))
            for flag in item.get("status", [])
        )
    ]
    severity_findings.sort(
        key=lambda item: 0 if str(item.get("severity")) == "critical" else 1
    )
    for item in severity_findings[:30]:
        lines.append(
            f"- {str(item.get('severity', 'unknown')).upper()} "
            f"{item.get('event_table')}: status={','.join(item.get('status', []))}; "
            f"raw_rows={item.get('raw_rows')}; parsed_rows={item.get('parsed_rows')}; "
            f"dlq_rows={item.get('dlq_rows')}; dlq_shapes={item.get('dlq_shapes')}"
        )
    parameter_findings = [
        item
        for item in artifact.get("parameter_results", [])
        if item.get("diagnosis")
        in {"source_payload_parameter_missing", "likely_parser_or_column_mapping_issue"}
    ]
    for item in parameter_findings[:30]:
        lines.append(
            f"- {item.get('event_table')}.{item.get('parameter')} "
            f"scope={item.get('scope')}: severity={item.get('severity')}; "
            f"status={item.get('status')}; diagnosis={item.get('diagnosis')}; "
            f"raw_presence_pct={pct_to_str(item.get('raw_presence_pct'))}; "
            f"target_missing_pct={pct_to_str(item.get('target_missing_pct'))}"
        )
    return path, "\n".join(lines)


def prioritize_parameter_problems(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or "status" not in df.columns:
        return df.iloc[0:0]

    problems = df[df["status"].isin(["problem", "error"])].copy()
    if problems.empty:
        return problems

    if "report_priority" not in problems.columns:
        problems["report_priority"] = "normal"
    priority = problems["report_priority"].astype(str).str.lower()
    problems["_priority_rank"] = priority.map(
        {"extreme": 0, "critical": 0, "high": 1, "normal": 2, "low": 3}
    ).fillna(2)

    contract = problems.get(
        "profile_schema_parameter",
        pd.Series(False, index=problems.index),
    )
    problems["_contract_rank"] = ~contract.astype(str).str.lower().isin(
        ["1", "true", "yes"]
    )
    problems["_schema_failure_rank"] = ~problems.get(
        "problem",
        pd.Series("", index=problems.index),
    ).astype(str).str.contains(r"missing_event|missing_column", regex=True)
    problems["_missing_rank"] = -pd.to_numeric(
        problems.get("missing_pct", pd.Series(0.0, index=problems.index)),
        errors="coerce",
    ).fillna(0.0)
    return problems.sort_values(
        [
            "_priority_rank",
            "_contract_rank",
            "_schema_failure_rank",
            "_missing_rank",
            "event_table",
            "parameter",
        ],
        kind="stable",
    )


def parameter_problem_lines(
    df: pd.DataFrame,
    *,
    limit: int,
    evidence_path: str | None = None,
) -> list[str]:
    problems = prioritize_parameter_problems(df)
    if problems.empty:
        return []

    lines = []
    grouped = problems.groupby(
        ["_priority_rank", "report_priority", "parameter"],
        sort=False,
        dropna=False,
    )
    for (_, priority, parameter), group in grouped:
        group = group.sort_values("_missing_rank", kind="stable")
        problem_names = sorted({
            name
            for value in group.get("problem", pd.Series(dtype=str)).astype(str)
            for name in value.split(",")
            if name and name != "nan"
        })
        details = []
        for _, row in group.iterrows():
            table = row.get("event_table")
            missing = pct_to_str(row.get("missing_pct"))
            invalid = pct_to_str(row.get("invalid_pct"))
            lookback_presence = pct_to_str(row.get("lookback_presence_pct"))
            expected = row.get("expected_present_rows")
            details.append(
                f"{table}=current missing {missing}/invalid {invalid}, "
                f"lookback presence {lookback_presence}, expected_present {expected}"
            )

        if len(group) == 1:
            label = f"{group.iloc[0].get('event_table')}.{parameter}"
        else:
            label = str(parameter)
        evidence = f"; evidence={evidence_path}" if evidence_path else ""
        lines.append(
            f"- {label} [{priority}]: problems={','.join(problem_names)}; "
            f"affected_events={len(group)}; {', '.join(details)}{evidence}"
        )
        if len(lines) >= limit:
            break
    return lines


def compact_parameter_report() -> tuple[str, str]:
    path = latest_file(os.path.join(REPORT_DIR, "parameter_quality_*.csv"))
    if path is None:
        return "NOT_FOUND", "No parameter-quality report found."

    print(f"Using parameter quality report: {path}")
    df = read_csv_or_empty(path)
    if df.empty or not {"status", "event_table", "parameter"}.issubset(df.columns):
        return path, "Parameter-quality report contains no rows."

    lines = parameter_problem_lines(df, limit=20)
    if not lines:
        return path, "No required-value or invalid-value problems found."
    return path, "\n".join(lines)


def compact_duplicate_samples() -> tuple[str, str]:
    path = latest_file(os.path.join(REPORT_DIR, "quality_duplicate_samples_*.csv"))
    if path is None:
        return "NOT_FOUND", "No duplicate drilldown file found."

    print(f"Using duplicate drilldown: {path}")

    df = read_csv_or_empty(path)
    if df.empty:
        return path, "No duplicate samples."

    required_cols = {
        "event_table",
        "rows_same_event_key_adid_time",
        "unique_main_identifiers",
    }
    if not required_cols.issubset(set(df.columns)):
        return path, df.head(5).to_json(orient="records", force_ascii=False)

    summary = (
        df.groupby("event_table", as_index=False)
        .agg(
            sample_groups=("event_table", "size"),
            max_rows_same_event_key_adid_time=("rows_same_event_key_adid_time", "max"),
            max_unique_main_identifiers=("unique_main_identifiers", "max"),
        )
        .sort_values("max_rows_same_event_key_adid_time", ascending=False)
        .head(5)
    )

    lines = []
    for row in summary.to_dict("records"):
        lines.append(
            f"- {row['event_table']}: duplicate_sample_groups={row['sample_groups']}, "
            f"max_rows_same_key_adid_time={row['max_rows_same_event_key_adid_time']}, "
            f"max_unique_{MAIN_IDENTIFIER}s="
            f"{row['max_unique_main_identifiers']}"
        )

    return path, "\n".join(lines)


def compact_suspicious_samples() -> tuple[str, str]:
    path = latest_file(os.path.join(REPORT_DIR, "quality_suspicious_samples_*.csv"))
    if path is None:
        return "NOT_FOUND", "No suspicious drilldown file found."

    print(f"Using suspicious drilldown: {path}")

    df = read_csv_or_empty(path)

    if df.empty:
        return path, "No suspicious samples."

    # Do not send explicitly expected same-second bursts to the model.
    if "event_table" in df.columns:
        skipped_tables = same_second_skipped_tables()
        if skipped_tables:
            df = df[~df["event_table"].isin(skipped_tables)].copy()

    if df.empty:
        return path, "Only expected same-second burst samples existed; skipped by event_context."

    required_cols = {
        "event_table",
        "rows_same_second",
        "unique_event_keys",
    }
    if not required_cols.issubset(set(df.columns)):
        return path, df.head(5).to_json(orient="records", force_ascii=False)

    summary = (
        df.groupby("event_table", as_index=False)
        .agg(
            sample_groups=("event_table", "size"),
            max_rows_same_second=("rows_same_second", "max"),
            max_unique_event_keys=("unique_event_keys", "max"),
        )
        .sort_values("max_rows_same_second", ascending=False)
        .head(5)
    )

    lines = []
    for row in summary.to_dict("records"):
        lines.append(
            f"- {row['event_table']}: suspicious_sample_groups={row['sample_groups']}, "
            f"max_rows_same_second={row['max_rows_same_second']}, "
            f"max_unique_event_keys={row['max_unique_event_keys']}"
        )

    return path, "\n".join(lines)


def compact_missing_ids() -> tuple[str, str]:
    path = latest_file(os.path.join(REPORT_DIR, "quality_missing_ids_*.csv"))
    if path is None:
        return "NOT_FOUND", "No missing IDs drilldown file found."

    print(f"Using missing IDs drilldown: {path}")

    df = read_csv_or_empty(path)
    if df.empty:
        return path, "No missing ID samples."

    keep_cols = [
        "event_table",
        "step",
        "type",
        "rows_in_range",
        "rows_yesterday",
        "missing_main_identifier_rows",
        "missing_session_id_rows",
        "missing_main_identifier_pct",
        "missing_session_id_pct",
    ]

    keep_cols = [col for col in keep_cols if col in df.columns]
    df = df[keep_cols].head(5)

    for col in ["missing_main_identifier_pct", "missing_session_id_pct"]:
        if col in df.columns:
            df[col] = df[col].apply(pct_to_str)

    lines = []
    for row in df.to_dict("records"):
        lines.append(
            f"- {row.get('event_table')} step={row.get('step')} type={row.get('type')}: "
            f"rows={row.get('rows_in_range', row.get('rows_yesterday'))}, "
            f"missing_{MAIN_IDENTIFIER}={row.get('missing_main_identifier_pct')}, "
            f"missing_session_id={row.get('missing_session_id_pct')}"
        )

    return path, "\n".join(lines)


def status_parts(value) -> set[str]:
    return {
        part.strip()
        for part in str(value or "").split(",")
        if part.strip()
    }


def build_deterministic_report(
    ai_agent_path: str,
    ai_agent_text: str,
    db_scan_path: str,
    quality_path: str,
    parameter_path: str,
    missing_path: str,
    recommendations: str,
    flow_path: str = "NOT_FOUND",
) -> str:
    quality_df = read_csv_or_empty(quality_path)
    system_parameters = []
    value_parameters = []
    confirmed = []
    critical_delivery = []
    low_delivery = []
    expected = []
    investigation = []

    flow_tables = set()
    if flow_path != "NOT_FOUND" and os.path.exists(flow_path):
        with open(flow_path, "r", encoding="utf-8") as handle:
            flow_artifact = json.load(handle)
        for item in flow_artifact.get("flow_results", []):
            flags = [str(flag) for flag in item.get("status", [])]
            severity = str(item.get("severity") or "")
            if severity not in {"critical", "low"}:
                if any(flag.startswith("critical_") for flag in flags):
                    severity = "critical"
                elif any(flag.startswith("low_") for flag in flags):
                    severity = "low"
            if severity not in {"critical", "low"}:
                continue
            table = str(item.get("event_table"))
            flow_tables.add(table)
            destination = critical_delivery if severity == "critical" else low_delivery
            destination.append(
                f"- {severity.upper()} {table}: {','.join(flags)}; "
                f"raw_rows={item.get('raw_rows')}, parsed_rows={item.get('parsed_rows')}, "
                f"dlq_rows={item.get('dlq_rows')}, dlq_shapes={item.get('dlq_shapes')}; "
                f"evidence={flow_path}"
            )
        for item in flow_artifact.get("parameter_results", []):
            diagnosis = item.get("diagnosis")
            if diagnosis not in {
                "source_payload_parameter_missing",
                "likely_parser_or_column_mapping_issue",
            }:
                continue
            line = (
                f"- {item.get('event_table')}.{item.get('parameter')} "
                f"[{item.get('report_priority')}]: {item.get('severity')} "
                f"{item.get('status')}; {diagnosis}; "
                f"source_presence={pct_to_str(item.get('raw_presence_pct'))}, "
                f"target_missing={pct_to_str(item.get('target_missing_pct'))}; "
                f"source_aliases={','.join(item.get('source_aliases', []))}; evidence={flow_path}"
            )
            if item.get("scope") == "system":
                system_parameters.append(line)
            else:
                value_parameters.append(line)
            if item.get("severity") == "critical":
                critical_delivery.append(line)
            elif item.get("severity") == "low":
                low_delivery.append(line)

    system_metric_columns = {
        "missing_adid_high": ("adid", "missing_adid_pct"),
        "missing_main_identifier_high": (
            MAIN_IDENTIFIER,
            "missing_main_identifier_pct",
        ),
        "missing_session_id_high": ("session identifier", "missing_session_id_pct"),
    }
    metric_columns = {
        "duplicate_high": ("duplicate_pct", "duplicate_pct"),
        "replicated_high": ("replicated_pct", "replicated_pct"),
    }

    for _, row in quality_df.iterrows():
        table = row.get("event_table")
        parts = status_parts(row.get("status"))
        rows_in_range = row.get("rows_in_range", row.get("rows_yesterday"))

        metrics = []
        for issue, (label, column) in system_metric_columns.items():
            if issue not in parts:
                continue
            sources = ""
            if issue == "missing_session_id_high":
                source_value = row.get("session_id_columns")
                if pd.notna(source_value) and str(source_value).strip():
                    sources = f"; sources={source_value}"
            system_parameters.append(
                f"- {table}: missing {label}={pct_to_str(row.get(column))}; "
                f"rows_in_range={rows_in_range}{sources}; evidence={quality_path}"
            )

        for issue, (label, column) in metric_columns.items():
            if issue in parts:
                metrics.append(f"{label}={pct_to_str(row.get(column))}")

        if metrics:
            confirmed.append(
                f"- {table}: {', '.join(metrics)}; "
                f"rows_in_range={rows_in_range}; evidence={quality_path}"
            )

        if "same_second_burst_high" in parts:
            investigation.append(
                f"- {table}: same_second_burst_pct={pct_to_str(row.get('same_second_burst_pct'))}; "
                "next check: drill down by adid, event_key, platform, region, client_version if available."
            )

        if "suspicious_high" in parts or "suspicious_low" in parts:
            issue = "suspicious_high" if "suspicious_high" in parts else "suspicious_low"
            investigation.append(
                f"- {table}: {issue} delta_vs_lookback_expected="
                f"{pct_to_str(row.get('delta_vs_lookback_expected'))}; "
                f"rows_in_range={rows_in_range}; expected_rows_from_lookback="
                f"{row.get('expected_rows_from_lookback')}."
            )

    if parameter_path != "NOT_FOUND" and os.path.exists(parameter_path):
        parameter_df = read_csv_or_empty(parameter_path)
        if {"status", "event_table", "parameter"}.issubset(parameter_df.columns):
            value_parameters.extend(
                parameter_problem_lines(
                    parameter_df,
                    limit=25,
                    evidence_path=parameter_path,
                )
            )

    if {"status", "event_table"}.issubset(quality_df.columns):
        no_rows_tables = (
            quality_df.loc[
                quality_df["status"].apply(
                    lambda value: bool(
                        {"no_rows_in_range", "no_rows_yesterday"}
                        & status_parts(value)
                    )
                ),
                "event_table",
            ]
            .astype(str)
            .tolist()
        )
    else:
        no_rows_tables = []
    if no_rows_tables:
        for table in no_rows_tables:
            if table not in flow_tables:
                investigation.append(
                    f"- {table}: no parsed rows in the configured period, but "
                    f"source_events/DLQ comparison is unavailable; severity cannot be "
                    f"classified; evidence={quality_path}"
                )

    if os.path.exists(db_scan_path):
        with open(db_scan_path, "r", encoding="utf-8") as f:
            db_scan = json.load(f)

        future_items = []
        schema_items = []

        for item in db_scan.get("results", []):
            table = item.get("table")
            future_rows = int(item.get("future_event_time_rows") or 0)
            if future_rows > 0:
                future_items.append((future_rows, item))

            schema_warnings = item.get("schema_warnings", [])
            if schema_warnings:
                schema_items.append((table, schema_warnings))

        for future_rows, item in sorted(
            future_items,
            key=lambda entry: entry[0],
            reverse=True,
        )[:8]:
            confirmed.append(
                f"- {item.get('table')}: future_event_time_rows={future_rows}; "
                f"max_future_event_time="
                f"{item.get('max_future_event_time', item.get('max_event_time'))}; "
                f"evidence={db_scan_path}"
            )

        for table, schema_warnings in schema_items[:8]:
            confirmed.append(
                f"- {table}: schema_warnings={'; '.join(schema_warnings)}; evidence={db_scan_path}"
            )

    if os.path.exists(missing_path):
        missing_df = read_csv_or_empty(missing_path)
        event_context = load_config_rules().get("event_context", {})
        missing_main_identifier_allowed, missing_session_id_allowed = missing_allowed_tables()
        for _, row in missing_df.head(5).iterrows():
            table = row.get("event_table")
            step = row.get("step")
            table_context = event_context.get(table, {})
            main_expected = (
                table_context.get("skip_main_identifier_check") is True
                or table in missing_main_identifier_allowed
            )
            session_expected = (
                table_context.get("skip_session_id_check") is True
                or table in missing_session_id_allowed
            )
            main_pct = pd.to_numeric(
                row.get("missing_main_identifier_pct"),
                errors="coerce",
            )
            session_pct = pd.to_numeric(
                row.get("missing_session_id_pct"), errors="coerce"
            )
            expected_labels = []
            unexpected_labels = []
            if pd.notna(main_pct) and main_pct > 0:
                (expected_labels if main_expected else unexpected_labels).append(
                    MAIN_IDENTIFIER
                )
            if pd.notna(session_pct) and session_pct > 0:
                (expected_labels if session_expected else unexpected_labels).append(
                    "session identifier"
                )

            if expected_labels:
                expected.append(
                    f"- {table} step={step}: expected missing "
                    f"{', '.join(expected_labels)} by event_context; "
                    f"missing_{MAIN_IDENTIFIER}_pct="
                    f"{pct_to_str(row.get('missing_main_identifier_pct'))}, "
                    f"missing_session_id_pct={pct_to_str(row.get('missing_session_id_pct'))}."
                )
            if unexpected_labels:
                investigation.append(
                    f"- {table} step={step}: unexpected missing "
                    f"{', '.join(unexpected_labels)}; "
                    f"missing_{MAIN_IDENTIFIER}_pct="
                    f"{pct_to_str(row.get('missing_main_identifier_pct'))}, "
                    f"missing_session_id_pct={pct_to_str(row.get('missing_session_id_pct'))}; "
                    "next check: validate expected ID availability for this step."
                )

    if not confirmed:
        confirmed.append("- No confirmed problems found in the latest quality evidence.")
    if not critical_delivery:
        critical_delivery.append("- No missing-event or DLQ critical findings found.")
    if not low_delivery:
        low_delivery.append("- No low raw-to-parsed delivery gaps found.")
    if not system_parameters:
        system_parameters.append("- No system-parameter problems exceeded configured thresholds.")
    if not value_parameters:
        value_parameters.append("- No required-value or invalid-value problems found.")
    if not expected:
        expected.append("- No obvious expected/false-positive group found.")
    if not investigation:
        investigation.append("- No investigation-only findings found.")

    return "\n".join([
        "0. AI-led DB investigation",
        ai_agent_text if ai_agent_path != "NOT_FOUND" else "- No AI-led DB investigation artifact found.",
        "",
        "1. CRITICAL: missing events/parameters in raw and target, plus DLQ failures",
        *critical_delivery[:100],
        "",
        "2. LOW: raw values present but parsed events/parameters missing",
        *low_delivery[:100],
        "",
        "3. System parameter problems",
        *system_parameters[:25],
        "",
        "4. Required and value-shape parameter problems",
        *value_parameters[:25],
        "",
        "5. Other confirmed problems",
        *confirmed[:25],
        "",
        "6. Explicitly expected by configured event context",
        *expected[:12],
        "",
        "7. Needs more investigation",
        *investigation[:20],
        "",
        "8. Recommended next harness checks",
        recommendations.strip(),
    ])


def fallback_recommendations() -> str:
    return "\n".join([
        "- Add a future-event-date drilldown by table, platform, app/client version, and client/server timestamp if available.",
        "- Add a duplicate/replicated event_key monitor for same_second_strict tables with BI-level deduplication impact estimates.",
        "- Add same-second burst drilldowns by adid, event_key, platform, region, event type, and event group.",
    ])


def normalize_recommendations(text: str) -> str:
    lines = [
        line.strip()
        for line in str(text).splitlines()
        if line.strip()
    ]

    bullet_lines = [
        line
        for line in lines
        if line.startswith(("-", "*", "1.", "2.", "3."))
    ]

    if len(bullet_lines) < 3:
        return fallback_recommendations()

    bullet_lines = bullet_lines[:3]
    check_words = re.compile(r"\b(add|check|compare|drill|monitor|run|validate|measure|flag)\b", re.IGNORECASE)

    if any(check_words.search(line) is None for line in bullet_lines):
        return fallback_recommendations()

    normalized = []
    for line in bullet_lines:
        line = re.sub(r"^\d+\.\s*", "- ", line)
        line = re.sub(r"^\*\s*", "- ", line)
        if not line.startswith("-"):
            line = f"- {line}"
        normalized.append(line)

    return "\n".join(normalized)


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)

    investigation_path, investigation_text = compact_database_investigation()
    flow_path, flow_text = compact_event_flow()
    database_scan_path, database_scan_text = compact_database_quality_scan()
    quality_path, quality_text = compact_quality_report()
    parameter_path, parameter_text = compact_parameter_report()
    duplicate_path, duplicate_text = compact_duplicate_samples()
    suspicious_path, suspicious_text = compact_suspicious_samples()
    missing_path, missing_text = compact_missing_ids()

    prompt = f"""
Suggest exactly 3 next read-only harness checks for this DB quality agent.
Do not repeat the full findings. Do not include metric values. Do not recommend changing or deleting raw data.

AI-led DB investigation ({investigation_path}):
{investigation_text}

Raw-to-parsed event flow and DLQ evidence ({flow_path}):
{flow_text}

Database quality scan ({database_scan_path}):
{database_scan_text}

Main quality findings ({quality_path}):
{quality_text}

Required/value parameter findings ({parameter_path}):
{parameter_text}

Duplicate drilldown ({duplicate_path}):
{duplicate_text}

Same-second burst drilldown ({suspicious_path}):
{suspicious_text}

Missing IDs drilldown ({missing_path}):
{missing_text}

Return only 3 bullet lines.
"""

    print(f"Recommendation prompt size: {len(prompt):,} characters")

    recommendations_degraded = False
    try:
        recommendations = ask_lmstudio(prompt)
    except Exception as e:
        recommendations_degraded = True
        print(f"LLM recommendation generation failed: {e}")
        recommendations = fallback_recommendations()

    recommendations = normalize_recommendations(recommendations)

    answer = build_deterministic_report(
        ai_agent_path=investigation_path,
        ai_agent_text=investigation_text,
        db_scan_path=database_scan_path,
        quality_path=quality_path,
        parameter_path=parameter_path,
        missing_path=missing_path,
        recommendations=recommendations,
        flow_path=flow_path,
    )

    # Deterministic wording cleanup.
    # Keep the harness read-only and avoid language that sounds like raw-data mutation.
    replacements = {
        "requiring deduplication logic implementation": "requiring BI-level deduplication monitoring",
        "requires deduplication logic implementation": "requires BI-level deduplication monitoring",
        "requiring deduplication logic": "requiring BI-level deduplication monitoring",
        "implement stricter deduplication logic": "add BI-level deduplication monitoring",
        "Implement stricter deduplication logic": "Add BI-level deduplication monitoring",
        "quarantine records": "flag records in a quality dashboard",
        "Quarantine records": "Flag records in a quality dashboard",
        "delete records": "flag records in a quality dashboard",
        "Delete records": "Flag records in a quality dashboard",
        "mutate raw data": "monitor raw data quality",
        "mutating raw data": "monitoring raw data quality",
        "Validate the root cause": "Validate the pattern",
        "validate the root cause": "validate the pattern",
        "Investigate the root cause": "Investigate the pattern",
        "investigate the root cause": "investigate the pattern",
        "root cause": "pattern",
        "Implement BI-level deduplication checks": "Add read-only BI-level deduplication checks",
        "Implement BI-level deduplication": "Add read-only BI-level deduplication",
    }

    for old, new in replacements.items():
        answer = answer.replace(old, new)

    timestamp = os.getenv("QUALITY_RUN_ID") or datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(REPORT_DIR, f"quality_report_{timestamp}.txt")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(answer)

    print("\n=== Quality report ===")
    print(answer)
    print(f"\nSaved quality report: {output_path}")

    if recommendations_degraded:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
