# Deterministic DB Quality Pipeline

Small no-AI pipeline for deterministic ClickHouse quality checks.

It has exactly three deterministic pipeline scripts:

1. `scripts/collect_metrics.py`
   - Discovers configured tables.
   - Scans event storage tables; views/materialized-view definitions remain in inventory but are not double-counted as event data.
   - Collects event and parameter metrics for the configured date range, using the historical lookback for expected volume, parameter presence, and common values.
   - Writes `reports/quality_metrics.json`, timestamped metrics, and complete event/parameter CSVs.

2. `scripts/collect_drilldowns.py`
   - Reads the metrics artifact.
   - Collects samples for duplicates, same-second bursts, and future timestamps.
   - Writes CSV drilldown artifacts.

3. `scripts/build_report.py`
   - Reads metrics and drilldowns.
   - Applies configured definitions, thresholds, blacklist, event groups, and event context.
   - Writes `reports/quality_report.txt` and timestamped report.

`run_pipeline.py` is only a convenience runner for these three scripts.
All deterministic artifacts, including the run manifest, are written under this
folder's `reports/` directory.

## Config

The deterministic pipeline uses the same root config files as the AI agent:

- `..\config\system_agent_config.json` - generic repository defaults, quality definitions, and shared LLM defaults.
- `..\config\personal_config.json` - local/private ClickHouse and LLM runtime settings; create from `..\config\personal_config.example.json`; ignored by git.
- `..\config\personal_agent_config.json` - local deployment profile rules, date range, blacklist, event groups, event context, and thresholds. The release ZIP creates this file from the generic, credential-free example config.

For a rolling measurement window, use hours or days:

```json
{
  "date_range": "1 hour",
  "lookback": "30 days"
}
```

`date_range` is the only period classified as current quality and uses `[now() - date_range, now())`; future timestamps are checked separately. `lookback` supplies the historical expected event volume and parameter presence/value baseline. For `1 hour` or `2 hours` with a day-based lookback, history is limited to the matching time-of-day slot on each prior day. Day-based windows are also supported.

Environment overrides:

- `DQ_PROFILE`
- `DQ_DATABASE`
- `DQ_DAYS_BACK`
- `DQ_START_DATE` / `DQ_END_DATE`
- `DQ_FROM_DATE` / `DQ_TO_DATE`
- `DQ_TABLE_PREFIXES`
- `DQ_TABLE_BLACKLIST`
- `DQ_MAX_EVENT_TABLES`
- `DQ_WORKERS` (default `4`; use `1` for sequential collection)
- `CH_HOST`
- `CH_PORT`
- `CH_USER`
- `CH_PASSWORD`
- `CH_SECURE`
- `CH_MAX_EXECUTION_TIME` (default `120` seconds)
- `CH_SEND_RECEIVE_TIMEOUT` (default is execution timeout plus 30 seconds)

For an exact range, write both dates. The start and end dates are inclusive:

```json
{
  "date_range": "2025-01-01 to 2025-01-31"
}
```

Equivalent object syntax is also supported:
`{"date_range": {"days_back": 7}}`,
`{"date_range": {"start_date": "2025-01-01", "end_date": "2025-01-31"}}`,
and the equivalent `from_date`/`to_date` form.

## Run

From this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item ..\config\personal_config.example.json ..\config\personal_config.json
# Fill ClickHouse host/user/password in ..\config\personal_config.json.
.\.venv\Scripts\python.exe run_pipeline.py
```

The runner exits with `0` for a clean run, `2` when reports were produced with
degraded stage results, and another nonzero code for a fatal stage failure.
An event-table limit that leaves discovered event tables unscanned is treated as
degraded instead of silently producing a partial-success report.

Or run stages manually:

```powershell
.\.venv\Scripts\python.exe scripts\collect_metrics.py
.\.venv\Scripts\python.exe scripts\collect_drilldowns.py
.\.venv\Scripts\python.exe scripts\build_report.py
```

Long ClickHouse queries show a small `|/-\` spinner with elapsed seconds by default. Disable it with:

```powershell
$env:DB_AGENT_SPINNER = "0"
```

Use `$env:DB_AGENT_SPINNER = "auto"` if you only want it in TTY-style terminals.

## Definitions

Definitions live in `..\config\system_agent_config.json` under `quality_definitions`.

- `duplicate`: extra rows sharing normalized `event_time + adid + event_key`
- `replicated`: extra distinct normalized `event_time + adid` occurrences beyond the first occurrence of each `event_key`
- `same_second_burst`: one `adid` has more than N different `event_key` values at the same timestamp
- `suspicious_high`: selected-window row count is above the amount expected from the lookback
- `suspicious_low`: selected-window row count is below the amount expected from the lookback
- `future_event_time`: timestamp exceeds future tolerance
  Temporarily disable it with `"quality_definitions": {"future_event_time": {"enabled": false}}` in your local config.
- `missing_identifier`: `NULL`, empty, all-zero UUID, or string `null`
  The active profile's `main_identifier` (for example, `user_id` or `account_id`) and session identifier (`session_id` or `session_uuid`) can be allowed by `event_groups.missing_main_identifier_allowed` and `event_groups.missing_session_id_allowed`.
- `no_rows`: zero rows in the configured date range
