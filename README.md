# DB AI Agent

Read-only quality and analysis pipeline for configurable ClickHouse databases.

## Components

- [deterministic_pipeline](deterministic_pipeline/README.md): no-AI version with exactly three deterministic scripts plus configs.

Before committing:

```powershell
python tools\check_git_safety.py
```

Create a deterministic ZIP containing Git-tracked and non-ignored files:

```powershell
python tools\make_share_zip.py
```

The archive is written to `dist/db-ai-agent.zip`.

Run the minimum local validation:

```powershell
python -m unittest discover -s tests
python -m compileall -q -x "\\.venv|\\.git" .
python tools\check_git_safety.py
```

## Current Architecture

Run the full quality pipeline with:

```powershell
python run_quality_pipeline.py
```

Long ClickHouse queries and LLM calls show a small `|/-\` spinner with elapsed seconds by default. Disable it with:

```powershell
$env:DB_AGENT_SPINNER = "0"
```

Use `$env:DB_AGENT_SPINNER = "auto"` if you only want it in TTY-style terminals.

Pipeline exit codes are:

- `0`: all stages completed without execution errors.
- `2`: the pipeline completed and wrote reports, but one or more stages recorded
  degraded results such as per-table query errors or an LLM fallback.
- Any other nonzero code: a stage failed before it could complete its artifact.

If the local virtual environment is stale, recreate it and install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_quality_pipeline.py
```

The pipeline is evidence-first: deterministic checks establish the facts, then AI
investigates unresolved causes with read-only SQL:

1. `scan_database_quality.py`
   - Inspects the database surface from `system.tables` and `system.columns`.
   - Discovers every non-materialized parsed table with a supported DateTime
     measurement column (`event_date`, `created_at`, `date`, `startdate`, or
     `loaded_at`); profile prefixes can still narrow this explicitly.
   - Checks broad deterministic baseline signals: future event dates, duplicate `event_date + adid + event_key` rows, missing IDs, same-second bursts, schema warnings, and empty recent tables.
   - Writes stable and timestamped `database_quality_scan` JSON plus `db_inventory_*.csv`.

2. `check_event_quality.py`
   - Runs deterministic known quality checks for the configured rolling hour/day or fixed measurement window.
   - Uses `db_problem_scan.scan_max_event_tables` as its table bound and prioritizes
     the largest active tables. Override with `QUALITY_MAX_EVENT_TABLES`.
   - Uses configured expected behavior from `config/personal_agent_config.json`.
   - Writes `reports/event_quality_*.csv`.

3. `check_parameter_quality.py`
   - Checks configured and inferred system, common, and event parameters.

4. `check_event_flow.py`
   - When source-flow checks are configured, compares source records with target-table rows for the same frozen window.
   - Attributes missing target parameters to source-payload absence or likely parser/column mapping.
   - Classifies missing target events/parameters as low when the matching value is
     present at the source, and critical when it is missing from both source and target.
   - Treats rows in configured failure-path tables as critical evidence.

5. `drill_down_quality_issues.py`
   - Reads the latest quality CSV and drills into flagged tables.
   - Writes duplicate samples, same-second burst samples, missing-ID breakdowns, and drilldown errors.

6. `investigate_database.py`
   - Receives deterministic source-flow evidence and the active DB inventory.
   - Proposes bounded read-only SQL only for unresolved causes.
   - Validates every SQL query against the active profile, allowed tables, and blacklist.
   - Writes stable and timestamped `database_investigation` JSON and text reports.

7. `generate_quality_report.py`
   - Combines the AI-led investigation and deterministic guardrail outputs.
   - Keeps exact metrics deterministic from CSV/JSON artifacts.
   - Uses the LLM only for read-only recommended next checks.

## Configuration

Configuration is layered so the repository can be shared safely:

1. `config/system_agent_config.json`
   - Generic defaults committed to the repository.
   - Contains quality definitions, default thresholds, date range defaults, and generic agent limits.

2. `config/personal_config.json`
   - Local/private runtime settings.
   - Contains ClickHouse connection and LLM endpoint/model/API key.
   - Create it from `config/personal_config.example.json`.
   - This file is ignored by git.

3. `config/personal_agent_config.json`
   - Local deployment-specific agent rules.
   - Contains active DB profile, table blacklist, event groups, event context, and threshold overrides.
   - Create it from `config/personal_agent_config.example.json`.
   - This file is ignored by git.

Main personal agent knobs:

- `active_database_profile`
- `database_profiles`
- `database_profiles.<profile>.main_identifier` (for example, `user_id` or `account_id`)
- `table_blacklist`
- `date_range` (`"1 hour"`, `"2 hours"`, `"7 days"`, or an exact date range)
- `lookback` (`"30 days"` by default)
- `event_groups.same_second_allowed`
- `event_groups.same_second_strict`
- `event_groups.missing_main_identifier_allowed`
- `event_groups.missing_session_id_allowed`
- `ai_db_agent.max_iterations`
- `ai_db_agent.max_queries_per_iteration`
- `db_problem_scan.days_back`
- `db_problem_scan.table_name_prefixes`
- `db_problem_scan.max_tables`
- `db_problem_scan.scan_max_event_tables`
- `db_problem_scan.priority_event_tables`
- `db_problem_scan.skip_missing_main_identifier_tables`
- `drilldown.max_tables`
- `drilldown.missing_id_tables`
- `event_context`
- `thresholds`
- `parameter_quality.auto_discovery`
- `parameter_quality.global_parameters`
- `parameter_quality.tables.<table>.parameters`

Quality definitions live in `config/system_agent_config.json` under `quality_definitions`:

- `duplicate`: extra rows sharing the same `event_date + adid + event_key`.
- `replicated`: extra distinct `event_date + adid` occurrences beyond the first occurrence of each `event_key`.
- `same_second_burst`: one `adid` producing several different `event_key` values at the same timestamp.
- `suspicious_high`: the selected window's row count is at least 20% above the amount expected from the configured lookback.
- `suspicious_low`: the selected window's row count is at least 20% below the amount expected from the configured lookback.
- `future_event_time`: `event_date` is more than the configured tolerance into the future.
  Temporarily disable it with `"quality_definitions": {"future_event_time": {"enabled": false}}` in your local config.
- `missing_identifier`: `NULL`, empty, all-zero UUID, or string `null`.
  The active profile's `main_identifier` (for example, `user_id` or `account_id`) and session identifier (`session_id` or `session_uuid`) can be allowed by `event_groups.missing_main_identifier_allowed` and `event_groups.missing_session_id_allowed`.
  Physical identifier aliases are configured under `quality_definitions.missing_identifier.aliases`.
  The logical `session_id` check accepts `session_id`, `session_uuid`, and `sessions_uuid` by default and counts a row as missing only when every available alias is missing.
- `no_rows`: zero rows in the configured period.

Configurable parameter checks run in `check_parameter_quality.py`. Missing and invalid percentages are always measured inside `date_range`. The separate `lookback` is used to infer whether a parameter is normally required, its normal presence rate, expected count in the current window, and its common historical values. By default, `parameter_quality.auto_discovery` reads every event table schema and checks every non-system column automatically; event-specific parameter lists are not required. System identifiers, timestamps, payload columns, and configured exclusions are skipped. `global_parameters` and `tables.<table>.parameters` refine inferred rules, while `tables.<table>.exclude_parameters` suppresses known optional fields. Rules support `aliases`, `require_column`, `required_value` (`true`, `false`, or `"auto"`), `invalid_values`, `allowed_values`, `allowed_pattern`, `min_value`, `max_value`, `max_missing_pct`, and `max_invalid_pct`. Current and lookback metrics for all parameters from one table are aggregated in one read-only query. `parameter_quality.date_range` is also accepted as a lookback alias.

For a rolling measurement window, use hours or days. The window ends at `now()`:

```json
{
  "date_range": "1 hour",
  "lookback": "30 days"
}
```

`"date_range": "2 hours"` and `"date_range": "1 day"` use the same logic. Event and parameter findings come only from the half-open measurement window `[now() - date_range, now())`; future timestamps are diagnosed separately. For a 1-hour or 2-hour measurement, the 30-day baseline uses the matching time-of-day slot on each prior day, so peak traffic is not compared with an all-day hourly average.

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

Environment overrides:

- `QUALITY_DAYS_BACK`
- `QUALITY_MAX_EVENT_TABLES`
- `AI_AGENT_DAYS_BACK`
- `QUALITY_START_DATE` / `QUALITY_END_DATE`
- `QUALITY_FROM_DATE` / `QUALITY_TO_DATE`
- `AI_AGENT_START_DATE` / `AI_AGENT_END_DATE`
- `AI_AGENT_FROM_DATE` / `AI_AGENT_TO_DATE`

Local LM Studio responses default to `llm.max_tokens = 12000`. Override with `LMSTUDIO_MAX_TOKENS`, `AI_AGENT_MAX_TOKENS`, or `config/personal_config.json` when needed.

Runtime connection settings can stay in `.env` or move to `config/personal_config.json`:

- `CH_HOST`
- `CH_PORT`
- `CH_USER`
- `CH_PASSWORD`
- `CH_SECURE`
- `LMSTUDIO_BASE_URL`
- `LMSTUDIO_MODEL`
- `LMSTUDIO_MAX_TOKENS`
- `AI_AGENT_BASE_URL`
- `AI_AGENT_MODEL`
- `AI_AGENT_MAX_TOKENS`
- `AI_AGENT_API_KEY`
- `DB_AGENT_PROFILE`
- `DB_AGENT_DATABASE`

Set `LMSTUDIO_MODEL` or `AI_AGENT_MODEL` to `active` to use the model currently loaded in LM Studio. If an OSS model is loaded, it is preferred automatically.

`DB_AGENT_PROFILE` switches profiles, for example:

```powershell
$env:DB_AGENT_PROFILE = "clickhouse.analytics"
.\.venv\Scripts\python.exe run_quality_pipeline.py
```

`DB_AGENT_DATABASE` is an explicit one-off override. Otherwise, the active profile's `database` is used.
