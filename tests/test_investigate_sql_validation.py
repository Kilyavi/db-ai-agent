import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import pandas as pd

from investigate_database import (
    ask_model,
    build_final_messages,
    build_planning_messages,
    compact_source_flow_evidence_for_prompt,
    configured_source_tables,
    date_range_prompt_instruction,
    discover_inventory,
    duplicate_investigation_reason,
    execute_investigation,
    execution_note_text,
    load_source_flow_evidence,
    observations_are_degraded,
    render_investigation_report,
    relevant_inventory_for_planner,
    validate_ai_sql,
)


class InvestigateSqlValidationTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "database": "analytics",
            "table_blacklist": [],
        }
        self.inventory = [
            {
                "table": "event_login",
                "columns": ["event_date", "user_id", "session_uuid"],
            }
        ]

    def test_accepts_explicit_readonly_projection(self):
        sql = validate_ai_sql(
            "SELECT count() AS rows FROM event_login LIMIT 10",
            self.config,
            self.inventory,
        )
        self.assertIn("count()", sql)

    def test_rejects_plain_wildcard_projection(self):
        with self.assertRaisesRegex(ValueError, "wildcard projections"):
            validate_ai_sql(
                "SELECT * FROM event_login LIMIT 10",
                self.config,
                self.inventory,
            )

    def test_rejects_wildcard_after_literal_in_union_branch(self):
        with self.assertRaisesRegex(ValueError, "wildcard projections"):
            validate_ai_sql(
                """
                SELECT 'event_login' AS table_name
                FROM event_login
                UNION ALL
                SELECT 'event_login', *
                FROM event_login
                LIMIT 10
                """,
                self.config,
                self.inventory,
            )

    def test_accepts_cte_alias_backed_by_allowed_table(self):
        sql = validate_ai_sql(
            """
            WITH recent AS
            (
                SELECT count() AS rows
                FROM event_login
            )
            SELECT rows
            FROM recent
            LIMIT 10
            """,
            self.config,
            self.inventory,
        )
        self.assertIn("FROM recent", sql)

    def test_rejects_identifier_alias_absent_from_referenced_tables(self):
        with self.assertRaisesRegex(ValueError, "session_id.*expose"):
            validate_ai_sql(
                "SELECT session_id FROM event_login LIMIT 10",
                self.config,
                self.inventory,
            )

    def test_rejects_direct_empty_string_identifier_comparison(self):
        with self.assertRaisesRegex(
            ValueError,
            "must not compare identifier 'session_uuid'",
        ):
            validate_ai_sql(
                "SELECT event_date FROM event_login "
                "WHERE session_uuid IS NULL OR session_uuid = '' LIMIT 10",
                self.config,
                self.inventory,
            )

    def test_accepts_type_safe_identifier_missing_expression(self):
        sql = validate_ai_sql(
            "SELECT countIf(nullIf(trimBoth(toString(session_uuid)), '') IS NULL) "
            "AS missing_session FROM event_login",
            self.config,
            self.inventory,
        )

        self.assertIn("trimBoth(toString(session_uuid))", sql)

    def test_trim_from_separator_is_not_parsed_as_a_table_reference(self):
        sql = validate_ai_sql(
            "SELECT countIf(nullIf(trim(BOTH ' ' FROM toString(session_uuid)), '') "
            "IS NULL) AS missing_session FROM event_login",
            self.config,
            self.inventory,
        )

        self.assertIn("FROM event_login", sql)

    def test_identifier_name_inside_json_key_literal_is_not_a_column(self):
        inventory = [{
            "table": "source_events",
            "columns": ["event_time", "payload"],
        }]
        sql = validate_ai_sql(
            "SELECT countIf(JSONHas(payload, 'session_id') = 0) AS missing "
            "FROM source_events",
            self.config,
            inventory,
        )

        self.assertIn("JSONHas(payload, 'session_id')", sql)

    def test_normalizes_raw_payload_session_identifier_canonical_form(self):
        sql = validate_ai_sql(
            "SELECT count() AS total_rows, "
            "countIf(nullIf(trimBoth(toString(session_id)), '') IS NULL) AS missing "
            "FROM source_events",
            self.config,
            [{"table": "source_events", "columns": ["payload"]}],
        )

        self.assertIn(
            "toString(JSONExtractString(JSONExtractRaw(payload, 'params'), "
            "'session_id'))",
            sql,
        )
        self.assertNotIn("toString(session_id)", sql)

    def test_does_not_normalize_missing_identifier_on_non_raw_table(self):
        with self.assertRaisesRegex(ValueError, "session_id.*expose"):
            validate_ai_sql(
                "SELECT countIf(nullIf(trimBoth(toString(session_id)), '') IS NULL) "
                "FROM event_login",
                self.config,
                self.inventory,
            )

    def test_normalizes_unary_bang_boolean_negation(self):
        sql = validate_ai_sql(
            "SELECT countIf(!JSONHas(payload, 'event')) AS missing, "
            "countIf(value != '!keep') AS other FROM source_events",
            self.config,
            [{"table": "source_events", "columns": ["payload", "value"]}],
        )

        self.assertIn("countIf(NOT JSONHas", sql)
        self.assertIn("value != '!keep'", sql)

    def test_normalizes_model_line_continuations_outside_literals(self):
        sql = validate_ai_sql(
            "SELECT countIf(\\\nJSONHas(payload, 'event')\\\n) AS present "
            "FROM source_events",
            self.config,
            [{"table": "source_events", "columns": ["payload"]}],
        )

        self.assertIn("countIf(\nJSONHas", sql)
        self.assertNotIn("\\\n", sql)

    def test_preserves_backslash_newline_inside_string_literal(self):
        sql = validate_ai_sql(
            "SELECT countIf(value = 'keep\\\nthis') FROM source_events",
            self.config,
            [{"table": "source_events", "columns": ["value"]}],
        )

        self.assertIn("'keep\\\nthis'", sql)

    def test_normalizes_literal_escaped_newlines_outside_literals(self):
        sql = validate_ai_sql(
            "SELECT count() AS total_rows,\\n"
            "countIf(JSONHas(payload, 'event')) AS present\\n"
            "FROM source_events",
            self.config,
            [{"table": "source_events", "columns": ["payload"]}],
        )

        self.assertIn("total_rows,\ncountIf", sql)
        self.assertIn("present\nFROM", sql)
        self.assertNotIn("\\n", sql)

    def test_preserves_literal_backslash_n_inside_string_literal(self):
        sql = validate_ai_sql(
            r"SELECT countIf(value = 'keep\nthis') FROM source_events",
            self.config,
            [{"table": "source_events", "columns": ["value"]}],
        )

        self.assertIn(r"'keep\nthis'", sql)

    def test_normalizes_payload_params_identifier_access(self):
        sql = validate_ai_sql(
            "SELECT countIf(JSONHas(payload.params, 'session_id')) AS present "
            "FROM source_events",
            self.config,
            [{"table": "source_events", "columns": ["event_time", "payload"]}],
        )

        self.assertIn(
            "JSONHas(JSONExtractRaw(payload, 'params'), 'session_id')",
            sql,
        )
        self.assertNotIn("payload.params", sql)

    def test_normalizes_jsonhas_compared_with_string(self):
        sql = validate_ai_sql(
            "SELECT count() FROM source_events_dlq "
            "WHERE JSONHas(payload, 'event', 'name') = 'namespace.event_player_ping'",
            self.config,
            [{"table": "source_events_dlq", "columns": ["event_time", "payload"]}],
        )

        self.assertIn(
            "JSONExtractString(payload, 'event', 'name') = 'namespace.event_player_ping'",
            sql,
        )
        self.assertNotIn("JSONHas(payload, 'event', 'name')", sql)

    def test_normalizes_iso_dlq_rejected_at_datetime(self):
        sql = validate_ai_sql(
            "SELECT min(toDateTime(JSONExtractString(payload, 'rejectedAt'))) "
            "FROM source_events_dlq",
            self.config,
            [{"table": "source_events_dlq", "columns": ["event_time", "payload"]}],
        )

        self.assertIn(
            "parseDateTime64BestEffortOrNull("
            "JSONExtractString(payload, 'rejectedAt'))",
            sql,
        )
        self.assertNotIn(
            "toDateTime(JSONExtractString(payload, 'rejectedAt'))",
            sql,
        )

    def test_normalizes_validation_errors_array_size(self):
        sql = validate_ai_sql(
            "SELECT countIf(arraySize(JSONExtractRaw(payload, 'validationErrors')) > 0) "
            "AS rows_with_errors FROM source_events_dlq",
            self.config,
            [{"table": "source_events_dlq", "columns": ["event_time", "payload"]}],
        )

        self.assertIn(
            "length(JSONExtract(payload, 'validationErrors', 'Array(String)')) > 0",
            sql,
        )
        self.assertNotIn("arraySize", sql)

    def test_rejects_unbalanced_parentheses_before_execution(self):
        with self.assertRaisesRegex(ValueError, "unbalanced parentheses"):
            validate_ai_sql(
                "SELECT countIf(isNull(payload) + countIf(isNull(payload)) "
                "FROM source_events_dlq",
                self.config,
                [{"table": "source_events_dlq", "columns": ["event_time", "payload"]}],
            )

    def test_raw_event_type_must_match_deterministic_source_type(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "mandatory_inventory_tables": ["source_events", "source_events_dlq"],
            "source_flow_evidence": {
                "raw_event_types": [{
                    "event_table": "event_player_ping",
                    "source_type": "event_player_ping",
                }],
            },
        }
        inventory = [{
            "table": "source_events",
            "columns": ["event_time", "payload", "type"],
        }]

        with self.assertRaisesRegex(ValueError, "unknown source type"):
            validate_ai_sql(
                "SELECT countIf(type = 'player_ping') FROM source_events",
                config,
                inventory,
            )

        sql = validate_ai_sql(
            "SELECT count() FROM source_events WHERE type = 'event_player_ping'",
            config,
            inventory,
        )
        self.assertIn("type = 'event_player_ping'", sql)

    def test_normalizes_missing_physical_type_on_single_dlq(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "mandatory_inventory_tables": ["source_events", "source_events_dlq"],
        }
        inventory = [{
            "table": "source_events_dlq",
            "columns": ["event_time", "payload"],
        }]

        sql = validate_ai_sql(
            "SELECT type, count() FROM source_events_dlq GROUP BY type",
            config,
            inventory,
        )

        self.assertNotIn("SELECT type", sql)
        self.assertIn("JSONExtractString(payload, 'event', 'name')", sql)

    def test_scalar_dlq_subquery_requires_its_own_measurement_window(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "mandatory_inventory_tables": ["source_events", "source_events_dlq"],
            "date_range": {
                "mode": "rolling",
                "interval_value": 1,
                "interval_unit": "day",
                "duration_seconds": 86400,
                "description": "last 1 day",
            },
        }
        inventory = [
            {
                "table": "source_events",
                "columns": ["event_time", "payload", "type"],
            },
            {
                "table": "source_events_dlq",
                "columns": ["event_time", "payload"],
            },
        ]

        window = (
            "event_time >= toDateTime('2026-08-05 22:02:55') - INTERVAL 1 DAY "
            "AND event_time < toDateTime('2026-08-05 22:02:55')"
        )
        with patch.dict(
            "os.environ",
            {"QUALITY_REFERENCE_TIME": "2026-08-05 22:02:55"},
        ):
            with self.assertRaisesRegex(
                ValueError,
                "exact configured event_time predicate in every SELECT scope",
            ):
                validate_ai_sql(
                    "SELECT count() AS raw_rows, "
                    "(SELECT count() FROM source_events_dlq) AS dlq_rows "
                    "FROM source_events WHERE type = 'event_player_ping' AND " + window,
                    config,
                    inventory,
                )

    def test_accepts_raw_type_in_union_with_payload_filtered_dlq(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "mandatory_inventory_tables": ["source_events", "source_events_dlq"],
            "date_range": {
                "mode": "rolling",
                "interval_value": 1,
                "interval_unit": "day",
                "duration_seconds": 86400,
                "description": "last 1 day",
            },
        }
        inventory = [
            {
                "table": "source_events",
                "columns": ["event_time", "payload", "type"],
            },
            {
                "table": "source_events_dlq",
                "columns": ["event_time", "payload"],
            },
        ]

        window = (
            "event_time >= toDateTime('2026-08-05 22:02:55') - INTERVAL 1 DAY "
            "AND event_time < toDateTime('2026-08-05 22:02:55')"
        )
        with patch.dict(
            "os.environ",
            {"QUALITY_REFERENCE_TIME": "2026-08-05 22:02:55"},
        ):
            sql = validate_ai_sql(
                "SELECT 'raw' AS source, count() FROM source_events "
                "WHERE type = 'event_player_ping' AND " + window + " UNION ALL "
                "SELECT 'dlq' AS source, count() FROM source_events_dlq "
                "WHERE JSONExtractString(payload, 'event', 'name') = "
                "'namespace.event_player_ping' AND " + window,
                config,
                inventory,
            )

        self.assertIn("type = 'event_player_ping'", sql)
        self.assertIn("JSONExtractString(payload, 'event', 'name')", sql)

    def test_rejects_type_in_payload_only_dlq_union_branch(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "mandatory_inventory_tables": ["source_events", "source_events_dlq"],
        }
        inventory = [
            {
                "table": "source_events",
                "columns": ["event_time", "payload", "type"],
            },
            {
                "table": "source_events_dlq",
                "columns": ["event_time", "payload"],
            },
        ]

        with self.assertRaisesRegex(ValueError, "physical column 'type'"):
            validate_ai_sql(
                "SELECT count() FROM source_events WHERE type = 'event_player_ping' "
                "UNION ALL SELECT count() FROM source_events_dlq "
                "WHERE type = 'namespace.event_player_ping'",
                config,
                inventory,
            )

    def test_blacklisted_name_in_literal_does_not_blacklist_allowed_raw_table(self):
        config = {
            "database": "analytics",
            "table_blacklist": ["back_shop_exchange"],
        }
        inventory = [{
            "table": "source_events_dlq",
            "columns": ["event_time", "type", "payload"],
        }]

        sql = validate_ai_sql(
            "SELECT count() AS rows FROM analytics.source_events_dlq "
            "WHERE type = 'back_shop_exchange' LIMIT 10",
            config,
            inventory,
        )

        self.assertIn("source_events_dlq", sql)

    def test_rejects_blacklisted_referenced_table(self):
        config = {
            "database": "analytics",
            "table_blacklist": ["back_shop_exchange"],
        }
        inventory = [{
            "table": "back_shop_exchange",
            "columns": ["event_date"],
        }]

        with self.assertRaisesRegex(ValueError, "blacklisted table"):
            validate_ai_sql(
                "SELECT count() AS rows FROM analytics.back_shop_exchange LIMIT 10",
                config,
                inventory,
            )

    def test_date_range_prompt_names_raw_event_time_explicitly(self):
        instruction = date_range_prompt_instruction({
            "mode": "rolling",
            "interval_value": 1,
            "interval_unit": "hour",
            "duration_seconds": 3600,
            "description": "last 1 hour",
        })

        self.assertIn("source_events, source_events_dlq, and partner_events_dlq", instruction)
        self.assertIn("event_time >=", instruction)
        self.assertIn("Never use event_date for a raw source or DLQ table", instruction)

    def test_reports_impossible_datetime_literal_as_medium_problem(self):
        with patch("investigate_database.query_df") as query_df_mock:
            observation = execute_investigation(
                {
                    "id": "bad_generated_date",
                    "tables": ["source_events"],
                    "sql": "SELECT count() FROM source_events "
                    "WHERE event_time < toDateTime('2026-08-55 22:02:55')",
                },
                self.config,
                [{"table": "source_events", "columns": ["event_time"]}],
            )

        query_df_mock.assert_not_called()
        self.assertEqual("problem", observation["status"])
        self.assertEqual("medium", observation["priority"])
        self.assertEqual("invalid_datetime_literal", observation["problem_code"])
        self.assertEqual("2026-08-55 22:02:55", observation["invalid_value"])
        self.assertIn("impossible datetime literal", observation["reason"])
        self.assertTrue(observations_are_degraded([observation]))

    def test_requires_exact_frozen_measurement_window(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "date_range": {
                "mode": "rolling",
                "interval_value": 1,
                "interval_unit": "day",
                "duration_seconds": 86400,
                "description": "last 1 day",
            },
        }
        inventory = [{"table": "source_events", "columns": ["event_time"]}]

        with patch.dict(
            "os.environ",
            {"QUALITY_REFERENCE_TIME": "2026-08-05 22:02:55"},
        ):
            accepted = validate_ai_sql(
                "SELECT count() FROM source_events WHERE "
                "event_time >= toDateTime('2026-08-05 22:02:55') - INTERVAL 1 DAY "
                "AND event_time < toDateTime('2026-08-05 22:02:55')",
                config,
                inventory,
            )
            self.assertIn("INTERVAL 1 DAY", accepted)

            with self.assertRaisesRegex(
                ValueError,
                "exact configured event_time predicate",
            ):
                validate_ai_sql(
                    "SELECT count() FROM source_events WHERE "
                    "event_time >= toDateTime('2026-08-04 22:02:55') - INTERVAL 1 DAY "
                    "AND event_time < toDateTime('2026-08-05 22:02:55')",
                    config,
                    inventory,
                )

    def test_repairs_one_character_truncation_of_configured_window_literal(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "date_range": {
                "mode": "rolling",
                "interval_value": 1,
                "interval_unit": "hour",
                "duration_seconds": 3600,
                "description": "last 1 hour",
            },
        }
        inventory = [{"table": "source_events", "columns": ["event_time"]}]

        with patch.dict(
            "os.environ",
            {"QUALITY_REFERENCE_TIME": "2026-08-06T18:28:42+04:00"},
        ):
            accepted = validate_ai_sql(
                "SELECT count() FROM source_events WHERE "
                "event_time >= parseDateTime64BestEffort('2026-08-06T18:28:42+04:00') "
                "- INTERVAL 1 HOUR AND "
                "event_time < parseDateTime64BestEffort('2026-08-06T18:28:42+04:0')",
                config,
                inventory,
            )

        self.assertIn("'2026-08-06T18:28:42+04:00'", accepted)
        self.assertNotIn("'2026-08-06T18:28:42+04:0'", accepted)

    def test_does_not_repair_different_measurement_timestamp(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "date_range": {
                "mode": "rolling",
                "interval_value": 1,
                "interval_unit": "hour",
                "duration_seconds": 3600,
                "description": "last 1 hour",
            },
        }
        inventory = [{"table": "source_events", "columns": ["event_time"]}]

        with patch.dict(
            "os.environ",
            {"QUALITY_REFERENCE_TIME": "2026-08-06T18:28:42+04:00"},
        ):
            with self.assertRaisesRegex(
                ValueError,
                "exact configured event_time predicate",
            ):
                validate_ai_sql(
                    "SELECT count() FROM source_events WHERE "
                    "event_time >= parseDateTime64BestEffort('2026-08-06T17:28:42+04:00') "
                    "- INTERVAL 1 HOUR AND "
                    "event_time < parseDateTime64BestEffort('2026-08-06T17:28:42+04:0')",
                    config,
                    inventory,
                )

    def test_normalizes_payload_params_path_for_single_legacy_dlq(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "mandatory_inventory_tables": ["source_events", "source_events_dlq"],
            "source_flow_evidence": {
                "dlq_summary": [{
                    "dlq_source_table": "source_events_dlq",
                    "dlq_shape": "legacy_event_envelope",
                }],
            },
        }
        inventory = [{
            "table": "source_events_dlq",
            "columns": ["event_time", "payload"],
        }]

        sql = validate_ai_sql(
            "SELECT countIf(JSONHas(payload, 'params', 'session_id')) "
            "FROM source_events_dlq",
            config,
            inventory,
        )

        self.assertIn(
            "JSONHas(payload, 'event', 'parameters', 'session_id')",
            sql,
        )
        self.assertNotIn("payload, 'params'", sql)

    def test_rejects_dlq_query_when_deterministic_window_has_no_rows(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "mandatory_inventory_tables": ["source_events", "partner_events_dlq"],
            "source_flow_evidence": {
                "status": "available",
                "dlq_summary": [],
            },
        }

        with self.assertRaisesRegex(ValueError, "zero rows in deterministic evidence"):
            validate_ai_sql(
                "SELECT count() AS total_rows FROM partner_events_dlq",
                config,
                [{
                    "table": "partner_events_dlq",
                    "columns": ["event_time", "payload"],
                }],
            )

    def test_zero_only_raw_aggregate_is_inconclusive_without_total_rows(self):
        config = {
            "database": "analytics",
            "table_blacklist": [],
            "mandatory_inventory_tables": ["source_events"],
            "result_preview_rows": 3,
        }
        inventory = [{
            "table": "source_events",
            "columns": ["payload"],
        }]

        with patch(
            "investigate_database.query_df",
            return_value=pd.DataFrame([{"json_ok": 0, "session_present": 0}]),
        ):
            observation = execute_investigation(
                {
                    "id": "zero_payload_metrics",
                    "tables": ["source_events"],
                    "sql": "SELECT countIf(isValidJSON(payload)) AS json_ok, "
                    "countIf(JSONHas(payload, 'params')) AS session_present "
                    "FROM source_events",
                },
                config,
                inventory,
            )

        self.assertEqual("inconclusive", observation["status"])
        self.assertTrue(observations_are_degraded([observation]))

    def test_deterministic_investigation_report_excludes_non_evidence(self):
        observations = [{
            "id": "good_count",
            "status": "ok",
            "tables": ["source_events"],
            "rows_returned": 1,
            "preview": [{"total_rows": "12"}],
        }, {
            "id": "bad_window",
            "status": "rejected",
            "rejection_reason": "wrong window",
        }]

        report = render_investigation_report(
            {"date_range": {"description": "last 1 day"}},
            observations,
        )

        self.assertIn("Observation statuses: ok=1, rejected=1", report)
        self.assertIn("Successful observations", report)
        self.assertIn("Excluded from evidence", report)
        self.assertNotIn("Critical missing-event", report)

    def test_deterministic_investigation_report_includes_medium_query_problem(self):
        report = render_investigation_report(
            {"date_range": {"description": "last 1 day"}},
            [{
                "id": "bad_generated_date",
                "status": "problem",
                "priority": "medium",
                "problem_code": "invalid_datetime_literal",
                "reason": "AI SQL contains an impossible datetime literal: "
                "'2026-08-55 22:02:55'; the query was not executed.",
            }],
        )

        self.assertIn("Observation statuses: problem=1", report)
        self.assertIn("AI query problems", report)
        self.assertIn("MEDIUM `bad_generated_date`", report)
        self.assertIn("2026-08-55 22:02:55", report)
        self.assertNotIn("Excluded from evidence", report)

    def test_duplicate_investigations_skip_successful_id_or_identical_sql(self):
        by_id = duplicate_investigation_reason(
            {"id": "payload_shape", "sql": "SELECT count() FROM source_events"},
            {"payload_shape"},
            set(),
        )
        by_sql = duplicate_investigation_reason(
            {
                "id": "renamed_check",
                "sql": " SELECT   count() FROM source_events; ",
            },
            set(),
            {"select count() from source_events"},
        )

        self.assertIn("already succeeded", by_id)
        self.assertIn("already executed", by_sql)
        self.assertFalse(observations_are_degraded([{"status": "skipped_duplicate"}]))

    def test_configured_source_tables_include_raw_and_dlq_defaults(self):
        self.assertEqual(
            ["source_events", "source_events_dlq"],
            configured_source_tables({}),
        )

    def test_configured_source_tables_include_every_configured_dlq(self):
        self.assertEqual(
            ["source_events", "source_events_dlq", "partner_events_dlq"],
            configured_source_tables({
                "source_flow": {
                    "raw_table": "source_events",
                    "dlq_tables": ["source_events_dlq", "partner_events_dlq"],
                }
            }),
        )

    def test_planner_compacts_parameter_evidence_and_unrelated_inventory(self):
        evidence = {
            "status": "available",
            "summary": {"critical_parameter_issues": 20},
            "critical_event_flows": [],
            "low_event_flows": [],
            "parameter_source_comparisons": [
                {
                    "event_table": f"event_{index}",
                    "parameter": "session_id",
                    "raw_rows": 10,
                    "raw_presence_pct": 1.0,
                    "unneeded_large_field": "x" * 1000,
                }
                for index in range(20)
            ],
            "raw_event_types": [],
            "dlq_summary": [],
        }
        compact = compact_source_flow_evidence_for_prompt(evidence)
        inventory = [
            {"table": "source_events"},
            {"table": "event_0"},
            {"table": "unrelated"},
        ]
        selected = relevant_inventory_for_planner(
            inventory,
            {"mandatory_inventory_tables": ["source_events"]},
            compact,
        )

        self.assertEqual(12, len(compact["parameter_source_comparisons"]))
        self.assertNotIn(
            "unneeded_large_field",
            compact["parameter_source_comparisons"][0],
        )
        self.assertEqual(["source_events", "event_0"], [item["table"] for item in selected])

    def test_inventory_always_discovers_configured_source_tables(self):
        frame = pd.DataFrame([
            {
                "table": "source_events",
                "engine": "MergeTree",
                "estimated_rows": 100,
                "column_count": 2,
                "columns": ["event_time", "payload"],
            },
            {
                "table": "source_events_dlq",
                "engine": "MergeTree",
                "estimated_rows": 5,
                "column_count": 3,
                "columns": ["event_time", "payload", "mode"],
            },
        ])
        config = {
            "database": "analytics",
            "table_name_prefixes": ["event_"],
            "mandatory_inventory_tables": ["source_events", "source_events_dlq"],
            "max_inventory_tables": 10,
            "table_blacklist": [],
            "rules": {},
        }

        with patch("investigate_database.query_df", return_value=frame) as query:
            inventory = discover_inventory(config)

        sql = query.call_args.args[0]
        self.assertIn("c.table IN ('source_events', 'source_events_dlq')", sql)
        self.assertIn(
            "ORDER BY table IN ('source_events', 'source_events_dlq') DESC",
            sql,
        )
        self.assertEqual(
            ["source_events", "source_events_dlq"],
            [item["table"] for item in inventory],
        )
        self.assertTrue(all(item["has_event_time"] for item in inventory))

    def test_planner_gives_safe_identifier_and_raw_payload_sql_shapes(self):
        config = {
            "profile": {
                "table_blacklist": [],
                "same_second_allowed_tables": [],
                "same_second_strict_tables": [],
            },
            "database": "analytics",
            "date_range": {
                "mode": "rolling",
                "interval_value": 1,
                "interval_unit": "day",
                "duration_seconds": 86400,
                "description": "last 1 day",
            },
            "source_flow_evidence": {"status": "available"},
            "max_queries_per_iteration": 3,
        }
        messages = build_planning_messages(config, [], [], 1)
        prompt = "\n".join(message["content"] for message in messages)

        self.assertIn(
            "countIf(nullIf(trimBoth(toString(session_id)), '') IS NULL)",
            prompt,
        )
        self.assertIn("payload-shape labels such as dlq_shape are derived", prompt)
        self.assertIn("never nest countIf inside countIf", prompt)
        self.assertIn("never wrap it in sum, count", prompt)
        self.assertIn("Never use GROUP BY 1", prompt)
        self.assertIn("do not query or join that missing table", prompt)
        self.assertIn("filtering payload.event.name", prompt)
        self.assertIn("parameter at the payload root", prompt)
        self.assertIn("Never write payload.params as SQL identifier access", prompt)
        self.assertIn("JSONHas(payload, 'params', 'session_id')", prompt)
        self.assertIn("never reference session_id, session_uuid, or sessions_uuid", prompt)
        self.assertIn("do not substitute partner_events for partner_events_dlq", prompt)
        self.assertIn("exact source_type", prompt)
        self.assertIn("critical_event_flow with raw_rows=0", prompt)
        self.assertIn("source_type mapping exists in raw_event_types", prompt)
        self.assertIn("Never use unary !", prompt)
        self.assertIn("DLQ inventories may have no physical type column", prompt)
        self.assertIn("same-second burst, not", prompt)
        self.assertIn("namespace.event_player_ping", prompt)
        self.assertIn("payload.event.parameters", prompt)
        self.assertIn("payload.validationErrors", prompt)
        self.assertIn("payload.rejectedAt", prompt)
        self.assertIn("AS missing_session_ids", prompt)
        self.assertIn("branch and scalar subquery", prompt)
        self.assertIn(
            "length(JSONExtract(payload, 'validationErrors', 'Array(String)')) > 0",
            prompt,
        )
        self.assertIn("Never use arraySize", prompt)

    def test_planning_retry_includes_exact_prior_error(self):
        config = {
            "profile": {
                "table_blacklist": [],
                "same_second_allowed_tables": [],
                "same_second_strict_tables": [],
            },
            "database": "analytics",
            "date_range": {
                "mode": "rolling",
                "interval_value": 1,
                "interval_unit": "day",
                "duration_seconds": 86400,
                "description": "last 1 day",
            },
            "source_flow_evidence": {"status": "available"},
            "max_queries_per_iteration": 3,
        }
        messages = build_planning_messages(
            config,
            [],
            [{
                "id": "bad_parentheses",
                "status": "rejected",
                "rejection_reason": "AI SQL has unbalanced parentheses",
            }],
            2,
        )
        prompt = "\n".join(message["content"] for message in messages)

        self.assertIn("reason=AI SQL has unbalanced parentheses", prompt)

    def test_final_prompt_does_not_expose_rejected_attempts(self):
        config = {
            "profile": {
                "same_second_allowed_tables": [],
                "same_second_strict_tables": [],
            },
            "source_flow_evidence": {"status": "available"},
        }
        observations = [{
            "id": "rejected_secret_hypothesis",
            "status": "rejected",
            "tables": ["source_events_dlq"],
        }]

        messages = build_final_messages(config, [], observations)
        prompt = "\n".join(message["content"] for message in messages)

        self.assertNotIn("rejected_secret_hypothesis", prompt)
        self.assertNotIn("source_events_dlq\"", prompt)
        self.assertEqual(
            "Execution notes\n- 1 rejected AI attempt was omitted because it is not evidence.",
            execution_note_text(observations),
        )

    def test_supplied_llm_config_skips_model_rediscovery(self):
        response = MagicMock()
        response.read.return_value = (
            b'{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}'
        )
        context = MagicMock()
        context.__enter__.return_value = response
        context.__exit__.return_value = False

        with (
            patch("investigate_database.get_llm_config") as get_config,
            patch("investigate_database.urllib.request.urlopen", return_value=context),
            patch.dict("os.environ", {"DB_AGENT_SPINNER": "0"}),
        ):
            result = ask_model(
                [],
                llm_config={
                    "base_url": "http://localhost:1234/v1",
                    "model": "test-model",
                    "api_key": None,
                    "max_tokens": 10,
                },
            )

        self.assertEqual("ok", result)
        get_config.assert_not_called()

    def test_ai_investigator_loads_current_source_flow_evidence(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "event_flow_run-1.json"
            path.write_text(
                json.dumps({
                    "summary": {"critical_event_flows": 1, "low_event_flows": 1},
                    "flow_results": [{
                        "event_table": "event_revenue",
                        "status": ["low_raw_seen_but_parsed_missing"],
                        "severity": "low",
                    }, {
                        "event_table": "app_login",
                        "status": ["critical_event_not_received"],
                        "severity": "critical",
                    }],
                    "parameter_results": [],
                    "raw_event_summary": [{
                        "event_table": "event_revenue",
                        "source_type": "namespace.event_revenue",
                        "raw_rows": 12,
                    }],
                    "dlq_summary": [],
                }),
                encoding="utf-8",
            )
            with (
                patch("investigate_database.REPORT_DIR", Path(directory)),
                patch.dict(os.environ, {"QUALITY_RUN_ID": "run-1"}, clear=False),
            ):
                evidence = load_source_flow_evidence()

        self.assertEqual("available", evidence["status"])
        self.assertEqual(
            "app_login",
            evidence["critical_event_flows"][0]["event_table"],
        )
        self.assertEqual(
            "event_revenue",
            evidence["low_event_flows"][0]["event_table"],
        )
        self.assertEqual(
            "namespace.event_revenue",
            evidence["raw_event_types"][0]["source_type"],
        )


if __name__ == "__main__":
    unittest.main()
