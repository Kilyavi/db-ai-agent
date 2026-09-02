import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

import check_parameter_quality
from quality_config import get_identifier_aliases


class ParameterQualityTests(unittest.TestCase):
    def test_problem_console_summary_is_safe_for_cp1252(self):
        class Cp1252Stream(io.StringIO):
            @property
            def encoding(self):
                return "cp1252"

        frame = pd.DataFrame([{
            "event_table": "event_event",
            "parameter": "reward_name",
            "status": "problem",
            "problem": "missing_values_Ж",
        }])
        stream = Cp1252Stream()

        with patch.object(check_parameter_quality.sys, "stdout", stream):
            check_parameter_quality.print_problem_summary(frame)

        self.assertIn("missing_values_?", stream.getvalue())

    def test_discovery_skips_materialized_views(self):
        captured = []
        with patch.object(
            check_parameter_quality,
            "query_df",
            side_effect=lambda sql: captured.append(sql) or pd.DataFrame(),
        ):
            self.assertEqual(
                [],
                check_parameter_quality.discover_tables("analytics", []),
            )

        self.assertIn("t.engine != 'MaterializedView'", captured[0])

    def test_default_session_identifier_aliases_cover_both_spellings(self):
        rules = {"quality_definitions": {"missing_identifier": {}}}
        self.assertEqual(
            ["session_id", "session_uuid", "sessions_uuid"],
            get_identifier_aliases("session_id", rules),
        )

    def test_duplicate_session_profile_entries_collapse_to_session_id(self):
        contract = {
            "schema_version": 3,
            "system_parameters": {
                "session_id": ["String", ["id-value"], "extreme"],
                "session_uuid": ["String", ["uuid-value"], "extreme"],
            },
            "events": {"event_login": {"parameters": {}}},
        }

        parameters = check_parameter_quality.profile_parameters(
            contract,
            "event_login",
            {"event_date", "session_id", "session_uuid"},
        )

        self.assertEqual(["session_id"], list(parameters))
        self.assertEqual(
            ["session_id", "session_uuid", "sessions_uuid"],
            parameters["session_id"]["aliases"],
        )
        self.assertEqual(["id-value"], parameters["session_id"]["examples"])

    def test_alias_expression_prefers_valid_value_and_retains_all_invalid_fallback(self):
        expression, source_columns = check_parameter_quality.parameter_value_expression(
            {"session_id", "session_uuid"},
            ["session_id", "session_uuid"],
            {"invalid_values": ["broken"]},
            [],
        )

        self.assertEqual(["session_id", "session_uuid"], source_columns)
        self.assertIn("lower(", expression)
        self.assertIn("'broken'", expression)
        self.assertEqual(2, expression.count("coalesce("))
        self.assertTrue(expression.endswith("))"))

    def test_region_rule_counts_nonempty_placeholder_as_invalid(self):
        config = {
            "date_range": {"mode": "rolling", "days_back": 30, "description": "last 30 days"},
            "default_invalid_values": ["N/A", "unknown"],
            "default_max_missing_pct": 0.0,
            "default_max_invalid_pct": 0.0,
            "top_values_limit": 10,
            "auto_discovery": {
                "required_min_presence_pct": 0.95,
                "flag_unpopulated": True,
            },
        }
        captured = []

        def fake_query(sql):
            captured.append(sql)
            return pd.DataFrame([{
                "rows_checked": 100,
                "missing_0": 0,
                "invalid_0": 2,
                "observed_0": ["RU", "N/A"],
            }])

        with patch.object(check_parameter_quality, "query_df", side_effect=fake_query):
            result = check_parameter_quality.check_parameter(
                database="analytics",
                table="event_task",
                parameter="region",
                rule={"allowed_pattern": "^[A-Z]{2}$"},
                columns={"event_date", "region"},
                config=config,
            )

        self.assertEqual("problem", result["status"])
        self.assertEqual("invalid_values", result["problem"])
        self.assertIn("lower(`parameter_0`) IN ('n/a', 'unknown')", captured[0])
        self.assertIn("NOT match(`parameter_0`, '^[A-Z]{2}$')", captured[0])
        self.assertIn("INTERVAL 30 DAY", captured[0])

    def test_schema_columns_are_discovered_without_table_parameter_list(self):
        config = {
            "auto_discovery": {
                "enabled": True,
                "exclude_columns": [
                    "event_date",
                    "event_key",
                    "adid",
                    "session_id",
                    "meta_data_jsonb",
                ],
                "exclude_patterns": ["*_json"],
                "default_rule": {"required_value": "auto"},
            },
            "global_parameters": {
                "region": {"allowed_pattern": "^[A-Z]{2}$"},
            },
            "tables": {},
        }

        rules = check_parameter_quality.rules_for_table(
            config,
            "event_task",
            {
                "event_date",
                "event_key",
                "adid",
                "session_id",
                "meta_data_jsonb",
                "region",
                "value",
                "money",
                "step",
            },
        )

        self.assertEqual({"money", "region", "step", "value"}, set(rules))
        self.assertEqual("auto", rules["money"]["required_value"])
        self.assertEqual("^[A-Z]{2}$", rules["region"]["allowed_pattern"])

    def test_configured_missing_main_identifier_is_not_treated_as_missing_problem(self):
        config = {
            "auto_discovery": {
                "enabled": False,
                "exclude_columns": [],
                "exclude_patterns": [],
                "default_rule": {},
            },
            "global_parameters": {},
            "tables": {},
            "parameter_missing_thresholds": {},
            "parameter_invalid_thresholds": {},
        }
        project_rules = {
            "event_context": {
                "event_enter": {"skip_main_identifier_check": True},
            },
        }

        rules = check_parameter_quality.rules_for_table(
            config,
            "event_enter",
            {"event_date", "user_id"},
            contract_parameters={
                "user_id": {
                    "required_value": True,
                    "max_missing_pct": 0.0,
                },
            },
            project_rules=project_rules,
        )

        self.assertEqual(1.0, rules["user_id"]["max_missing_pct"])
        self.assertTrue(rules["user_id"]["_missing_allowed_by_config"])

    def test_multiple_discovered_parameters_share_one_query(self):
        config = {
            "date_range": {"mode": "rolling", "days_back": 30, "description": "last 30 days"},
            "default_invalid_values": ["N/A"],
            "default_max_missing_pct": 0.0,
            "default_max_invalid_pct": 0.0,
            "top_values_limit": 10,
        }
        captured = []

        def fake_query(sql):
            captured.append(sql)
            return pd.DataFrame([{
                "rows_checked": 10,
                "missing_0": 10,
                "invalid_0": 0,
                "observed_0": ["<MISSING>"],
                "missing_1": 10,
                "invalid_1": 0,
                "observed_1": ["<MISSING>"],
                "missing_2": 10,
                "invalid_2": 0,
                "observed_2": ["<MISSING>"],
            }])

        with patch.object(check_parameter_quality, "query_df", side_effect=fake_query):
            results = check_parameter_quality.check_parameters(
                "analytics",
                "event_task",
                {
                    "value": {"required_value": True},
                    "money": {"required_value": True},
                    "step": {"required_value": True},
                },
                {"event_date", "value", "money", "step"},
                config,
            )

        self.assertEqual(1, len(captured))
        self.assertEqual(3, len(results))
        self.assertTrue(all(result["status"] == "problem" for result in results))
        self.assertIn("`parameter_2`", captured[0])

    def test_wide_parameter_sets_are_split_into_bounded_queries(self):
        config = {
            "date_range": {
                "mode": "rolling",
                "days_back": 30,
                "description": "last 30 days",
            },
            "default_invalid_values": [],
            "default_max_missing_pct": 0.0,
            "default_max_invalid_pct": 0.0,
            "top_values_limit": 10,
        }
        captured = []

        def fake_query(sql):
            captured.append(sql)
            return pd.DataFrame([{"rows_checked": 10}])

        parameter_rules = {
            f"parameter_{index}": {"required_value": True}
            for index in range(5)
        }
        columns = {"event_date", *parameter_rules}
        with (
            patch.object(check_parameter_quality, "PARAMETER_QUERY_BATCH_SIZE", 2),
            patch.object(check_parameter_quality, "query_df", side_effect=fake_query),
        ):
            results = check_parameter_quality.check_parameters(
                "analytics",
                "wide_event",
                parameter_rules,
                columns,
                config,
            )

        self.assertEqual(3, len(captured))
        self.assertEqual(list(parameter_rules), [row["parameter"] for row in results])
        self.assertNotIn("parameter_2", captured[0])
        self.assertIn("parameter_2", captured[1])

    def test_measurement_uses_hour_window_and_requiredness_uses_lookback(self):
        config = {
            "date_range": {
                "mode": "rolling",
                "interval_value": 2,
                "interval_unit": "hour",
                "hours_back": 2,
                "duration_seconds": 7200,
                "description": "last 2 hours",
            },
            "lookback": {
                "mode": "rolling",
                "interval_value": 30,
                "interval_unit": "day",
                "days_back": 30,
                "duration_seconds": 2592000,
                "description": "last 30 days",
            },
            "default_invalid_values": [],
            "default_max_missing_pct": 0.0,
            "default_max_invalid_pct": 0.0,
            "top_values_limit": 10,
            "auto_discovery": {
                "required_min_presence_pct": 0.95,
                "flag_unpopulated": True,
            },
        }
        captured = []

        with patch.object(
            check_parameter_quality,
            "query_df",
            side_effect=lambda sql: captured.append(sql) or pd.DataFrame([{
                "rows_checked": 100,
                "lookback_rows_checked": 1000,
                "missing_0": 20,
                "invalid_0": 0,
                "observed_0": ["purchase", "<MISSING>"],
                "lookback_missing_0": 10,
                "lookback_invalid_0": 0,
                "lookback_observed_0": ["purchase"],
            }]),
        ):
            result = check_parameter_quality.check_parameter(
                database="analytics",
                table="event_purchase",
                parameter="event_name",
                rule={"required_value": "auto"},
                columns={"event_date", "event_name"},
                config=config,
            )

        self.assertIn("now() - INTERVAL 2 HOUR", captured[0])
        self.assertIn(
            "WHERE `event_date` >= now() - INTERVAL 2 HOUR - INTERVAL 30 DAY",
            captured[0],
        )
        self.assertIn(
            "`__event_time` < now() - INTERVAL 2 HOUR",
            captured[0],
        )
        self.assertNotIn("PREWHERE", captured[0])
        self.assertTrue(result["inferred_required"])
        self.assertEqual(0.99, result["lookback_presence_pct"])
        self.assertEqual(99.0, result["expected_present_rows"])
        self.assertEqual("missing_values", result["problem"])

    def test_auto_required_ignores_rare_optional_but_flags_unpopulated(self):
        config = {
            "date_range": {"mode": "rolling", "days_back": 30, "description": "last 30 days"},
            "default_invalid_values": [],
            "default_max_missing_pct": 0.0,
            "default_max_invalid_pct": 0.0,
            "top_values_limit": 10,
            "auto_discovery": {
                "required_min_presence_pct": 0.95,
                "flag_unpopulated": True,
            },
        }

        with patch.object(
            check_parameter_quality,
            "query_df",
            return_value=pd.DataFrame([{
                "rows_checked": 100,
                "missing_0": 99,
                "invalid_0": 0,
                "observed_0": ["<MISSING>", "1.19.0"],
                "missing_1": 100,
                "invalid_1": 0,
                "observed_1": ["<MISSING>"],
            }]),
        ):
            results = check_parameter_quality.check_parameters(
                "analytics",
                "event_task",
                {
                    "client_version": {"required_value": "auto"},
                    "money": {"required_value": "auto"},
                },
                {"event_date", "client_version", "money"},
                config,
            )

        self.assertEqual("ok", results[0]["status"])
        self.assertFalse(results[0]["inferred_required"])
        self.assertEqual("unpopulated_column", results[1]["problem"])

    def test_required_table_parameter_reports_missing_column(self):
        result = check_parameter_quality.check_parameter(
            database="analytics",
            table="event_task",
            parameter="money",
            rule={"require_column": True, "required_value": True},
            columns={"event_date"},
            config={
                "date_range": {"description": "last 30 days"},
                "default_invalid_values": [],
                "default_max_missing_pct": 0.0,
                "default_max_invalid_pct": 0.0,
                "top_values_limit": 10,
            },
        )
        self.assertEqual("problem", result["status"])
        self.assertEqual("missing_column", result["problem"])

    def test_personal_parameter_thresholds_are_mapped_by_parameter_name(self):
        self.assertEqual(
            {"event_key": 0.001, "session_id": 0.01},
            check_parameter_quality.parameter_thresholds(
                {
                    "missing_event_key_pct": 0.001,
                    "missing_session_id_pct": 0.01,
                    "duplicate_pct": 0.5,
                },
                "missing_",
            ),
        )

    def test_personal_threshold_applies_without_overriding_event_rule(self):
        config = {
            "auto_discovery": {
                "enabled": False,
                "exclude_columns": [],
                "exclude_patterns": [],
                "default_rule": {},
            },
            "global_parameters": {},
            "tables": {},
            "parameter_missing_thresholds": {"event_key": 0.001},
            "parameter_invalid_thresholds": {},
        }

        inherited = check_parameter_quality.rules_for_table(
            config,
            "event_purchase",
            contract_parameters={"event_key": {"required_value": True}},
        )
        overridden = check_parameter_quality.rules_for_table(
            config,
            "event_purchase",
            contract_parameters={
                "event_key": {
                    "required_value": True,
                    "max_missing_pct": 0.02,
                }
            },
        )

        self.assertEqual(0.001, inherited["event_key"]["max_missing_pct"])
        self.assertEqual(0.02, overridden["event_key"]["max_missing_pct"])

    def test_parameter_threshold_filters_small_missing_value_noise(self):
        config = {
            "date_range": {"mode": "rolling", "days_back": 30, "description": "last 30 days"},
            "default_invalid_values": [],
            "default_max_missing_pct": 0.0,
            "default_max_invalid_pct": 0.0,
            "top_values_limit": 10,
            "auto_discovery": {
                "required_min_presence_pct": 0.95,
                "flag_unpopulated": True,
            },
        }

        with patch.object(
            check_parameter_quality,
            "query_df",
            return_value=pd.DataFrame([{
                "rows_checked": 100000,
                "missing_0": 5,
                "invalid_0": 0,
                "observed_0": ["purchase", "<MISSING>"],
            }]),
        ):
            result = check_parameter_quality.check_parameter(
                database="analytics",
                table="event_purchase",
                parameter="event_key",
                rule={"required_value": True, "max_missing_pct": 0.001},
                columns={"event_date", "event_key"},
                config=config,
            )

        self.assertEqual("ok", result["status"])
        self.assertEqual(0.00005, result["missing_pct"])
        self.assertEqual("", result["problem"])

    def test_generated_profile_schema_is_compact_grouped_and_create_once(self):
        config = {
            "profile_schema": {
                "common_parameter_min_events": 3,
            }
        }
        payload = check_parameter_quality.build_profile_schema(
            profile_name="clickhouse.analytics_secondary",
            database="analytics_secondary",
            table_schemas={
                "event_show": {
                    "event_date": "DateTime",
                    "adid": "String",
                    "event_name": "Nullable(String)",
                    "server_region": "Nullable(String)",
                    "step": "String",
                    "tier": "String",
                },
                "event_click": {
                    "event_date": "DateTime",
                    "adid": "String",
                    "event_name": "Nullable(String)",
                    "server_region": "Nullable(String)",
                    "step": "String",
                    "tier": "String",
                },
                "event_login": {
                    "event_date": "DateTime",
                    "adid": "String",
                    "event_name": "Nullable(String)",
                    "server_region": "Nullable(String)",
                    "step": "String",
                },
            },
            results=[
                *[
                    {
                        "event_table": table,
                        "parameter": "event_name",
                        "observed_values": f'["{table}", "<MISSING>"]',
                    }
                    for table in ("event_show", "event_click", "event_login")
                ],
                *[
                    {
                        "event_table": table,
                        "parameter": "server_region",
                        "observed_values": '["eu", "us", "<MISSING>"]',
                    }
                    for table in ("event_show", "event_click", "event_login")
                ],
                *[
                    {
                        "event_table": table,
                        "parameter": "step",
                        "observed_values": '["main", "<MISSING>"]',
                    }
                    for table in ("event_show", "event_click", "event_login")
                ],
                {
                    "event_table": "event_show",
                    "parameter": "tier",
                    "observed_values": '["1"]',
                },
                {
                    "event_table": "event_click",
                    "parameter": "tier",
                    "observed_values": '["2"]',
                },
            ],
            config=config,
        )

        self.assertEqual(3, payload["schema_version"])
        self.assertEqual(
            [
                "Nullable(String)",
                ["event_click", "event_login", "event_show"],
                "high",
            ],
            payload["system_parameters"]["event_name"],
        )
        self.assertEqual(
            [
                "String",
                ["4bcdd67e-0bbc-4ca8-b7a5-4ba29e28c30a"],
                "extreme",
            ],
            payload["system_parameters"]["adid"],
        )
        self.assertEqual(
            ["String", ["main"], "high"],
            payload["common_parameters"]["step"],
        )
        self.assertEqual(
            ["String", ["2"], "normal"],
            payload["events"]["event_click"]["parameters"]["tier"],
        )
        self.assertEqual(
            ["String", ["1"], "normal"],
            payload["events"]["event_show"]["parameters"]["tier"],
        )
        self.assertNotIn("schema", payload["events"]["event_show"])

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "clickhouse.analytics_secondary.json"
            self.assertTrue(check_parameter_quality.create_profile_schema_once(path, payload))
            text = path.read_text(encoding="utf-8")
            self.assertIn(
                '"event_name": ["Nullable(String)", ["event_click", "event_login", "event_show"], "high"]',
                text,
            )
            self.assertFalse(
                check_parameter_quality.create_profile_schema_once(
                    path,
                    {"events": {"replacement": {}}},
                )
            )
            saved = json.loads(path.read_text(encoding="utf-8"))

        self.assertIn("event_show", saved["events"])
        self.assertNotIn("replacement", saved["events"])

    def test_compact_system_parameter_is_required_unless_event_has_exception(self):
        contract = {
            "schema_version": 3,
            "system_parameters": {
                "event_name": ["LowCardinality(String)", ["event_show"], "high"],
            },
            "common_parameters": {},
            "events": {
                "event_show": {"parameters": {}},
                "event_legacy": {
                    "system_parameter_exceptions": ["event_name"],
                    "parameters": {},
                },
            }
        }
        config = {
            "auto_discovery": {
                "enabled": True,
                "exclude_columns": [],
                "exclude_patterns": [],
                "default_rule": {"required_value": "auto"},
            },
            "global_parameters": {},
            "tables": {},
        }

        rules = check_parameter_quality.rules_for_table(
            config,
            "event_show",
            columns={"event_date"},
            contract_parameters=check_parameter_quality.profile_parameters(
                contract,
                "event_show",
                {"event_date"},
            ),
        )

        self.assertTrue(rules["event_name"]["require_column"])
        self.assertTrue(rules["event_name"]["required_value"])
        self.assertTrue(rules["event_name"]["_profile_schema"])
        self.assertEqual(
            {},
            check_parameter_quality.profile_parameters(
                contract,
                "event_legacy",
                {"event_date"},
            ),
        )

    def test_null_event_parameter_is_ignored_whether_column_exists_or_not(self):
        contract = {
            "schema_version": 3,
            "system_parameters": {},
            "common_parameters": {
                "server_region": ["String", ["RU"], "high"],
            },
            "events": {
                "event_create_character": {"parameters": {"source": None}},
                "event_enter": {"parameters": {"server_region": None}},
            },
        }
        config = {
            "auto_discovery": {
                "enabled": True,
                "exclude_columns": [],
                "exclude_patterns": [],
                "default_rule": {"required_value": "auto"},
            },
            "global_parameters": {},
            "tables": {},
        }

        cases = [
            ("event_create_character", "source", {"event_date", "source"}),
            ("event_create_character", "source", {"event_date"}),
            ("event_enter", "server_region", {"event_date", "server_region"}),
            ("event_enter", "server_region", {"event_date"}),
        ]
        for table, parameter, columns in cases:
            with self.subTest(table=table, parameter=parameter, columns=columns):
                contract_parameters = check_parameter_quality.profile_parameters(
                    contract,
                    table,
                    columns,
                )
                rules = check_parameter_quality.rules_for_table(
                    config,
                    table,
                    columns,
                    contract_parameters=contract_parameters,
                )

                self.assertNotIn(parameter, rules)

    def test_unknown_table_requires_only_present_system_parameters(self):
        contract = {
            "schema_version": 3,
            "system_parameters": {
                "event_name": ["String", [], "extreme"],
                "adid": ["String", [], "extreme"],
            },
            "common_parameters": {},
            "events": {},
        }

        parameters = check_parameter_quality.profile_parameters(
            contract,
            "AccountWalletLog",
            {"date", "adid", "amount"},
        )

        self.assertNotIn("event_name", parameters)
        self.assertIn("adid", parameters)

    def test_incomplete_discovery_lists_tables_that_block_schema_generation(self):
        missing = check_parameter_quality.missing_profile_schema_tables(
            {"event_login", "event_show"},
            {"event_login": {"event_date": "DateTime"}},
        )
        self.assertEqual(["event_show"], missing)

    def test_raw_only_profile_event_is_optional_until_target_table_exists(self):
        self.assertIsNone(
            check_parameter_quality.missing_profile_event_result(
                "event_purchase",
                {
                    "parameters": {},
                    "required": False,
                    "discovered_from": "source_events",
                },
            )
        )
        self.assertEqual(
            "missing_event",
            check_parameter_quality.missing_profile_event_result(
                "event_login",
                {"parameters": {}},
            )["problem"],
        )


if __name__ == "__main__":
    unittest.main()
