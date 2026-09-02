import unittest
from unittest.mock import patch

import pandas as pd

import check_event_flow


class EventFlowTests(unittest.TestCase):
    def test_raw_profile_additions_preserve_contract_and_infer_event_parameters(self):
        profile = {
            "system_parameters": {
                "event_name": ["String", [], "high"],
                "session_id": ["String", [], "extreme"],
            },
            "common_parameters": {
                "currency": ["String", [], "high"],
            },
            "events": {
                "event_login": {"parameters": {"source": None}},
            },
        }
        source = pd.DataFrame([
            {"event_table": "event_login", "raw_rows": 10},
            {"event_table": "event_purchase", "raw_rows": 4},
            {"event_table": "event_level_up", "raw_rows": 2},
            {"event_table": "__UNKNOWN__", "raw_rows": 1},
        ])
        parameters = pd.DataFrame([
            {
                "event_table": "event_purchase",
                "parameter": "item_name",
                "raw_examples": ['"sample_case_name"'],
            },
            {
                "event_table": "event_purchase",
                "parameter": "quantity",
                "raw_examples": ["1", "2"],
            },
            {
                "event_table": "event_purchase",
                "parameter": "currency",
                "raw_examples": ['"VC"'],
            },
            {
                "event_table": "event_purchase",
                "parameter": "session_uuid",
                "raw_examples": ['"uuid"'],
            },
            {
                "event_table": "event_purchase",
                "parameter": "device_hash",
                "raw_examples": ['"hash"'],
            },
        ])

        additions = check_event_flow.raw_profile_event_additions(
            profile,
            source,
            parameters,
            "source_events",
        )

        self.assertEqual(
            ["event_level_up", "event_purchase"],
            sorted(additions),
        )
        self.assertEqual(
            ["item_name", "quantity"],
            list(additions["event_purchase"]["parameters"]),
        )
        self.assertEqual(
            ["String", ["sample_case_name"], "normal"],
            additions["event_purchase"]["parameters"]["item_name"],
        )
        self.assertEqual(
            ["Int64", ["1", "2"], "normal"],
            additions["event_purchase"]["parameters"]["quantity"],
        )
        self.assertFalse(additions["event_purchase"]["required"])
        self.assertEqual(
            {"source": None},
            profile["events"]["event_login"]["parameters"],
        )

    def test_blacklisted_event_rows_are_filtered_case_insensitively(self):
        frame = pd.DataFrame([
            {"event_table": "AccountInventoryLog", "raw_rows": 10},
            {"event_table": "DEBUG_EVENTS", "raw_rows": 5},
            {"event_table": "event_login", "raw_rows": 3},
        ])

        filtered = check_event_flow.filter_blacklisted_event_rows(
            frame,
            ["accountinventorylog", "debug_*"],
        )

        self.assertEqual(["event_login"], filtered["event_table"].tolist())

    def test_dlq_collection_exposes_legacy_envelope_evidence(self):
        captured = {}

        def fake_query(sql):
            captured["sql"] = sql
            return pd.DataFrame()

        with patch("check_event_flow.query_df", side_effect=fake_query):
            check_event_flow.collect_dlq_events(
                "analytics",
                "source_events_dlq",
                {"event_time", "payload"},
                {
                    "mode": "rolling",
                    "interval_value": 1,
                    "interval_unit": "day",
                    "duration_seconds": 86400,
                },
            )

        sql = captured["sql"]
        self.assertIn("JSONExtractString(payload, 'event', 'name')", sql)
        self.assertIn("JSONHas(payload, 'event', 'parameters')", sql)
        self.assertIn("JSONExtract(payload, 'validationErrors', 'Array(String)')", sql)
        self.assertIn("JSONExtractString(payload, 'rejectedAt')", sql)
        self.assertIn("'source_events_dlq' AS dlq_source_table", sql)

    def test_parameter_source_presence_never_exceeds_one(self):
        evidence = pd.DataFrame([{
            "event_table": "event_login",
            "parameter": "session_id",
            "raw_present_rows": 101,
        }])
        source = pd.DataFrame([{
            "event_table": "event_login",
            "raw_rows": 100,
        }])
        pairs = [{
            "event_table": "event_login",
            "parameter": "session_id",
            "scope": "system",
            "target_missing_pct": 0.5,
            "target_problem": "missing_values",
            "report_priority": "extreme",
        }]
        date_range = {
            "mode": "rolling",
            "interval_value": 1,
            "interval_unit": "day",
            "duration_seconds": 86400,
        }

        with patch("check_event_flow.query_df", return_value=evidence):
            results = check_event_flow.collect_source_parameter_evidence(
                "analytics",
                "source_events",
                {"event_time", "payload"},
                date_range,
                pairs,
                {},
                source,
            )

        self.assertEqual(1.0, results[0]["raw_presence_pct"])
        self.assertEqual(100, results[0]["raw_present_rows"])
        self.assertEqual(
            "likely_parser_or_column_mapping_issue",
            results[0]["diagnosis"],
        )
        self.assertEqual("low", results[0]["severity"])
        self.assertEqual(
            "low_target_parameter_missing_but_raw_present",
            results[0]["status"],
        )

    def test_parameter_missing_in_raw_and_target_is_critical(self):
        pair = {
            "event_table": "event_login",
            "parameter": "session_id",
            "scope": "system",
            "target_missing_pct": 0.5,
            "target_problem": "missing_values",
            "report_priority": "extreme",
        }
        evidence = pd.DataFrame([{
            "event_table": "event_login",
            "parameter": "session_id",
            "raw_present_rows": 50,
        }])
        source = pd.DataFrame([{
            "event_table": "event_login",
            "raw_rows": 100,
        }])

        with patch("check_event_flow.query_df", return_value=evidence):
            result = check_event_flow.collect_source_parameter_evidence(
                "analytics",
                "source_events",
                {"event_time", "payload"},
                {
                    "mode": "rolling",
                    "interval_value": 1,
                    "interval_unit": "day",
                    "duration_seconds": 86400,
                },
                [pair],
                {},
                source,
            )[0]

        self.assertEqual("critical", result["severity"])
        self.assertEqual(
            "critical_parameter_missing_in_raw_and_target",
            result["status"],
        )

    def test_event_name_uses_raw_type_as_source_evidence(self):
        source = pd.DataFrame([{
            "event_table": "event_login",
            "raw_rows": 100,
        }])
        pair = {
            "event_table": "event_login",
            "parameter": "event_name",
            "scope": "system",
            "target_missing_pct": 1.0,
            "target_problem": "missing_values",
            "report_priority": "high",
        }

        with patch("check_event_flow.query_df", return_value=pd.DataFrame()):
            result = check_event_flow.collect_source_parameter_evidence(
                "analytics",
                "source_events",
                {"event_time", "payload", "type"},
                {
                    "mode": "rolling",
                    "interval_value": 1,
                    "interval_unit": "day",
                    "duration_seconds": 86400,
                },
                [pair],
                {},
                source,
            )[0]

        self.assertEqual(["type"], result["source_aliases"])
        self.assertEqual(1.0, result["raw_presence_pct"])
        self.assertEqual("low", result["severity"])

    def test_missing_parsed_rows_use_raw_source_for_severity(self):
        quality = pd.DataFrame([
            {"event_table": "event_revenue", "status": "no_rows_in_range", "rows_in_range": 0},
            {"event_table": "app_sessions", "status": "no_rows_in_range", "rows_in_range": 0},
        ])
        source = pd.DataFrame([
            {"event_table": "event_revenue", "raw_rows": 12},
        ])
        dlq = pd.DataFrame([
            {"event_table": "app_sessions", "dlq_shape": "legacy_event_envelope", "dlq_rows": 3},
        ])

        results = {
            item["event_table"]: item
            for item in check_event_flow.build_flow_results(quality, source, dlq)
        }

        self.assertIn(
            "low_raw_seen_but_parsed_missing",
            results["event_revenue"]["status"],
        )
        self.assertEqual("low", results["event_revenue"]["severity"])
        self.assertIn(
            "critical_dlq_seen_but_parsed_missing",
            results["app_sessions"]["status"],
        )
        self.assertIn("critical_dlq_rows", results["app_sessions"]["status"])
        self.assertEqual("critical", results["app_sessions"]["severity"])

    def test_source_event_without_parsed_table_is_low(self):
        results = check_event_flow.build_flow_results(
            pd.DataFrame(columns=["event_table", "status"]),
            pd.DataFrame([{"event_table": "new_event", "raw_rows": 8}]),
            pd.DataFrame(columns=["event_table", "dlq_shape", "dlq_rows"]),
        )

        self.assertEqual("new_event", results[0]["event_table"])
        self.assertIn("low_missing_parsed_table", results[0]["status"])
        self.assertEqual("low", results[0]["severity"])

    def test_no_parsed_or_raw_event_is_critical(self):
        results = check_event_flow.build_flow_results(
            pd.DataFrame([{
                "event_table": "event_revenue",
                "status": "no_rows_in_range",
                "rows_in_range": 0,
            }]),
            pd.DataFrame(columns=["event_table", "raw_rows"]),
            pd.DataFrame(columns=["event_table", "dlq_shape", "dlq_rows"]),
        )

        self.assertIn("critical_event_not_received", results[0]["status"])
        self.assertEqual("critical", results[0]["severity"])

    def test_parameter_pairs_preserve_common_scope_and_priority(self):
        parameter_df = pd.DataFrame([
            {
                "event_table": "event_revenue",
                "parameter": "quantity",
                "status": "problem",
                "problem": "missing_values",
                "missing_pct": 0.4,
                "report_priority": "high",
            },
            {
                "event_table": "event_revenue",
                "parameter": "optional_note",
                "status": "ok",
                "problem": "",
                "missing_pct": 0,
                "report_priority": "normal",
            },
        ])
        profile = {"common_parameters": {"quantity": ["Int64", [], "high"]}}

        pairs = check_event_flow.parameter_problem_pairs(parameter_df, profile, 100)

        self.assertEqual(1, len(pairs))
        self.assertEqual("common", pairs[0]["scope"])
        self.assertEqual("quantity", pairs[0]["parameter"])

    def test_missing_target_column_is_treated_as_fully_missing(self):
        pairs = check_event_flow.parameter_problem_pairs(
            pd.DataFrame([{
                "event_table": "event_login",
                "parameter": "event_name",
                "status": "problem",
                "problem": "missing_column",
                "missing_pct": None,
                "report_priority": "high",
            }]),
            {},
            100,
        )

        self.assertEqual(1.0, pairs[0]["target_missing_pct"])

    def test_configured_missing_main_identifier_is_excluded_from_source_flow_findings(self):
        parameter_df = pd.DataFrame([{
            "event_table": "event_change_language",
            "parameter": "user_id",
            "status": "problem",
            "problem": "missing_values",
            "missing_pct": 0.34,
            "report_priority": "extreme",
        }])
        rules = {
            "event_context": {
                "event_change_language": {
                    "skip_main_identifier_check": True,
                },
            },
        }

        pairs = check_event_flow.parameter_problem_pairs(
            parameter_df,
            {},
            100,
            rules,
        )

        self.assertEqual([], pairs)

    def test_dlq_source_table_is_preserved_in_flow_result(self):
        results = check_event_flow.build_flow_results(
            pd.DataFrame(columns=["event_table", "status"]),
            pd.DataFrame(columns=["event_table", "raw_rows"]),
            pd.DataFrame([{
                "event_table": "adjust_install",
                "dlq_source_table": "partner_events_dlq",
                "dlq_shape": "legacy_event_envelope",
                "dlq_rows": 4,
            }]),
        )

        self.assertEqual("critical", results[0]["severity"])
        self.assertEqual(["partner_events_dlq"], results[0]["dlq_source_tables"])

    def test_excluded_adjust_target_is_not_compared_with_source_events(self):
        results = check_event_flow.build_flow_results(
            pd.DataFrame([{
                "event_table": "partner_events",
                "status": "no_rows_in_range",
                "rows_in_range": 0,
            }]),
            pd.DataFrame(columns=["event_table", "raw_rows"]),
            pd.DataFrame(columns=["event_table", "dlq_shape", "dlq_rows"]),
            {"partner_events"},
        )

        self.assertEqual("investigate", results[0]["severity"])
        self.assertIn(
            "investigate_source_comparison_not_applicable",
            results[0]["status"],
        )


if __name__ == "__main__":
    unittest.main()
