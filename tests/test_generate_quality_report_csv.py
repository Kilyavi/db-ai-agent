import json
import os
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd

import generate_quality_report


class GenerateQualityReportCsvTests(unittest.TestCase):
    def test_ai_narrative_is_omitted_when_no_observation_succeeded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "database_investigation_run-1.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({
                    "observations": [{
                        "id": "bad_query",
                        "status": "rejected",
                    }],
                    "final_report": "Unsupported claim from rejected SQL.",
                }, handle)
            with (
                patch.object(generate_quality_report, "REPORT_DIR", temp_dir),
                patch.dict(os.environ, {"QUALITY_RUN_ID": "run-1"}, clear=False),
            ):
                _, compact = generate_quality_report.compact_database_investigation()

        self.assertIn("observations_ok=0, rejected=1, errors=0", compact)
        self.assertIn("narrative omitted", compact)
        self.assertNotIn("Unsupported claim", compact)

    def test_ai_narrative_is_omitted_when_observation_succeeded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "database_investigation_run-2.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({
                    "observations": [{
                        "id": "raw_count",
                        "status": "ok",
                        "tables": ["source_events"],
                        "rows_returned": 1,
                        "hypothesis": "Count source rows.",
                        "preview": [{"raw_rows": "12"}],
                    }],
                    "final_report": "Unsupported causal narrative.",
                }, handle)
            with (
                patch.object(generate_quality_report, "REPORT_DIR", temp_dir),
                patch.dict(os.environ, {"QUALITY_RUN_ID": "run-2"}, clear=False),
            ):
                _, compact = generate_quality_report.compact_database_investigation()

        self.assertIn('preview=[{"raw_rows": "12"}]', compact)
        self.assertIn("structured successful observations", compact)
        self.assertNotIn("Unsupported causal narrative", compact)

    def test_medium_ai_query_problem_is_included_in_compact_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "database_investigation_run-3.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({
                    "observations": [{
                        "id": "bad_generated_date",
                        "status": "problem",
                        "priority": "medium",
                        "problem_code": "invalid_datetime_literal",
                        "tables": ["source_events"],
                        "reason": "AI SQL contains an impossible datetime literal: "
                        "'2026-08-55 22:02:55'; the query was not executed.",
                    }],
                }, handle)
            with (
                patch.object(generate_quality_report, "REPORT_DIR", temp_dir),
                patch.dict(os.environ, {"QUALITY_RUN_ID": "run-3"}, clear=False),
            ):
                _, compact = generate_quality_report.compact_database_investigation()

        self.assertIn("problems_medium=1", compact)
        self.assertIn("ai_query_problems:", compact)
        self.assertIn("MEDIUM bad_generated_date", compact)
        self.assertIn("invalid_datetime_literal", compact)
        self.assertIn("2026-08-55 22:02:55", compact)
        self.assertIn("not database findings", compact)

    def test_deterministic_report_prioritizes_system_then_value_parameters(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            quality_path = os.path.join(temp_dir, "event_quality.csv")
            parameter_path = os.path.join(temp_dir, "parameter_quality.csv")
            pd.DataFrame([{
                "event_table": "event_login",
                "status": "missing_session_id_high, duplicate_high",
                "rows_yesterday": 10,
                "missing_session_id_pct": 0.2,
                "duplicate_pct": 0.1,
                "session_id_columns": "session_id,session_uuid",
            }]).to_csv(quality_path, index=False)
            pd.DataFrame([{
                "event_table": "event_task",
                "parameter": "money",
                "status": "problem",
                "problem": "missing_values",
                "missing_pct": 1.0,
                "invalid_pct": 0.0,
                "observed_values": '["<MISSING>"]',
            }]).to_csv(parameter_path, index=False)

            report = generate_quality_report.build_deterministic_report(
                ai_agent_path="NOT_FOUND",
                ai_agent_text="",
                db_scan_path=os.path.join(temp_dir, "missing.json"),
                quality_path=quality_path,
                parameter_path=parameter_path,
                missing_path=os.path.join(temp_dir, "missing.csv"),
                recommendations="- Check one\n- Check two\n- Check three",
            )

        self.assertLess(
            report.index("3. System parameter problems"),
            report.index("4. Required and value-shape parameter problems"),
        )
        self.assertIn("sources=session_id,session_uuid", report)
        self.assertIn("event_task.money", report)

    def test_compact_quality_report_handles_bom_only_csv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "event_quality_20260629_125909.csv")
            with open(path, "wb") as f:
                f.write(b"\xef\xbb\xbf\r\n")

            with patch.object(generate_quality_report, "REPORT_DIR", temp_dir):
                actual_path, text = generate_quality_report.compact_quality_report()

        self.assertEqual(path, actual_path)
        self.assertEqual("Quality report contains no event-table rows.", text)

    def test_compact_missing_ids_handles_bom_only_csv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "quality_missing_ids_20260629_125909.csv")
            with open(path, "wb") as f:
                f.write(b"\xef\xbb\xbf\r\n")

            with patch.object(generate_quality_report, "REPORT_DIR", temp_dir):
                actual_path, text = generate_quality_report.compact_missing_ids()

        self.assertEqual(path, actual_path)
        self.assertEqual("No missing ID samples.", text)

    def test_profile_schema_high_priority_problem_is_not_hidden_by_csv_order(self):
        normal_rows = [
            {
                "event_table": f"event_event_{index:02d}",
                "parameter": "optional_value",
                "status": "problem",
                "problem": "missing_values",
                "missing_pct": 1.0,
                "profile_schema_parameter": False,
                "report_priority": "normal",
            }
            for index in range(30)
        ]
        profile_problem = {
            "event_table": "event_show",
            "parameter": "event_name",
            "status": "problem",
            "problem": "missing_values",
            "missing_pct": 0.0484,
            "profile_schema_parameter": True,
            "report_priority": "extreme",
        }

        prioritized = generate_quality_report.prioritize_parameter_problems(
            pd.DataFrame([*normal_rows, profile_problem])
        )

        self.assertEqual("event_show", prioritized.iloc[0]["event_table"])
        self.assertEqual("event_name", prioritized.iloc[0]["parameter"])

    def test_main_identifier_allowance_does_not_hide_missing_session(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            quality_path = os.path.join(temp_dir, "event_quality.csv")
            missing_path = os.path.join(temp_dir, "missing_ids.csv")
            pd.DataFrame([{
                "event_table": "app_enter",
                "status": "missing_session_id_high",
                "rows_in_range": 100,
                "missing_session_id_pct": 0.98,
                "session_id_columns": "session_uuid",
            }]).to_csv(quality_path, index=False)
            pd.DataFrame([{
                "event_table": "app_enter",
                "step": "NO_COLUMN",
                "missing_main_identifier_pct": 0.0,
                "missing_session_id_pct": 0.98,
            }]).to_csv(missing_path, index=False)

            with (
                patch.object(
                    generate_quality_report,
                    "missing_allowed_tables",
                    return_value=({"app_enter"}, set()),
                ),
                patch.object(
                    generate_quality_report,
                    "load_config_rules",
                    return_value={"event_context": {}},
                ),
            ):
                report = generate_quality_report.build_deterministic_report(
                    ai_agent_path="NOT_FOUND",
                    ai_agent_text="",
                    db_scan_path=os.path.join(temp_dir, "missing.json"),
                    quality_path=quality_path,
                    parameter_path="NOT_FOUND",
                    missing_path=missing_path,
                    recommendations="",
                )

        self.assertIn("unexpected missing session identifier", report)
        self.assertNotIn(
            "step=NO_COLUMN: expected missing session identifier",
            report,
        )

    def test_no_rows_without_flow_evidence_is_not_guessed_critical(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            quality_path = os.path.join(temp_dir, "event_quality.csv")
            pd.DataFrame([{
                "event_table": "event_revenue",
                "status": "no_rows_in_range",
                "rows_in_range": 0,
            }]).to_csv(quality_path, index=False)

            report = generate_quality_report.build_deterministic_report(
                ai_agent_path="NOT_FOUND",
                ai_agent_text="",
                db_scan_path=os.path.join(temp_dir, "missing.json"),
                quality_path=quality_path,
                parameter_path="NOT_FOUND",
                missing_path=os.path.join(temp_dir, "missing.csv"),
                recommendations="",
            )

        self.assertIn("source_events/DLQ comparison is unavailable", report)
        self.assertIn("severity cannot be classified", report)
        self.assertNotIn("CRITICAL event_revenue", report)

    def test_event_flow_evidence_explains_missing_parsed_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            quality_path = os.path.join(temp_dir, "event_quality.csv")
            flow_path = os.path.join(temp_dir, "event_flow.json")
            pd.DataFrame([{
                "event_table": "event_revenue",
                "status": "no_rows_in_range",
                "rows_in_range": 0,
            }]).to_csv(quality_path, index=False)
            with open(flow_path, "w", encoding="utf-8") as handle:
                json.dump({
                    "flow_results": [{
                        "event_table": "event_revenue",
                        "raw_rows": 48525,
                        "parsed_rows": 0,
                        "dlq_rows": 0,
                        "dlq_shapes": [],
                        "status": ["low_raw_seen_but_parsed_missing"],
                        "severity": "low",
                    }],
                    "parameter_results": [],
                }, handle)

            report = generate_quality_report.build_deterministic_report(
                ai_agent_path="NOT_FOUND",
                ai_agent_text="",
                db_scan_path=os.path.join(temp_dir, "missing.json"),
                quality_path=quality_path,
                parameter_path="NOT_FOUND",
                missing_path=os.path.join(temp_dir, "missing.csv"),
                recommendations="",
                flow_path=flow_path,
            )

        self.assertIn("LOW event_revenue", report)
        self.assertIn("low_raw_seen_but_parsed_missing", report)
        self.assertIn("raw_rows=48525, parsed_rows=0", report)
        self.assertNotIn("source_events/DLQ comparison unavailable", report)


if __name__ == "__main__":
    unittest.main()
