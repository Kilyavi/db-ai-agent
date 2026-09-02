import os
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd

import check_event_quality


class CheckEventQualityTests(unittest.TestCase):
    def test_selected_period_supports_two_hour_window(self):
        with patch.object(
            check_event_quality,
            "DATE_RANGE",
            {
                "mode": "rolling",
                "interval_value": 2,
                "interval_unit": "hour",
                "duration_seconds": 7200,
                "description": "last 2 hours",
            },
        ):
            self.assertEqual(
                "event_date >= now() - INTERVAL 2 HOUR AND event_date < now()",
                check_event_quality.selected_period_condition("event_date"),
            )

    def test_discovery_skips_materialized_views(self):
        captured = []
        with patch.object(
            check_event_quality,
            "query_df",
            side_effect=lambda sql: captured.append(sql) or pd.DataFrame(),
        ):
            self.assertEqual([], check_event_quality.get_event_tables())

        self.assertIn("t.engine != 'MaterializedView'", captured[0])

    def test_discovery_accepts_created_at_datetime_tables(self):
        frame = pd.DataFrame([{
            "event_table": "partner_events",
            "time_column": "created_at",
            "estimated_rows": 100,
        }])
        with patch.object(check_event_quality, "query_df", return_value=frame):
            mapping = check_event_quality.get_event_table_time_columns()

        self.assertEqual({"partner_events": "created_at"}, mapping)

    def test_missing_session_requires_all_aliases_to_be_missing(self):
        expression = check_event_quality.missing_expr(
            columns={"session_id", "session_uuid"},
            column=["session_id", "session_uuid", "sessions_uuid"],
        )

        self.assertIn("`session_id`", expression)
        self.assertIn("`session_uuid`", expression)
        self.assertIn(") AND (", expression)
        self.assertNotIn("`sessions_uuid`", expression)

    def test_empty_discovery_writes_empty_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.object(check_event_quality, "REPORT_DIR", temp_dir),
                patch.object(check_event_quality, "get_event_tables", return_value=[]),
            ):
                check_event_quality.main()

            reports = [
                name for name in os.listdir(temp_dir) if name.startswith("event_quality_")
            ]
            self.assertEqual(1, len(reports))
            frame = pd.read_csv(os.path.join(temp_dir, reports[0]))
            self.assertTrue(frame.empty)
            self.assertIn("status", frame.columns)

    def test_anomaly_metrics_share_one_query(self):
        queries = []
        responses = [
            pd.DataFrame(
                [
                    {
                        "event_table": "event_event",
                        "rows_yesterday": 10,
                        "missing_adid_rows": 0,
                        "missing_main_identifier_rows": 0,
                        "missing_session_id_rows": 0,
                    }
                ]
            ),
            pd.DataFrame(
                [
                    {
                        "duplicate_rows": 1,
                        "replicated_rows": 2,
                        "same_second_burst_rows": 0,
                    }
                ]
            ),
            pd.DataFrame(
                [{"rows_yesterday_for_volume": 10, "median_prev_days": 10}]
            ),
        ]

        def fake_query(sql):
            queries.append(sql)
            return responses.pop(0)

        with (
            patch.object(
                check_event_quality,
                "get_columns",
                return_value={"event_date", "adid", "event_key"},
            ),
            patch.object(check_event_quality, "query_df", side_effect=fake_query),
        ):
            result = check_event_quality.quality_check_table("event_event")

        self.assertEqual(3, len(queries))
        self.assertIn("row_number() OVER", queries[1])
        self.assertEqual(1, result.loc[0, "duplicate_rows"])
        self.assertEqual(2, result.loc[0, "replicated_rows"])


if __name__ == "__main__":
    unittest.main()
