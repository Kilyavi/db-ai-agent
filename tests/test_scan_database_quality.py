import json
import unittest
from unittest.mock import patch

import pandas as pd

import scan_database_quality


class ScanDatabaseQualityTests(unittest.TestCase):
    def test_automatic_selection_skips_materialized_views(self):
        selected, source, not_scanned = scan_database_quality.select_event_tables(
            inventory=[
                {
                    "table": "app_account",
                    "engine": "MergeTree",
                    "has_event_date": True,
                    "estimated_rows": 100,
                },
                {
                    "table": "mv_app_account",
                    "engine": "MaterializedView",
                    "has_event_date": True,
                    "estimated_rows": 100,
                },
            ],
            explicit_tables=None,
            priority_event_tables=[],
            scan_max_event_tables=10,
        )

        self.assertEqual(["app_account"], selected)
        self.assertEqual("discovered", source)
        self.assertEqual([], not_scanned)

    def test_inventory_keeps_estimated_rows_and_orders_by_size(self):
        captured = []

        def fake_query(sql):
            captured.append(sql)
            return pd.DataFrame(
                [
                    {
                        "table": "event_large",
                        "engine": "MergeTree",
                        "estimated_rows": 123,
                        "column_count": 1,
                        "columns": ["event_date"],
                    }
                ]
            )

        with patch.object(scan_database_quality, "query_df", side_effect=fake_query):
            inventory = scan_database_quality.discover_table_inventory(
                "analytics", ["event_"], 10
            )

        self.assertEqual(123, inventory[0]["estimated_rows"])
        self.assertIn("estimated_rows,", captured[0])
        self.assertIn("ORDER BY estimated_rows DESC", captured[0])

    def test_inventory_selects_created_at_as_measurement_time(self):
        item = scan_database_quality.normalize_inventory_record({
            "table": "partner_events",
            "engine": "MergeTree",
            "columns": ["created_at", "loaded_at", "activity_kind"],
            "column_types": [
                ("created_at", "DateTime"),
                ("loaded_at", "DateTime64(3, 'UTC')"),
                ("activity_kind", "String"),
            ],
        })

        self.assertEqual("created_at", item["measurement_time_column"])

    def test_scan_separates_future_rows_from_current_metrics(self):
        captured = []

        def fake_query(sql):
            captured.append(sql)
            if "AS rows_total" in sql:
                return pd.DataFrame([{"rows_total": 0}])
            if "AS future_event_time_rows" in sql:
                return pd.DataFrame([{
                    "future_event_time_rows": 1,
                    "max_future_event_time": pd.Timestamp("2026-07-17 12:00:00"),
                }])
            return pd.DataFrame(
                [{"duplicate_rows": 0, "same_second_burst_rows": 0}]
            )

        with patch.object(scan_database_quality, "query_df", side_effect=fake_query):
            result = scan_database_quality.scan_table(
                database="analytics",
                table="event_event",
                date_range={"mode": "rolling", "days_back": 7},
                days_back=7,
                skip_missing_main_identifier_tables=set(),
                skip_missing_session_id_tables=set(),
                same_second_allowed_tables=set(),
                same_second_strict_tables=set(),
                future_event_time_enabled=True,
                future_tolerance_minutes=15,
                same_second_unique_event_key_threshold=4,
                columns={"event_date", "adid", "user_id", "session_id", "event_key"},
            )

        self.assertEqual(3, len(captured))
        combined = "\n".join(captured)
        self.assertNotIn("parseDateTimeBestEffortOrNull", combined)
        self.assertIn("00000000-0000-0000-0000-000000000000", combined)
        self.assertIn("INTERVAL 15 MINUTE", combined)
        self.assertIn("event_date < now()", combined)
        self.assertIn("unique_event_keys > 4", combined)
        self.assertEqual("2026-07-17 12:00:00", result["max_future_event_time"])
        json.dumps(result)

    def test_scan_skips_future_query_when_check_is_disabled(self):
        captured = []

        def fake_query(sql):
            captured.append(sql)
            if "AS rows_total" in sql:
                return pd.DataFrame([{"rows_total": 0}])
            return pd.DataFrame(
                [{"duplicate_rows": 0, "same_second_burst_rows": 0}]
            )

        with patch.object(scan_database_quality, "query_df", side_effect=fake_query):
            result = scan_database_quality.scan_table(
                database="analytics",
                table="event_event",
                date_range={"mode": "rolling", "days_back": 7},
                days_back=7,
                skip_missing_main_identifier_tables=set(),
                skip_missing_session_id_tables=set(),
                same_second_allowed_tables=set(),
                same_second_strict_tables=set(),
                future_event_time_enabled=False,
                future_tolerance_minutes=15,
                same_second_unique_event_key_threshold=4,
                columns={"event_date", "adid", "user_id", "session_id", "event_key"},
            )

        self.assertEqual(2, len(captured))
        self.assertNotIn("AS future_event_time_rows", "\n".join(captured))
        self.assertEqual(0, result["future_event_time_rows"])
        self.assertIsNone(result["max_future_event_time"])

    def test_session_identifier_uses_any_configured_alias(self):
        captured = []

        def fake_query(sql):
            captured.append(sql)
            if "AS rows_total" in sql:
                return pd.DataFrame([{"rows_total": 0}])
            return pd.DataFrame(
                [{"duplicate_rows": 0, "same_second_burst_rows": 0}]
            )

        with patch.object(scan_database_quality, "query_df", side_effect=fake_query):
            result = scan_database_quality.scan_table(
                database="analytics",
                table="event_event",
                date_range={"mode": "rolling", "days_back": 7},
                days_back=7,
                skip_missing_main_identifier_tables=set(),
                skip_missing_session_id_tables=set(),
                same_second_allowed_tables=set(),
                same_second_strict_tables=set(),
                future_event_time_enabled=True,
                future_tolerance_minutes=15,
                same_second_unique_event_key_threshold=4,
                columns={
                    "event_date",
                    "adid",
                    "user_id",
                    "session_id",
                    "session_uuid",
                    "event_key",
                },
                identifier_aliases={
                    "adid": ["adid"],
                    "user_id": ["user_id"],
                    "session_id": ["session_id", "session_uuid", "sessions_uuid"],
                    "event_key": ["event_key"],
                },
            )

        self.assertIn("coalesce(", captured[0])
        self.assertIn("`session_uuid`", captured[0])
        self.assertEqual(
            ["session_id", "session_uuid"],
            result["identifier_sources"]["session_id"],
        )

    def test_main_identifier_uses_profile_column(self):
        captured = []

        def fake_query(sql):
            captured.append(sql)
            if "AS rows_total" in sql:
                return pd.DataFrame([{"rows_total": 0}])
            return pd.DataFrame(
                [{"duplicate_rows": 0, "same_second_burst_rows": 0}]
            )

        with patch.object(scan_database_quality, "query_df", side_effect=fake_query):
            result = scan_database_quality.scan_table(
                database="analytics",
                table="app_event",
                date_range={"mode": "rolling", "days_back": 1},
                days_back=1,
                skip_missing_main_identifier_tables=set(),
                skip_missing_session_id_tables=set(),
                same_second_allowed_tables=set(),
                same_second_strict_tables=set(),
                future_event_time_enabled=True,
                future_tolerance_minutes=10,
                same_second_unique_event_key_threshold=3,
                columns={"event_date", "adid", "user_id", "session_uuid", "event_key"},
                identifier_aliases={
                    "adid": ["adid"],
                    "user_id": ["user_id"],
                    "session_id": ["session_id", "session_uuid"],
                    "event_key": ["event_key"],
                },
            )

        self.assertIn("`user_id`", captured[0])
        self.assertEqual(["user_id"], result["identifier_sources"]["user_id"])
        self.assertEqual("user_id", result["main_identifier"])


if __name__ == "__main__":
    unittest.main()
