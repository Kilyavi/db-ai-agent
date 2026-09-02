import unittest
import os
import tempfile
from unittest.mock import patch

import drill_down_quality_issues


class DrilldownConfigTests(unittest.TestCase):
    def test_clean_quality_report_does_not_trigger_fallback_tables(self):
        with (
            patch.object(drill_down_quality_issues, "load_rules", return_value={}),
            patch.object(
                drill_down_quality_issues,
                "get_tables_from_latest_quality",
                return_value=([], "reports/event_quality_clean.csv"),
            ),
        ):
            config = drill_down_quality_issues.get_drilldown_config()

        self.assertEqual([], config["tables"])
        self.assertEqual("latest_quality_report", config["table_source"])

    def test_fixed_range_is_used_by_drilldown_queries(self):
        fixed_range = {
            "mode": "fixed",
            "start_date": "2026-02-01",
            "end_date_exclusive": "2026-02-03",
        }
        with patch.object(drill_down_quality_issues, "DATE_RANGE", fixed_range):
            condition = drill_down_quality_issues.selected_period_condition("event_date")

        self.assertIn("2026-02-01 00:00:00", condition)
        self.assertIn("2026-02-03 00:00:00", condition)
        self.assertNotIn("today()", condition)

    def test_latest_file_is_scoped_to_current_run(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = os.path.join(temp_dir, "event_quality_old.csv")
            run_path = os.path.join(temp_dir, "event_quality_run-123.csv")
            open(old_path, "w", encoding="utf-8").close()
            open(run_path, "w", encoding="utf-8").close()

            with patch.dict(os.environ, {"QUALITY_RUN_ID": "run-123"}):
                selected = drill_down_quality_issues.latest_file(
                    os.path.join(temp_dir, "event_quality_*.csv")
                )

        self.assertEqual(run_path, selected)


if __name__ == "__main__":
    unittest.main()
