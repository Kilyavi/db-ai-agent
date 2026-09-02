import json
import os
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from deterministic_pipeline.scripts import build_report, collect_metrics
from tools import make_deterministic_zip


class DeterministicReleaseTests(unittest.TestCase):
    def test_table_limit_uses_shared_scan_setting(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                137,
                collect_metrics.max_event_tables(
                    {"db_problem_scan": {"scan_max_event_tables": 137}}
                ),
            )

    def test_table_limit_environment_override_wins(self):
        with patch.dict(os.environ, {"DQ_MAX_EVENT_TABLES": "23"}, clear=True):
            self.assertEqual(23, collect_metrics.max_event_tables({}))

    def test_collection_workers_use_bounded_config(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                4,
                collect_metrics.collection_workers({"collection": {"workers": 4}}),
            )

    def test_materialized_view_is_inventory_only_not_event_storage(self):
        self.assertFalse(
            collect_metrics.is_event_storage_table(
                {"has_event_date": True, "engine": "MaterializedView"}
            )
        )
        self.assertTrue(
            collect_metrics.is_event_storage_table(
                {"has_event_date": True, "engine": "MergeTree"}
            )
        )

    def test_tiny_volume_baseline_does_not_create_percentage_alert(self):
        classified = build_report.classify_result(
            {"thresholds": {"suspicious_volume_min_expected_rows": 10}},
            {
                "table": "event_device_performance",
                "status": "checked",
                "rows_total": 1,
                "rows_in_range": 1,
                "expected_rows_from_lookback": 0.033,
                "delta_vs_lookback_expected": 29.0,
            },
        )
        self.assertFalse(
            any("suspicious_high" in line for line in classified["investigate"])
        )

    def test_zero_rows_is_critical_not_expected(self):
        classified = build_report.classify_result(
            {},
            {
                "table": "event_revenue",
                "status": "checked",
                "rows_total": 0,
                "rows_in_range": 0,
            },
        )

        self.assertIn(
            "CRITICAL event_revenue: no rows in selected period",
            classified["confirmed"],
        )
        self.assertFalse(
            any("no rows" in line for line in classified["expected"])
        )

    def test_unpopulated_parameters_are_grouped_by_table(self):
        lines = build_report.summarize_parameter_problems(
            {
                "parameter_results": [
                    {
                        "event_table": "event_a",
                        "parameter": parameter,
                        "status": "problem",
                        "problem": "unpopulated_column",
                    }
                    for parameter in ("alpha", "beta")
                ]
            }
        )
        self.assertEqual(1, len(lines))
        self.assertIn("2 columns", lines[0])
        self.assertIn("alpha, beta", lines[0])

    def test_release_zip_is_minimal_git_free_and_analytics(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "release.zip"
            make_deterministic_zip.build_zip(output)
            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
                self.assertTrue(names)
                self.assertFalse(any(".git" in Path(name).parts for name in names))
                self.assertFalse(any("reports" in Path(name).parts for name in names))
                self.assertFalse(any(name.endswith("personal_config.json") for name in names))
                agent_name = (
                    "deterministic-quality/config/personal_agent_config.json"
                )
                agent_config = json.loads(archive.read(agent_name))
                self.assertEqual(
                    "clickhouse.analytics",
                    agent_config["active_database_profile"],
                )
                self.assertEqual(
                    "user_id",
                    agent_config["database_profiles"]["clickhouse.analytics"][
                        "main_identifier"
                    ],
                )


if __name__ == "__main__":
    unittest.main()
