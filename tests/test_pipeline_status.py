import unittest
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import run_quality_pipeline
from deterministic_pipeline import run_pipeline as deterministic_runner
from deterministic_pipeline.lib import config as deterministic_config
from deterministic_pipeline.lib.artifacts import atomic_write_text
from deterministic_pipeline.scripts import collect_metrics
from deterministic_pipeline.scripts import build_report as deterministic_report


class PipelineStatusTests(unittest.TestCase):
    def test_pipeline_reference_times_include_the_utc_offset(self):
        started_at = datetime(
            2026,
            8,
            6,
            17,
            8,
            46,
            tzinfo=timezone(timedelta(hours=4)),
        )

        self.assertEqual(
            "2026-08-06T17:08:46+04:00",
            run_quality_pipeline.format_reference_time(started_at),
        )
        self.assertEqual(
            "2026-08-06T17:08:46+04:00",
            deterministic_runner.format_reference_time(started_at),
        )

    def test_legacy_pipeline_runs_source_flow_before_ai(self):
        scripts = [stage["script"] for stage in run_quality_pipeline.STAGES]
        self.assertLess(
            scripts.index("check_event_flow.py"),
            scripts.index("investigate_database.py"),
        )

    def test_legacy_pipeline_marks_only_final_two_stages_as_llm(self):
        llm_scripts = [
            stage["script"]
            for stage in run_quality_pipeline.STAGES
            if stage.get("uses_llm")
        ]
        self.assertEqual(
            ["investigate_database.py", "generate_quality_report.py"],
            llm_scripts,
        )

    def test_legacy_runner_forces_managed_model_identifier(self):
        with patch.object(
            run_quality_pipeline.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0),
        ) as run:
            run_quality_pipeline.run_script(
                {"name": "test", "script": "investigate_database.py"},
                "run-id",
                "2026-08-06T18:00:00+04:00",
                "quality-pipeline-gpt-oss",
            )

        environment = run.call_args.kwargs["env"]
        self.assertEqual(
            "quality-pipeline-gpt-oss",
            environment["AI_AGENT_MODEL"],
        )
        self.assertEqual(
            "quality-pipeline-gpt-oss",
            environment["LMSTUDIO_MODEL"],
        )

    def test_pipeline_llm_unloads_when_stage_raises(self):
        with (
            patch.object(run_quality_pipeline, "load_model") as load_model,
            patch.object(run_quality_pipeline, "unload_model") as unload_model,
        ):
            with self.assertRaisesRegex(RuntimeError, "stage failed"):
                with run_quality_pipeline.managed_pipeline_llm() as identifier:
                    self.assertEqual("quality-pipeline-gpt-oss", identifier)
                    raise RuntimeError("stage failed")

        load_model.assert_called_once_with(
            model="openai/gpt-oss-20b",
            identifier="quality-pipeline-gpt-oss",
            context_length=65536,
            gpu_offload="max",
            parallel=1,
            replace_loaded=True,
        )
        unload_model.assert_called_once_with("quality-pipeline-gpt-oss")

    def test_legacy_runner_recognizes_degraded_exit_code(self):
        with patch.object(
            run_quality_pipeline.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=2),
        ):
            result = run_quality_pipeline.run_script(
                {"name": "test", "script": "check_event_quality.py"},
                "run-id",
            )

        self.assertEqual("degraded", result["status"])

    def test_deterministic_runner_recognizes_degraded_exit_code(self):
        with patch.object(
            deterministic_runner.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=2),
        ):
            result = deterministic_runner.run_script(
                "test", Path("script.py"), "run-id"
            )

        self.assertEqual("degraded", result["status"])

    def test_deterministic_outputs_stay_inside_pipeline_directory(self):
        expected = Path(deterministic_config.__file__).resolve().parents[1] / "reports"
        self.assertEqual(expected, deterministic_config.output_dir())

    def test_deterministic_metrics_initializes_empty_parameter_results(self):
        date_range = {
            "mode": "rolling",
            "interval_value": 1,
            "interval_unit": "hour",
            "duration_seconds": 3600,
            "description": "last 1 hour",
        }
        lookback = {
            "mode": "rolling",
            "interval_value": 30,
            "interval_unit": "day",
            "duration_seconds": 2592000,
            "description": "last 30 days",
        }
        with TemporaryDirectory() as directory:
            with (
                patch.object(collect_metrics, "load_pipeline_config", return_value={}),
                patch.object(collect_metrics, "output_dir", return_value=Path(directory)),
                patch.object(collect_metrics, "discover_inventory", return_value=[]),
                patch.object(collect_metrics, "get_database", return_value="analytics"),
                patch.object(
                    collect_metrics,
                    "get_date_range_description",
                    return_value="last 1 hour",
                ),
                patch.object(collect_metrics, "get_date_range", return_value=date_range),
                patch.object(collect_metrics, "get_lookback_range", return_value=lookback),
                patch.object(collect_metrics, "get_main_identifier", return_value="user_id"),
            ):
                collect_metrics.main()

                artifact = Path(directory) / collect_metrics.STABLE_METRICS_JSON
                self.assertIn('"parameter_results": []', artifact.read_text("utf-8"))
                self.assertIn('"coverage_complete": true', artifact.read_text("utf-8"))
                self.assertTrue(
                    (Path(directory) / collect_metrics.STABLE_EVENT_QUALITY_CSV).exists()
                )
                self.assertTrue(
                    (Path(directory) / collect_metrics.STABLE_PARAMETER_QUALITY_CSV).exists()
                )

    def test_deterministic_identifier_normalization_matches_definition(self):
        expression = collect_metrics.norm_expr({"user_id"}, "user_id")
        self.assertIn("trim(BOTH ' '", expression)
        self.assertIn("00000000-0000-0000-0000-000000000000", expression)
        self.assertIn("lower(toString", expression)

    def test_deterministic_identifier_normalization_uses_present_aliases(self):
        expression = collect_metrics.norm_expr(
            {"session_uuid"},
            "session_id",
            ["session_id", "session_uuid", "sessions_uuid"],
        )

        self.assertIn("`session_uuid`", expression)
        self.assertNotIn("`session_id`", expression)
        self.assertTrue(expression.endswith("AS session_id_norm"))

    def test_atomic_artifact_write_truncates_previous_content(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            path.write_text("stale trailing content", encoding="utf-8")

            atomic_write_text(path, "{}")

            self.assertEqual("{}", path.read_text(encoding="utf-8"))

    def test_empty_deterministic_csv_is_reported_as_zero_rows(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "empty.csv"
            path.write_text("", encoding="utf-8")

            self.assertIn("(0 rows)", deterministic_report.summarize_csv(str(path)))


if __name__ == "__main__":
    unittest.main()
