import os
import unittest
from unittest.mock import patch

from quality_config import (
    date_range_sql_condition,
    get_date_range,
    get_lookback_range,
    historical_lookback_sql_condition,
    lookback_comparison_window_count,
)


class DateRangeConfigTests(unittest.TestCase):
    def get_range(self, date_range, env=None):
        with patch.dict(os.environ, env or {}, clear=True):
            return get_date_range({"date_range": date_range})

    def test_recommended_rolling_form(self):
        result = self.get_range("7 days")
        self.assertEqual("rolling", result["mode"])
        self.assertEqual(7, result["days_back"])

    def test_hour_rolling_forms(self):
        one_hour = self.get_range("1 hour")
        two_hours = self.get_range("2 hours")

        self.assertEqual("hour", one_hour["interval_unit"])
        self.assertEqual(1, one_hour["interval_value"])
        self.assertEqual(3600, one_hour["duration_seconds"])
        self.assertEqual("last 2 hours", two_hours["description"])
        self.assertEqual(
            "event_date >= now() - INTERVAL 2 HOUR AND event_date < now()",
            date_range_sql_condition(two_hours, "event_date"),
        )

    def test_pipeline_reference_time_freezes_rolling_window(self):
        date_range = self.get_range("1 hour")
        with patch.dict(
            os.environ,
            {"QUALITY_REFERENCE_TIME": "2026-07-17 12:30:00"},
            clear=True,
        ):
            condition = date_range_sql_condition(date_range, "event_date")

        self.assertEqual(
            "event_date >= toDateTime('2026-07-17 12:30:00') - INTERVAL 1 HOUR "
            "AND event_date < toDateTime('2026-07-17 12:30:00')",
            condition,
        )

    def test_offset_reference_time_preserves_the_absolute_instant(self):
        date_range = self.get_range("1 hour")
        with patch.dict(
            os.environ,
            {"QUALITY_REFERENCE_TIME": "2026-08-06T17:08:46+04:00"},
            clear=True,
        ):
            condition = date_range_sql_condition(date_range, "event_time")

        reference = (
            "parseDateTime64BestEffort('2026-08-06T17:08:46+04:00')"
        )
        self.assertEqual(
            f"event_time >= {reference} - INTERVAL 1 HOUR "
            f"AND event_time < {reference}",
            condition,
        )

    def test_recommended_fixed_form_is_inclusive(self):
        result = self.get_range("2026-02-01 to 2026-05-05")
        self.assertEqual("fixed", result["mode"])
        self.assertEqual("2026-02-01", result["start_date"])
        self.assertEqual("2026-05-05", result["end_date"])
        self.assertEqual("2026-05-06", result["end_date_exclusive"])

    def test_compact_aliases(self):
        self.assertEqual(7, self.get_range("7d")["days_back"])
        self.assertEqual(7, self.get_range("last 7 days")["days_back"])
        self.assertEqual(2, self.get_range("2h")["hours_back"])
        result = self.get_range("2026-02-01..2026-02-03")
        self.assertEqual(3, result["days_back"])

    def test_positive_integer_scalar(self):
        self.assertEqual(7, self.get_range(7)["days_back"])

    def test_legacy_object_forms(self):
        self.assertEqual(4, self.get_range({"days_back": 4})["days_back"])

        start_end = self.get_range(
            {"start_date": "2026-02-01", "end_date": "2026-02-02"}
        )
        self.assertEqual("fixed", start_end["mode"])

        from_to = self.get_range(
            {"from_date": "2026-02-01", "to_date": "2026-02-02"}
        )
        self.assertEqual(start_end, from_to)

    def test_invalid_scalars(self):
        for value in ("next week", "0 days", 0, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.get_range(value)

    def test_reversed_fixed_range(self):
        with self.assertRaises(ValueError):
            self.get_range("2026-05-05 to 2026-02-01")

    def test_days_environment_overrides_rolling_scalar(self):
        result = self.get_range("7 days", {"QUALITY_DAYS_BACK": "2"})
        self.assertEqual(2, result["days_back"])

    def test_shared_scalar_overrides_legacy_stage_default(self):
        with patch.dict(os.environ, {}, clear=True):
            result = get_date_range(
                {"date_range": "1 day"},
                days_candidates=[7],
            )

        self.assertEqual(1, result["days_back"])
        self.assertEqual("last 1 day", result["description"])

    def test_stage_environment_still_overrides_shared_scalar(self):
        with patch.dict(os.environ, {"AI_AGENT_DAYS_BACK": "3"}, clear=True):
            result = get_date_range(
                {"date_range": "1 day"},
                env_prefix="AI_AGENT",
                days_env_var="AI_AGENT_DAYS_BACK",
                days_candidates=[7],
            )

        self.assertEqual(3, result["days_back"])

    def test_fixed_scalar_wins_over_days_environment(self):
        result = self.get_range(
            "2026-02-01 to 2026-02-03",
            {"QUALITY_DAYS_BACK": "2"},
        )
        self.assertEqual("fixed", result["mode"])
        self.assertEqual(3, result["days_back"])

    def test_fixed_environment_pair_overrides_config(self):
        result = self.get_range(
            "7 days",
            {
                "QUALITY_START_DATE": "2026-03-01",
                "QUALITY_END_DATE": "2026-03-02",
            },
        )
        self.assertEqual("fixed", result["mode"])
        self.assertEqual("2026-03-01", result["start_date"])
        self.assertEqual("2026-03-02", result["end_date"])

    def test_lookback_is_independent_from_measurement_range(self):
        rules = {
            "date_range": "1 hour",
            "lookback": "30 days",
        }

        with patch.dict(os.environ, {}, clear=True):
            measurement = get_date_range(rules)
            lookback = get_lookback_range(rules)

        self.assertEqual("last 1 hour", measurement["description"])
        self.assertEqual("last 30 days", lookback["description"])

        condition = historical_lookback_sql_condition(
            measurement,
            lookback,
            "event_date",
        )
        self.assertIn("event_date < now() - INTERVAL 1 HOUR", condition)
        self.assertIn("toStartOfDay(event_date)", condition)
        self.assertEqual(
            30.0,
            lookback_comparison_window_count(measurement, lookback),
        )

    def test_legacy_parameter_date_range_becomes_lookback(self):
        rules = {"date_range": "1 day"}
        section = {"date_range": "30 days"}

        self.assertEqual(
            "last 30 days",
            get_lookback_range(rules, section)["description"],
        )


if __name__ == "__main__":
    unittest.main()
