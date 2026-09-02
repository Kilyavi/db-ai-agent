import unittest
from unittest.mock import patch

import pandas as pd

import drill_down_quality_issues


class DrilldownColumnsTests(unittest.TestCase):
    def test_get_columns_returns_empty_set_for_empty_query_shape(self):
        with patch.object(
            drill_down_quality_issues,
            "query_df",
            return_value=pd.DataFrame(),
        ):
            self.assertEqual(set(), drill_down_quality_issues.get_columns("event_enter"))

    def test_duplicate_drilldown_aliases_profile_main_identifier(self):
        captured = []

        with (
            patch.object(
                drill_down_quality_issues,
                "MAIN_IDENTIFIER_ALIASES",
                ["user_id"],
            ),
            patch.object(
                drill_down_quality_issues,
                "query_df",
                side_effect=lambda sql: captured.append(sql) or pd.DataFrame(),
            ),
        ):
            drill_down_quality_issues.duplicate_samples(
                "app_account",
                {"event_date", "event_key", "adid", "user_id"},
            )

        self.assertIn("`user_id`", captured[0])
        self.assertIn("AS main_identifier", captured[0])
        self.assertIn("uniqExact(main_identifier)", captured[0])


if __name__ == "__main__":
    unittest.main()
