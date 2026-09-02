import os
import unittest
from unittest.mock import patch

from quality_config import (
    get_identifier_aliases,
    get_main_identifier,
    get_missing_main_identifier_allowed_tables,
    get_missing_main_identifier_allowed_tables,
    get_profile_context,
    get_table_prefixes,
    is_table_blacklisted,
    is_parameter_missing_allowed,
)


class ProfilePrefixConfigTests(unittest.TestCase):
    def test_table_blacklist_matching_is_case_insensitive(self):
        patterns = ["accountinventorylog", "debug_*"]

        self.assertTrue(is_table_blacklisted("AccountInventoryLog", patterns))
        self.assertTrue(is_table_blacklisted("DEBUG_EVENTS", patterns))
        self.assertFalse(is_table_blacklisted("event_login", patterns))

    def test_empty_profile_prefixes_disable_prefix_filter(self):
        rules = {
            "active_database_profile": "clickhouse.analytics",
            "database_profiles": {
                "clickhouse.analytics": {
                    "database": "analytics",
                    "table_name_prefixes": [],
                },
            },
        }

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual([], get_table_prefixes(rules))

    def test_missing_profile_prefixes_use_default(self):
        rules = {
            "active_database_profile": "clickhouse.analytics",
            "database_profiles": {
                "clickhouse.analytics": {
                    "database": "analytics",
                },
            },
        }

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(["event_"], get_table_prefixes(rules))

    def test_main_identifier_is_resolved_from_active_profile(self):
        rules = {
            "active_database_profile": "clickhouse.analytics",
            "database_profiles": {
                "clickhouse.analytics_secondary": {
                    "database": "analytics_secondary",
                    "main_identifier": "user_id",
                },
                "clickhouse.analytics": {
                    "database": "analytics",
                    "main_identifier": "user_id",
                },
            },
        }

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual("user_id", get_main_identifier(rules))
            self.assertEqual(["user_id"], get_identifier_aliases("user_id", rules))
            self.assertEqual("user_id", get_profile_context(rules)["main_identifier"])

        rules["active_database_profile"] = "clickhouse.analytics_secondary"
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual("user_id", get_main_identifier(rules))
            self.assertEqual(["user_id"], get_identifier_aliases("user_id", rules))

    def test_invalid_main_identifier_is_rejected(self):
        rules = {
            "active_database_profile": "clickhouse.analytics",
            "database_profiles": {
                "clickhouse.analytics": {
                    "database": "analytics",
                    "main_identifier": "user_id; DROP TABLE x",
                },
            },
        }

        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                get_main_identifier(rules)

    def test_missing_main_identifier_group_uses_canonical_name(self):
        rules = {
            "event_groups": {
                "missing_main_identifier_allowed": {"tables": ["event_enter"]},
            },
        }

        self.assertEqual(
            {"event_enter"},
            get_missing_main_identifier_allowed_tables(rules),
        )
        self.assertEqual(
            ["event_enter"],
            get_profile_context(rules)["missing_main_identifier_allowed_tables"],
        )

    def test_identifier_missing_allowance_uses_groups_and_event_context(self):
        rules = {
            "event_groups": {
                "missing_main_identifier_allowed": {
                    "tables": ["event_change_language"],
                },
            },
            "event_context": {
                "event_loading": {"skip_main_identifier_check": True},
                "event_enter": {"skip_main_identifier_check": True},
                "event_login_screen": {"skip_main_identifier_check": True},
            },
        }

        for table in (
            "event_change_language",
            "event_loading",
            "event_enter",
            "event_login_screen",
        ):
            self.assertTrue(
                is_parameter_missing_allowed(table, "user_id", rules),
                table,
            )
        self.assertFalse(
            is_parameter_missing_allowed("event_login", "user_id", rules)
        )


if __name__ == "__main__":
    unittest.main()
