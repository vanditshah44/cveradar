"""
Tests for NVD configuration parsing.

These samples focus on the cases that break most naive parsers:
- nested AND/OR trees
- vulnerable targets combined with non-vulnerable environment constraints
- preserving enough context to debug how a leaf was produced
"""

from app.tasks.nvd_sync import _extract_affected_products


class TestExtractAffectedProducts:
    def test_nested_and_or_tree_creates_conjunction_groups(self):
        cve_data = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "AND",
                            "children": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:acme:webapp:1.0.0:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "target-1",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:acme:webapp:1.0.1:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "target-2",
                                        },
                                    ],
                                },
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "platform-1",
                                        }
                                    ],
                                },
                            ],
                        }
                    ]
                }
            ]
        }

        affected = _extract_affected_products(cve_data)

        assert len(affected) == 4

        groups: dict[str, list[dict]] = {}
        for row in affected:
            groups.setdefault(row["condition_group"], []).append(row)

        assert len(groups) == 2
        assert all(len(rows) == 2 for rows in groups.values())

        for rows in groups.values():
            vulnerable_rows = [row for row in rows if row["is_vulnerable_match"]]
            env_rows = [row for row in rows if not row["is_vulnerable_match"]]
            assert len(vulnerable_rows) == 1
            assert len(env_rows) == 1
            assert vulnerable_rows[0]["product"] == "webapp"
            assert env_rows[0]["product"] == "windows_10"
            assert vulnerable_rows[0]["match_context"]["group_size"] == 2
            assert env_rows[0]["match_context"]["group_size"] == 2

    def test_preserves_context_and_version_range_metadata(self):
        cve_data = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "1.20.0",
                                    "versionEndExcluding": "1.24.3",
                                    "matchCriteriaId": "nginx-range",
                                }
                            ],
                        }
                    ]
                }
            ]
        }

        affected = _extract_affected_products(cve_data)

        assert len(affected) == 1
        row = affected[0]

        assert row["vendor"] == "nginx"
        assert row["product"] == "nginx"
        assert row["version_start"] == "1.20.0"
        assert row["version_start_including"] is True
        assert row["version_end"] == "1.24.3"
        assert row["version_end_including"] is False
        assert row["single_version"] is None
        assert row["condition_group"] == "config_0_group_0"
        assert "configurations[0]" in row["config_path"]
        assert row["match_context"]["match_criteria_id"] == "nginx-range"
        assert row["match_context"]["criteria"] == "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
        assert row["match_context"]["operator_path"] == ["OR"]
