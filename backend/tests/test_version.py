"""
Tests for version comparison utility.

These tests cover the most important and tricky cases:
- Standard semver ranges
- Inclusive vs exclusive bounds
- Edge cases: suffixes, unparseable versions, wildcards
- Single version matching

Run: pytest tests/test_version.py -v
"""
import pytest

from app.utils.version import parse_version, version_in_range


class TestParseVersion:
    def test_standard_semver(self):
        v = parse_version("1.24.0")
        assert v is not None
        assert str(v) == "1.24.0"

    def test_openssh_suffix(self):
        # "9.6p1" is common for OpenSSH
        v = parse_version("9.6p1")
        assert v is not None

    def test_docker_suffix(self):
        # "1.24.0-alpine" — strip the Alpine suffix
        v = parse_version("1.24.0-alpine")
        assert v is not None

    def test_wildcard_returns_none(self):
        assert parse_version("*") is None

    def test_empty_returns_none(self):
        assert parse_version("") is None
        assert parse_version(None) is None  # type: ignore


class TestVersionInRange:
    def test_in_range_inclusive_start(self):
        # Affects >= 1.20.0 and < 1.24.3
        assert version_in_range("1.22.0", "1.20.0", True, "1.24.3", False, None)

    def test_at_inclusive_start(self):
        assert version_in_range("1.20.0", "1.20.0", True, "1.24.3", False, None)

    def test_at_exclusive_start_is_not_in_range(self):
        assert not version_in_range("1.20.0", "1.20.0", False, "1.24.3", False, None)

    def test_at_exclusive_end_is_not_in_range(self):
        # Affects < 1.24.3, so 1.24.3 is NOT affected
        assert not version_in_range("1.24.3", "1.20.0", True, "1.24.3", False, None)

    def test_at_inclusive_end_is_in_range(self):
        # Affects <= 1.24.3
        assert version_in_range("1.24.3", "1.20.0", True, "1.24.3", True, None)

    def test_below_range(self):
        assert not version_in_range("1.19.9", "1.20.0", True, "1.24.3", False, None)

    def test_above_range(self):
        assert not version_in_range("1.25.0", "1.20.0", True, "1.24.3", False, None)

    def test_no_bounds_matches_all(self):
        # All versions affected
        assert version_in_range("99.99.99", None, True, None, False, None)

    def test_single_version_match(self):
        assert version_in_range("1.24.0", None, True, None, False, "1.24.0")

    def test_single_version_no_match(self):
        assert not version_in_range("1.24.1", None, True, None, False, "1.24.0")

    def test_only_start_bound(self):
        # Affects >= 1.20.0 (no end)
        assert version_in_range("99.0.0", "1.20.0", True, None, False, None)
        assert not version_in_range("1.19.9", "1.20.0", True, None, False, None)

    def test_only_end_bound(self):
        # Affects < 1.24.3 (no start)
        assert version_in_range("0.1.0", None, True, "1.24.3", False, None)
        assert not version_in_range("1.24.3", None, True, "1.24.3", False, None)

    def test_unparseable_version_matches_conservatively(self):
        # If we can't parse the user's version, we assume they're affected
        # Better to over-alert than miss a real vulnerability
        assert version_in_range("not-a-version", "1.20.0", True, "1.24.3", False, None)
