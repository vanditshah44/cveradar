"""
Tests for priority score computation.

The priority score is the product's core value. Getting it wrong
means users don't trust the tool. Test all formula combinations.
"""
import pytest

from app.services.priority import compute_priority, severity_label


class TestComputePriority:
    def test_kev_only(self):
        # Just KEV, no CVSS or EPSS data yet
        assert compute_priority(None, None, True) == 30.0

    def test_cvss_only(self):
        # CVSS 10.0, nothing else
        assert compute_priority(10.0, None, False) == 30.0

    def test_epss_only(self):
        # EPSS 1.0 (certainty of exploitation)
        assert compute_priority(None, 1.0, False) == 40.0

    def test_all_max(self):
        # Perfect storm: KEV + EPSS 1.0 + CVSS 10.0
        # 30 + 40 + 30 = 100
        assert compute_priority(10.0, 1.0, True) == 100.0

    def test_capped_at_100(self):
        # Should never exceed 100
        assert compute_priority(10.0, 1.0, True) <= 100.0

    def test_all_zero(self):
        assert compute_priority(0.0, 0.0, False) == 0.0

    def test_all_none(self):
        # No data yet — score is 0
        assert compute_priority(None, None, False) == 0.0

    def test_high_cvss_low_epss_no_kev(self):
        # CVSS 9.8, EPSS 0.01 (theoretical but not exploited)
        score = compute_priority(9.8, 0.01, False)
        assert score == pytest.approx(29.4 + 0.4, rel=0.01)

    def test_medium_cvss_high_epss_kev(self):
        # CVSS 7.0, EPSS 0.8, KEV — this is the dangerous combo
        # 30 + 32 + 21 = 83
        score = compute_priority(7.0, 0.8, True)
        assert score == pytest.approx(83.0, rel=0.01)


class TestSeverityLabel:
    def test_critical(self):
        assert severity_label(9.5) == "Critical"
        assert severity_label(10.0) == "Critical"
        assert severity_label(9.0) == "Critical"

    def test_high(self):
        assert severity_label(7.5) == "High"
        assert severity_label(7.0) == "High"

    def test_medium(self):
        assert severity_label(5.0) == "Medium"
        assert severity_label(4.0) == "Medium"

    def test_low(self):
        assert severity_label(2.0) == "Low"
        assert severity_label(0.1) == "Low"

    def test_none(self):
        assert severity_label(0.0) == "None"

    def test_unknown(self):
        assert severity_label(None) == "Unknown"
