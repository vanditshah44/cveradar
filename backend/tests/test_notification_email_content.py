from types import SimpleNamespace

from app.services.notification_email import format_affected_version_range, pick_useful_reference


def test_format_affected_version_range_for_single_version():
    requirement = SimpleNamespace(
        single_version="1.24.0",
        version_start=None,
        version_start_including=True,
        version_end=None,
        version_end_including=False,
    )

    assert format_affected_version_range(requirement) == "= 1.24.0"


def test_format_affected_version_range_for_bounded_range():
    requirement = SimpleNamespace(
        single_version=None,
        version_start="1.20.0",
        version_start_including=True,
        version_end="1.24.3",
        version_end_including=False,
    )

    assert format_affected_version_range(requirement) == ">= 1.20.0 and < 1.24.3"


def test_pick_useful_reference_prefers_vendor_advisory():
    cve = SimpleNamespace(
        references=[
            {"url": "https://example.com/third-party", "tags": ["Third Party Advisory"]},
            {"url": "https://vendor.example.com/advisory", "tags": ["Vendor Advisory"]},
        ]
    )

    reference = pick_useful_reference(cve)

    assert reference["url"] == "https://vendor.example.com/advisory"
