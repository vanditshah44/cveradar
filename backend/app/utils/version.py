"""
version.py — Version comparison for CVE matching.

This is one of the trickiest parts of the project. Software versioning
is not standardized — different projects use different schemes:
  - nginx: 1.24.0 (semver-like)
  - OpenSSL: 3.0.7 (semver-like)
  - WordPress: 6.4.2 (semver-like)
  - PHP: 8.2.15 (semver-like)
  - Ubuntu: 22.04 (year.month)
  - OpenSSH: 9.6p1 (version + patch level suffix)

The `packaging` library handles most of these correctly via PEP 440
version parsing. For edge cases (suffixes like "p1", "alpine"), we
strip the suffix and compare the numeric part.

Design decision: when in doubt, match liberally (err toward over-alerting).
Better to get a false positive alert than to miss a real vulnerability.
"""
import re
import logging

from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)


def parse_version(version_str: str) -> Version | None:
    """Parse a version string into a comparable Version object.

    Handles common version string quirks:
    - "9.6p1" → "9.6.1" (OpenSSH-style patch suffix)
    - "1.24.0-alpine" → "1.24.0" (Docker tag suffix)
    - "2:8.2.15-1" → "8.2.15" (Debian epoch prefix)
    - "8.2.15-1ubuntu0.2" → "8.2.15" (distro patch suffix)

    Returns None if the version can't be parsed (caller should match liberally).
    """
    if not version_str or version_str in ("*", "-", "N/A", ""):
        return None

    cleaned = version_str.strip()

    # Remove Debian/Ubuntu epoch prefix (e.g., "2:8.2.15" → "8.2.15")
    cleaned = re.sub(r"^\d+:", "", cleaned)

    # Strip common suffixes that break parsing:
    # "-alpine", "-debian", "-ubuntu0.2", "-1ubuntu", "p1", etc.
    cleaned = re.sub(r"[-_](alpine|debian|ubuntu|centos|rhel|el\d|deb\d).*$", "", cleaned, flags=re.IGNORECASE)

    # OpenSSH-style: "9.6p1" → "9.6.1"
    cleaned = re.sub(r"p(\d+)$", r".\1", cleaned)

    # Strip trailing non-numeric junk (e.g., "8.2.15-1" → "8.2.15")
    cleaned = re.sub(r"[-+].*$", "", cleaned)

    try:
        return Version(cleaned)
    except InvalidVersion:
        logger.debug("Could not parse version: %r (cleaned: %r)", version_str, cleaned)
        return None


def version_in_range(
    version_str: str,
    version_start: str | None,
    version_start_including: bool,
    version_end: str | None,
    version_end_including: bool,
    single_version: str | None,
) -> bool:
    """Check if a version falls within a CVE's affected range.

    This function is called for every (stack_item, affected_product) pair.
    It needs to be fast and correct.

    Conservative matching (return True on parse failure): if we can't
    determine whether a version is in range, we assume it IS affected.
    This is the safe choice — we'd rather alert unnecessarily than miss
    a real vulnerability.

    Args:
        version_str:           the user's version (e.g., "1.24.0")
        version_start:         range start version (may be None)
        version_start_including: if True, range is >= start; if False, > start
        version_end:           range end version (may be None)
        version_end_including:   if True, range is <= end; if False, < end
        single_version:        if set, only this exact version is affected

    Returns:
        True if the version is in the affected range.
    """
    # Single version match (most precise — exact version)
    if single_version:
        v = parse_version(version_str)
        sv = parse_version(single_version)
        if v is None or sv is None:
            return version_str == single_version  # fall back to string equality
        return v == sv

    # No range constraints at all — all versions affected
    if not version_start and not version_end:
        return True

    v = parse_version(version_str)
    if v is None:
        # Can't parse user's version — match conservatively
        return True

    # Check lower bound
    if version_start:
        sv = parse_version(version_start)
        if sv is None:
            return True  # can't parse bound — match conservatively
        if version_start_including:
            if v < sv:
                return False
        else:
            if v <= sv:
                return False

    # Check upper bound
    if version_end:
        ev = parse_version(version_end)
        if ev is None:
            return True  # can't parse bound — match conservatively
        if version_end_including:
            if v > ev:
                return False
        else:
            if v >= ev:
                return False

    return True
