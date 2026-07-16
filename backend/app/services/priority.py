"""
priority.py — Priority score computation.

The priority score is CVE Radar's core differentiator. It answers:
"Should I care about this CVE right now?"

Formula (0–100 scale):
  kev_boost   = 30 if in CISA KEV (actively exploited in the wild)
  epss_weight = epss_score * 40  (probability of exploitation in next 30 days)
  cvss_weight = (cvss_score / 10) * 30

  priority = min(100, kev_boost + epss_weight + cvss_weight)

Why this weighting?
  - KEV is the highest signal: if CISA says it's being actively exploited,
    patch immediately regardless of CVSS score.
  - EPSS (0-1 probability) reflects real-world exploitation data from
    FIRST.org. A CVSS 10.0 that nobody exploits should rank lower than
    a CVSS 7.0 that's in 80% of active exploit kits.
  - CVSS contributes but is least important. It's a theoretical severity
    score from the NVD, not a real-world exploitation signal.

Examples:
  CVSS 10.0, no EPSS, no KEV  →  0 + 0 + 30 = 30  (critical but theoretical)
  CVSS 7.0, EPSS 0.8, KEV    →  30 + 32 + 21 = 83 (actively exploited, HIGH PRIORITY)
  CVSS 9.8, EPSS 0.95, KEV   →  30 + 38 + 29 = 97 (patch NOW)
"""


def compute_priority(
    cvss_score: float | None,
    epss_score: float | None,
    kev_flag: bool,
) -> float:
    """Compute priority score (0.0–100.0).

    Any component can be None/missing (e.g., EPSS hasn't been fetched yet).
    Missing components contribute 0 — the score will update when enrichment runs.
    """
    kev_boost = 30.0 if kev_flag else 0.0
    epss_weight = (epss_score * 40.0) if epss_score is not None else 0.0
    cvss_weight = ((cvss_score / 10.0) * 30.0) if cvss_score is not None else 0.0

    return min(100.0, kev_boost + epss_weight + cvss_weight)


def severity_label(cvss_score: float | None) -> str:
    """Map CVSS score to severity label.

    Uses CVSS v3.x severity thresholds from NIST:
      None/0.0        → "None"
      0.1 – 3.9       → "Low"
      4.0 – 6.9       → "Medium"
      7.0 – 8.9       → "High"
      9.0 – 10.0      → "Critical"
    """
    if cvss_score is None:
        return "Unknown"
    if cvss_score == 0.0:
        return "None"
    if cvss_score < 4.0:
        return "Low"
    if cvss_score < 7.0:
        return "Medium"
    if cvss_score < 9.0:
        return "High"
    return "Critical"
