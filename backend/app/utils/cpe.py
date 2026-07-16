"""
cpe.py — CPE 2.3 string parsing utilities.

CPE (Common Platform Enumeration) is a structured naming scheme for IT systems.
Format: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:...

Examples:
  cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*   → app, nginx, nginx, 1.24.0
  cpe:2.3:o:canonical:ubuntu_linux:22.04:*:...   → os, canonical, ubuntu_linux
  cpe:2.3:a:nodejs:node.js:20.11.0:*:...         → app, nodejs, node.js

The 13 fields: cpe, 2.3, part, vendor, product, version, update,
               edition, language, sw_edition, target_sw, target_hw, other

We only care about: vendor (field[3]), product (field[4]), version (field[5])
"""


def parse_cpe_string(cpe: str) -> tuple[str, str, str] | None:
    """Parse a CPE 2.3 string into (vendor, product, version).

    Returns None if the string is malformed or not CPE 2.3 format.

    >>> parse_cpe_string("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*")
    ('nginx', 'nginx', '1.24.0')
    >>> parse_cpe_string("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*")
    ('nodejs', 'node.js', '*')
    """
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None

    parts = cpe.split(":")
    # CPE 2.3 has exactly 13 colon-separated fields
    if len(parts) < 6:
        return None

    vendor = parts[3]
    product = parts[4]
    version = parts[5] if len(parts) > 5 else "*"

    # Wildcard or N/A values — not useful for matching
    if vendor in ("*", "-") or product in ("*", "-"):
        return None

    return vendor, product, version


def build_cpe_string(vendor: str, product: str, version: str) -> str:
    """Build a CPE 2.3 string from components.

    Used when adding items to a user's stack.

    >>> build_cpe_string("nginx", "nginx", "1.24.0")
    'cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'
    """
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
