"""
notification_email.py — Build rich, branded notification email content.

Two email types:
  1. Daily digest  — summary of new CVEs affecting the user's stack (sent every morning)
  2. KEV alert     — instant alert when a CVE is added to CISA's Known Exploited Vulnerabilities list

Design principles:
  - Table-based layout for maximum email client compatibility (Gmail, Outlook, Apple Mail, mobile)
  - Inline CSS only — no <style> blocks (stripped by many clients)
  - No JavaScript — blocked universally in email
  - Auto-authenticating dashboard links — clicking from any device logs the user in directly
    using a single-use, 15-minute signed magic link token (same replay-guard as the login flow)
  - Open-redirect safe — the `next` param in the verify URL is validated server-side
"""
from collections import defaultdict
from dataclasses import dataclass
from html import escape
from urllib.parse import quote, urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.cve import Cve, CveAffectedProduct
from app.models.match import UserCveMatch
from app.models.stack_item import StackItem
from app.models.user import User
from app.services.priority import compute_priority, severity_label
from app.utils.version import version_in_range

REFERENCE_TAG_PREFERENCE = [
    "Vendor Advisory",
    "Patch",
    "Mitigation",
    "Release Notes",
    "Third Party Advisory",
]


# ── Helpers ────────────────────────────────────────────────────────────────────

@dataclass
class MatchEmailContext:
    product_name: str
    user_version: str
    affected_range: str
    why: str
    supporting_stack: list[str]


def _matches_requirement(stack_item: StackItem, requirement: CveAffectedProduct) -> bool:
    if stack_item.vendor != requirement.vendor:
        return False
    if stack_item.cpe_product != requirement.product:
        return False
    return version_in_range(
        stack_item.version,
        requirement.version_start,
        requirement.version_start_including,
        requirement.version_end,
        requirement.version_end_including,
        requirement.single_version,
    )


def format_affected_version_range(affected_product: CveAffectedProduct | object) -> str:
    single_version = getattr(affected_product, "single_version", None)
    version_start = getattr(affected_product, "version_start", None)
    version_start_including = getattr(affected_product, "version_start_including", True)
    version_end = getattr(affected_product, "version_end", None)
    version_end_including = getattr(affected_product, "version_end_including", False)

    if single_version:
        return f"= {single_version}"
    parts = []
    if version_start:
        parts.append(f"{'≥' if version_start_including else '>'} {version_start}")
    if version_end:
        parts.append(f"{'≤' if version_end_including else '<'} {version_end}")
    return " and ".join(parts) if parts else "Not specified by NVD"


def pick_useful_reference(cve: Cve) -> dict | None:
    references = cve.references or []
    if not isinstance(references, list) or not references:
        return None
    for preferred_tag in REFERENCE_TAG_PREFERENCE:
        for ref in references:
            if preferred_tag in (ref.get("tags") or []):
                return ref
    url_keywords = ["advisory", "security", "patch", "fix", "release", "bulletin"]
    for ref in references:
        url = (ref.get("url") or "").lower()
        if any(kw in url for kw in url_keywords):
            return ref
    return references[0]


def _reference_label(reference: dict | None) -> str:
    if not reference:
        return "Reference"
    tags = reference.get("tags") or []
    for preferred_tag in REFERENCE_TAG_PREFERENCE:
        if preferred_tag in tags:
            return preferred_tag
    source = reference.get("source")
    if source:
        return source
    parsed = urlparse(reference.get("url") or "")
    return parsed.netloc or "Reference"


def _stack_item_label(stack_item: StackItem) -> str:
    product_name = stack_item.product_name or stack_item.cpe_product or stack_item.vendor
    return f"{product_name} {stack_item.version}"


def _requirement_specificity_key(req: CveAffectedProduct) -> tuple[int, int, int]:
    return (
        1 if req.single_version else 0,
        1 if req.version_start else 0,
        1 if req.version_end else 0,
    )


def _choose_group_for_match(
    target_stack_item: StackItem,
    user_stack_items: list[StackItem],
    grouped_requirements: dict[str, list[CveAffectedProduct]],
) -> tuple[CveAffectedProduct | None, list[str]]:
    candidates = []
    for requirements in grouped_requirements.values():
        target_reqs = [
            r for r in requirements
            if r.is_vulnerable_match and _matches_requirement(target_stack_item, r)
        ]
        if not target_reqs:
            continue
        supporting_stack: list[str] = []
        satisfied = True
        for req in requirements:
            matching = [s for s in user_stack_items if _matches_requirement(s, req)]
            if not matching:
                satisfied = False
                break
            if not req.is_vulnerable_match:
                supporting_stack.append(_stack_item_label(matching[0]))
        if not satisfied:
            continue
        best = sorted(target_reqs, key=_requirement_specificity_key, reverse=True)[0]
        score = (len(requirements), len(supporting_stack), _requirement_specificity_key(best))
        candidates.append((score, best, supporting_stack))

    if candidates:
        _, best_req, supporting_stack = max(candidates, key=lambda c: c[0])
        return best_req, supporting_stack
    return None, []


def build_match_email_contexts(
    db: Session,
    *,
    user: User,
    cve: Cve,
    matches: list[UserCveMatch] | None = None,
) -> list[MatchEmailContext]:
    if matches is None:
        matches = (
            db.execute(
                select(UserCveMatch).where(
                    UserCveMatch.user_id == user.id,
                    UserCveMatch.cve_id == cve.cve_id,
                    UserCveMatch.dismissed == False,  # noqa: E712
                )
            ).scalars().all()
        )
    if not matches:
        return []

    stack_item_ids = [m.stack_item_id for m in matches]
    stack_items = {
        s.id: s
        for s in db.execute(select(StackItem).where(StackItem.id.in_(stack_item_ids))).scalars().all()
    }
    user_stack_items = db.execute(select(StackItem).where(StackItem.user_id == user.id)).scalars().all()
    affected_products = db.execute(
        select(CveAffectedProduct).where(CveAffectedProduct.cve_id == cve.cve_id)
    ).scalars().all()

    grouped: dict[str, list[CveAffectedProduct]] = defaultdict(list)
    for ap in affected_products:
        group_id = ap.condition_group or f"ungrouped:{ap.id}"
        grouped[group_id].append(ap)

    contexts: list[MatchEmailContext] = []
    seen_ids: set = set()

    for match in matches:
        si = stack_items.get(match.stack_item_id)
        if not si or si.id in seen_ids:
            continue
        seen_ids.add(si.id)

        target_req, supporting_stack = _choose_group_for_match(si, user_stack_items, grouped)
        if not target_req:
            fallbacks = [
                ap for ap in affected_products
                if ap.is_vulnerable_match and _matches_requirement(si, ap)
            ]
            target_req = sorted(fallbacks, key=_requirement_specificity_key, reverse=True)[0] if fallbacks else None

        affected_range = format_affected_version_range(target_req) if target_req else "Not specified by NVD"
        why = (
            f"You run {si.product_name} {si.version}, which falls in the vulnerable range "
            f"{affected_range} for {cve.cve_id}."
        )
        if supporting_stack:
            why += " Additional NVD conditions are also satisfied by " + ", ".join(supporting_stack) + "."

        contexts.append(MatchEmailContext(
            product_name=si.product_name,
            user_version=si.version,
            affected_range=affected_range,
            why=why,
            supporting_stack=supporting_stack,
        ))
    return contexts


# ── Authenticated link generation ──────────────────────────────────────────────

def _make_auth_link(user_email: str, destination: str) -> str:
    """Generate a single-use magic link that logs the user in and redirects to destination.

    This allows the email recipient to open the link from any device and land
    directly on the relevant page without needing to enter their email again.

    Security properties (same as the login magic link):
      - Signed with SECRET_KEY (HS256 JWT)
      - 15-minute expiry
      - Single-use: Redis replay guard blocks reuse after first click
      - Redirect is a relative path (validated in the verify endpoint — no open redirect)
    """
    from app.services.auth import create_magic_link_token
    token = create_magic_link_token(user_email)
    safe_dest = quote(destination, safe="/")
    return f"{settings.FRONTEND_URL}/auth/verify?token={token}&next={safe_dest}"


def _cve_detail_link(user_email: str, cve_id: str) -> str:
    return _make_auth_link(user_email, f"/cve/{cve_id}")


def _dashboard_link(user_email: str) -> str:
    return _make_auth_link(user_email, "/dashboard")


def _settings_link(user_email: str) -> str:
    return _make_auth_link(user_email, "/settings")


# ── Severity styling ───────────────────────────────────────────────────────────

def _severity_colors(cvss_score: float | None) -> tuple[str, str]:
    """Return (background, text) colors for a CVSS score badge."""
    if cvss_score is None:
        return "#e2e8f0", "#475569"
    if cvss_score >= 9.0:
        return "#fef2f2", "#991b1b"   # Critical — red
    if cvss_score >= 7.0:
        return "#fff7ed", "#c2410c"   # High — orange
    if cvss_score >= 4.0:
        return "#fffbeb", "#b45309"   # Medium — amber
    return "#f0fdf4", "#166534"       # Low — green


def _priority_bar(priority: int) -> str:
    """Render a simple inline progress bar for priority score (0–100)."""
    clamped = max(0, min(100, priority))
    if clamped >= 80:
        bar_color = "#ef4444"
    elif clamped >= 50:
        bar_color = "#f97316"
    elif clamped >= 30:
        bar_color = "#eab308"
    else:
        bar_color = "#22c55e"
    return (
        f'<table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-top:6px;">'
        f'<tr>'
        f'<td width="{clamped}%" style="height:4px;background:{bar_color};border-radius:2px 0 0 2px;font-size:0;">&nbsp;</td>'
        f'<td style="height:4px;background:#e2e8f0;border-radius:0 2px 2px 0;font-size:0;">&nbsp;</td>'
        f'</tr>'
        f'</table>'
    )


# ── Shared sub-components ──────────────────────────────────────────────────────

def _email_wrapper(body_content: str) -> str:
    """Wrap content in a full, valid HTML email document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>CVE Radar</title>
  <!--[if mso]><noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript><![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f1f5f9;">
  <tr>
    <td align="center" style="padding:32px 16px;">
      <table width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;">
        {body_content}
      </table>
    </td>
  </tr>
</table>
</body>
</html>"""


def _email_footer(user_email: str) -> str:
    settings_url = escape(_settings_link(user_email), quote=True)
    return f"""
<tr>
  <td style="padding:20px 0 8px;text-align:center;">
    <p style="margin:0;color:#94a3b8;font-size:12px;line-height:1.6;">
      CVE Radar &nbsp;·&nbsp;
      <a href="{settings_url}" style="color:#94a3b8;text-decoration:underline;">Manage notifications</a>
      &nbsp;·&nbsp;
      <a href="{settings_url}" style="color:#94a3b8;text-decoration:underline;">Unsubscribe</a>
    </p>
    <p style="margin:6px 0 0;color:#cbd5e1;font-size:11px;">
      You received this because CVE Radar found new vulnerabilities in your tech stack.
    </p>
  </td>
</tr>"""


def _render_match_context_rows(contexts: list[MatchEmailContext], limit: int = 2) -> str:
    if not contexts:
        return ""
    rows = []
    for ctx in contexts[:limit]:
        rows.append(f"""
<tr>
  <td style="padding:10px 0 0;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0"
           style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;">
      <tr>
        <td style="padding:12px 14px;">
          <p style="margin:0 0 4px;font-size:13px;color:#475569;">
            <span style="font-weight:600;color:#0f172a;">&#x1F4E6; {escape(ctx.product_name)} {escape(ctx.user_version)}</span>
            &nbsp;&rarr;&nbsp;
            <span style="font-family:monospace;background:#e2e8f0;color:#0f172a;padding:1px 6px;border-radius:4px;font-size:12px;">{escape(ctx.affected_range)}</span>
          </p>
          <p style="margin:0;font-size:12px;color:#64748b;line-height:1.5;">{escape(ctx.why)}</p>
        </td>
      </tr>
    </table>
  </td>
</tr>""")
    if len(contexts) > limit:
        rows.append(
            f'<tr><td style="padding:6px 0 0;font-size:12px;color:#94a3b8;">'
            f'+ {len(contexts) - limit} more matched product(s) in your stack.</td></tr>'
        )
    return "".join(rows)


# ── KEV Alert Email ────────────────────────────────────────────────────────────

def build_kev_alert_email(db: Session, user: User, cve: Cve) -> tuple[str, str]:
    """Build subject + HTML body for an instant KEV alert."""
    contexts = build_match_email_contexts(db, user=user, cve=cve)
    reference = pick_useful_reference(cve)
    priority = round(compute_priority(cve.cvss_score, cve.epss_score, cve.kev_flag))
    cvss_str = str(round(cve.cvss_score, 1)) if cve.cvss_score is not None else "N/A"
    epss_pct = f"{cve.epss_score * 100:.1f}%" if cve.epss_score is not None else "N/A"
    description = escape((cve.description or "No description available.")[:300])
    detail_url = escape(_cve_detail_link(user.email, cve.cve_id), quote=True)
    dashboard_url = escape(_dashboard_link(user.email), quote=True)
    ref_html = ""
    if reference and reference.get("url"):
        ref_html = (
            f'<a href="{escape(reference["url"], quote=True)}" '
            f'style="display:inline-block;margin-top:10px;padding:10px 20px;background:#fff;'
            f'border:1px solid #fecaca;color:#b91c1c;border-radius:6px;text-decoration:none;font-size:13px;font-weight:600;">'
            f'&#x1F517; {escape(_reference_label(reference))}</a>'
        )
    match_rows = _render_match_context_rows(contexts, limit=3)

    subject = f"[CVE Radar] URGENT: {cve.cve_id} is now actively exploited — check your stack"

    body_content = f"""
<!-- Header -->
<tr>
  <td style="background:linear-gradient(135deg,#7f1d1d 0%,#b91c1c 100%);border-radius:12px 12px 0 0;padding:0;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding:20px 28px 12px;">
          <table cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="background:rgba(255,255,255,0.15);border-radius:6px;padding:4px 10px;">
                <span style="color:white;font-size:11px;font-weight:700;letter-spacing:1px;">&#x26A0;&#xFE0F; ACTIVE EXPLOIT &nbsp;·&nbsp; CISA KEV</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="padding:0 28px 10px;">
          <span style="color:white;font-size:26px;font-weight:800;letter-spacing:-0.5px;">{escape(cve.cve_id)}</span>
        </td>
      </tr>
      <tr>
        <td style="padding:0 28px 24px;">
          <!-- Stats row -->
          <table cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="background:rgba(0,0,0,0.25);border-radius:6px;padding:6px 14px;margin-right:8px;">
                <span style="color:#fca5a5;font-size:11px;font-weight:600;">CVSS</span><br>
                <span style="color:white;font-size:18px;font-weight:700;">{escape(cvss_str)}</span>
              </td>
              <td style="width:8px;">&nbsp;</td>
              <td style="background:rgba(0,0,0,0.25);border-radius:6px;padding:6px 14px;">
                <span style="color:#fca5a5;font-size:11px;font-weight:600;">EPSS</span><br>
                <span style="color:white;font-size:18px;font-weight:700;">{escape(epss_pct)}</span>
              </td>
              <td style="width:8px;">&nbsp;</td>
              <td style="background:rgba(0,0,0,0.25);border-radius:6px;padding:6px 14px;">
                <span style="color:#fca5a5;font-size:11px;font-weight:600;">PRIORITY</span><br>
                <span style="color:white;font-size:18px;font-weight:700;">{priority}/100</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </td>
</tr>

<!-- Body -->
<tr>
  <td style="background:white;padding:28px;">
    <!-- Logo bar -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:20px;">
      <tr>
        <td>
          <span style="font-size:15px;font-weight:700;color:#0f172a;">&#x26A1; CVE Radar</span>
        </td>
        <td align="right">
          <span style="font-size:12px;color:#94a3b8;">Instant KEV Alert</span>
        </td>
      </tr>
    </table>

    <!-- Description -->
    <p style="margin:0 0 20px;color:#334155;font-size:14px;line-height:1.7;border-left:3px solid #fca5a5;padding-left:14px;">
      {description}
    </p>

    <!-- Why you got this -->
    <p style="margin:0 0 10px;font-size:13px;font-weight:700;color:#0f172a;text-transform:uppercase;letter-spacing:0.5px;">
      &#x1F3AF; Why you got this alert
    </p>
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      {match_rows}
    </table>

    <!-- CTA buttons -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:24px;">
      <tr>
        <td>
          <a href="{detail_url}"
             style="display:inline-block;background:#b91c1c;color:white;padding:12px 22px;
                    border-radius:8px;text-decoration:none;font-size:14px;font-weight:700;">
            View CVE Details &rarr;
          </a>
          {ref_html}
        </td>
      </tr>
      <tr>
        <td style="padding-top:12px;">
          <a href="{dashboard_url}"
             style="display:inline-block;background:#f8fafc;border:1px solid #e2e8f0;color:#475569;
                    padding:10px 18px;border-radius:8px;text-decoration:none;font-size:13px;">
            &#x1F4CA; Open Dashboard
          </a>
        </td>
      </tr>
    </table>

    <!-- Notice -->
    <p style="margin:20px 0 0;padding:12px;background:#fef2f2;border-radius:8px;
              font-size:12px;color:#991b1b;border:1px solid #fecaca;">
      &#x1F512; These links are one-time sign-in links unique to your account.
      Do not forward this email — links expire in 15 minutes.
    </p>
  </td>
</tr>

<!-- Footer -->
{_email_footer(user.email)}
"""
    html = _email_wrapper(body_content)
    return subject, html


# ── Daily Digest Email ─────────────────────────────────────────────────────────

def _render_cve_card(
    user: User,
    cve: Cve,
    contexts: list[MatchEmailContext],
    priority: int,
    reference: dict | None,
) -> str:
    sev = severity_label(cve.cvss_score)
    cvss_str = str(round(cve.cvss_score, 1)) if cve.cvss_score is not None else "N/A"
    epss_pct = f"{cve.epss_score * 100:.1f}%" if cve.epss_score is not None else "N/A"
    bg, fg = _severity_colors(cve.cvss_score)
    description = escape((cve.description or "No description available.")[:200])
    detail_url = escape(_cve_detail_link(user.email, cve.cve_id), quote=True)
    bar_html = _priority_bar(priority)
    match_rows = _render_match_context_rows(contexts, limit=2)

    kev_badge = ""
    if cve.kev_flag:
        kev_badge = (
            '<td style="padding-left:8px;" valign="middle">'
            '<span style="background:#b91c1c;color:white;padding:2px 8px;border-radius:999px;'
            'font-size:10px;font-weight:700;letter-spacing:0.5px;">KEV</span>'
            '</td>'
        )

    ref_link = ""
    if reference and reference.get("url"):
        ref_link = (
            f'<a href="{escape(reference["url"], quote=True)}" '
            f'style="color:#0369a1;font-size:12px;text-decoration:none;">'
            f'&#x1F517; {escape(_reference_label(reference))}</a>'
        )

    return f"""
<tr>
  <td style="padding-bottom:14px;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0"
           style="border:1px solid #e2e8f0;border-radius:10px;background:white;overflow:hidden;">

      <!-- Card header -->
      <tr>
        <td style="background:#f8fafc;padding:12px 16px;border-bottom:1px solid #e2e8f0;">
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td valign="middle">
                <a href="{detail_url}"
                   style="font-size:15px;font-weight:700;color:#0f172a;text-decoration:none;">
                  {escape(cve.cve_id)}
                </a>
              </td>
              {kev_badge}
              <td align="right" valign="middle">
                <span style="background:{bg};color:{fg};padding:3px 10px;border-radius:999px;
                             font-size:11px;font-weight:700;">{escape(sev)}</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Card body -->
      <tr>
        <td style="padding:14px 16px;">
          <p style="margin:0 0 12px;font-size:13px;color:#475569;line-height:1.6;">
            {description}
          </p>

          <!-- Score row -->
          <table cellpadding="0" cellspacing="0" border="0" style="margin-bottom:10px;">
            <tr>
              <td style="padding-right:16px;">
                <span style="font-size:11px;color:#94a3b8;font-weight:600;text-transform:uppercase;
                             letter-spacing:0.5px;">CVSS</span><br>
                <span style="font-size:16px;font-weight:700;color:#0f172a;">{escape(cvss_str)}</span>
              </td>
              <td style="padding-right:16px;">
                <span style="font-size:11px;color:#94a3b8;font-weight:600;text-transform:uppercase;
                             letter-spacing:0.5px;">EPSS</span><br>
                <span style="font-size:16px;font-weight:700;color:#0f172a;">{escape(epss_pct)}</span>
              </td>
              <td>
                <span style="font-size:11px;color:#94a3b8;font-weight:600;text-transform:uppercase;
                             letter-spacing:0.5px;">PRIORITY</span><br>
                <span style="font-size:16px;font-weight:700;color:#0f172a;">{priority}/100</span>
                {bar_html}
              </td>
            </tr>
          </table>

          <!-- Match contexts -->
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            {match_rows}
          </table>

          <!-- Links -->
          <table cellpadding="0" cellspacing="0" border="0" style="margin-top:12px;">
            <tr>
              <td>
                <a href="{detail_url}"
                   style="display:inline-block;background:#0f172a;color:white;padding:8px 16px;
                          border-radius:6px;text-decoration:none;font-size:13px;font-weight:600;">
                  View Details
                </a>
              </td>
              <td style="padding-left:12px;vertical-align:middle;">
                {ref_link}
              </td>
            </tr>
          </table>
        </td>
      </tr>

    </table>
  </td>
</tr>"""


def build_daily_digest_email(
    db: Session,
    user: User,
    matches: list[UserCveMatch],
    cves: dict[str, Cve],
) -> tuple[str, str]:
    """Build subject + HTML body for the daily digest."""
    grouped_matches: dict[str, list[UserCveMatch]] = defaultdict(list)
    for match in matches:
        grouped_matches[match.cve_id].append(match)

    ordered_cve_ids = sorted(
        grouped_matches,
        key=lambda cve_id: max(m.priority_score for m in grouped_matches[cve_id]),
        reverse=True,
    )
    cve_count = len(ordered_cve_ids)
    kev_count = sum(1 for cid in ordered_cve_ids if cves.get(cid) and cves[cid].kev_flag)
    critical_count = sum(
        1 for cid in ordered_cve_ids
        if cves.get(cid) and cves[cid].cvss_score is not None and cves[cid].cvss_score >= 9.0
    )

    subject = f"[CVE Radar] {cve_count} new CVE{'s' if cve_count != 1 else ''} affecting your stack"

    # Build CVE cards (top 10)
    cards_html = ""
    for cve_id in ordered_cve_ids[:10]:
        cve = cves.get(cve_id)
        if not cve:
            continue
        cve_matches = grouped_matches[cve_id]
        contexts = build_match_email_contexts(db, user=user, cve=cve, matches=cve_matches)
        priority = round(max(
            (m.priority_score for m in cve_matches),
            default=compute_priority(cve.cvss_score, cve.epss_score, cve.kev_flag)
        ))
        reference = pick_useful_reference(cve)
        cards_html += _render_cve_card(user, cve, contexts, priority, reference)

    overflow_html = ""
    if cve_count > 10:
        dashboard_url = escape(_dashboard_link(user.email), quote=True)
        overflow_html = f"""
<tr>
  <td style="padding-bottom:16px;text-align:center;">
    <p style="margin:0;font-size:13px;color:#64748b;">
      And <strong>{cve_count - 10} more</strong> CVEs in your digest.
      <a href="{dashboard_url}" style="color:#0369a1;text-decoration:none;">View all &rarr;</a>
    </p>
  </td>
</tr>"""

    dashboard_url = escape(_dashboard_link(user.email), quote=True)
    settings_url = escape(_settings_link(user.email), quote=True)

    body_content = f"""
<!-- Header -->
<tr>
  <td style="background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);border-radius:12px 12px 0 0;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding:22px 28px 16px;">
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td>
                <span style="color:white;font-size:18px;font-weight:800;letter-spacing:-0.5px;">
                  &#x26A1; CVE Radar
                </span>
              </td>
              <td align="right">
                <span style="background:#334155;color:#94a3b8;padding:4px 10px;border-radius:6px;font-size:11px;">
                  Daily Digest
                </span>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Stats summary row -->
      <tr>
        <td style="padding:0 28px 24px;">
          <table cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="background:rgba(255,255,255,0.08);border-radius:8px;padding:10px 18px;text-align:center;">
                <span style="color:white;font-size:24px;font-weight:800;display:block;">{cve_count}</span>
                <span style="color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">New CVEs</span>
              </td>
              <td style="width:10px;">&nbsp;</td>
              <td style="background:rgba(255,255,255,0.08);border-radius:8px;padding:10px 18px;text-align:center;">
                <span style="color:#fca5a5;font-size:24px;font-weight:800;display:block;">{critical_count}</span>
                <span style="color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Critical</span>
              </td>
              <td style="width:10px;">&nbsp;</td>
              <td style="background:rgba(185,28,28,0.3);border-radius:8px;padding:10px 18px;text-align:center;border:1px solid rgba(185,28,28,0.5);">
                <span style="color:#fca5a5;font-size:24px;font-weight:800;display:block;">{kev_count}</span>
                <span style="color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">KEV Listed</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </td>
</tr>

<!-- CVE cards -->
<tr>
  <td style="background:#f8fafc;padding:20px 16px;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      {cards_html}
      {overflow_html}
    </table>
  </td>
</tr>

<!-- CTA -->
<tr>
  <td style="background:white;padding:20px 28px;border-top:1px solid #e2e8f0;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td>
          <a href="{dashboard_url}"
             style="display:block;background:#0f172a;color:white;text-align:center;padding:14px;
                    border-radius:8px;text-decoration:none;font-size:14px;font-weight:700;">
            &#x1F4CA; Open Dashboard &rarr;
          </a>
        </td>
      </tr>
      <tr>
        <td style="padding-top:10px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#94a3b8;">
            &#x1F512; These are one-time sign-in links unique to your account.
            Do not forward — links expire in 15 minutes.
          </p>
        </td>
      </tr>
    </table>
  </td>
</tr>

<!-- Footer -->
{_email_footer(user.email)}
"""
    html = _email_wrapper(body_content)
    return subject, html
