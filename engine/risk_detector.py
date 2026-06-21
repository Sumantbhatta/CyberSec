"""Rule-based risk detection engine with 8 detection rules."""

from datetime import datetime, timedelta

from data.models import RiskFinding, RiskCategory, Severity, Platform, AccountStatus
from config import MITRE_MAPPING


DORMANT_THRESHOLD_DAYS = 90
PRIVILEGE_ADMIN_ROLES = {"AdministratorAccess", "IAMFullAccess", "Domain Admins", "Enterprise Admins", "IT-FullAccess"}
UNUSED_PERMISSION_THRESHOLD = 0.5  # Flag if >50% permissions unused


def detect_risks(unified_identities, people, audit_events=None):
    """Run all detection rules against unified identities."""
    findings = []
    people_emails = {p["email"] for p in people if not p["terminated"]}
    terminated_emails = {p["email"] for p in people if p["terminated"]}
    audit_events = audit_events or []

    for identity in unified_identities:
        findings.extend(_detect_orphaned(identity, people_emails))
        findings.extend(_detect_dormant_admin(identity))
        findings.extend(_detect_privilege_spike(identity))
        findings.extend(_detect_cross_platform_mismatch(identity))
        findings.extend(_detect_offboarding_failure(identity, terminated_emails))
        findings.extend(_detect_excessive_permissions(identity))
        findings.extend(_detect_token_abuse(identity))
        findings.extend(_detect_unused_permissions(identity))

    # SSO cascade rule needs audit events and all account IDs
    account_id_to_identity = {}
    for identity in unified_identities:
        for acc in identity.platform_accounts.values():
            account_id_to_identity[acc.id] = identity

    findings.extend(_detect_sso_cascade(audit_events, account_id_to_identity))

    # Attach MITRE references to all findings
    for finding in findings:
        finding.mitre_refs = MITRE_MAPPING.get(finding.category.value, [])

    return findings


def _detect_orphaned(identity, known_emails):
    """Rule 1: Accounts with no matching HR record."""
    findings = []
    if identity.primary_email and identity.primary_email not in known_emails:
        for platform, account in identity.platform_accounts.items():
            if account.status == AccountStatus.ACTIVE and not account.is_service_account:
                # Skip accounts with documented justification
                if account.justification:
                    continue
                findings.append(RiskFinding(
                    identity_id=identity.id,
                    category=RiskCategory.ORPHANED_ACCOUNT,
                    severity=Severity.HIGH if account.is_admin else Severity.MEDIUM,
                    title=f"Orphaned account: {account.username} ({platform})",
                    description=f"Active account '{account.username}' on {platform} has no matching HR record. "
                                f"No employee found with email {identity.primary_email}.",
                    platform=platform,
                    evidence={
                        "username": account.username,
                        "email": identity.primary_email,
                        "is_admin": account.is_admin,
                        "last_login": account.last_login.isoformat() if account.last_login else None,
                        "groups": account.groups,
                        "mfa_enabled": account.mfa_enabled,
                    },
                ))
    return findings


def _detect_dormant_admin(identity):
    """Rule 2: Admin accounts inactive for 90+ days."""
    findings = []
    now = datetime.now()

    for platform, account in identity.platform_accounts.items():
        if not account.is_admin or account.status != AccountStatus.ACTIVE:
            continue
        if account.justification:
            continue

        if account.last_login:
            days_inactive = (now - account.last_login).days
            if days_inactive >= DORMANT_THRESHOLD_DAYS:
                severity = Severity.CRITICAL if days_inactive > 180 else Severity.HIGH
                findings.append(RiskFinding(
                    identity_id=identity.id,
                    category=RiskCategory.DORMANT_ADMIN,
                    severity=severity,
                    title=f"Dormant admin: {account.username} ({days_inactive}d inactive)",
                    description=f"Admin account '{account.username}' on {platform} has not logged in "
                                f"for {days_inactive} days. Admin privileges should be revoked or account disabled.",
                    platform=platform,
                    evidence={
                        "username": account.username,
                        "days_inactive": days_inactive,
                        "last_login": account.last_login.isoformat(),
                        "mfa_enabled": account.mfa_enabled,
                        "groups": account.groups,
                        "is_admin": True,
                    },
                ))
    return findings


def _detect_privilege_spike(identity):
    """Rule 3: Accounts with suspicious recent privilege escalation."""
    findings = []

    for platform, account in identity.platform_accounts.items():
        if platform != Platform.AWS_IAM.value:
            continue
        if account.justification:
            continue

        escalation_markers = [p for p in account.permissions if p.startswith("escalated:")]
        if escalation_markers and "AdministratorAccess" in account.roles:
            findings.append(RiskFinding(
                identity_id=identity.id,
                category=RiskCategory.PRIVILEGE_SPIKE,
                severity=Severity.HIGH,
                title=f"Privilege spike: {account.username} granted admin recently",
                description=f"Account '{account.username}' ({account.department}) received AdministratorAccess "
                            f"recently. This is unusual for their role as {account.title}.",
                platform=platform,
                evidence={
                    "username": account.username,
                    "department": account.department,
                    "title": account.title,
                    "new_roles": account.roles,
                    "escalation_time": escalation_markers[0].split(":", 1)[1] if escalation_markers else None,
                    "is_admin": True,
                },
            ))
    return findings


def _detect_cross_platform_mismatch(identity):
    """Rule 4: Inconsistent account status across platforms."""
    findings = []
    accounts = identity.platform_accounts

    if len(accounts) < 2:
        return findings

    statuses = {platform: acc.status for platform, acc in accounts.items()}
    disabled_platforms = [p for p, s in statuses.items() if s in (AccountStatus.DISABLED, AccountStatus.SUSPENDED)]
    active_platforms = [p for p, s in statuses.items() if s == AccountStatus.ACTIVE]

    if disabled_platforms and active_platforms:
        findings.append(RiskFinding(
            identity_id=identity.id,
            category=RiskCategory.CROSS_PLATFORM_MISMATCH,
            severity=Severity.HIGH,
            title=f"Status mismatch: {identity.display_name} disabled on {', '.join(disabled_platforms)}",
            description=f"Identity '{identity.display_name}' is disabled/suspended on "
                        f"{', '.join(disabled_platforms)} but still active on {', '.join(active_platforms)}. "
                        f"This indicates incomplete access revocation.",
            platform=", ".join(active_platforms),
            evidence={
                "status_by_platform": {p: s.value for p, s in statuses.items()},
                "disabled_on": disabled_platforms,
                "active_on": active_platforms,
            },
        ))
    return findings


def _detect_offboarding_failure(identity, terminated_emails):
    """Rule 5: Terminated employees with active accounts."""
    findings = []

    if identity.primary_email not in terminated_emails:
        return findings

    for platform, account in identity.platform_accounts.items():
        if account.status == AccountStatus.ACTIVE:
            findings.append(RiskFinding(
                identity_id=identity.id,
                category=RiskCategory.OFFBOARDING_FAILURE,
                severity=Severity.CRITICAL,
                title=f"Offboarding failure: {account.username} still active post-termination",
                description=f"Terminated employee '{identity.display_name}' still has an active account "
                            f"on {platform}. Immediate deprovisioning required.",
                platform=platform,
                evidence={
                    "username": account.username,
                    "email": identity.primary_email,
                    "platform": platform,
                    "is_admin": account.is_admin,
                    "last_login": account.last_login.isoformat() if account.last_login else None,
                    "mfa_enabled": account.mfa_enabled,
                },
            ))
    return findings


def _detect_excessive_permissions(identity):
    """Rule 6: Non-technical users with admin-level access."""
    findings = []
    non_tech_departments = {"Finance", "HR", "Marketing", "Sales", "Legal"}

    if identity.department not in non_tech_departments:
        return findings

    for platform, account in identity.platform_accounts.items():
        if not account.is_admin:
            continue
        if account.justification:
            continue

        admin_groups = set(account.groups) & PRIVILEGE_ADMIN_ROLES
        admin_roles = set(account.roles) & PRIVILEGE_ADMIN_ROLES

        if admin_groups or admin_roles:
            findings.append(RiskFinding(
                identity_id=identity.id,
                category=RiskCategory.EXCESSIVE_PERMISSIONS,
                severity=Severity.HIGH,
                title=f"Excessive permissions: {account.username} ({identity.department}) has admin access",
                description=f"{identity.department} user '{account.username}' has privileged access "
                            f"({', '.join(admin_groups | admin_roles)}) on {platform}. "
                            f"This violates least-privilege principles.",
                platform=platform,
                evidence={
                    "username": account.username,
                    "department": identity.department,
                    "title": identity.title,
                    "admin_groups": list(admin_groups),
                    "admin_roles": list(admin_roles),
                    "all_groups": account.groups,
                    "is_admin": True,
                },
            ))
    return findings


def _detect_token_abuse(identity):
    """Rule 7: Token/credential abuse - expired tokens, scope violations."""
    findings = []

    for platform, account in identity.platform_accounts.items():
        if not account.access_tokens:
            continue

        for token in account.access_tokens:
            # Expired token still in use
            if token.get("is_expired") and token.get("last_used"):
                findings.append(RiskFinding(
                    identity_id=identity.id,
                    category=RiskCategory.TOKEN_ABUSE,
                    severity=Severity.HIGH,
                    title=f"Expired token in use: {account.username} ({platform})",
                    description=f"Account '{account.username}' has an expired API token (ID: {token.get('token_id', 'N/A')}) "
                                f"that was still used recently. Token expired on {token.get('expires_at', 'unknown')}.",
                    platform=platform,
                    evidence={
                        "username": account.username,
                        "token_id": token.get("token_id"),
                        "scope": token.get("scope"),
                        "expired_at": token.get("expires_at"),
                        "last_used": token.get("last_used"),
                        "is_admin": account.is_admin,
                    },
                ))
                break  # One finding per account

            # Scope violation: read token doing writes
            if token.get("scope_violation"):
                findings.append(RiskFinding(
                    identity_id=identity.id,
                    category=RiskCategory.TOKEN_ABUSE,
                    severity=Severity.CRITICAL if account.is_admin else Severity.HIGH,
                    title=f"Token scope violation: {account.username} read-only token performing writes",
                    description=f"Account '{account.username}' has a '{token.get('scope', 'read')}' scoped token "
                                f"that performed unauthorized actions: {token.get('observed_actions', ['write'])}.",
                    platform=platform,
                    evidence={
                        "username": account.username,
                        "token_id": token.get("token_id"),
                        "declared_scope": token.get("scope"),
                        "observed_actions": token.get("observed_actions", []),
                        "is_admin": account.is_admin,
                    },
                ))
                break

    return findings


def _detect_unused_permissions(identity):
    """Rule 8: Granted permissions that are never exercised."""
    findings = []

    for platform, account in identity.platform_accounts.items():
        if not account.granted_permissions or account.status != AccountStatus.ACTIVE:
            continue
        if account.justification:
            continue

        granted = set(account.granted_permissions)
        used = set(account.used_permissions)
        unused = granted - used
        usage_ratio = len(used) / max(len(granted), 1)

        # Flag if more than 50% permissions are unused AND at least 4 unused
        if usage_ratio < UNUSED_PERMISSION_THRESHOLD and len(unused) >= 4:
            findings.append(RiskFinding(
                identity_id=identity.id,
                category=RiskCategory.UNUSED_PERMISSIONS,
                severity=Severity.MEDIUM,
                title=f"Unused permissions: {account.username} uses {len(used)}/{len(granted)} permissions",
                description=f"Account '{account.username}' on {platform} has {len(unused)} granted permissions "
                            f"that have never been exercised ({100 - int(usage_ratio * 100)}% unused). "
                            f"Consider revoking: {', '.join(list(unused)[:5])}.",
                platform=platform,
                evidence={
                    "username": account.username,
                    "granted_count": len(granted),
                    "used_count": len(used),
                    "unused_count": len(unused),
                    "usage_ratio": round(usage_ratio, 2),
                    "unused_permissions": list(unused)[:10],
                    "is_admin": account.is_admin,
                    "department": account.department,
                },
            ))

    return findings


def _detect_sso_cascade(audit_events, account_id_to_identity):
    """Rule 9: SSO cascade login — same identity on 3+ platforms within 15 minutes.

    This pattern indicates credential compromise or automated lateral movement
    via stolen SSO tokens. Mapped to MITRE T1078 / T1550.
    """
    from collections import defaultdict

    SSO_WINDOW_MINUTES = 15
    MIN_PLATFORMS = 3

    findings = []

    # Group login events by identity_id
    login_events = [
        e for e in audit_events
        if e.event_type.value in ("login_success", "sso_cascade_login")
    ]

    events_by_identity = defaultdict(list)
    for event in login_events:
        if event.identity_id in account_id_to_identity:
            events_by_identity[event.identity_id].append(event)

    already_flagged = set()

    for account_id, events in events_by_identity.items():
        if account_id in already_flagged:
            continue

        # Sort by timestamp
        events_sorted = sorted(events, key=lambda e: e.timestamp)

        # Sliding window: look for 3+ different platforms within 15 min
        for i, base_event in enumerate(events_sorted):
            window_end = base_event.timestamp + timedelta(minutes=SSO_WINDOW_MINUTES)
            window_events = [e for e in events_sorted[i:] if e.timestamp <= window_end]
            platforms_in_window = set(e.platform.value for e in window_events)

            if len(platforms_in_window) >= MIN_PLATFORMS:
                identity = account_id_to_identity.get(account_id)
                if not identity:
                    continue

                # Check for anomalous flag or suspicious source IP
                is_anomalous = any(e.is_anomalous for e in window_events)
                source_ips = list(set(e.source_ip for e in window_events))

                findings.append(RiskFinding(
                    identity_id=identity.id,
                    category=RiskCategory.PRIVILEGE_SPIKE,
                    severity=Severity.CRITICAL if is_anomalous else Severity.HIGH,
                    title=f"SSO cascade: {identity.display_name or account_id[:8]} logged into {len(platforms_in_window)} platforms in {SSO_WINDOW_MINUTES}min",
                    description=f"Identity logged into {', '.join(sorted(platforms_in_window))} within a {SSO_WINDOW_MINUTES}-minute window. "
                                f"This rapid cross-platform login pattern may indicate credential compromise or stolen SSO token reuse.",
                    platform=", ".join(sorted(platforms_in_window)),
                    evidence={
                        "platforms": sorted(platforms_in_window),
                        "login_count": len(window_events),
                        "window_minutes": SSO_WINDOW_MINUTES,
                        "source_ips": source_ips[:5],
                        "is_anomalous": is_anomalous,
                        "first_login": base_event.timestamp.isoformat(),
                        "is_admin": any(
                            acc.is_admin
                            for acc in identity.platform_accounts.values()
                        ),
                    },
                ))
                already_flagged.add(account_id)
                break

    return findings
