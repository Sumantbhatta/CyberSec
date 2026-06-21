"""Cluster related risk findings into actionable incidents."""

from collections import defaultdict

from data.models import Incident, Severity


def cluster_incidents(findings, unified_identities):
    """Group related findings into incidents by identity and root cause."""
    # Phase 1: Group by identity
    by_identity = defaultdict(list)
    for finding in findings:
        by_identity[finding.identity_id].append(finding)

    # Phase 2: Group by category across identities (systemic issues)
    by_category = defaultdict(list)
    for finding in findings:
        by_category[finding.category.value].append(finding)

    incidents = []

    # Create per-identity incidents for identities with multiple findings
    identity_map = {i.id: i for i in unified_identities}
    for identity_id, id_findings in by_identity.items():
        if len(id_findings) >= 2:
            identity = identity_map.get(identity_id)
            name = identity.display_name if identity else identity_id[:8]
            incidents.append(Incident(
                title=f"Multiple risks for {name}",
                root_cause="compound_risk",
                affected_identities=[identity_id],
                findings=id_findings,
                severity=_max_severity(id_findings),
                aggregate_score=_normalized_score(id_findings),
            ))

    # Create systemic incidents for widespread category issues
    for category, cat_findings in by_category.items():
        if len(cat_findings) >= 3:
            affected = list(set(f.identity_id for f in cat_findings))
            incidents.append(Incident(
                title=f"Systemic: {_category_title(category)} ({len(cat_findings)} findings)",
                root_cause=category,
                affected_identities=affected,
                findings=cat_findings,
                severity=_max_severity(cat_findings),
                aggregate_score=_normalized_score(cat_findings),
            ))

    # Sort by aggregate score descending
    incidents.sort(key=lambda i: i.aggregate_score, reverse=True)
    return incidents


def _max_severity(findings):
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    for severity in severity_order:
        if any(f.severity == severity for f in findings):
            return severity
    return Severity.LOW


def _normalized_score(findings):
    """Compute a 0–100 aggregate score for a group of findings.

    Uses the same diminishing-returns model as score_identity:
    max score + 10% of each additional finding, capped at 100.
    This keeps incident scores comparable to individual finding scores.
    """
    if not findings:
        return 0.0
    scores = sorted([f.score for f in findings], reverse=True)
    aggregate = scores[0]
    for s in scores[1:]:
        aggregate += s * 0.10
    return round(min(aggregate, 100), 1)


def _category_title(category):
    titles = {
        "OrphanedAccount": "Orphaned Accounts",
        "DormantAdmin": "Dormant Admin Accounts",
        "PrivilegeSpike": "Privilege Escalations",
        "CrossPlatformMismatch": "Cross-Platform Mismatches",
        "OffboardingFailure": "Offboarding Failures",
        "ExcessivePermissions": "Excessive Permissions",
        "TokenAbuse": "Token & Credential Abuse",
        "UnusedPermissions": "Unused Permissions",
    }
    return titles.get(category, category)
