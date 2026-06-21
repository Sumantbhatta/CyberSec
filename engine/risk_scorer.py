"""Weighted risk scoring engine with behavioral baseline."""

from data.models import Severity, RiskCategory
from config import RISK_WEIGHTS, RISK_MULTIPLIERS, SEVERITY_THRESHOLDS


def score_finding(finding):
    """Calculate risk score (0-100) for a single finding."""
    base_weight = RISK_WEIGHTS.get(finding.category.value, 20)

    multiplier = 1.0
    evidence = finding.evidence

    if evidence.get("is_admin"):
        multiplier *= RISK_MULTIPLIERS["admin"]

    if evidence.get("department") in ("Finance", "HR"):
        multiplier *= RISK_MULTIPLIERS["pii_access"]

    if "production" in str(evidence.get("groups", [])).lower():
        multiplier *= RISK_MULTIPLIERS["production"]

    # Multi-platform flag from cross-platform findings
    if "active_on" in evidence and len(evidence.get("active_on", [])) > 1:
        multiplier *= RISK_MULTIPLIERS["multi_platform"]

    # Dormant days amplifier
    days_inactive = evidence.get("days_inactive", 0)
    if days_inactive > 180:
        multiplier *= 1.6
    elif days_inactive > 120:
        multiplier *= 1.3

    # No MFA on admin is very risky
    if evidence.get("is_admin") and evidence.get("mfa_enabled") is False:
        multiplier *= RISK_MULTIPLIERS["no_mfa"]

    # Offboarding with active admin is critical
    if finding.category == RiskCategory.OFFBOARDING_FAILURE:
        multiplier *= 1.5

    # Token abuse with scope violation
    if finding.category == RiskCategory.TOKEN_ABUSE:
        if evidence.get("observed_actions"):
            multiplier *= RISK_MULTIPLIERS["expired_token"]

    # Service account multiplier
    if evidence.get("username", "").startswith(("svc_", "app_", "bot_", "sys_")):
        multiplier *= RISK_MULTIPLIERS["service_account"]

    score = min(base_weight * multiplier, 100)
    finding.score = round(score, 1)
    finding.severity = _severity_from_score(score)

    return finding


def score_identity(identity):
    """Calculate aggregate risk score for a unified identity."""
    if not identity.findings:
        identity.risk_score = 0
        return identity

    # Aggregate: max finding score + 15% of each additional finding
    scores = sorted([f.score for f in identity.findings], reverse=True)
    aggregate = scores[0]
    for s in scores[1:]:
        aggregate += s * 0.15

    identity.risk_score = min(round(aggregate, 1), 100)
    return identity


def apply_behavioral_score(identity, audit_events):
    """Blend behavioral deviation score into identity risk score.

    Adds up to +15 points based on anomalous login patterns and
    failure rates observed in the audit event stream. Called after
    score_identity() so it amplifies — not replaces — the base score.
    """
    deviation = compute_behavioral_baseline(identity, audit_events)
    if deviation > 0:
        # Blend: up to 15% boost from behavioral signals
        boost = deviation * 0.15
        identity.risk_score = min(round(identity.risk_score + boost, 1), 100)
        identity.behavioral_deviation = round(deviation, 1)
    else:
        identity.behavioral_deviation = 0.0
    return identity


def compute_behavioral_baseline(identity, audit_events):
    """Compute behavioral deviation score from audit event baseline."""
    if not audit_events:
        return 0.0

    identity_events = [e for e in audit_events if e.identity_id in
                       [acc.id for acc in identity.platform_accounts.values()]]

    if len(identity_events) < 5:
        return 0.0

    # Baseline metrics
    anomalous = sum(1 for e in identity_events if e.is_anomalous)
    failures = sum(1 for e in identity_events if e.outcome == "failure")
    total = len(identity_events)

    # Deviation score: anomalous ratio + failure ratio
    anomaly_ratio = anomalous / total
    failure_ratio = failures / total

    deviation = (anomaly_ratio * 50) + (failure_ratio * 30)
    return min(round(deviation, 1), 100)


def _severity_from_score(score):
    """Map numeric score to severity level."""
    if score >= SEVERITY_THRESHOLDS["critical"]:
        return Severity.CRITICAL
    elif score >= SEVERITY_THRESHOLDS["high"]:
        return Severity.HIGH
    elif score >= SEVERITY_THRESHOLDS["medium"]:
        return Severity.MEDIUM
    return Severity.LOW
