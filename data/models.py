"""Data models for identity sprawl detection."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class Platform(Enum):
    ACTIVE_DIRECTORY = "active_directory"
    AWS_IAM = "aws_iam"
    OKTA = "okta"


class AccountStatus(Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    SUSPENDED = "suspended"
    LOCKED = "locked"


class RiskCategory(Enum):
    ORPHANED_ACCOUNT = "OrphanedAccount"
    DORMANT_ADMIN = "DormantAdmin"
    PRIVILEGE_SPIKE = "PrivilegeSpike"
    CROSS_PLATFORM_MISMATCH = "CrossPlatformMismatch"
    OFFBOARDING_FAILURE = "OffboardingFailure"
    EXCESSIVE_PERMISSIONS = "ExcessivePermissions"
    TOKEN_ABUSE = "TokenAbuse"
    UNUSED_PERMISSIONS = "UnusedPermissions"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EventType(Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PRIVILEGE_CHANGE = "privilege_change"
    RESOURCE_ACCESS = "resource_access"
    TOKEN_USAGE = "token_usage"
    GROUP_ADD = "group_add"
    GROUP_REMOVE = "group_remove"
    ROLE_ASSIGN = "role_assign"
    PASSWORD_RESET = "password_reset"
    MFA_CHANGE = "mfa_change"


@dataclass
class AuditEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    event_type: EventType = EventType.LOGIN_SUCCESS
    platform: Platform = Platform.ACTIVE_DIRECTORY
    identity_id: str = ""
    username: str = ""
    source_ip: str = ""
    target_resource: str = ""
    action: str = ""
    outcome: str = "success"
    details: dict = field(default_factory=dict)
    is_anomalous: bool = False

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "platform": self.platform.value,
            "identity_id": self.identity_id,
            "username": self.username,
            "source_ip": self.source_ip,
            "target_resource": self.target_resource,
            "action": self.action,
            "outcome": self.outcome,
            "details": self.details,
            "is_anomalous": self.is_anomalous,
        }


@dataclass
class PlatformIdentity:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    platform: Platform = Platform.ACTIVE_DIRECTORY
    username: str = ""
    email: str = ""
    display_name: str = ""
    department: str = ""
    title: str = ""
    status: AccountStatus = AccountStatus.ACTIVE
    is_admin: bool = False
    groups: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    permissions: list = field(default_factory=list)
    granted_permissions: list = field(default_factory=list)
    used_permissions: list = field(default_factory=list)
    last_login: Optional[datetime] = None
    created_at: Optional[datetime] = None
    mfa_enabled: bool = True
    manager: str = ""
    is_service_account: bool = False
    access_tokens: list = field(default_factory=list)
    justification: str = ""

    def to_dict(self):
        return {
            "id": self.id,
            "platform": self.platform.value,
            "username": self.username,
            "email": self.email,
            "display_name": self.display_name,
            "department": self.department,
            "title": self.title,
            "status": self.status.value,
            "is_admin": self.is_admin,
            "groups": self.groups,
            "roles": self.roles,
            "permissions": self.permissions,
            "granted_permissions": self.granted_permissions,
            "used_permissions": self.used_permissions,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "mfa_enabled": self.mfa_enabled,
            "manager": self.manager,
            "is_service_account": self.is_service_account,
            "access_tokens": self.access_tokens,
            "justification": self.justification,
        }


@dataclass
class AccessToken:
    token_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    platform: Platform = Platform.AWS_IAM
    scope: str = "read"
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_expired: bool = False

    def to_dict(self):
        return {
            "token_id": self.token_id,
            "platform": self.platform.value,
            "scope": self.scope,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "is_expired": self.is_expired,
        }


@dataclass
class UnifiedIdentity:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    primary_email: str = ""
    display_name: str = ""
    department: str = ""
    title: str = ""
    manager: str = ""
    platform_accounts: dict = field(default_factory=dict)
    risk_score: float = 0.0
    findings: list = field(default_factory=list)
    is_service_account: bool = False
    has_justification: bool = False
    behavioral_deviation: float = 0.0

    def to_dict(self):
        return {
            "id": self.id,
            "primary_email": self.primary_email,
            "display_name": self.display_name,
            "department": self.department,
            "title": self.title,
            "manager": self.manager,
            "platform_accounts": {
                k: v.to_dict() for k, v in self.platform_accounts.items()
            },
            "risk_score": self.risk_score,
            "behavioral_deviation": self.behavioral_deviation,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
            "is_service_account": self.is_service_account,
            "has_justification": self.has_justification,
        }


@dataclass
class Group:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    platform: Platform = Platform.ACTIVE_DIRECTORY
    members: list = field(default_factory=list)
    parent_groups: list = field(default_factory=list)
    permissions: list = field(default_factory=list)
    is_privileged: bool = False

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "platform": self.platform.value,
            "members": self.members,
            "parent_groups": self.parent_groups,
            "permissions": self.permissions,
            "is_privileged": self.is_privileged,
        }


@dataclass
class RiskFinding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    identity_id: str = ""
    category: RiskCategory = RiskCategory.ORPHANED_ACCOUNT
    severity: Severity = Severity.MEDIUM
    score: float = 0.0
    title: str = ""
    description: str = ""
    platform: str = ""
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    compliance_refs: list = field(default_factory=list)
    mitre_refs: list = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.now)

    def to_dict(self):
        return {
            "id": self.id,
            "identity_id": self.identity_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "score": self.score,
            "title": self.title,
            "description": self.description,
            "platform": self.platform,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "compliance_refs": self.compliance_refs,
            "mitre_refs": self.mitre_refs,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }


@dataclass
class Incident:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    root_cause: str = ""
    affected_identities: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    aggregate_score: float = 0.0
    remediation_steps: list = field(default_factory=list)
    status: str = "open"

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "root_cause": self.root_cause,
            "affected_identities": self.affected_identities,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
            "severity": self.severity.value,
            "aggregate_score": self.aggregate_score,
            "remediation_steps": self.remediation_steps,
            "status": self.status,
        }
