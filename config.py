"""Configuration constants for identity sprawl detector."""

NUM_IDENTITIES = 250
PLATFORMS = ["active_directory", "aws_iam", "okta"]

FUZZY_MATCH_THRESHOLD = 0.75

RISK_WEIGHTS = {
    "OrphanedAccount": 40,
    "DormantAdmin": 55,
    "PrivilegeSpike": 50,
    "CrossPlatformMismatch": 35,
    "OffboardingFailure": 60,
    "ExcessivePermissions": 45,
    "TokenAbuse": 55,
    "UnusedPermissions": 30,
}


RISK_MULTIPLIERS = {
    "admin": 1.5,
    "pii_access": 1.4,
    "production": 1.3,
    "multi_platform": 1.2,
    "no_mfa": 1.3,
    "service_account": 1.2,
    "expired_token": 1.4,
}

SEVERITY_THRESHOLDS = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
}

# MITRE ATT&CK technique mappings
MITRE_MAPPING = {
    "OrphanedAccount": ["T1078 - Valid Accounts", "T1078.002 - Domain Accounts"],
    "DormantAdmin": ["T1078 - Valid Accounts", "T1078.001 - Default Accounts"],
    "PrivilegeSpike": ["T1098 - Account Manipulation", "T1098.001 - Additional Cloud Credentials"],
    "CrossPlatformMismatch": ["T1078 - Valid Accounts", "T1550 - Use Alternate Authentication Material"],
    "OffboardingFailure": ["T1078 - Valid Accounts", "T1098 - Account Manipulation"],
    "ExcessivePermissions": ["T1078.004 - Cloud Accounts", "T1098.003 - Additional Cloud Roles"],
    "TokenAbuse": ["T1550.001 - Application Access Token", "T1528 - Steal Application Access Token"],
    "UnusedPermissions": ["T1078 - Valid Accounts"],
}

AD_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Backup Operators", "Server Operators", "Account Operators",
    "HR-ReadWrite", "Finance-ReadOnly", "IT-FullAccess",
    "VPN-Users", "Remote-Desktop-Users", "Print-Operators",
    "Dev-Team", "QA-Team", "Security-Audit",
]

AWS_ROLES = [
    "AdministratorAccess", "PowerUserAccess", "ReadOnlyAccess",
    "S3FullAccess", "EC2FullAccess", "IAMFullAccess",
    "LambdaFullAccess", "RDSFullAccess", "SecurityAudit",
    "DatabaseAdmin", "NetworkAdmin", "BillingAccess",
]

OKTA_GROUPS = [
    "Everyone", "Engineering", "Finance", "HR",
    "IT-Admins", "Security-Team", "Executive",
    "Contractors", "Vendors", "Support-Staff",
    "Privileged-Access", "MFA-Enrolled", "SSO-Users",
]

DEPARTMENTS = [
    "Engineering", "Finance", "HR", "IT", "Security",
    "Marketing", "Sales", "Legal", "Operations", "Executive",
]
