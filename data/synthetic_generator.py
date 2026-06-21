"""Synthetic data generator for identity sprawl scenarios - 250+ identities."""

import random
from datetime import datetime, timedelta
from faker import Faker

from data.models import (
    PlatformIdentity, Platform, AccountStatus, Group,
    AuditEvent, EventType, AccessToken
)
from config import (
    NUM_IDENTITIES, AD_GROUPS, AWS_ROLES, OKTA_GROUPS, DEPARTMENTS
)

fake = Faker()
Faker.seed(42)
random.seed(42)

SERVICE_ACCOUNT_PREFIXES = [
    "svc", "app", "bot", "sys", "api", "batch", "etl", "cicd", "monitor", "backup"
]

SERVICE_ACCOUNT_SYSTEMS = [
    "jenkins", "terraform", "ansible", "datadog", "splunk", "jira",
    "confluence", "gitlab", "artifactory", "vault", "k8s", "prometheus",
    "grafana", "elasticsearch", "kafka", "airflow", "snowflake",
]

ALL_PERMISSIONS = {
    "active_directory": [
        "read:directory", "write:directory", "manage:users", "manage:groups",
        "reset:passwords", "login:workstation", "manage:gpo", "manage:dns",
        "manage:dhcp", "manage:certificates", "audit:logs", "manage:backups",
        "manage:servers", "remote:desktop", "manage:exchange",
    ],
    "aws_iam": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
        "ec2:RunInstances", "ec2:TerminateInstances", "ec2:DescribeInstances",
        "iam:CreateUser", "iam:DeleteUser", "iam:AttachPolicy",
        "lambda:InvokeFunction", "lambda:CreateFunction",
        "rds:CreateDBInstance", "rds:DeleteDBInstance", "rds:DescribeDBInstances",
        "kms:Encrypt", "kms:Decrypt", "sts:AssumeRole",
        "cloudwatch:PutMetricData", "logs:CreateLogGroup",
    ],
    "okta": [
        "sso:login", "manage:users", "manage:apps", "manage:policies",
        "manage:groups", "read:audit_logs", "manage:mfa", "manage:api_tokens",
        "manage:identity_providers", "manage:authorization_servers",
    ],
}


def generate_identities():
    """Generate synthetic identities across 3 platforms (250+ total)."""
    people = _generate_people(NUM_IDENTITIES)
    ad_accounts = []
    aws_accounts = []
    okta_accounts = []

    for person in people:
        if random.random() < 0.92:
            ad_accounts.append(_create_ad_account(person))
        if person["department"] in ["Engineering", "IT", "Security", "Operations"] or random.random() < 0.25:
            aws_accounts.append(_create_aws_account(person))
        if random.random() < 0.88:
            okta_accounts.append(_create_okta_account(person))

    # Add service accounts (20-30 across platforms)
    svc_ad, svc_aws, svc_okta = _create_service_accounts()
    ad_accounts.extend(svc_ad)
    aws_accounts.extend(svc_aws)
    okta_accounts.extend(svc_okta)

    groups = _create_groups()
    _assign_group_memberships(ad_accounts, groups, Platform.ACTIVE_DIRECTORY)
    _assign_group_memberships(aws_accounts, groups, Platform.AWS_IAM)
    _assign_group_memberships(okta_accounts, groups, Platform.OKTA)

    # Assign granted vs used permissions
    _assign_permission_usage(ad_accounts, "active_directory")
    _assign_permission_usage(aws_accounts, "aws_iam")
    _assign_permission_usage(okta_accounts, "okta")

    # Generate access tokens for AWS and Okta accounts
    _assign_access_tokens(aws_accounts, Platform.AWS_IAM)
    _assign_access_tokens(okta_accounts, Platform.OKTA)

    # Generate audit events
    all_accounts = ad_accounts + aws_accounts + okta_accounts
    audit_events = _generate_audit_events(all_accounts)

    return {
        "people": people,
        "accounts": {
            Platform.ACTIVE_DIRECTORY.value: ad_accounts,
            Platform.AWS_IAM.value: aws_accounts,
            Platform.OKTA.value: okta_accounts,
        },
        "groups": groups,
        "audit_events": audit_events,
    }


def _generate_people(count):
    """Generate base person records with 50-100 offboarding records."""
    people = []
    for i in range(count):
        first = fake.first_name()
        last = fake.last_name()
        dept = random.choice(DEPARTMENTS)
        people.append({
            "first_name": first,
            "last_name": last,
            "email": f"{first.lower()}.{last.lower()}@societe-generale.com",
            "department": dept,
            "title": _title_for_department(dept),
            "manager": fake.name(),
            "hire_date": fake.date_between(start_date="-5y", end_date="-30d"),
            "terminated": False,
            "termination_date": None,
        })

    # Mark ~25% as terminated (gives us 50-65 offboarding records from 250 people)
    termination_count = max(55, int(count * 0.22))
    for person in random.sample(people, termination_count):
        person["terminated"] = True
        person["termination_date"] = fake.date_between(start_date="-120d", end_date="-3d")

    return people


def _create_ad_account(person):
    """Create Active Directory identity."""
    first = person["first_name"]
    last = person["last_name"]
    username = f"{first[0].lower()}{last.lower()}"
    days_ago = random.randint(1, 180)
    last_login = datetime.now() - timedelta(days=days_ago)
    is_admin = person["department"] in ["IT", "Security"] and random.random() < 0.3

    status = AccountStatus.ACTIVE
    if person["terminated"] and random.random() < 0.6:
        status = AccountStatus.DISABLED

    return PlatformIdentity(
        platform=Platform.ACTIVE_DIRECTORY,
        username=username,
        email=person["email"],
        display_name=f"{first} {last}",
        department=person["department"],
        title=person["title"],
        status=status,
        is_admin=is_admin,
        last_login=last_login,
        created_at=datetime.combine(person["hire_date"], datetime.min.time()),
        mfa_enabled=random.random() < 0.7,
        manager=person["manager"],
        is_service_account=False,
    )


def _create_aws_account(person):
    """Create AWS IAM identity."""
    first = person["first_name"]
    last = person["last_name"]
    username = f"{first.lower()}.{last.lower()}" if random.random() < 0.6 else f"{first.lower()}_{last.lower()}"
    days_ago = random.randint(1, 120)
    last_login = datetime.now() - timedelta(days=days_ago)
    is_admin = person["department"] in ["IT", "Security"] and random.random() < 0.25

    roles = []
    if is_admin:
        roles = random.sample(["AdministratorAccess", "IAMFullAccess", "SecurityAudit"], k=random.randint(1, 2))
    elif person["department"] == "Engineering":
        roles = random.sample(["PowerUserAccess", "S3FullAccess", "LambdaFullAccess", "EC2FullAccess"], k=random.randint(1, 3))
    else:
        roles = random.sample(["ReadOnlyAccess", "S3FullAccess", "BillingAccess"], k=random.randint(1, 2))

    status = AccountStatus.ACTIVE
    if person["terminated"] and random.random() < 0.5:
        status = AccountStatus.DISABLED

    return PlatformIdentity(
        platform=Platform.AWS_IAM,
        username=username,
        email=person["email"],
        display_name=f"{first} {last}",
        department=person["department"],
        title=person["title"],
        status=status,
        is_admin=is_admin,
        roles=roles,
        last_login=last_login,
        created_at=datetime.combine(person["hire_date"], datetime.min.time()) + timedelta(days=random.randint(1, 30)),
        mfa_enabled=random.random() < 0.8,
        manager=person["manager"],
        is_service_account=False,
    )


def _create_okta_account(person):
    """Create Okta identity."""
    first = person["first_name"]
    last = person["last_name"]
    username = person["email"]
    days_ago = random.randint(0, 60)
    last_login = datetime.now() - timedelta(days=days_ago)
    is_admin = person["department"] in ["IT", "Security"] and random.random() < 0.15

    status = AccountStatus.ACTIVE
    if person["terminated"] and random.random() < 0.7:
        status = AccountStatus.SUSPENDED

    return PlatformIdentity(
        platform=Platform.OKTA,
        username=username,
        email=person["email"],
        display_name=f"{first} {last}",
        department=person["department"],
        title=person["title"],
        status=status,
        is_admin=is_admin,
        last_login=last_login,
        created_at=datetime.combine(person["hire_date"], datetime.min.time()),
        mfa_enabled=random.random() < 0.9,
        manager=person["manager"],
        is_service_account=False,
    )


def _create_service_accounts():
    """Create 20-30 service accounts across platforms."""
    ad_svc = []
    aws_svc = []
    okta_svc = []

    for system in random.sample(SERVICE_ACCOUNT_SYSTEMS, 15):
        prefix = random.choice(SERVICE_ACCOUNT_PREFIXES)
        svc_name = f"{prefix}_{system}"
        email = f"{svc_name}@service.societe-generale.com"
        created = datetime.now() - timedelta(days=random.randint(60, 730))

        # Most service accounts exist on AD + AWS
        if random.random() < 0.85:
            ad_svc.append(PlatformIdentity(
                platform=Platform.ACTIVE_DIRECTORY,
                username=svc_name,
                email=email,
                display_name=f"SVC-{system.upper()}",
                department="IT",
                title="Service Account",
                status=AccountStatus.ACTIVE,
                is_admin=random.random() < 0.3,
                groups=["Service-Accounts"] + (["Domain Admins"] if random.random() < 0.15 else []),
                last_login=datetime.now() - timedelta(days=random.randint(0, 5)),
                created_at=created,
                mfa_enabled=False,
                is_service_account=True,
            ))

        if random.random() < 0.8:
            aws_svc.append(PlatformIdentity(
                platform=Platform.AWS_IAM,
                username=svc_name,
                email=email,
                display_name=f"SVC-{system.upper()}",
                department="IT",
                title="Service Account",
                status=AccountStatus.ACTIVE,
                is_admin=random.random() < 0.25,
                roles=random.sample(["S3FullAccess", "EC2FullAccess", "LambdaFullAccess", "AdministratorAccess"], k=random.randint(1, 3)),
                last_login=datetime.now() - timedelta(hours=random.randint(1, 48)),
                created_at=created,
                mfa_enabled=False,
                is_service_account=True,
            ))

        if random.random() < 0.4:
            okta_svc.append(PlatformIdentity(
                platform=Platform.OKTA,
                username=email,
                email=email,
                display_name=f"SVC-{system.upper()}",
                department="IT",
                title="Service Account",
                status=AccountStatus.ACTIVE,
                is_admin=False,
                last_login=datetime.now() - timedelta(hours=random.randint(1, 24)),
                created_at=created,
                mfa_enabled=False,
                is_service_account=True,
            ))

    return ad_svc, aws_svc, okta_svc


def _assign_permission_usage(accounts, platform_key):
    """Assign granted vs used permissions to simulate unused permission detection."""
    platform_perms = ALL_PERMISSIONS.get(platform_key, [])

    for account in accounts:
        if account.is_admin:
            granted = random.sample(platform_perms, k=min(random.randint(8, 15), len(platform_perms)))
        else:
            granted = random.sample(platform_perms, k=min(random.randint(2, 6), len(platform_perms)))

        # Users typically exercise only 40-70% of their permissions
        usage_ratio = random.uniform(0.3, 0.75)
        used_count = max(1, int(len(granted) * usage_ratio))
        used = random.sample(granted, k=used_count)

        account.granted_permissions = granted
        account.used_permissions = used


def _assign_access_tokens(accounts, platform):
    """Assign API tokens to accounts."""
    for account in accounts:
        if random.random() < 0.4:  # 40% have tokens
            num_tokens = random.randint(1, 3)
            tokens = []
            for _ in range(num_tokens):
                created = datetime.now() - timedelta(days=random.randint(30, 400))
                expires = created + timedelta(days=random.choice([90, 180, 365]))
                is_expired = expires < datetime.now()
                # For expired tokens, simulate abuse: 40% chance they were used after expiry
                if is_expired:
                    last_used = datetime.now() - timedelta(days=random.randint(0, 14))
                else:
                    last_used = datetime.now() - timedelta(days=random.randint(0, 60))

                tokens.append({
                    "token_id": str(fake.uuid4())[:12],
                    "scope": random.choice(["read", "read-write", "admin"]),
                    "created_at": created.isoformat(),
                    "expires_at": expires.isoformat(),
                    "last_used": last_used.isoformat(),
                    "is_expired": is_expired,
                })
            account.access_tokens = tokens


def _generate_audit_events(all_accounts):
    """Generate 800-1200 audit events across all accounts."""
    events = []
    active_accounts = [a for a in all_accounts if a.status == AccountStatus.ACTIVE]

    # Normal login events (500-600)
    for _ in range(550):
        account = random.choice(active_accounts)
        ts = datetime.now() - timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        events.append(AuditEvent(
            timestamp=ts,
            event_type=EventType.LOGIN_SUCCESS,
            platform=account.platform,
            identity_id=account.id,
            username=account.username,
            source_ip=fake.ipv4_private(),
            action="login",
            outcome="success",
        ))

    # Failed logins (50-80)
    for _ in range(65):
        account = random.choice(active_accounts)
        ts = datetime.now() - timedelta(days=random.randint(0, 14), hours=random.randint(0, 23))
        events.append(AuditEvent(
            timestamp=ts,
            event_type=EventType.LOGIN_FAILURE,
            platform=account.platform,
            identity_id=account.id,
            username=account.username,
            source_ip=fake.ipv4_public(),
            action="login",
            outcome="failure",
            details={"reason": random.choice(["invalid_password", "mfa_failed", "account_locked", "ip_blocked"])},
        ))

    # Privilege change events (80-120)
    for _ in range(100):
        account = random.choice(active_accounts)
        ts = datetime.now() - timedelta(days=random.randint(0, 60), hours=random.randint(0, 23))
        event_type = random.choice([EventType.GROUP_ADD, EventType.ROLE_ASSIGN, EventType.PRIVILEGE_CHANGE])
        events.append(AuditEvent(
            timestamp=ts,
            event_type=event_type,
            platform=account.platform,
            identity_id=account.id,
            username=account.username,
            source_ip=fake.ipv4_private(),
            action=event_type.value,
            outcome="success",
            details={
                "target_group": random.choice(AD_GROUPS + AWS_ROLES + OKTA_GROUPS),
                "performed_by": fake.user_name(),
            },
        ))

    # Resource access events (150-200)
    resources = [
        "s3://prod-data-lake/customer-pii/", "s3://finance-reports/quarterly/",
        "rds://prod-db-01/users", "ec2://prod-web-cluster",
        "\\\\fileserver\\HR-Confidential", "\\\\fileserver\\Finance-Records",
        "https://okta.societe-generale.com/admin", "kms://prod-encryption-key",
        "secretsmanager://prod/database-creds", "dynamodb://user-sessions",
    ]
    for _ in range(180):
        account = random.choice(active_accounts)
        ts = datetime.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))
        events.append(AuditEvent(
            timestamp=ts,
            event_type=EventType.RESOURCE_ACCESS,
            platform=account.platform,
            identity_id=account.id,
            username=account.username,
            source_ip=fake.ipv4_private(),
            target_resource=random.choice(resources),
            action=random.choice(["read", "write", "delete", "list"]),
            outcome="success",
        ))

    # Token usage events (50-80)
    token_accounts = [a for a in active_accounts if a.access_tokens]
    for _ in range(min(70, len(token_accounts) * 3)):
        if not token_accounts:
            break
        account = random.choice(token_accounts)
        ts = datetime.now() - timedelta(days=random.randint(0, 14), hours=random.randint(0, 23))
        token = random.choice(account.access_tokens)
        events.append(AuditEvent(
            timestamp=ts,
            event_type=EventType.TOKEN_USAGE,
            platform=account.platform,
            identity_id=account.id,
            username=account.username,
            source_ip=fake.ipv4_public() if random.random() < 0.3 else fake.ipv4_private(),
            action=random.choice(["api_call", "sdk_request", "cli_command"]),
            outcome="success",
            details={
                "token_id": token.get("token_id", "unknown"),
                "scope": token.get("scope", "read"),
                "api_endpoint": random.choice(["/v1/users", "/v1/resources", "/v1/admin/config", "/v1/secrets"]),
            },
        ))

    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events


def _create_groups():
    """Create group objects for all platforms."""
    groups = []

    privileged_ad = {"Domain Admins", "Enterprise Admins", "Schema Admins", "IT-FullAccess"}
    for name in AD_GROUPS + ["Service-Accounts"]:
        groups.append(Group(
            name=name,
            platform=Platform.ACTIVE_DIRECTORY,
            is_privileged=name in privileged_ad,
            permissions=_permissions_for_group(name, "ad"),
        ))

    privileged_aws = {"AdministratorAccess", "IAMFullAccess", "SecurityAudit"}
    for name in AWS_ROLES:
        groups.append(Group(
            name=name,
            platform=Platform.AWS_IAM,
            is_privileged=name in privileged_aws,
            permissions=_permissions_for_group(name, "aws"),
        ))

    privileged_okta = {"IT-Admins", "Privileged-Access"}
    for name in OKTA_GROUPS:
        groups.append(Group(
            name=name,
            platform=Platform.OKTA,
            is_privileged=name in privileged_okta,
            permissions=_permissions_for_group(name, "okta"),
        ))

    return groups


def _assign_group_memberships(accounts, groups, platform):
    """Assign accounts to groups for a given platform."""
    platform_groups = [g for g in groups if g.platform == platform]
    if not platform_groups:
        return

    for account in accounts:
        num_groups = random.randint(1, 4)
        assigned = random.sample(platform_groups, k=min(num_groups, len(platform_groups)))
        account.groups = list(set(account.groups + [g.name for g in assigned]))
        for g in assigned:
            g.members.append(account.id)


def _title_for_department(dept):
    titles = {
        "Engineering": ["Software Engineer", "Senior Developer", "Tech Lead", "DevOps Engineer", "Staff Engineer", "Principal Engineer"],
        "Finance": ["Financial Analyst", "Controller", "Accountant", "CFO", "Treasury Analyst"],
        "HR": ["HR Specialist", "Recruiter", "HR Director", "People Ops", "Compensation Analyst"],
        "IT": ["System Administrator", "IT Manager", "Network Engineer", "IT Director", "DBA"],
        "Security": ["Security Analyst", "CISO", "SOC Analyst", "Security Engineer", "Pen Tester"],
        "Marketing": ["Marketing Manager", "Content Lead", "Brand Strategist", "Digital Marketer"],
        "Sales": ["Account Executive", "Sales Director", "BDR", "Sales Engineer"],
        "Legal": ["Legal Counsel", "Compliance Officer", "Paralegal", "Privacy Counsel"],
        "Operations": ["Operations Manager", "Program Manager", "COO", "Release Manager"],
        "Executive": ["CEO", "VP", "Director", "Managing Director", "SVP"],
    }
    return random.choice(titles.get(dept, ["Specialist"]))


def _permissions_for_group(name, platform_type):
    """Generate realistic permissions for a group."""
    if platform_type == "ad":
        base = ["read:directory", "login:workstation"]
        if "Admin" in name:
            return base + ["write:directory", "manage:users", "manage:groups", "reset:passwords", "manage:gpo"]
        if "Operators" in name:
            return base + ["manage:backups", "manage:servers"]
        return base
    elif platform_type == "aws":
        if "Admin" in name or "Full" in name:
            return ["*:*"]
        if "ReadOnly" in name:
            return ["s3:GetObject", "ec2:DescribeInstances", "rds:DescribeDBInstances"]
        return ["s3:GetObject", "s3:PutObject"]
    else:
        base = ["sso:login"]
        if "Admin" in name or "Privileged" in name:
            return base + ["manage:users", "manage:apps", "manage:policies", "manage:api_tokens"]
        return base
