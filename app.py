"""Flask application entry point for Identity Sprawl Detector."""

from flask import Flask, render_template

from data.synthetic_generator import generate_identities
from data.seed_scenarios import seed_scenarios
from engine.identity_resolver import resolve_identities
from engine.privilege_graph import build_privilege_graph
from engine.risk_detector import detect_risks
from engine.risk_scorer import score_finding, score_identity, compute_behavioral_baseline
from engine.incident_cluster import cluster_incidents
from engine.remediation import generate_remediation
from api.routes import api_bp, init_state


def create_app():
    app = Flask(__name__)
    # Generate and process data
    print("[*] Generating synthetic identity data (250+ identities)...")
    raw_data = generate_identities()
    raw_data = seed_scenarios(raw_data)

    print("[*] Resolving cross-platform identities...")
    unified_identities = resolve_identities(raw_data)

    # Mark service accounts and justified accounts
    for identity in unified_identities:
        identity.is_service_account = any(
            acc.is_service_account for acc in identity.platform_accounts.values()
        )
        identity.has_justification = any(
            bool(acc.justification) for acc in identity.platform_accounts.values()
        )

    print("[*] Building privilege graph...")
    graph = build_privilege_graph(unified_identities, raw_data["groups"])

    print("[*] Running risk detection engine (8 rules)...")
    audit_events = raw_data.get("audit_events", [])
    findings = detect_risks(unified_identities, raw_data["people"], audit_events)

    print("[*] Scoring findings...")
    for finding in findings:
        score_finding(finding)
        generate_remediation(finding)

    # Attach findings to identities and compute behavioral baseline
    finding_map = {}
    for f in findings:
        finding_map.setdefault(f.identity_id, []).append(f)
    for identity in unified_identities:
        identity.findings = finding_map.get(identity.id, [])
        score_identity(identity)

    # Update graph node risk scores
    for identity in unified_identities:
        if identity.id in graph:
            graph.nodes[identity.id]["risk_score"] = identity.risk_score

    print("[*] Clustering incidents...")
    incidents = cluster_incidents(findings, unified_identities)

    # Compute alert consolidation metric
    standalone_alerts = len(findings)
    consolidated_alerts = len(incidents)
    consolidation_ratio = 1 - (consolidated_alerts / max(standalone_alerts, 1))

    # Initialize API state
    init_state(unified_identities, findings, incidents, graph,
               raw_data["groups"], raw_data["people"], audit_events)

    # Register routes
    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    # Summary stats
    stats = {
        "identities": len(unified_identities),
        "findings": len(findings),
        "incidents": len(incidents),
        "critical": sum(1 for f in findings if f.severity.value == "critical"),
        "high": sum(1 for f in findings if f.severity.value == "high"),
        "categories": len(set(f.category.value for f in findings)),
        "consolidation": f"{consolidation_ratio:.0%}",
        "audit_events": len(audit_events),
    }
    print(f"[+] Ready: {stats['identities']} identities, {stats['findings']} findings, "
          f"{stats['incidents']} incidents ({stats['critical']} critical, {stats['high']} high)")
    print(f"[+] Detection: {stats['categories']} categories, "
          f"alert consolidation: {stats['consolidation']}, "
          f"audit events: {stats['audit_events']}")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)
