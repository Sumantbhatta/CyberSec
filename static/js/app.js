/**
 * Main orchestrator for Identity Sprawl Detector dashboard.
 */

document.addEventListener('DOMContentLoaded', () => {
    loadDashboard();
});

async function loadDashboard() {
    try {
        const [summary, risks, incidents] = await Promise.all([
            fetch('/api/dashboard/summary').then(r => r.json()),
            fetch('/api/risks').then(r => r.json()),
            fetch('/api/incidents').then(r => r.json()),
        ]);

        renderSummaryCards(summary);
        renderHeaderStats(summary);
        initGraph();
        initRiskTable(risks.findings);
        renderIncidents(incidents.incidents);
        setupFilters();
        initCharts();  // Plotly analytics charts
    } catch (err) {
        console.error('Dashboard load failed:', err);
    }
}

function renderSummaryCards(summary) {
    const container = document.getElementById('summary-cards');
    const cards = [
        { value: summary.total_identities, label: 'Identities', class: '' },
        { value: summary.total_findings, label: 'Risk Findings', class: '' },
        { value: summary.severity_counts.critical, label: 'Critical', class: 'stat-critical' },
        { value: summary.severity_counts.high, label: 'High', class: 'stat-high' },
        { value: summary.alert_consolidation_ratio + '%', label: 'Alert Reduction', class: 'stat-medium' },
        { value: summary.mfa_coverage.percentage + '%', label: 'MFA Coverage', class: summary.mfa_coverage.percentage < 80 ? 'stat-high' : 'stat-medium' },
        { value: summary.audit_events_count, label: 'Audit Events', class: '' },
        { value: summary.service_accounts, label: 'Service Accts', class: '' },
    ];

    container.innerHTML = cards.map(c => `
        <div class="col">
            <div class="stat-card">
                <div class="stat-value ${c.class}">${c.value}</div>
                <div class="stat-label">${c.label}</div>
            </div>
        </div>
    `).join('');
}

function renderHeaderStats(summary) {
    const container = document.getElementById('header-stats');
    const platforms = summary.platform_counts;
    container.innerHTML = Object.entries(platforms).map(([p, count]) => `
        <span class="badge platform-${p}">${p.replace('_', ' ')}: ${count}</span>
    `).join('');
}

function renderIncidents(incidents) {
    const container = document.getElementById('incidents-list');
    if (!incidents || incidents.length === 0) {
        container.innerHTML = '<p class="text-muted">No clustered incidents detected.</p>';
        return;
    }

    container.innerHTML = incidents.slice(0, 10).map(incident => `
        <div class="incident-card severity-${incident.severity}">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h6 class="mb-1">${incident.title}</h6>
                    <small class="text-muted">
                        Root cause: ${incident.root_cause} |
                        Affected: ${incident.affected_identities.length} identities |
                        Findings: ${incident.findings.length}
                    </small>
                </div>
                <div class="text-end">
                    <span class="badge badge-${incident.severity}">${incident.severity.toUpperCase()}</span>
                    <div class="mt-1"><small class="text-muted">Score: ${incident.aggregate_score.toFixed(1)}</small></div>
                </div>
            </div>
            ${incident.remediation_steps.length > 0 ? `
                <div class="mt-2">
                    <small class="text-muted">Remediation: ${incident.remediation_steps.join(', ')}</small>
                </div>
            ` : ''}
        </div>
    `).join('');
}

function setupFilters() {
    document.getElementById('filter-category').addEventListener('change', applyFilters);
    document.getElementById('filter-severity').addEventListener('change', applyFilters);
}

async function applyFilters() {
    const category = document.getElementById('filter-category').value;
    const severity = document.getElementById('filter-severity').value;

    let url = '/api/risks?';
    if (category) url += `category=${category}&`;
    if (severity) url += `severity=${severity}&`;

    const data = await fetch(url).then(r => r.json());
    updateRiskTable(data.findings);
}

function toggleCharts() {
    const body = document.getElementById('charts-body');
    const btn  = document.getElementById('btn-toggle-charts');
    if (body.style.display === 'none') {
        body.style.display = '';
        btn.textContent = 'Hide';
        // Re-trigger Plotly resize so charts fit correctly after reveal
        ['chart-severity', 'chart-category', 'chart-department', 'chart-score-dist'].forEach(id => {
            const el = document.getElementById(id);
            if (el && el.data) Plotly.relayout(el, {});
        });
    } else {
        body.style.display = 'none';
        btn.textContent = 'Show';
    }
}

async function openComplianceReport() {
    const modal = new bootstrap.Modal(document.getElementById('complianceModal'));
    modal.show();
    const content = document.getElementById('compliance-content');
    content.innerHTML = '<div class="loading-spinner"></div>';

    try {
        const data = await fetch('/api/compliance').then(r => r.json());
        let html = `<p class="text-muted">Total findings mapped: <strong>${data.total_findings}</strong></p>`;

        // Coverage badges
        html += '<h6>Framework Coverage</h6><div class="mb-3">';
        for (const [fw, covered] of Object.entries(data.coverage)) {
            const label = fw.replace(/_/g, ' ').toUpperCase();
            html += `<span class="badge ${covered ? 'bg-success' : 'bg-secondary'} me-2 mb-1">${label}</span>`;
        }
        html += '</div>';

        // MITRE ATT&CK table
        html += '<h6 class="mt-3">MITRE ATT&CK Techniques</h6>';
        html += '<table class="table table-dark table-sm table-hover"><thead><tr><th>Technique</th><th>Name</th><th>Findings</th><th>Categories</th></tr></thead><tbody>';
        const techniques = Object.entries(data.mitre_attack).sort((a, b) => b[1].finding_count - a[1].finding_count);
        for (const [id, info] of techniques) {
            html += `<tr>
                <td><code>${id}</code></td>
                <td>${info.name.split(' - ')[1] || info.name}</td>
                <td><span class="badge bg-danger">${info.finding_count}</span></td>
                <td>${info.categories.map(c => `<span class="compliance-tag">${c}</span>`).join('')}</td>
            </tr>`;
        }
        html += '</tbody></table>';

        // Compliance frameworks
        html += '<h6 class="mt-3">Compliance Frameworks</h6>';
        html += '<table class="table table-dark table-sm table-hover"><thead><tr><th>Framework</th><th>Finding Count</th><th>Controls</th></tr></thead><tbody>';
        for (const [fw, info] of Object.entries(data.frameworks)) {
            const controls = Object.keys(info.controls).length;
            html += `<tr><td><strong>${fw}</strong></td><td>${info.finding_count}</td><td>${controls} controls</td></tr>`;
        }
        html += '</tbody></table>';

        content.innerHTML = html;
    } catch (err) {
        content.innerHTML = '<p class="text-danger">Failed to load compliance data.</p>';
    }
}

async function openRiskReport() {
    const modal = new bootstrap.Modal(document.getElementById('riskReportModal'));
    modal.show();
    const content = document.getElementById('risk-report-content');
    content.innerHTML = '<div class="loading-spinner"></div>';

    try {
        const data = await fetch('/api/report').then(r => r.json());
        const s = data.executive_summary;
        let html = `
            <div class="row g-3 mb-4">
                <div class="col"><div class="stat-card"><div class="stat-value">${s.total_identities_assessed}</div><div class="stat-label">Identities</div></div></div>
                <div class="col"><div class="stat-card"><div class="stat-value stat-critical">${s.critical_findings}</div><div class="stat-label">Critical</div></div></div>
                <div class="col"><div class="stat-card"><div class="stat-value stat-high">${s.high_findings}</div><div class="stat-label">High</div></div></div>
                <div class="col"><div class="stat-card"><div class="stat-value stat-medium">${s.alert_consolidation}</div><div class="stat-label">Alert Reduction</div></div></div>
            </div>
            <h6>Top 10 Highest Risk Identities</h6>
            <table class="table table-dark table-sm table-hover">
                <thead><tr><th>#</th><th>Identity</th><th>Dept</th><th>Risk Score</th><th>Findings</th><th>Platforms</th></tr></thead>
                <tbody>
        `;
        for (const entry of data.top_10_risky_identities) {
            const platforms = Object.keys(entry.platforms).map(p => `<span class="platform-badge platform-${p}">${p.replace('active_directory','AD').replace('aws_iam','AWS').replace('okta','Okta')}</span>`).join('');
            const scoreClass = entry.risk_score >= 80 ? 'stat-critical' : entry.risk_score >= 60 ? 'stat-high' : 'stat-medium';
            html += `<tr>
                <td>${entry.rank}</td>
                <td><strong>${entry.identity}</strong><br><small class="text-muted">${entry.email}</small></td>
                <td>${entry.department}</td>
                <td><span class="${scoreClass}" style="font-weight:700;">${entry.risk_score.toFixed(0)}</span></td>
                <td>${entry.finding_count}</td>
                <td>${platforms}</td>
            </tr>`;
        }
        html += '</tbody></table>';

        html += '<h6 class="mt-3">Recommendations</h6><ul class="text-muted">';
        for (const rec of data.recommendations) {
            html += `<li>${rec}</li>`;
        }
        html += '</ul>';

        content.innerHTML = html;
    } catch (err) {
        content.innerHTML = '<p class="text-danger">Failed to load risk report.</p>';
    }
}
