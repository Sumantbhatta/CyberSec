/**
 * Identity detail panel rendering.
 */

async function loadIdentityDetail(identityId) {
    const container = document.getElementById('identity-detail');
    container.innerHTML = '<div class="loading-spinner"></div>';

    try {
        const identity = await fetch(`/api/identities/${identityId}`).then(r => r.json());
        container.innerHTML = renderIdentityDetail(identity);
    } catch (err) {
        container.innerHTML = '<p class="text-danger">Failed to load identity details.</p>';
        console.error('Identity detail error:', err);
    }
}

function renderIdentityDetail(identity) {
    const riskClass = identity.risk_score >= 80 ? 'stat-critical' :
                      identity.risk_score >= 60 ? 'stat-high' :
                      identity.risk_score >= 40 ? 'stat-medium' : 'stat-low';

    let html = `
        <div class="mb-3">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h5 class="mb-1">${identity.display_name || 'Unknown'}</h5>
                    <small class="text-muted">${identity.primary_email}</small><br>
                    <small class="text-muted">${identity.department} - ${identity.title}</small>
                </div>
                <div class="text-end">
                    <div class="stat-value ${riskClass}" style="font-size:2rem;">${identity.risk_score.toFixed(0)}</div>
                    <small class="text-muted">Risk Score</small>
                </div>
            </div>
        </div>

        <h6 class="border-bottom border-secondary pb-2 mt-3">Cross-Platform Status</h6>
        <div class="table-responsive">
            <table class="table table-dark table-sm">
                <thead>
                    <tr>
                        <th>Platform</th>
                        <th>Username</th>
                        <th>Status</th>
                        <th>Admin</th>
                        <th>MFA</th>
                        <th>Last Login</th>
                    </tr>
                </thead>
                <tbody>
    `;

    const platforms = identity.platform_accounts || {};
    for (const [platform, account] of Object.entries(platforms)) {
        const statusClass = `status-${account.status}`;
        const lastLogin = account.last_login ? formatRelativeDate(account.last_login) : 'Never';
        html += `
            <tr>
                <td><span class="platform-badge platform-${platform}">${platformLabel(platform)}</span></td>
                <td><code>${account.username}</code></td>
                <td><span class="${statusClass}">${account.status}</span></td>
                <td>${account.is_admin ? '<span class="text-danger">YES</span>' : 'No'}</td>
                <td>${account.mfa_enabled ? '<span class="text-success">ON</span>' : '<span class="text-warning">OFF</span>'}</td>
                <td><small>${lastLogin}</small></td>
            </tr>
        `;
    }

    html += `</tbody></table></div>`;

    // Groups & Roles
    html += `<h6 class="border-bottom border-secondary pb-2 mt-3">Groups & Roles</h6>`;
    for (const [platform, account] of Object.entries(platforms)) {
        const items = [...(account.groups || []), ...(account.roles || [])];
        if (items.length > 0) {
            html += `<div class="mb-2"><small class="text-muted">${platformLabel(platform)}:</small> `;
            html += items.map(g => `<span class="badge bg-secondary me-1">${g}</span>`).join('');
            html += `</div>`;
        }
    }

    // Effective Permissions
    if (identity.effective_permissions && identity.effective_permissions.length > 0) {
        html += `<h6 class="border-bottom border-secondary pb-2 mt-3">Effective Permissions (${identity.effective_permissions.length})</h6>`;
        html += `<div class="mb-2">`;
        html += identity.effective_permissions.slice(0, 15).map(p =>
            `<span class="compliance-tag">${p}</span>`
        ).join('');
        if (identity.effective_permissions.length > 15) {
            html += `<span class="text-muted ms-1">+${identity.effective_permissions.length - 15} more</span>`;
        }
        html += `</div>`;
    }

    // Findings with MITRE refs
    if (identity.findings && identity.findings.length > 0) {
        html += `<h6 class="border-bottom border-secondary pb-2 mt-3">Findings (${identity.findings.length})</h6>`;
        identity.findings.forEach(f => {
            const mitre = f.mitre_refs && f.mitre_refs.length > 0
                ? `<div class="mt-1">${f.mitre_refs.map(m => `<span class="compliance-tag" style="border-color:rgba(239,83,80,0.4);color:#ef5350;">${m.split(' - ')[0]}</span>`).join('')}</div>`
                : '';
            html += `
                <div class="mb-2 p-2" style="background:rgba(0,0,0,0.2);border-radius:4px;">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="badge badge-${f.severity} me-1">${f.severity}</span>
                            <small>${f.title}</small>
                        </div>
                        <small class="text-muted">${f.score.toFixed(1)}</small>
                    </div>
                    ${mitre}
                </div>
            `;
        });
    }

    // Remediation
    if (identity.remediation && identity.remediation.length > 0) {
        html += `<h6 class="border-bottom border-secondary pb-2 mt-3">Remediation</h6>`;
        identity.remediation.forEach(r => {
            if (r.commands && r.commands.length > 0) {
                html += `<div class="remediation-code mb-2">${r.commands.map(c =>
                    c.startsWith('#') ?
                        `<span class="cmd-comment">${escapeHtmlDetail(c)}</span>` :
                        `<span class="cmd-action">${escapeHtmlDetail(c)}</span>`
                ).join('\n')}</div>`;
                if (r.compliance && r.compliance.length > 0) {
                    html += `<div class="mb-2">${r.compliance.map(c => `<span class="compliance-tag">${c}</span>`).join('')}</div>`;
                }
            }
        });
    }

    return html;
}

function platformLabel(platform) {
    const labels = {
        'active_directory': 'AD',
        'aws_iam': 'AWS',
        'okta': 'Okta',
    };
    return labels[platform] || platform;
}

function formatRelativeDate(isoString) {
    const date = new Date(isoString);
    const now = new Date();
    const diffDays = Math.floor((now - date) / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 30) return `${diffDays}d ago`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo ago`;
    return `${Math.floor(diffDays / 365)}y ago`;
}

function escapeHtmlDetail(text) {
    // Shared with risk_table.js — delegates to the common escapeHtml utility
    return escapeHtml(text);
}
