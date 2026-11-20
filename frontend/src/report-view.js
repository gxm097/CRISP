// Report view: builds a printable report from /api/generated-reports/:id

const reportEl = document.getElementById('report');

// turn special characters into safe text before putting them on the page
function escapeHtml(value) {
    return String(value ?? '—')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function formatDate(value) {
    return value ? new Date(value).toLocaleString() : '—';
}

function severityBadge(severity) {
    const level = String(severity).toLowerCase();
    return `<span class="badge severity-${escapeHtml(level)}">${escapeHtml(severity)}</span>`;
}

function headerHtml(report) {
    return `
        <header class="report-header">
            <div class="brand">CRISP</div>
            <h1>${escapeHtml(report.type)}</h1>
            <p class="meta">
                ${escapeHtml(report.organization)} &middot;
                Generated ${escapeHtml(formatDate(report.createdDate))}
                by ${escapeHtml(report.generatedBy)}
            </p>
        </header>`;
}

function summaryHtml(data) {
    const s = data.summary;
    const run = data.latestRun;

    const stats = [
        ['Total assets', s.totalAssets],
        ['Actively monitored', s.activeAssets],
        ['Open findings', s.openFindings],
        ['Critical', s.critical],
        ['High', s.high],
        ['Known exploited', s.knownExploited],
        ['Security posture', s.posture === null ? '—' : s.posture + '%']
    ];

    const topFindings = data.findings.slice(0, 10);

    return `
        <section>
            <h2>Exposure overview</h2>
            <div class="stat-grid">
                ${stats.map(([label, value]) => `
                    <div class="stat">
                        <div class="stat-value">${escapeHtml(value)}</div>
                        <div class="stat-label">${label}</div>
                    </div>`).join('')}
            </div>
            <p class="note">Security posture is the share of actively monitored assets with no open Critical or High finding.</p>
        </section>

        <section>
            <h2>Latest completed assessment</h2>
            ${run ? `
                <table>
                    <tr><th>Completed</th><td>${escapeHtml(formatDate(run.completedAt))}</td></tr>
                    <tr><th>Duration</th><td>${escapeHtml(run.durationMinutes)} min</td></tr>
                    <tr><th>Assets assessed</th><td>${escapeHtml(run.assetsAssessed)}</td></tr>
                </table>` : '<p>No completed assessments yet.</p>'}
        </section>

        <section>
            <h2>Highest risk findings</h2>
            ${topFindings.length ? `
                <table>
                    <thead>
                        <tr><th>CVE</th><th>Asset</th><th>CVSS</th><th>Severity</th><th>Known exploited</th></tr>
                    </thead>
                    <tbody>
                        ${topFindings.map(f => `
                            <tr>
                                <td class="nowrap">${escapeHtml(f.cve)}</td>
                                <td>${escapeHtml(f.asset)}</td>
                                <td>${escapeHtml(f.cvss)}</td>
                                <td>${severityBadge(f.severity)}</td>
                                <td>${f.kev ? 'Yes' : 'No'}</td>
                            </tr>`).join('')}
                    </tbody>
                </table>` : '<p>No open findings.</p>'}
        </section>`;
}

function findingsHtml(data) {
    if (data.findings.length === 0) {
        return '<section><p>No open findings.</p></section>';
    }

    return `
        <section>
            <h2>Open findings (${data.findings.length})</h2>
            ${data.findings.map(f => `
                <article class="finding">
                    <h3>${escapeHtml(f.cve)} &mdash; ${escapeHtml(f.title)}</h3>
                    <p>${severityBadge(f.severity)} CVSS ${escapeHtml(f.cvss)} &middot; Known exploited: ${f.kev ? 'Yes' : 'No'}</p>
                    <table>
                        <tr><th>Affected asset</th><td>${escapeHtml(f.asset)} (${escapeHtml(f.assetType)})</td></tr>
                        <tr><th>Installed version</th><td>${escapeHtml(f.version)}</td></tr>
                        <tr><th>Affected versions</th><td>${escapeHtml(f.affectedVersions)}</td></tr>
                        <tr><th>First detected</th><td>${escapeHtml(formatDate(f.firstDetected))}</td></tr>
                        <tr><th>Status</th><td>${escapeHtml(f.status)}</td></tr>
                    </table>
                    <p class="description">${escapeHtml(f.description)}</p>
                </article>`).join('')}
        </section>`;
}

async function loadReport() {
    const id = new URLSearchParams(window.location.search).get('id');

    try {
        const res = await fetch('/api/generated-reports/' + encodeURIComponent(id), { credentials: 'same-origin' });
        if (!res.ok) throw new Error();
        const data = await res.json();

        document.title = 'CRISP - ' + data.report.type;
        reportEl.innerHTML = headerHtml(data.report) +
            (data.report.type === 'Vulnerability Findings' ? findingsHtml(data) : summaryHtml(data));
    } catch (error) {
        reportEl.innerHTML = '<p>Could not load this report.</p>';
    }
}

document.getElementById('print-btn').addEventListener('click', () => window.print());

loadReport();