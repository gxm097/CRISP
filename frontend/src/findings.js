// Findings page: loads findings once, then search and filters work in the browser

const searchInput = document.getElementById('findings-search');
const severityFilter = document.getElementById('severity-filter');
const statusFilter = document.getElementById('status-filter');
const tbody = document.getElementById('findings-body');

let allFindings = [];

// turn special characters into safe text before putting them on the page
function escapeHtml(value) {
    return String(value ?? '—')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function renderFindings() {
    const search = searchInput.value.trim().toLowerCase();
    const severity = severityFilter.value;
    const status = statusFilter.value;

    const rows = allFindings.filter(f =>
        (!severity || String(f.severity).toLowerCase() === severity) &&
        (!status || String(f.status).toLowerCase() === status) &&
        `${f.cve} ${f.title} ${f.asset}`.toLowerCase().includes(search)
    );

    if (rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8">No findings match.</td></tr>';
        return;
    }

    tbody.innerHTML = rows.map(f => `
        <tr>
            <td>${escapeHtml(f.cve)}</td>
            <td>${escapeHtml(f.title)}</td>
            <td>${escapeHtml(f.asset)}<br><small>${escapeHtml(f.assetType)}</small></td>
            <td>${escapeHtml(f.cvss)}</td>
            <td><span class="badge severity-${escapeHtml(String(f.severity).toLowerCase())}">${escapeHtml(f.severity)}</span></td>
            <td>${f.kev ? 'Yes' : 'No'}</td>
            <td>${escapeHtml(f.status)}</td>
            <td>${escapeHtml(f.firstDetected)}</td>
        </tr>
    `).join('');
}

async function loadFindings() {
    try {
        const res = await fetch('/api/findings', { credentials: 'same-origin' });
        if (!res.ok) throw new Error();
        allFindings = await res.json();
        renderFindings();
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="8">Could not load findings.</td></tr>';
    }
}

searchInput.addEventListener('input', renderFindings);
severityFilter.addEventListener('change', renderFindings);
statusFilter.addEventListener('change', renderFindings);

loadFindings();