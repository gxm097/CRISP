// Reports page: generate reports and list the ones already generated

const reportsBody = document.getElementById('reports-body');
const reportSearch = document.querySelector('.search-input');

let allReports = [];

function openReport(id) {
    window.open('/report-view?id=' + encodeURIComponent(id), '_blank');
}

function renderReports() {
    const search = reportSearch.value.trim().toLowerCase();
    const rows = allReports.filter(r =>
        `${r.type} ${r.generatedBy}`.toLowerCase().includes(search)
    );

    if (rows.length === 0) {
        reportsBody.innerHTML = '<tr><td colspan="4">No reports yet. Generate one above.</td></tr>';
        return;
    }

    reportsBody.innerHTML = rows.map(r => `
        <tr>
            <td>${r.type}</td>
            <td>${new Date(r.createdDate).toLocaleString()}</td>
            <td>${r.generatedBy ?? '—'}</td>
            <td><button class="download-btn" data-id="${r.id}">Open / Save PDF</button></td>
        </tr>
    `).join('');
}

async function loadReports() {
    try {
        const res = await fetch('/api/generated-reports', { credentials: 'same-origin' });
        if (!res.ok) throw new Error();
        allReports = await res.json();
        renderReports();
    } catch (error) {
        reportsBody.innerHTML = '<tr><td colspan="4">Could not load reports.</td></tr>';
    }
}

// Generate Report buttons
document.querySelectorAll('.generate-report-btn').forEach(button => {
    button.addEventListener('click', async () => {
        button.disabled = true;
        button.textContent = 'Generating…';

        const res = await fetch('/api/generated-reports', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: button.dataset.type })
        });

        button.disabled = false;
        button.textContent = 'Generate Report';

        if (!res.ok) {
            alert('Could not generate the report.');
            return;
        }

        const { id } = await res.json();
        openReport(id);
        loadReports();
    });
});

// Open buttons in the table
reportsBody.addEventListener('click', event => {
    const button = event.target.closest('button[data-id]');
    if (button) openReport(button.dataset.id);
});

reportSearch.addEventListener('input', renderReports);

loadReports();