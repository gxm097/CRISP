//invetory bar 
    const search = document.getElementById("search");
    const type = document.getElementById("asset-type");
    const vendor = document.getElementById("vendor");

    function applyFilters() {
        const params = new URLSearchParams({
            q: search.value,
            type: type.value,
            vendor: vendor.value
        });
                fetch(`/api/assets?${params}`)
        .then(r => r.json())
        .then(renderTable);

        loadSummary();
    }

    // fill the 4 stat cards at the top of the page
    function loadSummary() {
        fetch('/api/inventory/summary', { credentials: 'same-origin' })
        .then(r => r.ok ? r.json() : null)
        .then(summary => {
            if (!summary) return;
            document.querySelectorAll('[data-stat]').forEach(card => {
                card.textContent = summary[card.dataset.stat] ?? '---';
            });
        });
    }

    type.addEventListener("change", applyFilters);
    vendor.addEventListener("change", applyFilters);

    let timer;
    search.addEventListener("input", () => {
        clearTimeout(timer);
        timer = setTimeout(applyFilters, 300);
    });

    //asset button

    const overlay = document.getElementById('assetMode');
    const form= document.getElementById('assetForm')
    function openMode(){
        overlay.classList.add('open');
    }
    function closeMode(){
        overlay.classList.remove('open');
    }
    document.querySelector('.asset-btn').addEventListener('click', openMode);
    document.getElementById('closeMode').addEventListener('click', closeMode);
    document.getElementById('cancelMode').addEventListener('click', closeMode);

    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) closeMode();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeMode();
    });

    form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form));

    const res = await fetch('/api/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });

    if (!res.ok) {
        const err = await res.json();
        alert(err.error || 'Could not save asset');
        return;
    }

    form.reset();
    closeMode();
    applyFilters();
});

// Import CSV
const csvInput = document.getElementById('csvFile');

document.querySelector('.import-btn').addEventListener('click', () => csvInput.click());

csvInput.addEventListener('change', async () => {
    const file = csvInput.files[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.csv')) {
        alert('Only CSV files are supported.');
        csvInput.value = '';
        return;
    }

    const status = document.getElementById('import-status');
    const importButton = document.querySelector('.import-btn');
    importButton.disabled = true;
    status.textContent = 'Uploading ' + file.name + '…';

    const form = new FormData();
    form.append('file', file);
    form.append('importType', document.getElementById('import-type').value);

    try {
        const res = await fetch('/api/import-jobs', {
            method: 'POST',
            credentials: 'same-origin',
            body: form
        });
        const result = await res.json();
        if (!res.ok) {
            throw new Error(result.errors?.join('\n') || result.error || 'Could not start import');
        }

        csvInput.value = '';
        while (result.status !== 'Completed' && result.status !== 'Failed') {
            status.textContent = result.stage + ' (' + result.progress + '%)';
            await new Promise(resolve => setTimeout(resolve, 3000));
            const poll = await fetch('/api/import-jobs/' + encodeURIComponent(result.jobId), {
                credentials: 'same-origin'
            });
            const latest = await poll.json();
            if (!poll.ok) throw new Error(latest.message || 'Could not read import status');
            Object.assign(result, latest);
        }

        if (result.status === 'Failed') {
            throw new Error(result.errors.join('\n'));
        }

        status.textContent = 'Import completed for ' + result.filename;
        applyFilters();
    } catch (error) {
        status.textContent = 'Import failed: ' + error.message;
        alert(error.message);
    } finally {
        importButton.disabled = false;
    }
});

function parseCsv(text) {
    text = text.replace(/^\uFEFF/, '');
    const lines = [];
    let row = [], cell = '', inQuotes = false;

    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (inQuotes) {
            if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
            else if (c === '"') inQuotes = false;
            else cell += c;
        } else if (c === '"') inQuotes = true;
        else if (c === ',') { row.push(cell); cell = ''; }
        else if (c === '\n') { row.push(cell); lines.push(row); row = []; cell = ''; }
        else if (c !== '\r') cell += c;
    }
    if (cell || row.length) { row.push(cell); lines.push(row); }

    const filled = lines.filter(r => r.some(v => v.trim() !== ''));
    if (filled.length < 2) return [];

    // match friendly column names like "Asset Name" or "Product/Model"
    const columnNames = {
        assetname: 'name', name: 'name',
        assettype: 'type', type: 'type',
        vendor: 'vendor',
        productmodel: 'product', product: 'product',
        version: 'version',
        publicfacing: 'public', public: 'public'
    };
    const headers = filled[0].map(h => columnNames[h.toLowerCase().replace(/[^a-z]/g, '')] || h);

    return filled.slice(1).map(r =>
        Object.fromEntries(headers.map((h, i) => [h, (r[i] || '').trim()]))
    );
}

    function renderTable(assets) {
    const tbody = document.getElementById("inventory-body");

    if (!Array.isArray(assets) || assets.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6">No assets found</td></tr>`;
        return;
    }

    tbody.innerHTML = assets.map(a => `
      <tr>
        <td>${a.name}</td>
        <td>${a.type}</td>
        <td>${a.vendor ?? ""} / ${a.product ?? ""}</td>
        <td>${a.version ?? "—"}</td>
        <td>${a.status}</td>
        <td>${a.findings}</td>
      </tr>
    `).join("");
}

// load the table when the page opens
applyFilters();