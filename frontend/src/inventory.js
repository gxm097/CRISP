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