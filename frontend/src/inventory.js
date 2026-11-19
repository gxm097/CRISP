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
        open.log('clicked');
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

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        console.log(Object.fromEntries(new FormData(form)));
        form.reset();
        closeMode();
    })