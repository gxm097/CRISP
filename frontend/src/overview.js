
//current date
    const now = new Date();
    document.getElementById("date").textContent = now.toLocaleDateString("en-US",{
        weekday: "long",
        year: "numeric",
        month: "long",
        day: "numeric"
    });

    async function loadDashboard() {
        const res = await fetch("api/dashboard");
        const data = await res.json();

        document.querySelector('[data-stat="assets"]').textContent = data.assets;
        document.querySelector('[data-stat="findings"]').textContent = data.findings;
    
        //table
        const tbody = document.getElementById("findings-body");
        tbody.innerHTML = data.priorityFindings.map(f => `
          <tr>
            <td>${f.cve}</td>  
            <td>${f.asset}</td> 
            <td>${f.cvss}</td> 
            <td>${f.severity}</td> 
            <td>${f.status}</td> 
            <td>${f.discovered}</td>  
          </tr>          
            `).join("");
    }

    loadDashboard() 

    document.querySelector(".btn").addEventListener("click", async() => {
        await fetch("/api/assessments", {method: "POST"});
        loadDashboard();
    })

    //greeting in header
    function getGreeting() {
        const hour = new Date().getHours();

        if(hour < 12 ) return "Good morning";
        if (hour < 18 ) return "Good afternoon"
        return "Good evening";
    }

    document.getElementById("greeting").textContent = getGreeting();

    document.getElementById("username").textContent = UserActivation.first.Name;


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
    vendor.addEventListender("change", applyFilters);

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
