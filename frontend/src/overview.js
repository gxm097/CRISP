//current date
    const now = new Date();
    document.getElementById("date").textContent = now.toLocaleDateString("en-US",{
        weekday: "long",
        year: "numeric",
        month: "long",
        day: "numeric"
    });

    async function loadDashboard() {
        const res = await fetch("/api/dashboard", { credentials: 'same-origin' });
        if (!res.ok) return;
        const data = await res.json();

        const assets = document.querySelector('[data-stat="assets"]');
        const findings = document.querySelector('[data-stat="findings"]');
        if (assets) assets.textContent = data.assets;
        if (findings) findings.textContent = data.findings;
    
        const tbody = document.getElementById("findings-body");
        if (tbody) {
            tbody.innerHTML = (data.priorityFindings || []).map(f => `
              <tr>
                <td>${f.cve ?? '—'}</td>
                <td>${f.asset ?? '—'}</td>
                <td>${f.cvss ?? '—'}</td>
                <td>${f.severity ?? '—'}</td>
                <td>${f.status ?? '—'}</td>
                <td>${f.discovered ?? '—'}</td>
              </tr>
            `).join("") || '<tr><td colspan="6">No priority findings.</td></tr>';
        }
    }

    loadDashboard() 

    document.querySelector(".btn").addEventListener("click", async() => {
        const res = await fetch("/api/assessments", {
            method: "POST",
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: '{}'
        });
        if (!res.ok) {
            const body = await res.json().catch(() => null);
            alert(body?.message || body?.error || 'Could not start assessment');
            return;
        }
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

    // TODO: show the logged-in user's name once the backend has login sessions
    // document.getElementById("username").textContent = UserActivation.first.Name;



