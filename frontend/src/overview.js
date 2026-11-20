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

        const runButton = document.querySelector(".btn");

    runButton.addEventListener("click", async () => {
        runButton.disabled = true;
        runButton.textContent = "Starting…";

        const res = await fetch("/api/assessments", {
            method: "POST",
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: '{}'
        });

        runButton.disabled = false;
        runButton.textContent = "Run assessment";

        if (!res.ok) {
            const body = await res.json().catch(() => null);
            alert(body?.message || body?.error || 'Could not start assessment');
            return;
        }

        alert('Assessment started. You can follow its progress on the Assessments page.');
        loadDashboard();
    });

    //greeting in header
    function getGreeting() {
        const hour = new Date().getHours();

        if(hour < 12 ) return "Good morning";
        if (hour < 18 ) return "Good afternoon"
        return "Good evening";
    }

    document.getElementById("greeting").textContent = getGreeting();

        // show the logged-in user's name
    fetch("/api/users/me", { credentials: 'same-origin' })
        .then(res => res.ok ? res.json() : null)
        .then(user => {
            if (user) document.getElementById("username").textContent = user.username;
        });



