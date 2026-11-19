
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

    // TODO: show the logged-in user's name once the backend has login sessions
    // document.getElementById("username").textContent = UserActivation.first.Name;


    
