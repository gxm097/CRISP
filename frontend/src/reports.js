document.addEventListener("DOMContentLoaded", () => {

    // Generate Report Buttons

    const generateButtons =
        document.querySelectorAll(".report-card button");

    generateButtons.forEach(button => {

        button.addEventListener("click", () => {

            const reportName =
                button.parentElement.querySelector("h3").textContent;

            console.log(`Generating report: ${reportName}`);

            alert(`${reportName} generation started.`);
        });

    });

    // Search Reports Table

    const searchInput =
        document.querySelector(".search-input");

    const rows =
        document.querySelectorAll(".report-table table tr");

    if (searchInput) {

        searchInput.addEventListener("keyup", () => {

            const search =
                searchInput.value.toLowerCase();

            rows.forEach((row, index) => {

                if (index === 0) return;

                const text =
                    row.textContent.toLowerCase();

                row.style.display =
                    text.includes(search)
                    ? ""
                    : "none";

            });

        });

    }

});