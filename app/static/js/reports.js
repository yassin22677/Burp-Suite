document.addEventListener("DOMContentLoaded", () => {
    const rows = document.querySelectorAll("#vulnTableBody tr");
    const searchInput = document.getElementById("searchInput");
    const severityFilter = document.getElementById("severityFilter");
    const exportCSV = document.getElementById("exportCSV");
    const exportJSON = document.getElementById("exportJSON");
    const exportPDF = document.getElementById("exportPDF");
    const ctx1 = document.getElementById("severityChart");
    const ctx2 = document.getElementById("trendChart");
    const insightText = document.getElementById("insightText");

    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const vulns = [];

    // Collect data from table rows
    rows.forEach((r) => {
        const data = {
            id: r.children[0].innerText.trim(),
            severity: r.children[1].innerText.trim(),
            name: r.children[2].innerText.trim(),
            endpoint: r.children[3].innerText.trim(),
            status: r.children[4].innerText.trim(),
            confidence: r.children[5].innerText.trim().replace("%", "")
        };
        vulns.push(data);
        if (counts[data.severity] !== undefined) counts[data.severity]++;
    });

    // Update severity counters
    document.getElementById("criticalCount").innerText = counts.Critical;
    document.getElementById("highCount").innerText = counts.High;
    document.getElementById("mediumCount").innerText = counts.Medium;
    document.getElementById("lowCount").innerText = counts.Low;

    // === Charts ===
    new Chart(ctx1, {
        type: "bar",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                data: [counts.Critical, counts.High, counts.Medium, counts.Low],
                backgroundColor: ["#ef4444", "#facc15", "#0ea5e9", "#22c55e"]
            }]
        },
        options: {
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true } }
        }
    });

    new Chart(ctx2, {
        type: "line",
        data: {
            labels: ["Mon", "Tue", "Wed", "Thu", "Fri"],
            datasets: [{
                label: "Vulnerabilities Detected",
                data: [2, 4, 8, 5, 7],
                borderColor: "#60a5fa",
                fill: true,
                backgroundColor: "rgba(96,165,250,0.3)"
            }]
        },
        options: { plugins: { legend: { display: true } } }
    });

    // === AI-style insights ===
    const highest = Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || "None";
    const avgConfidence = vulns.length > 0
        ? Math.round(vulns.reduce((a, v) => a + parseInt(v.confidence || 0), 0) / vulns.length)
        : 0;

    insightText.innerText = `Most detected issues are ${highest}-severity. Average confidence ≈ ${avgConfidence}%. Focus remediation on critical endpoints first.`;

    // === Search + Filter ===
    function filterTable() {
        const sVal = searchInput.value.toLowerCase();
        const sevVal = severityFilter.value;
        rows.forEach((r) => {
            const name = r.children[2].innerText.toLowerCase();
            const sev = r.children[1].innerText.trim();
            const visible = (sevVal === "All" || sev === sevVal) && name.includes(sVal);
            r.style.display = visible ? "" : "none";
        });
    }
    searchInput.addEventListener("input", filterTable);
    severityFilter.addEventListener("change", filterTable);

    // === Sorting (fixed syntax) ===
    document.querySelectorAll("#vulnTable th[data-sort]").forEach((header) => {
        header.style.cursor = "pointer";
        header.addEventListener("click", () => {
            const index = header.cellIndex;
            const sorted = Array.from(rows).sort((a, b) => {
                const A = a.children[index].innerText.trim();
                const B = b.children[index].innerText.trim();
                return A.localeCompare(B, undefined, { numeric: true, sensitivity: "base" });
            });
            const tbody = document.querySelector("#vulnTableBody");
            tbody.innerHTML = "";
            sorted.forEach((r) => tbody.appendChild(r));
        });
    });

    // === Export CSV ===
    exportCSV.addEventListener("click", () => {
        let csv = "ID,Severity,Name,Endpoint,Status,Confidence\n";
        vulns.forEach((v) => {
            csv += `${v.id},${v.severity},${v.name},${v.endpoint},${v.status},${v.confidence}\n`;
        });
        const blob = new Blob([csv], { type: "text/csv" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "Burp_AI_Report.csv";
        a.click();
    });

    // === Export JSON ===
    exportJSON.addEventListener("click", () => {
        const blob = new Blob([JSON.stringify(vulns, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "Burp_AI_Report.json";
        a.click();
    });

    // === Export PDF ===
    exportPDF.addEventListener("click", () => {
        const { jsPDF } = window.jspdf;
        const pdf = new jsPDF();
        pdf.text("Burp Config AI - Vulnerability Report", 10, 10);
        vulns.slice(0, 10).forEach((v, i) => {
            pdf.text(`${i + 1}. [${v.severity}] ${v.name} - ${v.endpoint}`, 10, 20 + i * 10);
        });
        pdf.save("Burp_AI_Report.pdf");
    });

    // === Modal Details ===
    document.querySelectorAll(".viewDetailsBtn").forEach((btn) => {
        btn.addEventListener("click", () => {
            document.getElementById("modalName").innerText = btn.dataset.name;
            document.getElementById("modalSeverity").innerText = btn.dataset.severity;
            document.getElementById("modalEndpoint").innerText = btn.dataset.endpoint;
            document.getElementById("modalStatus").innerText = btn.dataset.status;
            document.getElementById("modalConfidence").innerText = btn.dataset.confidence;
            document.getElementById("modalDescription").innerText = btn.dataset.description || "No description available.";
        });
    });

    // === Theme Toggle ===
    const themeToggle = document.getElementById("themeToggle");
    themeToggle.addEventListener("click", (event) => {
        document.body.classList.toggle("light-mode");
        event.target.textContent = document.body.classList.contains("light-mode") ? "☀" : "🌙";
    });
});
