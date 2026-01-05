// dashboard.js – Burp-AI Dashboard (Final Stable Version)
(() => {
    const state = {
        burpConnected: true,
        lastScan: { target: "https://example.com", date: "2025-11-06 22:15" },
        aiMode: "Adaptive (RL Active)",
        tpr: 0.72,
        fpReduction: 0.38,
        currentConfig: { scannerThreshold: "Medium", passiveChecks: true, rateLimit: 5 },
        aiRecommendation: { scannerThreshold: "Low", passiveChecks: true, rateLimit: 2 },
        scanResults: sampleFindings(),
        learningHistory: sampleLearning()
    };

    const $ = sel => document.querySelector(sel);

    // ==================== INITIALIZATION ====================
    function init() {
        $("#last-scan").textContent = `Last scan: ${state.lastScan.target} • ${state.lastScan.date}`;
        $("#tpr").textContent = `${Math.round(state.tpr * 100)}%`;
        $("#fpr").textContent = `${Math.round(state.fpReduction * 100)}%`;
        $("#current-config-pre").textContent = JSON.stringify(state.currentConfig, null, 2);
        $("#ai-reco-pre").textContent = JSON.stringify(state.aiRecommendation, null, 2);
        $("#triggered-action").textContent =
            `Adjusted rate limit from ${state.currentConfig.rateLimit} → ${state.aiRecommendation.rateLimit}`;
        $("#xai-explain").textContent =
            "The RL agent observed multiple 429 and 5xx codes — lowering request rate reduces overload.";

        renderFindings();
        renderReportsPanel();
        renderReport();
        renderDBSummary();
        renderLearningHistory();
        renderSpark();
        setupHandlers();
        navButtons();
        themeToggle();
        notify("Dashboard loaded — Burp Suite connected.");
    }

    // ==================== RENDER FUNCTIONS ====================
    function renderFindings() {
        const tbody = $("#findings-table tbody");
        if (!tbody) return;
        tbody.innerHTML = "";
        const filter = $("#severity-filter")?.value || "All";
        state.scanResults.forEach(f => {
            if (filter !== "All" && f.severity !== filter) return;
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="mono">${escapeHtml(f.url)}</td>
                <td>${escapeHtml(f.vuln)}</td>
                <td><span class="chip ${f.severity.toLowerCase()}">${escapeHtml(f.severity)}</span></td>
                <td>${Math.round(f.confidence * 100)}%</td>`;
            tbody.appendChild(tr);
        });
    }

    function renderReport() {
        const el = $("#report-html");
        if (!el) return;
        el.innerHTML = `
            <h3>Burp-AI Summary</h3>
            <ul>
                <li>True Positive Rate: ${Math.round(state.tpr * 100)}%</li>
                <li>False Positive Reduction: ${Math.round(state.fpReduction * 100)}%</li>
            </ul>`;
    }

    function renderReportsPanel() {
        const counts = { high: 0, medium: 0, low: 0 };
        state.scanResults.forEach(f => counts[f.severity.toLowerCase()]++);

        $("#highCount").textContent = counts.high;
        $("#mediumCount").textContent = counts.medium;
        $("#lowCount").textContent = counts.low;

        const tbody = $("#vulnTableBody");
        if (!tbody) return;
        tbody.innerHTML = "";
        state.scanResults.forEach((f, i) => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${i + 1}</td>
                <td><span class="chip ${f.severity.toLowerCase()}">${f.severity}</span></td>
                <td>${f.vuln}</td>
                <td>${f.url}</td>
                <td>${f.true_positive ? "Unresolved" : "Unverified"}</td>
                <td>${Math.round(f.confidence * 100)}%</td>`;
            tbody.appendChild(tr);
        });

        // ===== Export Buttons =====
        const csvBtn = $("#exportCSV");
        const jsonBtn = $("#exportJSON");
        const pdfBtn = $("#exportPDF");

        csvBtn?.addEventListener("click", () => {
            const header = ["ID", "Severity", "Name", "Endpoint", "Status", "Confidence"];
            const rows = state.scanResults.map((r, i) => [
                i + 1,
                r.severity,
                r.vuln,
                r.url,
                r.true_positive ? "Unresolved" : "Unverified",
                `${Math.round(r.confidence * 100)}%`
            ]);
            const csv = [header, ...rows].map(r => r.join(",")).join("\n");
            downloadFile(csv, "BurpAI_Report.csv", "text/csv");
            notify("Report exported as CSV.");
        });

        jsonBtn?.addEventListener("click", () => {
            const data = JSON.stringify(state.scanResults, null, 2);
            downloadFile(data, "BurpAI_Report.json", "application/json");
            notify("Report exported as JSON.");
        });

        pdfBtn?.addEventListener("click", () => {
            const html = `
                <html><head><title>Burp-AI Report</title></head><body>
                <h2>Burp-AI Vulnerability Report</h2>
                <table border="1" cellspacing="0" cellpadding="6" style="font-family:Arial;font-size:12px;border-collapse:collapse;">
                <tr><th>ID</th><th>Severity</th><th>Name</th><th>Endpoint</th><th>Status</th><th>Confidence</th></tr>
                ${state.scanResults.map((r, i) => `
                    <tr>
                        <td>${i + 1}</td>
                        <td>${r.severity}</td>
                        <td>${r.vuln}</td>
                        <td>${r.url}</td>
                        <td>${r.true_positive ? "Unresolved" : "Unverified"}</td>
                        <td>${Math.round(r.confidence * 100)}%</td>
                    </tr>`).join("")}
                </table>
                </body></html>`;
            const blob = new Blob([html], { type: "text/html" });
            const url = URL.createObjectURL(blob);
            const w = window.open(url, "_blank");
            setTimeout(() => w?.print(), 800);
            notify("PDF export opened in new tab.");
        });
    }

    function renderDBSummary() {
        $("#db-summary").innerHTML = `
            <li>Scan records: ${state.scanResults.length}</li>
            <li>Learning episodes: ${state.learningHistory.length}</li>`;
    }

    function renderLearningHistory() {
        const el = $("#learning-history");
        el.innerHTML = state.learningHistory
            .map(h => `<div>${escapeHtml(h.ts)} — ${escapeHtml(h.action)}</div>`)
            .join("");
    }

    function renderSpark() {
        const svg = $("#spark");
        if (!svg) return;
        const values = state.learningHistory.map(() => Math.random());
        const points = values.map((v, i) => `${i * 25},${40 - v * 40}`).join(" ");
        svg.innerHTML = `<polyline fill="none" stroke="#60a5fa" stroke-width="2" points="${points}" />`;
    }

    // ==================== EVENT HANDLERS ====================
    function setupHandlers() {
        $("#apply-reco")?.addEventListener("click", () => {
            state.currentConfig = { ...state.aiRecommendation };
            $("#current-config-pre").textContent = JSON.stringify(state.currentConfig, null, 2);
            renderReport();
            renderReportsPanel();
            notify("AI recommendation applied.");
        });

        $("#reject-reco")?.addEventListener("click", () => {
            state.learningHistory.unshift({ ts: new Date().toISOString(), action: "reject" });
            renderLearningHistory();
            notify("Recommendation rejected.");
        });

        $("#severity-filter")?.addEventListener("change", renderFindings);
    }

    // ==================== NAVIGATION ====================
    function navButtons() {
        const panels = [
            "overview-cards",
            "config-panel",
            "decision-panel",
            "results-panel",
            "reports-panel",
            "logs-panel"
        ];

        const map = {
            overview: ["overview-cards", "config-panel", "decision-panel", "results-panel"],
            config: ["config-panel"],
            decision: ["decision-panel"],
            reports: ["reports-panel"],
            logs: ["logs-panel"]
        };

        document.querySelectorAll(".nav-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                document.querySelectorAll(".nav-btn").forEach(n => n.classList.remove("active"));
                btn.classList.add("active");
                const view = btn.dataset.view;
                panels.forEach(id => {
                    const el = document.getElementById(id);
                    if (el) el.style.display = map[view]?.includes(id) ? "" : "none";
                });
            });
        });
    }

    // ==================== THEME TOGGLE ====================
    function themeToggle() {
        const toggle = $("#theme-toggle");
        toggle?.addEventListener("click", () => {
            const body = document.body;
            body.classList.toggle("light");
            body.classList.toggle("dark");
            toggle.textContent = body.classList.contains("light") ? "🌙" : "☀️";
        });
    }

    // ==================== HELPERS ====================
    function downloadFile(data, filename, type) {
        const blob = new Blob([data], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, c => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
        }[c]));
    }

    function notify(msg) {
        const t = document.createElement("div");
        t.className = "toast";
        t.textContent = msg;
        document.getElementById("toaster").appendChild(t);
        setTimeout(() => t.remove(), 4000);
    }

    // ==================== SAMPLE DATA ====================
    function sampleFindings() {
        return [
            { url: "/login", vuln: "SQL Injection", severity: "High", confidence: 0.92, true_positive: true },
            { url: "/search", vuln: "Reflected XSS", severity: "Medium", confidence: 0.75, true_positive: false },
            { url: "/upload", vuln: "File Upload", severity: "Low", confidence: 0.55, true_positive: false }
        ];
    }

    function sampleLearning() {
        return [
            { ts: "2025-11-06T22:00:00Z", action: "apply" },
            { ts: "2025-11-06T21:20:00Z", action: "reject" }
        ];
    }

    window.addEventListener("DOMContentLoaded", init);
})();
