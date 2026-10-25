/**
 * EmailCheck - Interactive Client Engine
 * Live input stats, sample loader, search, filters, dynamic metrics, sorting, CSV export, theme toggle
 */

(function () {
    "use strict";

    const MAX_EMAILS = 20;

    // Theme Controller
    function initTheme() {
        const themeToggle = document.getElementById("themeToggle");
        const themeIcon = document.getElementById("themeIcon");
        const savedTheme = localStorage.getItem("emailcheck-theme");
        const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        const activeTheme = savedTheme || (prefersDark ? "dark" : "light");

        document.documentElement.setAttribute("data-theme", activeTheme);
        updateThemeIcon(activeTheme);

        if (themeToggle) {
            themeToggle.addEventListener("click", () => {
                const current = document.documentElement.getAttribute("data-theme") || "light";
                const next = current === "dark" ? "light" : "dark";
                document.documentElement.setAttribute("data-theme", next);
                localStorage.setItem("emailcheck-theme", next);
                updateThemeIcon(next);
            });
        }
    }

    function updateThemeIcon(theme) {
        const icon = document.getElementById("themeIcon");
        if (!icon) return;
        if (theme === "dark") {
            // Sun icon for switching to light
            icon.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>`;
            icon.setAttribute("aria-label", "Switch to light theme");
        } else {
            // Moon icon for switching to dark
            icon.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>`;
            icon.setAttribute("aria-label", "Switch to dark theme");
        }
    }

    // Toast Notification System
    function showToast(message, duration = 2500) {
        let toast = document.getElementById("appToast");
        if (!toast) {
            toast = document.createElement("div");
            toast.id = "appToast";
            toast.className = "toast";
            document.body.appendChild(toast);
        }
        toast.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> <span>${message}</span>`;
        toast.classList.add("show");
        clearTimeout(toast._timeout);
        toast._timeout = setTimeout(() => {
            toast.classList.remove("show");
        }, duration);
    }

    // Input Workbench & Live Statistics
    function initWorkbench() {
        const textarea = document.getElementById("emailTextarea");
        const uniqueCountEl = document.getElementById("uniqueCount");
        const remainingSlotsEl = document.getElementById("remainingSlots");
        const duplicateWarningEl = document.getElementById("duplicateWarning");
        const capacityFill = document.getElementById("capacityFill");
        const btnSubmit = document.getElementById("btnSubmit");
        const checkForm = document.getElementById("checkForm");
        const btnSample = document.getElementById("btnSample");
        const btnClear = document.getElementById("btnClear");

        if (!textarea) return;

        function updateStats() {
            const rawText = textarea.value;
            const lines = rawText.split("\n").map(l => l.trim()).filter(l => l.length > 0);
            const totalLines = lines.length;
            const uniqueSet = new Set(lines);
            const uniqueCount = uniqueSet.size;
            const duplicates = totalLines - uniqueCount;
            const remaining = Math.max(0, MAX_EMAILS - uniqueCount);

            if (uniqueCountEl) uniqueCountEl.textContent = uniqueCount;
            if (remainingSlotsEl) remainingSlotsEl.textContent = `${remaining} slots left`;

            // Duplicate warning badge
            if (duplicateWarningEl) {
                if (duplicates > 0) {
                    duplicateWarningEl.textContent = `${duplicates} duplicate${duplicates > 1 ? "s" : ""} filtered`;
                    duplicateWarningEl.style.display = "inline-flex";
                } else {
                    duplicateWarningEl.style.display = "none";
                }
            }

            // Capacity Fill Bar
            if (capacityFill) {
                const percent = Math.min(100, (uniqueCount / MAX_EMAILS) * 100);
                capacityFill.style.width = `${percent}%`;
                capacityFill.classList.remove("near-limit", "at-limit");
                if (uniqueCount > MAX_EMAILS) {
                    capacityFill.classList.add("at-limit");
                } else if (uniqueCount >= MAX_EMAILS * 0.8) {
                    capacityFill.classList.add("near-limit");
                }
            }

            // Over-limit validation
            if (uniqueCount > MAX_EMAILS) {
                if (uniqueCountEl && uniqueCountEl.parentElement) {
                    uniqueCountEl.parentElement.classList.add("badge-danger");
                }
                if (btnSubmit) {
                    btnSubmit.disabled = true;
                    btnSubmit.title = `Maximum ${MAX_EMAILS} unique addresses allowed.`;
                }
            } else {
                if (uniqueCountEl && uniqueCountEl.parentElement) {
                    uniqueCountEl.parentElement.classList.remove("badge-danger");
                }
                if (btnSubmit) {
                    btnSubmit.disabled = false;
                    btnSubmit.title = "";
                }
            }
        }

        textarea.addEventListener("input", updateStats);
        updateStats(); // Initial execution

        // Load Sample Data
        if (btnSample) {
            btnSample.addEventListener("click", () => {
                const sampleBatch = [
                    "alex.developer@github.com",
                    "contact@cloudflare.com",
                    "engineering@google.com",
                    "hello@nonexistent-domain-xyz987654.test",
                    "invalid..dots@syntax-error.org",
                    "missing-at-sign.com"
                ];
                textarea.value = sampleBatch.join("\n");
                updateStats();
                showToast("Loaded sample dataset (6 addresses)");
                textarea.focus();
            });
        }

        // Clear button
        if (btnClear) {
            btnClear.addEventListener("click", () => {
                textarea.value = "";
                updateStats();
                textarea.focus();
            });
        }

        // Form submit spinner & duplicate click prevention
        if (checkForm) {
            checkForm.addEventListener("submit", (e) => {
                const lines = textarea.value.split("\n").map(l => l.trim()).filter(l => l.length > 0);
                const uniqueSet = new Set(lines);
                if (uniqueSet.size === 0) {
                    e.preventDefault();
                    showToast("Please enter at least one email address.");
                    textarea.focus();
                    return;
                }
                if (uniqueSet.size > MAX_EMAILS) {
                    e.preventDefault();
                    showToast(`Limit exceeded: Please enter up to ${MAX_EMAILS} addresses.`);
                    return;
                }

                if (btnSubmit) {
                    btnSubmit.disabled = true;
                    btnSubmit.innerHTML = `
                        <svg class="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="12" y1="2" x2="12" y2="6"/>
                            <line x1="12" y1="18" x2="12" y2="22"/>
                            <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/>
                            <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/>
                            <line x1="2" y1="12" x2="6" y2="12"/>
                            <line x1="18" y1="12" x2="22" y2="12"/>
                            <line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/>
                            <line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/>
                        </svg>
                        <span>Assessing DNS Records...</span>
                    `;
                }
            });
        }
    }

    // Results Table: Search, Filter, Dynamic Counts, Sort, Copy, CSV
    function initResultsTable() {
        const table = document.getElementById("resultsTable");
        if (!table) return;

        const tbody = table.querySelector("tbody");
        const rows = Array.from(tbody.querySelectorAll("tr:not(.empty-state-row)"));
        const searchInput = document.getElementById("tableSearch");
        const statusFilter = document.getElementById("statusFilter");
        const filteredCountBadge = document.getElementById("filteredCountBadge");
        const btnCopyFiltered = document.getElementById("btnCopyFiltered");
        const btnDownloadCsv = document.getElementById("btnDownloadCsv");

        // Stat Card Elements for live metric synchronization
        const statUniqueEl = document.getElementById("statUniqueAssessed");
        const statMailConfigEl = document.getElementById("statMailConfig");
        const statNoMxEl = document.getElementById("statNoMx");
        const statDomainNotFoundEl = document.getElementById("statDomainNotFound");
        const statInvalidFormatEl = document.getElementById("statInvalidFormat");

        let currentSort = { col: -1, asc: true };

        function applyFilters() {
            const query = (searchInput ? searchInput.value.trim().toLowerCase() : "");
            const filter = (statusFilter ? statusFilter.value : "ALL");

            let visibleCount = 0;
            let visibleMailConfig = 0;
            let visibleNoMx = 0;
            let visibleDomainNotFound = 0;
            let visibleInvalidFormat = 0;

            rows.forEach(row => {
                const email = row.dataset.email ? row.dataset.email.toLowerCase() : "";
                const domain = row.dataset.domain ? row.dataset.domain.toLowerCase() : "";
                const status = row.dataset.status ? row.dataset.status : "";
                const reason = row.dataset.reason ? row.dataset.reason.toLowerCase() : "";

                const matchesQuery = !query || email.includes(query) || domain.includes(query) || reason.includes(query);
                const matchesStatus = filter === "ALL" || status === filter;

                if (matchesQuery && matchesStatus) {
                    row.style.display = "";
                    visibleCount++;

                    // Count metrics for visible rows
                    if (status === "Mail configuration detected") visibleMailConfig++;
                    else if (status === "No MX record detected" || status === "Null MX - Does not accept email") visibleNoMx++;
                    else if (status === "Domain not found") visibleDomainNotFound++;
                    else if (status === "Invalid format") visibleInvalidFormat++;
                } else {
                    row.style.display = "none";
                }
            });

            // Update badge counter
            if (filteredCountBadge) {
                filteredCountBadge.textContent = `Showing ${visibleCount} of ${rows.length}`;
            }

            // Dynamically synchronize summary card counts
            if (statUniqueEl) statUniqueEl.textContent = visibleCount;
            if (statMailConfigEl) statMailConfigEl.textContent = visibleMailConfig;
            if (statNoMxEl) statNoMxEl.textContent = visibleNoMx;
            if (statDomainNotFoundEl) statDomainNotFoundEl.textContent = visibleDomainNotFound;
            if (statInvalidFormatEl) statInvalidFormatEl.textContent = visibleInvalidFormat;

            // Handle empty state
            let emptyRow = tbody.querySelector(".empty-state-row");
            if (visibleCount === 0) {
                if (!emptyRow) {
                    emptyRow = document.createElement("tr");
                    emptyRow.className = "empty-state-row";
                    emptyRow.innerHTML = `<td colspan="6" class="empty-table-state">No matching email assessments found. Try refining your search or filter.</td>`;
                    tbody.appendChild(emptyRow);
                }
                emptyRow.style.display = "";
            } else if (emptyRow) {
                emptyRow.style.display = "none";
            }
        }

        if (searchInput) searchInput.addEventListener("input", applyFilters);
        if (statusFilter) statusFilter.addEventListener("change", applyFilters);

        // Column Sorting with clean ASCII escapes
        const headers = table.querySelectorAll("thead th.sortable");
        headers.forEach((th, index) => {
            th.addEventListener("click", () => {
                const colIdx = parseInt(th.dataset.col || index, 10);
                const isAsc = currentSort.col === colIdx ? !currentSort.asc : true;
                currentSort = { col: colIdx, asc: isAsc };

                // Clear other header sort indicators
                headers.forEach(h => {
                    const arrow = h.querySelector(".sort-arrow");
                    if (arrow) arrow.textContent = "\u2195"; // ↕
                });
                const arrow = th.querySelector(".sort-arrow");
                if (arrow) arrow.textContent = isAsc ? "\u2191" : "\u2193"; // ↑ : ↓

                rows.sort((a, b) => {
                    let aVal = a.cells[colIdx] ? a.cells[colIdx].innerText.trim() : "";
                    let bVal = b.cells[colIdx] ? b.cells[colIdx].innerText.trim() : "";
                    return isAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
                });

                rows.forEach(r => tbody.appendChild(r));
                applyFilters();
            });
        });

        // Copy Individual Email Address
        table.addEventListener("click", (e) => {
            const copyBtn = e.target.closest(".btn-copy");
            if (copyBtn) {
                const email = copyBtn.dataset.copy;
                if (email) {
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(email).then(() => {
                            showToast(`Copied ${email}`);
                        }).catch(() => {
                            fallbackCopy(email);
                        });
                    } else {
                        fallbackCopy(email);
                    }
                }
            }
        });

        // Copy Filtered Results
        if (btnCopyFiltered) {
            btnCopyFiltered.addEventListener("click", () => {
                const visibleEmails = rows
                    .filter(r => r.style.display !== "none")
                    .map(r => r.dataset.email)
                    .filter(Boolean);

                if (visibleEmails.length === 0) {
                    showToast("No visible emails to copy.");
                    return;
                }

                const textToCopy = visibleEmails.join("\n");
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(textToCopy).then(() => {
                        showToast(`Copied ${visibleEmails.length} email address${visibleEmails.length > 1 ? "es" : ""}`);
                    }).catch(() => {
                        fallbackCopy(textToCopy);
                    });
                } else {
                    fallbackCopy(textToCopy);
                }
            });
        }

        // CSV Export with Formula Injection Shielding
        if (btnDownloadCsv) {
            btnDownloadCsv.addEventListener("click", (e) => {
                e.preventDefault();
                exportResultsToCsv(rows);
            });
        }
    }

    function fallbackCopy(text) {
        const temp = document.createElement("textarea");
        temp.value = text;
        temp.style.position = "fixed";
        temp.style.left = "-9999px";
        temp.style.top = "-9999px";
        document.body.appendChild(temp);
        temp.focus();
        temp.select();
        try {
            document.execCommand("copy");
            showToast("Copied to clipboard!");
        } catch (err) {
            showToast("Clipboard access denied. Please copy manually.");
        }
        document.body.removeChild(temp);
    }

    function sanitizeCsvCell(field) {
        if (field === null || field === undefined) return '""';
        let rawStr = String(field);
        let trimmed = rawStr.replace(/^[ ]+/, "");
        // Neutralize spreadsheet formula injection for =, +, -, @, \t, \r
        if (/^[=+@\-\t\r]/.test(trimmed)) {
            rawStr = "'" + rawStr;
        }
        let escaped = rawStr.replace(/"/g, '""');
        return `"${escaped}"`;
    }

    function exportResultsToCsv(rows) {
        const headers = ["Email Address", "Assessment Status", "Domain", "Reason / Evidence", "Mail Servers"];
        const visibleRows = rows.filter(r => r.style.display !== "none");

        if (visibleRows.length === 0) {
            showToast("No visible rows to export.");
            return;
        }

        const csvLines = [headers.join(",")];

        visibleRows.forEach(r => {
            const email = r.dataset.email || "";
            const status = r.dataset.status || "";
            const domain = r.dataset.domain || "";
            const reason = r.dataset.reason || "";
            const mx = r.dataset.mx || "";

            const rowData = [email, status, domain, reason, mx].map(sanitizeCsvCell);
            csvLines.push(rowData.join(","));
        });

        const csvContent = "\ufeff" + csvLines.join("\r\n");
        const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
        const now = new Date();
        const dateStr = now.toISOString().slice(0, 10);
        const fileName = `emailcheck_results_${dateStr}.csv`;

        const link = document.createElement("a");
        const url = URL.createObjectURL(blob);
        link.setAttribute("href", url);
        link.setAttribute("download", fileName);
        link.style.visibility = "hidden";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(url), 1000);

        showToast(`Exported ${visibleRows.length} results to ${fileName}`);
    }

    // Initialize on DOM ready
    document.addEventListener("DOMContentLoaded", () => {
        initTheme();
        initWorkbench();
        initResultsTable();
    });
})();
