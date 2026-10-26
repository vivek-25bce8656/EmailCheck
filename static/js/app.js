/**
 * EmailCheck PRO - Interactive Client Engine
 * High-throughput email batch processing (100 default / 500 advanced limit),
 * live input statistics, interactive sample loader, inconclusive address retry,
 * real-time search & classification filter, dynamic metrics, sorting,
 * spreadsheet formula-injection safe CSV export, and persistent theme switcher.
 */

(function () {
    "use strict";

    const DEFAULT_BATCH_LIMIT = 100;
    const MAX_BATCH_LIMIT = 500;
    let currentBatchLimit = DEFAULT_BATCH_LIMIT;

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

    // Helper: Split tokens by newlines, commas, or semicolons
    function parseTokens(rawText) {
        if (!rawText || typeof rawText !== "string") return [];
        return rawText
            .split(/[\r\n,;]+/)
            .map(t => t.trim())
            .filter(t => t.length > 0);
    }

    // Input Workbench, Batch Sizing, Progress & Live Statistics
    function initWorkbench() {
        const textarea = document.getElementById("emailTextarea");
        const uniqueCountEl = document.getElementById("uniqueCount");
        const remainingSlotsEl = document.getElementById("remainingSlots");
        const duplicateWarningEl = document.getElementById("duplicateWarning");
        const duplicateCountNumEl = document.getElementById("duplicateCountNum");
        const maxCapacityLabel = document.getElementById("maxCapacityLabel");
        const capacityFill = document.getElementById("capacityFill");
        const btnSubmit = document.getElementById("btnSubmit");
        const submitBtnText = document.getElementById("submitBtnText");
        const checkForm = document.getElementById("checkForm");
        const btnSample = document.getElementById("btnSample");
        const btnClear = document.getElementById("btnClear");
        const clientAlert = document.getElementById("clientAlert");
        const clientAlertMessage = document.getElementById("clientAlertMessage");
        const progressBar = document.getElementById("processingProgressBar");
        const progressBarFill = document.getElementById("progressBarFill");
        const progressStatusText = document.getElementById("progressStatusText");
        const progressCountText = document.getElementById("progressCountText");

        // Batch Limit Controls
        const btnLimit100 = document.getElementById("btnLimit100");
        const btnLimit500 = document.getElementById("btnLimit500");
        const batchLimitInput = document.getElementById("batchLimitInput");
        const serverExportForm = document.getElementById("serverExportForm");

        if (!textarea) return;

        // Initialize current batch limit from hidden input
        if (batchLimitInput && batchLimitInput.value) {
            const parsed = parseInt(batchLimitInput.value, 10);
            if (parsed === 500) {
                currentBatchLimit = 500;
            } else {
                currentBatchLimit = 100;
            }
        }

        function setBatchLimit(newLimit) {
            currentBatchLimit = (newLimit === 500) ? 500 : 100;

            if (batchLimitInput) batchLimitInput.value = currentBatchLimit;
            if (maxCapacityLabel) maxCapacityLabel.textContent = currentBatchLimit;

            // Sync with export form
            if (serverExportForm) {
                let exportLimitInput = serverExportForm.querySelector('input[name="batch_limit"]');
                if (!exportLimitInput) {
                    exportLimitInput = document.createElement("input");
                    exportLimitInput.type = "hidden";
                    exportLimitInput.name = "batch_limit";
                    serverExportForm.appendChild(exportLimitInput);
                }
                exportLimitInput.value = currentBatchLimit;
            }

            // Update UI buttons state
            if (btnLimit100 && btnLimit500) {
                if (currentBatchLimit === 500) {
                    btnLimit100.classList.remove("active");
                    btnLimit100.setAttribute("aria-pressed", "false");
                    btnLimit500.classList.add("active");
                    btnLimit500.setAttribute("aria-pressed", "true");
                } else {
                    btnLimit500.classList.remove("active");
                    btnLimit500.setAttribute("aria-pressed", "false");
                    btnLimit100.classList.add("active");
                    btnLimit100.setAttribute("aria-pressed", "true");
                }
            }

            updateStats();
            showToast(`Batch limit set to ${currentBatchLimit} addresses`);
        }

        if (btnLimit100) {
            btnLimit100.addEventListener("click", () => setBatchLimit(100));
        }
        if (btnLimit500) {
            btnLimit500.addEventListener("click", () => setBatchLimit(500));
        }

        function hideAlert() {
            if (clientAlert) {
                clientAlert.style.display = "none";
                if (clientAlertMessage) clientAlertMessage.textContent = "";
            }
        }

        function showAlert(msg) {
            if (clientAlert && clientAlertMessage) {
                clientAlertMessage.textContent = msg;
                clientAlert.style.display = "flex";
            }
        }

        function updateStats() {
            const tokens = parseTokens(textarea.value);
            const totalTokens = tokens.length;
            const uniqueSet = new Set(tokens);
            const uniqueCount = uniqueSet.size;
            const duplicates = totalTokens - uniqueCount;
            const remaining = Math.max(0, currentBatchLimit - uniqueCount);

            if (uniqueCountEl) uniqueCountEl.textContent = uniqueCount;
            if (remainingSlotsEl) remainingSlotsEl.textContent = `${remaining} slots left`;
            if (maxCapacityLabel) maxCapacityLabel.textContent = currentBatchLimit;

            // Duplicate warning badge
            if (duplicateWarningEl) {
                if (duplicates > 0) {
                    if (duplicateCountNumEl) {
                        duplicateCountNumEl.textContent = duplicates;
                    }
                    duplicateWarningEl.style.display = "inline-flex";
                } else {
                    duplicateWarningEl.style.display = "none";
                }
            }

            // Capacity Fill Bar
            if (capacityFill) {
                const percent = Math.min(100, (uniqueCount / currentBatchLimit) * 100);
                capacityFill.style.width = `${percent}%`;
                capacityFill.classList.remove("near-limit", "at-limit");
                if (uniqueCount > currentBatchLimit) {
                    capacityFill.classList.add("at-limit");
                } else if (uniqueCount >= currentBatchLimit * 0.8) {
                    capacityFill.classList.add("near-limit");
                }
            }

            // Over-limit validation
            if (uniqueCount > currentBatchLimit) {
                if (uniqueCountEl && uniqueCountEl.parentElement) {
                    uniqueCountEl.parentElement.classList.add("badge-danger");
                }
                showAlert(`Selected limit exceeded: ${uniqueCount} addresses entered. Limit is ${currentBatchLimit} (switch to 500 mode or remove ${uniqueCount - currentBatchLimit} addresses).`);
                if (btnSubmit) {
                    btnSubmit.disabled = true;
                    btnSubmit.title = `Maximum ${currentBatchLimit} unique addresses allowed in this batch.`;
                }
            } else {
                if (uniqueCountEl && uniqueCountEl.parentElement) {
                    uniqueCountEl.parentElement.classList.remove("badge-danger");
                }
                hideAlert();
                if (btnSubmit) {
                    btnSubmit.disabled = false;
                    btnSubmit.title = "";
                }
            }
        }

        textarea.addEventListener("input", updateStats);
        updateStats(); // Initial execution

        // Load Sample Data demonstrating diverse scenarios
        if (btnSample) {
            btnSample.addEventListener("click", () => {
                const sampleBatch = [
                    "alex.developer@github.com",
                    "contact@cloudflare.com",
                    "engineering@google.com",
                    "infrastructure@microsoft.com",
                    "user@null-mx-test.example",
                    "dev.team@nonexistent-domain-xyz987654.test",
                    "invalid..consecutive.dots@syntax-error.org",
                    "missing-at-sign.com",
                    "user+subaddress@company.co.uk",
                    "support@cloud-provider-test.net"
                ];
                textarea.value = sampleBatch.join("\n");
                updateStats();
                showToast(`Loaded sample dataset (${sampleBatch.length} diverse addresses)`);
                textarea.focus();
            });
        }

        // Clear button
        if (btnClear) {
            btnClear.addEventListener("click", () => {
                textarea.value = "";
                hideAlert();
                updateStats();
                textarea.focus();
            });
        }

        // Form submit animation, progress simulation & client validation
        if (checkForm) {
            checkForm.addEventListener("submit", (e) => {
                const tokens = parseTokens(textarea.value);
                const uniqueSet = new Set(tokens);
                const count = uniqueSet.size;

                if (count === 0) {
                    e.preventDefault();
                    showAlert("Please enter at least one email address to assess.");
                    showToast("Please enter at least one email address.");
                    textarea.focus();
                    return;
                }
                if (count > currentBatchLimit) {
                    e.preventDefault();
                    showAlert(`Batch size of ${count} exceeds current limit of ${currentBatchLimit}. Select 500 Addresses or trim your list.`);
                    showToast(`Limit exceeded: Please submit up to ${currentBatchLimit} addresses.`);
                    return;
                }

                // Show active progress indicator
                if (progressBar) {
                    progressBar.style.display = "block";
                    if (progressCountText) {
                        progressCountText.textContent = `Assessing ${count} addresses...`;
                    }
                    if (progressBarFill) {
                        progressBarFill.style.width = "25%";
                        setTimeout(() => {
                            if (progressBarFill) progressBarFill.style.width = "65%";
                        }, 400);
                        setTimeout(() => {
                            if (progressBarFill) progressBarFill.style.width = "90%";
                        }, 1200);
                    }
                }

                if (btnSubmit) {
                    btnSubmit.disabled = true;
                    if (submitBtnText) submitBtnText.textContent = "Resolving Authoritative DNS...";
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
                        <span>Assessing DNS Records (${count})...</span>
                    `;
                }
            });
        }
    }

    // Results Table: Search, Filter, Live Synchronized Metrics, Sorting, Copy, CSV & Retry
    function initResultsTable() {
        const table = document.getElementById("resultsTable");
        const btnRetryUnknown = document.getElementById("btnRetryUnknown");
        const textarea = document.getElementById("emailTextarea");
        const checkForm = document.getElementById("checkForm");

        // Handle Retry for Inconclusive (Unknown) assessments
        if (btnRetryUnknown && textarea) {
            btnRetryUnknown.addEventListener("click", () => {
                const unknownRows = document.querySelectorAll('#resultsTable tbody tr[data-status="Unknown"]');
                const unknownEmails = [];
                unknownRows.forEach(r => {
                    const em = r.dataset.email;
                    if (em && !unknownEmails.includes(em)) {
                        unknownEmails.push(em);
                    }
                });

                if (unknownEmails.length === 0) {
                    showToast("No inconclusive addresses found to retry.");
                    return;
                }

                textarea.value = unknownEmails.join("\n");
                const countBadge = document.getElementById("uniqueCount");
                if (countBadge) countBadge.textContent = unknownEmails.length;

                // Scroll smoothly to workbench
                const workbench = document.getElementById("inputSectionTitle");
                if (workbench) workbench.scrollIntoView({ behavior: "smooth" });

                showToast(`Loaded ${unknownEmails.length} inconclusive address(es) for retry`);
                textarea.focus();
            });
        }

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
        const statLikelyDeliveredEl = document.getElementById("statLikelyDelivered");
        const statLikelyToBounceEl = document.getElementById("statLikelyToBounce");
        const statUnknownEl = document.getElementById("statUnknown");

        let currentSort = { col: -1, asc: true };

        function applyFilters() {
            const query = (searchInput ? searchInput.value.trim().toLowerCase() : "");
            const filter = (statusFilter ? statusFilter.value : "ALL");

            let visibleCount = 0;
            let visibleLikelyDelivered = 0;
            let visibleLikelyToBounce = 0;
            let visibleUnknown = 0;

            rows.forEach(row => {
                const email = row.dataset.email ? row.dataset.email.toLowerCase() : "";
                const domain = row.dataset.domain ? row.dataset.domain.toLowerCase() : "";
                const status = row.dataset.status ? row.dataset.status : "";
                const reason = row.dataset.reason ? row.dataset.reason.toLowerCase() : "";
                const syntax = row.dataset.syntax ? row.dataset.syntax.toLowerCase() : "";
                const dns = row.dataset.dns ? row.dataset.dns.toLowerCase() : "";
                const limitation = row.dataset.limitation ? row.dataset.limitation.toLowerCase() : "";

                const matchesQuery = (
                    !query ||
                    email.includes(query) ||
                    domain.includes(query) ||
                    status.toLowerCase().includes(query) ||
                    reason.includes(query) ||
                    syntax.includes(query) ||
                    dns.includes(query) ||
                    limitation.includes(query)
                );

                const matchesStatus = (filter === "ALL" || status === filter);

                if (matchesQuery && matchesStatus) {
                    row.style.display = "";
                    visibleCount++;

                    if (status === "Likely delivered") visibleLikelyDelivered++;
                    else if (status === "Likely to bounce") visibleLikelyToBounce++;
                    else if (status === "Unknown") visibleUnknown++;
                } else {
                    row.style.display = "none";
                }
            });

            // Update badge counter
            if (filteredCountBadge) {
                filteredCountBadge.textContent = `Showing ${visibleCount} of ${rows.length}`;
            }

            // Dynamically synchronize summary card counts with current filter
            if (statUniqueEl) statUniqueEl.textContent = visibleCount;
            if (statLikelyDeliveredEl) statLikelyDeliveredEl.textContent = visibleLikelyDelivered;
            if (statLikelyToBounceEl) statLikelyToBounceEl.textContent = visibleLikelyToBounce;
            if (statUnknownEl) statUnknownEl.textContent = visibleUnknown;

            // Handle empty state
            let emptyRow = tbody.querySelector(".empty-state-row");
            if (visibleCount === 0) {
                if (!emptyRow) {
                    emptyRow = document.createElement("tr");
                    emptyRow.className = "empty-state-row";
                    emptyRow.innerHTML = `<td colspan="8" class="empty-table-state" style="text-align: center; padding: 2.5rem 1rem; color: var(--text-muted); font-size: 0.9rem;">No matching email assessments found. Try refining your search query or filter.</td>`;
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
        const headers = [
            "Email Address",
            "Classification",
            "Short Explanation",
            "Syntax Validation",
            "DNS Mail-Routing Assessment",
            "Limitations & Uncertainty",
            "Domain",
            "Primary Mail Server"
        ];
        const visibleRows = rows.filter(r => r.style.display !== "none");

        if (visibleRows.length === 0) {
            showToast("No visible rows to export.");
            return;
        }

        const csvLines = [headers.join(",")];

        visibleRows.forEach(r => {
            const email = r.dataset.email || "";
            const status = r.dataset.status || "";
            const reason = r.dataset.reason || "";
            const syntax = r.dataset.syntax || "";
            const dns = r.dataset.dns || "";
            const limitation = r.dataset.limitation || "";
            const domain = r.dataset.domain || "";
            const mx = r.dataset.mx || "";

            const rowData = [email, status, reason, syntax, dns, limitation, domain, mx].map(sanitizeCsvCell);
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
