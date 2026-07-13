/* ═══════════════════════════════════════════════════════════════════════════
   Social URL Status Checker — Client-Side Logic (v2.0)
   ═══════════════════════════════════════════════════════════════════════════ */

(() => {
    "use strict";

    // ── DOM references ───────────────────────────────────────────────────
    const urlInput      = document.getElementById("urlInput");
    const urlCount      = document.getElementById("urlCount");
    const checkBtn      = document.getElementById("checkBtn");
    const btnText       = document.getElementById("checkBtnText");
    const stopBtn       = document.getElementById("stopBtn");
    const refreshBtn    = document.getElementById("refreshBtn");
    const clearBtn      = document.getElementById("clearBtn");
    const progressWrap  = document.getElementById("progressWrapper");
    const progressFill  = document.getElementById("progressFill");
    const progressText  = document.getElementById("progressText");
    const statsSection  = document.getElementById("statsSection");
    const resultsSection = document.getElementById("resultsSection");
    const resultsBody   = document.getElementById("resultsBody");
    const exportBtn     = document.getElementById("exportBtn");
    const exportZipBtn  = document.getElementById("exportZipBtn");
    const copyBtn       = document.getElementById("copyBtn");
    const copyIcon      = document.getElementById("copyIcon");
    const copySuccessIcon = document.getElementById("copySuccessIcon");
    const copyText      = document.getElementById("copyText");
    const filtersEl     = document.getElementById("filters");
    const platformFiltersEl = document.getElementById("platformFilters");

    const statEls = {
        total:     document.getElementById("statTotal"),
        pending:   document.getElementById("statPending"),
        eta:       document.getElementById("statEta"),
        active:    document.getElementById("statActive"),
        taken_down: document.getElementById("statDown"),
        uncertain:  document.getElementById("statUncertain"),
    };

    // ── State ────────────────────────────────────────────────────────────
    let allResults = [];
    let currentFilter = "all";
    let currentPlatformFilter = "all";
    let rowIndex = 0;
    let startTime = 0;

    // ── Platform display config ──────────────────────────────────────────
    const PLATFORM_ICONS = {
        telegram:    '<i class="fab fa-telegram" style="color: #0088cc;"></i>',
        youtube:     '<i class="fab fa-youtube" style="color: #FF0000;"></i>',
        facebook:    '<i class="fab fa-facebook" style="color: #1877F2;"></i>',
        instagram:   '<i class="fab fa-instagram" style="color: #E1306C;"></i>',
        x:           '<i class="fab fa-twitter"></i>',
        linkedin:    '<i class="fab fa-linkedin" style="color: #0077b5;"></i>',
        app_store:   '<i class="fab fa-google-play" style="color: #3DDC84;"></i>',
        generic:     '<i class="fas fa-globe"></i>',
    };

    const STATUS_LABELS = {
        active:     "Active",
        taken_down: "Taken Down",
        uncertain:  "Uncertain",
        error:      "Error",
    };

    // ── Input & URL normalization ────────────────────────────────────────
    function parseUrls(text) {
        const rawLines = text.split(/\r?\n/).map(l => l.trim());
        const merged = [];
        
        for (let line of rawLines) {
            if (!line) continue;
            
            const hasScheme = /^https?\s*:\/\//i.test(line);
            
            if (merged.length === 0 || hasScheme) {
                merged.push(line);
                continue;
            }
            
            const prev = merged[merged.length - 1];
            
            // Special continuation characters (starts with / ? & = - _ .)
            const startsWithSpecial = /^[/?&=\-_.]/.test(line);
            const prevEndsWithSlash = /\/$/.test(prev);
            
            // Looks like a brand new URL (bare domain) e.g. adanirealtyworli.com
            const isNewURL = /^www\./i.test(line) || /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/.test(line);
            
            if (startsWithSpecial) {
                merged[merged.length - 1] += line;
            } else if (prevEndsWithSlash && !/^www\./i.test(line) && !isNewURL) {
                merged[merged.length - 1] += line;
            } else if (isNewURL) {
                merged.push(line);
            } else {
                // If it doesn't look like a new URL, assume it's a broken fragment of the previous one
                merged[merged.length - 1] += line;
            }
        }
        
        const uniqueUrls = new Set();
        const finalUrls = [];
        for (let u of merged) {
            if (!u) continue;
            // Basic frontend normalization for deduplication
            let norm = u.replace(/^(https?)\s*:\s*\/\//i, "$1://");
            if (!/^https?:\/\//i.test(norm) && norm.indexOf('.') !== -1) {
                norm = "https://" + norm;
            }
            if (!uniqueUrls.has(norm)) {
                uniqueUrls.add(norm);
                finalUrls.push(u); // Keep original text
            }
        }
        
        return finalUrls;
    }

    function updateUrlCount() {
        const n = parseUrls(urlInput.value).length;
        urlCount.textContent = `${n} URL${n !== 1 ? "s" : ""}`;
    }

    urlInput.addEventListener("input", updateUrlCount);

    // ── Clear & Refresh ──────────────────────────────────────────────────
    clearBtn.addEventListener("click", () => {
        urlInput.value = "";
        updateUrlCount();
        resetUI();
    });
    
    refreshBtn.addEventListener("click", () => {
        if (currentAbortController) {
            currentAbortController.abort();
        }
        urlInput.value = "";
        updateUrlCount();
        resetUI();
    });

    function resetUI() {
        allResults = [];
        rowIndex = 0;
        currentFilter = "all";
        currentPlatformFilter = "all";

        progressWrap.style.display = "none";
        statsSection.style.display = "none";
        resultsSection.style.display = "none";
        resultsBody.innerHTML = "";
        progressFill.style.width = "0%";
        exportBtn.style.display = "none";
        exportZipBtn.style.display = "none";
        copyBtn.style.display = "none";

        Object.values(statEls).forEach(el => el.textContent = "0");
        setActiveFilter("all");
        setActivePlatformFilter("all");
    }

    let currentAbortController = null;
    let etaInterval = null;
    let currentProgress = { completed: 0, total: 0 };

    checkBtn.addEventListener("click", () => {
        const urls = parseUrls(urlInput.value);
        if (urls.length === 0) { urlInput.focus(); return; }
        startCheck(urls);
    });

    stopBtn.addEventListener("click", () => {
        if (currentAbortController) {
            currentAbortController.abort();
            progressText.textContent = "Stopped by user.";
            checkBtn.style.display = "inline-flex";
            stopBtn.style.display = "none";
            if (etaInterval) clearInterval(etaInterval);
        }
    });

    let lastResultTime = 0;

    function updateETA() {
        if (currentProgress.completed > 0 && currentProgress.completed < currentProgress.total) {
            const elapsed = Date.now() - startTime;
            const msPerUrlAvg = elapsed / currentProgress.completed;
            
            // Make ETA highly responsive: if it stalls, increase the ETA dynamically
            const currentStallTime = Date.now() - lastResultTime;
            const effectiveMsPerUrl = msPerUrlAvg + (currentStallTime * 0.5);
            
            const etaSec = Math.max(0, Math.floor((effectiveMsPerUrl * (currentProgress.total - currentProgress.completed)) / 1000));
            statEls.eta.textContent = etaSec > 60 ? `${Math.floor(etaSec / 60)}m ${etaSec % 60}s` : `${etaSec}s`;
        }
    }

    async function startCheck(urls) {
        resetUI();
        currentProgress = { completed: 0, total: urls.length };

        // Show progress & stats
        progressWrap.style.display = "block";
        progressFill.style.width = "0%";
        progressText.textContent = `Checking ${urls.length} URLs...`;
        statsSection.style.display = "grid";
        resultsSection.style.display = "block";

        statEls.total.textContent = urls.length;
        statEls.eta.textContent = "--";

        checkBtn.style.display = "none";
        stopBtn.style.display = "inline-flex";
        startTime = Date.now();
        lastResultTime = startTime;
        
        if (etaInterval) clearInterval(etaInterval);
        etaInterval = setInterval(updateETA, 1000);

        currentAbortController = new AbortController();

        try {
            await streamCheck(urls, currentAbortController.signal);
        } catch (err) {
            if (err.name === "AbortError") {
                console.log("Check aborted by user");
            } else {
                console.error("Check failed:", err);
                progressText.textContent = `Error: ${err.message}`;
            }
        } finally {
            checkBtn.style.display = "inline-flex";
            stopBtn.style.display = "none";
            btnText.textContent = "Run";
            currentAbortController = null;
            if (etaInterval) clearInterval(etaInterval);
        }
    }

    // ── SSE streaming ────────────────────────────────────────────────────
    async function streamCheck(urls, signal) {
        const response = await fetch("/api/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ urls }),
            signal: signal,
        });

        if (!response.ok) throw new Error(`Server returned ${response.status}`);

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const parts = buffer.split("\n\n");
            buffer = parts.pop();

            for (const part of parts) {
                for (const line of part.split("\n")) {
                    if (line.startsWith("data: ")) {
                        try { handleEvent(JSON.parse(line.slice(6))); } catch (_) {}
                    }
                }
            }
        }

        // Flush remaining
        if (buffer.trim()) {
            for (const line of buffer.split("\n")) {
                if (line.startsWith("data: ")) {
                    try { handleEvent(JSON.parse(line.slice(6))); } catch (_) {}
                }
            }
        }
    }

    // ── Event handler ────────────────────────────────────────────────────
    function handleEvent(data) {
        if (data.done) {
            const s = data.summary;
            progressFill.style.width = "100%";
            progressText.textContent = `Completed — ${s.total} URLs checked`;
            statEls.eta.textContent = "0s";
            statEls.pending.textContent = "0";
            statEls.active.textContent = s.active;
            statEls.taken_down.textContent = s.taken_down;
            statEls.uncertain.textContent = s.uncertain || 0;
            exportBtn.style.display = "inline-flex";
            exportZipBtn.style.display = "inline-flex";
            copyBtn.style.display = "inline-flex";
            checkBtn.style.display = "inline-flex";
            stopBtn.style.display = "none";
            return;
        }

        // Individual result
        if (data.status !== "error") {
            allResults.push(data);
            appendRow(data);
            
            // Show export/copy buttons immediately so user doesn't have to wait for the whole run to finish
            if (allResults.length > 0) {
                exportBtn.style.display = "inline-flex";
                exportZipBtn.style.display = "inline-flex";
                copyBtn.style.display = "inline-flex";
            }
        }

        // Progress
        const p = data.progress;
        if (p) {
            if (currentProgress.completed !== p.completed) {
                lastResultTime = Date.now();
            }
            currentProgress = p; // Update global state for ETA interval
            
            // Ensure UI total always perfectly matches backend's deduplicated total
            if (parseInt(statEls.total.textContent) !== p.total) {
                statEls.total.textContent = p.total;
                progressText.textContent = `Checking ${p.total} URLs...`; // Update text if it just started
            }
            
            const pct = Math.round((p.completed / p.total) * 100);
            progressFill.style.width = `${pct}%`;

            const elapsed = Date.now() - startTime;
            const msPerUrl = elapsed / p.completed;
            const etaSec = Math.max(0, Math.floor((msPerUrl * (p.total - p.completed)) / 1000));
            statEls.eta.textContent = etaSec > 60 ? `${Math.floor(etaSec / 60)}m ${etaSec % 60}s` : `${etaSec}s`;

            progressText.textContent = `Checking... ${p.completed}/${p.total} (${pct}%)`;
        }

        // Running stats
        const total = parseInt(statEls.total.textContent) || 0;
        const counts = { active: 0, taken_down: 0, uncertain: 0 };
        for (const r of allResults) counts[r.status] = (counts[r.status] || 0) + 1;
        // Pending should be Total - (Total results processed including errors). We can derive it from p.completed
        if (p) {
            statEls.pending.textContent = Math.max(0, p.total - p.completed);
        } else {
            statEls.pending.textContent = Math.max(0, total - allResults.length); // fallback
        }
        statEls.active.textContent = counts.active;
        statEls.taken_down.textContent = counts.taken_down;
        statEls.uncertain.textContent = counts.uncertain;
    }

    // ── Row rendering ────────────────────────────────────────────────────
    function appendRow(data) {
        rowIndex++;
        const tr = document.createElement("tr");
        tr.dataset.status = data.status;
        tr.dataset.platform = data.platform;
        tr.style.animationDelay = `${Math.min(rowIndex * 0.02, 0.5)}s`;

        const matchStatus = currentFilter === "all" || data.status === currentFilter;
        const matchPlatform = currentPlatformFilter === "all" || data.platform === currentPlatformFilter;
        if (!matchStatus || !matchPlatform) tr.classList.add("hidden-row");

        const httpClass = getHttpClass(data.http_code);
        const icon = PLATFORM_ICONS[data.platform] || PLATFORM_ICONS.generic;
        let platName = data.platform || "generic";
        if (platName === "x") platName = "X (Twitter)";
        else if (platName === "app_store") platName = "Apps";
        else platName = platName.split('_').map(cap).join(' ');

        tr.innerHTML = `
            <td class="col-num" style="text-align:center;color:var(--text-muted)">${rowIndex}</td>
            <td class="col-url"><a href="${esc(data.url)}" target="_blank" rel="noopener noreferrer" class="url-cell" title="${esc(data.url)}">${truncUrl(data.url, 65)}</a></td>
            <td class="col-platform"><span class="platform-badge">${icon} ${cap(platName)}</span></td>
            <td class="col-status"><span class="status-pill status-pill--${data.status}"><span class="status-dot"></span>${STATUS_LABELS[data.status] || data.status}</span></td>
            <td class="col-reason"><span class="reason-text">${esc(data.reason || "—")}</span></td>
            <td class="col-http"><span class="http-code ${httpClass}">${data.http_code ?? "—"}</span></td>
        `;
        resultsBody.appendChild(tr);
    }

    function getHttpClass(code) {
        if (code == null) return "http-code--na";
        if (code >= 200 && code < 300) return "http-code--ok";
        if (code >= 300 && code < 400) return "http-code--warn";
        return "http-code--error";
    }

    function truncUrl(url, max) {
        return url.length <= max ? esc(url) : esc(url.slice(0, max)) + "…";
    }

    function esc(str) {
        const d = document.createElement("div");
        d.textContent = str;
        return d.innerHTML;
    }

    function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

    // ── Filters ──────────────────────────────────────────────────────────
    filtersEl.addEventListener("click", (e) => {
        const pill = e.target.closest(".filter-pill");
        if (!pill) return;
        currentFilter = pill.dataset.filter;
        setActiveFilter(currentFilter);
        applyFilters();
    });

    platformFiltersEl.addEventListener("click", (e) => {
        const pill = e.target.closest(".filter-pill");
        if (!pill) return;
        currentPlatformFilter = pill.dataset.platform;
        setActivePlatformFilter(currentPlatformFilter);
        applyFilters();
    });

    function setActiveFilter(f) {
        filtersEl.querySelectorAll(".filter-pill").forEach(p =>
            p.classList.toggle("filter-pill--active-filter", p.dataset.filter === f));
    }

    function setActivePlatformFilter(p) {
        platformFiltersEl.querySelectorAll(".filter-pill").forEach(pill =>
            pill.classList.toggle("filter-pill--active-filter", pill.dataset.platform === p));
    }

    function applyFilters() {
        resultsBody.querySelectorAll("tr").forEach(row => {
            const ok = (currentFilter === "all" || row.dataset.status === currentFilter) &&
                       (currentPlatformFilter === "all" || row.dataset.platform === currentPlatformFilter);
            row.classList.toggle("hidden-row", !ok);
        });
    }

    // ── Export Logic (Instant Inline Dropdown) ─────────────────────────────
    const exportModal = document.getElementById("exportModal");
    const closeExportModalBtn = document.getElementById("closeExportModalBtn");
    const cancelExportBtn = document.getElementById("cancelExportBtn");
    const confirmExportBtn = document.getElementById("confirmExportBtn");
    const exportFilterSelect = document.getElementById("exportFilterSelect");
    const exportModalMsg = document.getElementById("exportModalMsg");

    let currentExportType = "";

    function openExportModal(type) {
        if (allResults.length === 0) return;
        currentExportType = type;
        exportModalMsg.textContent = "";
        exportFilterSelect.value = currentFilter;
        exportModal.style.display = "flex";
    }

    function closeExportModal() {
        exportModal.style.display = "none";
    }

    exportBtn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        openExportModal("csv");
    });

    exportZipBtn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        openExportModal("zip");
    });

    closeExportModalBtn.addEventListener("click", (e) => {
        e.preventDefault();
        closeExportModal();
    });
    cancelExportBtn.addEventListener("click", (e) => {
        e.preventDefault();
        closeExportModal();
    });
    exportModal.addEventListener("click", (e) => {
        if (e.target === exportModal) closeExportModal();
    });

    confirmExportBtn.addEventListener("click", async (e) => {
        e.preventDefault();
        const filterVal = exportFilterSelect.value;
        const filtered = allResults.filter(r => filterVal === "all" || r.status === filterVal);

        if (filtered.length === 0) {
            exportModalMsg.textContent = "No results match the selected status filter.";
            exportModalMsg.style.color = "var(--danger)";
            return;
        }

        closeExportModal();

        if (currentExportType === "csv") {
            const headers = ["#", "URL", "Platform", "Status", "Reason", "HTTP Code"];
            const rows = filtered.map((r, i) => [
                i + 1,
                `"${r.url.replace(/"/g, '""')}"`,
                r.platform || "generic",
                r.status,
                `"${(r.reason || "").replace(/"/g, '""')}"`,
                r.http_code ?? "",
            ]);

            const csv = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
            const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");

            a.href = url;
            a.download = `url-status-report-${ts}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        } else if (currentExportType === "zip") {
            exportZipBtn.disabled = true;
            const orig = exportZipBtn.innerHTML;
            exportZipBtn.innerHTML = "Exporting...";

            try {
                const response = await fetch("/api/export", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ results: filtered }),
                });
                if (!response.ok) throw new Error("Export failed");

                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");
                a.href = url;
                a.download = `url-report-${ts}.zip`;
                a.click();
                URL.revokeObjectURL(url);
            } catch (e) {
                console.error("ZIP export error:", e);
                alert("Failed to export ZIP");
            } finally {
                exportZipBtn.disabled = false;
                exportZipBtn.innerHTML = orig;
            }
        }
    });

    // ── Keyboard shortcut: Ctrl+Enter ────────────────────────────────────
    urlInput.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            checkBtn.click();
        }
    });

    // ── Init ─────────────────────────────────────────────────────────────
    updateUrlCount();

    // ── Copy functionality ───────────────────────────────────────────────
    copyBtn.addEventListener("click", async () => {
        const filtered = allResults.filter(r => {
            const matchStatus = currentFilter === "all" || r.status === currentFilter;
            const matchPlatform = currentPlatformFilter === "all" || r.platform === currentPlatformFilter;
            return matchStatus && matchPlatform;
        });

        if (filtered.length === 0) return;

        const urls = filtered.map(r => r.url).join("\n");
        try {
            await navigator.clipboard.writeText(urls);
            
            copyIcon.style.display = "none";
            copySuccessIcon.style.display = "inline-block";
            copyText.textContent = `Copied ${filtered.length}`;
            copyBtn.style.color = "var(--success)";
            copyBtn.style.borderColor = "var(--success)";
            copyBtn.style.transform = "scale(1.05)";

            setTimeout(() => {
                copyIcon.style.display = "inline-block";
                copySuccessIcon.style.display = "none";
                copyText.textContent = "Copy URLs";
                copyBtn.style.color = "";
                copyBtn.style.borderColor = "";
                copyBtn.style.transform = "scale(1)";
            }, 2000);
        } catch (err) {
            console.error("Failed to copy", err);
            alert("Failed to copy to clipboard.");
        }
    });

    // ── Cookie Manager Modal ─────────────────────────────────────────────
    const settingsBtn = document.getElementById("settingsBtn");
    const cookieModal = document.getElementById("cookieModal");
    const closeModalBtn = document.getElementById("closeModalBtn");
    const saveCookiesBtn = document.getElementById("saveCookiesBtn");
    const cookieSaveMsg = document.getElementById("cookieSaveMsg");

    const cookieTextareas = {
        facebook: document.getElementById("cookie-facebook"),
        linkedin: document.getElementById("cookie-linkedin"),
        instagram: document.getElementById("cookie-instagram"),
        x: document.getElementById("cookie-x")
    };

    async function loadCookies() {
        try {
            const res = await fetch("/api/cookies");
            if (res.ok) {
                const data = await res.json();
                for (const [platform, txtArea] of Object.entries(cookieTextareas)) {
                    const arr = data[platform];
                    txtArea.value = (arr && arr.length > 0) ? JSON.stringify(arr, null, 2) : "";
                }
            }
        } catch (e) {
            console.error("Failed to load cookies", e);
        }
    }

    settingsBtn.addEventListener("click", () => {
        cookieSaveMsg.textContent = "";
        loadCookies();
        cookieModal.style.display = "flex";
    });

    closeModalBtn.addEventListener("click", () => {
        cookieModal.style.display = "none";
    });

    cookieModal.addEventListener("click", (e) => {
        if (e.target === cookieModal) cookieModal.style.display = "none";
    });

    saveCookiesBtn.addEventListener("click", async () => {
        const cookies = {};
        let hasError = false;

        for (const [platform, txtArea] of Object.entries(cookieTextareas)) {
            const val = txtArea.value.trim();
            if (!val) {
                cookies[platform] = [];
                continue;
            }
            try {
                const parsed = JSON.parse(val);
                if (!Array.isArray(parsed)) throw new Error("Must be JSON array");
                cookies[platform] = parsed;
            } catch (e) {
                hasError = true;
                txtArea.style.borderColor = "var(--danger)";
            }
        }

        if (hasError) {
            cookieSaveMsg.textContent = "Invalid JSON in one or more fields.";
            cookieSaveMsg.style.color = "var(--danger)";
            return;
        }

        try {
            saveCookiesBtn.disabled = true;
            saveCookiesBtn.textContent = "Saving...";
            const res = await fetch("/api/cookies", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cookies })
            });

            if (res.ok) {
                cookieSaveMsg.textContent = "Cookies saved successfully!";
                cookieSaveMsg.style.color = "var(--success)";
                for (const txtArea of Object.values(cookieTextareas)) {
                    txtArea.style.borderColor = "var(--border)";
                }
            } else {
                throw new Error("Failed to save");
            }
        } catch (e) {
            cookieSaveMsg.textContent = "Error saving cookies.";
            cookieSaveMsg.style.color = "var(--danger)";
        } finally {
            saveCookiesBtn.disabled = false;
            saveCookiesBtn.textContent = "Save Cookies";
        }
    });

})();
