// === AUTHENTICATION LOGIC ===

async function handleLogin(e) {
    e.preventDefault();
    const btn = document.getElementById('login-btn');
    const email = document.getElementById('login-email').value;
    // In your template, password input didn't have an ID, but it's the second input in the form
    const password = e.target.querySelector('input[type="password"]').value;

    // 1. Loading State
    const originalText = btn.innerText;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Signing in...';
    btn.disabled = true;

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (data.error) {
            showToast('Login Failed', data.error, 'error');
        } else {
            // 3. Save Session
            localStorage.setItem('user_id', data.user_id);
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('user_email', email);

            // 4. Redirect to Dashboard
            window.location.href = 'dashboard.html';
        }
    } catch (err) {
        console.error(err);
        showToast('Network Error', 'Connection to authentication server failed.', 'error');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function handleSignup(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    const fullName = e.target.querySelector('input[type="text"]').value;
    const email = e.target.querySelector('input[type="email"]').value;
    const password = e.target.querySelectorAll('input[type="password"]')[0].value;
    const confirmPassword = e.target.querySelectorAll('input[type="password"]')[1].value;

    if (password !== confirmPassword) {
        showToast('Validation Error', "Passwords do not match!", 'warning');
        return;
    }

    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Creating Account...';
    btn.disabled = true;

    console.log("DEBUG: Sending Signup Data:", { email, fullName, passwordLength: password.length });
    try {
        const response = await fetch('/api/auth/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: email,
                password: password,
                full_name: fullName
            })
        });

        const data = await response.json();

        if (data.error) {
            showToast('Signup Failed', data.error, 'error');
        } else {
            // Show Success Modal instead of alert
            const modal = document.getElementById('signup-success-modal');
            if (modal) {
                modal.classList.remove('hidden');
            } else {
                showToast('Email Sent', 'Confirmation mail sent to your mail please confirm and revisit', 'success');
                setTimeout(() => { window.location.href = 'login.html'; }, 3000);
            }
        }
    } catch (err) {
        console.error(err);
        showToast('Registration Error', 'Network error during signup process.', 'error');
    } finally {
        btn.innerHTML = 'Create Account';
        btn.disabled = false;
    }
}

function handleLogout() {
    localStorage.clear();
    try {
        sessionStorage.removeItem('sentinel_active_tab');
    } catch (e) { /* ignore */ }
    window.location.href = 'login.html';
}

function checkAuth() {
    const userId = localStorage.getItem('user_id');
    const isLoginPage = window.location.pathname.includes('login.html') || window.location.pathname.includes('signup.html') || window.location.pathname === '/' || window.location.pathname === '';

    if (!userId && !isLoginPage) {
        window.location.href = 'login.html';
    } else if (userId) {
        // Update UI if needed
        const userEmailSpan = document.getElementById('user-email-display');
        if (userEmailSpan) userEmailSpan.innerText = localStorage.getItem('user_email');
    }
}

/** Valid tab ids on dashboard.html — used so refresh restores Scan/History/etc. */
const DASHBOARD_TAB_IDS = ['dashboard', 'scan', 'history', 'profile'];

function getStoredDashboardTab() {
    const hash = (window.location.hash || '').replace(/^#/, '').toLowerCase();
    if (DASHBOARD_TAB_IDS.includes(hash)) return hash;
    const stored = sessionStorage.getItem('sentinel_active_tab');
    if (stored && DASHBOARD_TAB_IDS.includes(stored)) return stored;
    return 'dashboard';
}

function restoreDashboardTab() {
    if (!document.getElementById('tab-dashboard')) return;
    switchTab(getStoredDashboardTab());
}

// === NAVIGATION TABS (Dashboard / Scan / History) ===

let typeChart = null;
let threatChart = null;
let activityChart = null;

let lastDashboardData = null;

async function refreshDashboard() {
    const userId = localStorage.getItem('user_id');
    if (!userId) return;

    try {
        const response = await fetch('/api/dashboard-stats', {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        console.log('DEBUG: Dashboard Data Received:', data);
        lastDashboardData = data;

        // Update Stat Cards
        const totalEl = document.getElementById('stat-total-scans');
        const threatEl = document.getElementById('stat-threats');
        const safeEl = document.getElementById('stat-safe');
        const rateEl = document.getElementById('stat-rate');

        if (totalEl) totalEl.innerText = data.total_scans || 0;
        if (threatEl) threatEl.innerText = data.threats_detected || 0;
        if (safeEl) safeEl.innerText = data.safe_results || 0;
        if (rateEl) rateEl.innerText = (data.detection_rate || 0) + '%';

        // Update Charts
        updateCharts(data);

        // Update Recent Scans List
        renderRecentScans(data.recent_scans || []);

        // Update Global Profile Info
        updateProfileInfo(data);
    } catch (err) {
        console.error('Failed to refresh dashboard:', err);
    }
}

function updateProfileInfo(data) {
    if (!data) return;

    // Header Display
    const nameEls = document.querySelectorAll('#profile-name');
    const emailEls = document.querySelectorAll('#profile-email');
    const joinedEl = document.getElementById('profile-joined');
    const initialsEl = document.getElementById('profile-avatar-initials');

    if (data.user_name) {
        nameEls.forEach(el => el.innerText = data.user_name);
        // Set initials
        const parts = data.user_name.split(' ');
        const initials = parts.map(p => p[0]).join('').toUpperCase().substring(0, 2);
        if (initialsEl) initialsEl.innerText = initials;
    }

    const email = localStorage.getItem('user_email');
    if (email) {
        emailEls.forEach(el => el.innerText = email);
    }

    if (joinedEl && data.joined_date) joinedEl.innerText = data.joined_date;

    // Stats
    const countEl = document.getElementById('profile-scans-count');
    const threatsEl = document.getElementById('profile-threats-count');

    if (countEl) countEl.innerText = data.total_scans || 0;
    if (threatsEl) threatsEl.innerText = data.threats_detected || 0;
}

function switchTab(tabId) {
    if (!DASHBOARD_TAB_IDS.includes(tabId)) tabId = 'dashboard';

    const activeTab = document.getElementById(`tab-${tabId}`);
    if (!activeTab) return;

    // 1. Update Navbar Buttons
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.classList.remove('active');
        const oc = item.getAttribute('onclick');
        if (oc && oc.includes(`'${tabId}'`)) {
            item.classList.add('active');
        }
    });

    // 2. Update Tab Visibility
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => {
        tab.classList.add('hidden');
        tab.classList.remove('active');
    });

    activeTab.classList.remove('hidden');
    activeTab.classList.add('active');

    // 3. Tab Specific Logic
    if (tabId === 'dashboard') {
        refreshDashboard();
    } else if (tabId === 'history') {
        fetchHistory();
    } else if (tabId === 'profile') {
        if (lastDashboardData) updateProfileInfo(lastDashboardData);
        else refreshDashboard();
    }

    // Remember tab across refresh; keep URL hash in sync for bookmarking
    try {
        sessionStorage.setItem('sentinel_active_tab', tabId);
        if (document.getElementById('tab-dashboard')) {
            const base = `${window.location.pathname}${window.location.search}`;
            window.history.replaceState(null, '', `${base}#${tabId}`);
        }
    } catch (e) { /* ignore storage / history errors */ }

    // Close mobile menu if open
    const userDropdown = document.getElementById('user-dropdown');
    if (userDropdown) userDropdown.classList.add('hidden');
}

function renderRecentScans(scans) {
    const container = document.getElementById('recent-scans-list');
    if (!container) return;

    if (scans.length === 0) {
        container.innerHTML = `
            <div class="empty-state small">
                No scans yet. Start by scanning a URL, email, or file.
            </div>
        `;
        return;
    }

    container.innerHTML = '';
    scans.forEach(scan => {
        const date = new Date(scan.created_at).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        const risk = getRiskLevel(scan.result, scan.confidence);

        // Icon mapping
        let icon = 'fa-shield-halved';
        if (scan.scan_type === 'URL') icon = 'fa-link';
        if (scan.scan_type === 'File') icon = 'fa-file-shield';
        if (scan.scan_type === 'Email') icon = 'fa-envelope';
        if (scan.scan_type === 'SMS') icon = 'fa-comment-sms';
        if (scan.scan_type === 'QR') icon = 'fa-qrcode';
        if (scan.scan_type === 'Web') icon = 'fa-globe';
        if (scan.scan_type === 'Domain') icon = 'fa-magnifying-glass';

        const item = document.createElement('div');
        item.className = 'recent-scan-item';
        item.onclick = () => openScanDetailModal(scan);
        item.innerHTML = `
            <div class="scan-info-main">
                <div class="scan-type-icon">
                    <i class="fa-solid ${icon}"></i>
                </div>
                <div class="scan-details-text">
                    <h4 class="truncate" style="max-width: 200px;">${scan.input_data}</h4>
                    <p>${scan.scan_type} • ${date}</p>
                </div>
            </div>
            <div class="scan-status">
                <span class="badge ${risk.class}">${risk.label}</span>
            </div>
        `;
        container.appendChild(item);
    });
}


function closeScanModal() {
    const modal = document.getElementById('scan-detail-modal');
    if (modal) modal.classList.add('hidden');
} function updateCharts(data) {
    const typeCanvas = document.getElementById('typeChart');
    const threatCanvas = document.getElementById('threatChart');
    const activityCanvas = document.getElementById('activityChart');
    if (!typeCanvas || !threatCanvas || !activityCanvas) return;

    // Apply Global Chart Defaults for Premium Look
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', system-ui, -apple-system, sans-serif";
    Chart.defaults.font.size = 12;
    Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(15, 23, 42, 0.9)';
    Chart.defaults.plugins.tooltip.borderColor = 'rgba(255, 255, 255, 0.1)';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 12;
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
    Chart.defaults.plugins.tooltip.titleFont = { size: 13, weight: 'bold' };
    Chart.defaults.plugins.tooltip.usePointStyle = true;

    const typeCtx = typeCanvas.getContext('2d');
    const threatCtx = threatCanvas.getContext('2d');
    const activityCtx = activityCanvas.getContext('2d');

    // --- ACTIVITY CHART (LINE) ---
    const activityLabels = Object.keys(data.activity_breakdown || {}).map(date => {
        const d = new Date(date);
        return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    });
    const activityValues = Object.values(data.activity_breakdown || {});

    if (activityChart) activityChart.destroy();

    // Create elegant gradient for activity
    const activityGradient = activityCtx.createLinearGradient(0, 0, 0, 300);
    activityGradient.addColorStop(0, 'rgba(6, 182, 212, 0.35)');
    activityGradient.addColorStop(1, 'rgba(6, 182, 212, 0.02)');

    activityChart = new Chart(activityCtx, {
        type: 'line',
        data: {
            labels: activityLabels,
            datasets: [{
                label: 'Scans',
                data: activityValues,
                borderColor: '#06b6d4',
                borderWidth: 3,
                backgroundColor: activityGradient,
                fill: true,
                tension: 0.45,
                pointBackgroundColor: '#06b6d4',
                pointBorderColor: 'rgba(255,255,255,0.8)',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 7,
                pointHoverBorderWidth: 3,
                backgroundOpacity: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index',
            },
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.04)', drawBorder: false },
                    ticks: {
                        stepSize: 1,
                        padding: 10
                    }
                },
                x: {
                    grid: { display: false, drawBorder: false },
                    ticks: { padding: 10 }
                }
            },
            animations: {
                tension: {
                    duration: 1000,
                    easing: 'linear'
                }
            }
        }
    });

    // --- TYPE CHART (DOUGHNUT) ---
    const typeLabels = Object.keys(data.type_breakdown || {});
    const typeValues = Object.values(data.type_breakdown || {});

    if (typeChart) typeChart.destroy();
    typeChart = new Chart(typeCtx, {
        type: 'doughnut',
        data: {
            labels: typeLabels,
            datasets: [{
                data: typeValues,
                backgroundColor: [
                    '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4'
                ],
                borderWidth: 0,
                hoverOffset: 12,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '76%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 8,
                        padding: 20,
                        usePointStyle: true,
                        font: { size: 11 }
                    }
                }
            }
        }
    });

    // --- THREAT CHART (PIE) ---
    const threatLabels = Object.keys(data.threat_breakdown || {});
    const threatValues = Object.values(data.threat_breakdown || {});

    if (threatChart) threatChart.destroy();
    threatChart = new Chart(threatCtx, {
        type: 'pie',
        data: {
            labels: threatLabels,
            datasets: [{
                data: threatValues,
                backgroundColor: ['#ef4444', '#10b981'],
                borderWidth: 0,
                hoverOffset: 12,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 8,
                        padding: 20,
                        usePointStyle: true,
                        font: { size: 11 }
                    }
                }
            }
        }
    });
}

function switchTab(tabId) {
    // 1. Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.add('hidden'));

    // 2. Clear all active nav items
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.classList.remove('active');
        // Simple match for activation
        if (btn.innerText.toLowerCase().includes(tabId)) {
            btn.classList.add('active');
        }
    });

    // 3. Show selected tab
    const targetTab = document.getElementById(`tab-${tabId}`);
    if (targetTab) targetTab.classList.remove('hidden');

    // 4. Load data based on tab
    if (tabId === 'dashboard') {
        refreshDashboard();
    } else if (tabId === 'history') {
        fetchHistory();
    }
}

function getRiskLevel(result, confidence) {
    if (!result) return { label: 'Unknown', class: 'badge-low' };
    const res = result.toString().toLowerCase();
    const conf = parseFloat(confidence) || 0;

    // Define Safe keywords
    const isSafe = res.includes('safe') || res.includes('benign') || res.includes('good') || res === '0' || res.includes('secure');

    if (isSafe) return { label: 'Safe', class: 'badge-safe' };

    // If not safe, determine risk based on confidence
    if (conf > 0.8) return { label: 'High Risk', class: 'badge-high' };
    if (conf > 0.5) return { label: 'Medium Risk', class: 'badge-medium' };
    return { label: 'Low Risk', class: 'badge-low' };
}

async function fetchHistory() {
    const historyContainer = document.getElementById('history-container');
    const loadingState = document.getElementById('history-loading');
    const emptyState = document.getElementById('history-empty');

    if (!historyContainer || !loadingState || !emptyState) return;

    loadingState.classList.remove('hidden');
    emptyState.classList.add('hidden');

    // Remove individual rows if any
    const existingRows = historyContainer.querySelectorAll('.history-row');
    existingRows.forEach(row => row.remove());

    const typeFilter = document.getElementById('history-type-filter')?.value || 'all';

    try {
        const response = await fetch(`/api/user-scans?user_id=${localStorage.getItem('user_id')}`);
        const scans = await response.json();

        loadingState.classList.add('hidden');

        if (!scans || scans.length === 0) {
            emptyState.classList.remove('hidden');
            return;
        }

        // Create or clear wrapper
        let cardsWrapper = historyContainer.querySelector('.history-cards-container');
        if (!cardsWrapper) {
            cardsWrapper = document.createElement('div');
            cardsWrapper.className = 'history-cards-container';
            historyContainer.appendChild(cardsWrapper);
        }
        cardsWrapper.innerHTML = '';

        const searchTerm = document.getElementById('history-search')?.value.toLowerCase() || '';

        const filteredScans = scans.filter(scan => {
            const matchesSearch = scan.input_data.toLowerCase().includes(searchTerm) ||
                scan.scan_type.toLowerCase().includes(searchTerm) ||
                scan.result.toLowerCase().includes(searchTerm);
            const matchesType = typeFilter === 'all' || scan.scan_type === typeFilter;
            return matchesSearch && matchesType;
        });

        if (filteredScans.length === 0) {
            emptyState.classList.remove('hidden');
            return;
        }

        filteredScans.forEach((scan, index) => {
            const risk = getRiskLevel(scan.result, scan.confidence);
            const date = new Date(scan.created_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

            let icon = 'fa-shield-halved';
            if (scan.scan_type === 'URL') icon = 'fa-link';
            if (scan.scan_type === 'File') icon = 'fa-file-shield';
            if (scan.scan_type === 'Email') icon = 'fa-envelope';
            if (scan.scan_type === 'SMS') icon = 'fa-comment-slash';
            if (scan.scan_type === 'QR') icon = 'fa-qrcode';
            if (scan.scan_type === 'Domain') icon = 'fa-globe';

            const card = document.createElement('div');
            card.className = 'history-card';
            card.style.animationDelay = `${index * 0.05}s`;
            card.onclick = () => openScanDetailModal(scan);

            card.innerHTML = `
                <div class="card-icon">
                    <i class="fa-solid ${icon}"></i>
                </div>
                <div class="card-main">
                    <h4>${scan.scan_type} Intelligence Scan</h4>
                    <p title="${scan.input_data}">${scan.input_data.length > 50 ? scan.input_data.substring(0, 50) + '...' : scan.input_data}</p>
                </div>
                <div class="card-meta">
                    <label>Executed On</label>
                    <span style="font-size: 0.8rem;">${date}</span>
                </div>
                <div class="card-meta">
                    <label>Confidence</label>
                    <span style="font-family: monospace;">${(scan.confidence * 100).toFixed(1)}%</span>
                </div>
                <div class="card-badge ${risk.class}">
                    ${risk.label}
                </div>
            `;
            cardsWrapper.appendChild(card);
        });
    } catch (err) {
        console.error(err);
        loadingState.classList.add('hidden');
    }
}

function openScanDetailModal(scan) {
    const modal = document.getElementById('scan-detail-modal');
    if (!modal) return;

    const risk = getRiskLevel(scan.result, scan.confidence);
    const date = new Date(scan.created_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

    // Populate basic info
    const dateEl = document.getElementById('modal-date');
    if (dateEl) dateEl.innerText = `Forensic Analysis Timestamp: ${date}`;

    const inputEl = document.getElementById('modal-input');
    if (inputEl) inputEl.innerText = scan.input_data;

    // Populate stats
    const resultEl = document.getElementById('modal-result');
    if (resultEl) {
        resultEl.innerText = (scan.result || 'Unknown').toUpperCase();
        resultEl.className = `modal-stat-value ${risk.class === 'badge-safe' ? 'text-success' : 'text-danger'}`;
    }

    const confEl = document.getElementById('modal-confidence');
    if (confEl) {
        confEl.innerText = `${((scan.confidence || 0) * 100).toFixed(1)}%`;
        confEl.style.color = 'var(--accent)';
    }

    // Reason
    const reasonEl = document.getElementById('modal-reason');
    if (reasonEl) {
        reasonEl.innerText = scan.reason || 'AI Intelligence Engine: No critical structural vulnerabilities or malicious signatures detected in this specific artifact.';
    }

    // Icon and Highlight Color
    const iconBox = document.getElementById('modal-type-icon');
    if (iconBox) {
        let color = 'var(--accent)';
        let icon = 'fa-shield-halved';

        if (scan.scan_type === 'URL') icon = 'fa-link';
        if (scan.scan_type === 'File') { icon = 'fa-file-shield'; color = '#a855f7'; }
        if (scan.scan_type === 'Email') { icon = 'fa-envelope'; color = '#22c55e'; }
        if (scan.scan_type === 'SMS') { icon = 'fa-comment-slash'; color = '#eab308'; }
        if (scan.scan_type === 'QR') icon = 'fa-qrcode';
        if (scan.scan_type === 'Domain') icon = 'fa-globe';
        if (scan.scan_type === 'Web') icon = 'fa-browser';

        iconBox.innerHTML = `<i class="fa-solid ${icon}"></i>`;
        iconBox.style.color = color;
        iconBox.style.background = `${color}1A`;
        iconBox.style.borderColor = `${color}33`;
    }

    modal.classList.remove('hidden');
}

function closeScanModal() {
    const modal = document.getElementById('scan-detail-modal');
    if (modal) modal.classList.add('hidden');
}

async function shareEvidence(data) {
    const reportText = `Sentinel Shield Security Report\nTarget: ${data.url || data.input_data}\nVerdict: ${data.threat_status || data.result}\nConfidence: ${((data.confidence || 0) * 100).toFixed(1)}%\nScan Time: ${data.scan_time || new Date().toLocaleString()}`;
    
    if (navigator.share) {
        try {
            await navigator.share({
                title: 'Sentinel Shield Security Report',
                text: reportText,
                url: window.location.href
            });
        } catch (err) {
            console.error('Error sharing:', err);
        }
    } else {
        try {
            await navigator.clipboard.writeText(reportText);
            showToast('Evidence Shared', 'Report summary copied to clipboard!', 'success');
        } catch (err) {
            console.error('Error copying to clipboard:', err);
            showToast('Copy Failed', 'Could not copy report. Please copy manually.', 'error');
        }
    }
}

async function addToBlacklist(inputData, scanType) {
    showConfirm(
        'Add to Blacklist',
        `Are you sure you want to add "${inputData}" to the blacklist? This will flag future encounters with this artifact.`,
        async () => {
            try {
                const response = await fetch('/api/blacklist', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-User-Id': localStorage.getItem('user_id')
                    },
                    body: JSON.stringify({ input_data: inputData, scan_type: scanType })
                });
                const result = await response.json();
                if (result.error) {
                    showToast('Action Failed', result.error, 'error');
                } else {
                    showToast('Success', result.message, 'success');
                }
            } catch (err) {
                console.error('Blacklist error:', err);
                showToast('Network Error', 'Failed to connect to security server.', 'error');
            }
        }
    );
}

async function addToWhitelist(inputData, scanType) {
    showConfirm(
        'Add to Whitelist',
        `Are you sure you want to add "${inputData}" to the whitelist? This will mark it as safe for your account.`,
        async () => {
            try {
                const response = await fetch('/api/whitelist', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-User-Id': localStorage.getItem('user_id')
                    },
                    body: JSON.stringify({ input_data: inputData, scan_type: scanType })
                });
                const result = await response.json();
                if (result.error) {
                    showToast('Action Failed', result.error, 'error');
                } else {
                    showToast('Success', result.message, 'success');
                }
            } catch (err) {
                console.error('Whitelist error:', err);
                showToast('Network Error', 'Failed to connect to security server.', 'error');
            }
        }
    );
}

function escapeHtml(str) {
    if (str == null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function renderIndicatorGridCells(indicators) {
    if (!indicators || !indicators.length) return '';
    return indicators.map((ind) => {
        let icon = '<i class="fa-solid fa-check" style="color:#34d399;"></i>';
        if (ind.status === 'danger' || (ind.risk && ind.risk === 'high')) {
            icon = '<i class="fa-solid fa-xmark" style="color:#ef4444;"></i>';
        } else if (ind.status === 'warning' || (ind.risk && ind.risk === 'medium')) {
            icon = '<i class="fa-solid fa-triangle-exclamation" style="color:#f59e0b;"></i>';
        }
        const label = escapeHtml(ind.name || ind.label);
        const val = escapeHtml(ind.value);
        return `
            <div class="indicator-card" style="
                padding: 0.875rem 1rem;
                border-radius: 10px;
                border: 1px solid rgba(51,65,85,0.6);
                background: rgba(30,41,59,0.25);
                transition: background 0.2s, border-color 0.2s;
                cursor: default;
            " onmouseover="this.style.background='rgba(30,41,59,0.6)';this.style.borderColor='rgba(71,85,105,0.8)'"
               onmouseout ="this.style.background='rgba(30,41,59,0.25)';this.style.borderColor='rgba(51,65,85,0.6)'">
                <div style="font-size:9px; font-weight:700; color:#475569; text-transform:uppercase; letter-spacing:0.1em; margin-bottom:0.5rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${label}</div>
                <div style="display:flex; justify-content:space-between; align-items:center; gap:0.5rem;">
                    <span style="font-size:0.85rem; font-weight:700; color:#f1f5f9; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1;">${val}</span>
                    <span style="flex-shrink:0; font-size:1rem; line-height:1;">${icon}</span>
                </div>
            </div>`;
    }).join('');
}

function renderPremiumTechnicalIndicatorsCard(indicators) {
    if (!indicators || !indicators.length) return '';
    return `
                <div class="glass-card result-glass-card result-card--indicators">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3" style="margin:0 0 1rem 0;">Technical Indicators</h3>
                    <div class="indicators-grid result-indicators-grid">
                        ${renderIndicatorGridCells(indicators)}
                    </div>
                </div>`;
}

// === SCAN TOOLS SWITCHER ===

function openTool(element, toolId) {
    document.querySelectorAll('.tool-item').forEach(item => {
        item.classList.remove('active');
    });
    element.classList.add('active');

    const panels = document.querySelectorAll('.tool-panel');
    panels.forEach(panel => {
        panel.classList.add('hidden');
        panel.style.opacity = '0';
        panel.style.transform = 'translateY(10px)';
    });

    const activePanel = document.getElementById(`tool-${toolId}`);
    if (activePanel) {
        activePanel.classList.remove('hidden');
        // Trigger reflow for animation
        void activePanel.offsetWidth;
        activePanel.style.opacity = '1';
        activePanel.style.transform = 'translateY(0)';
    }
}

function renderScanResult(containerId, data, scanType) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.classList.remove('hidden');
    container.innerHTML = '';

    const resultWrapper = document.createElement('div');
    resultWrapper.className = 'premium-dashboard-container';

    if (data.error) {
        resultWrapper.innerHTML = `
            <div class="glass-card" style="border-top: 4px solid #ef4444;">
                <div class="flex items-center gap-4 text-red-400">
                    <i class="fa-solid fa-triangle-exclamation text-3xl"></i>
                    <div>
                        <h3 class="font-bold text-lg">Analysis Error</h3>
                        <p class="text-sm opacity-80">${data.error}</p>
                    </div>
                </div>
            </div>
        `;
        container.appendChild(resultWrapper);
        return;
    }

    const url = data.url || data.input_data || 'Target Scanned';
    const threatStatus = data.threat_status || data.result || 'Unknown';
    const confidence = parseFloat(data.confidence) || 0.0;
    const riskScore = data.risk_score || (confidence * 100).toFixed(0);
    const engine = data.engine || 'General Analysis Engine';
    const scanTime = data.scan_time || new Date().toLocaleString();

    const isSafe = threatStatus.toLowerCase().includes('safe') || threatStatus.toLowerCase().includes('benign') || threatStatus.toLowerCase().includes('legitimate');
    const isHighRisk = !isSafe && (threatStatus.toLowerCase().includes('phishing') || threatStatus.toLowerCase().includes('malware') || parseFloat(riskScore) > 60);

    let statusColor = '#f59e0b';
    let statusClass = 'status-warning';

    if (isSafe) {
        statusColor = '#10b981';
        statusClass = 'status-safe';
    } else if (isHighRisk) {
        statusColor = '#ef4444';
        statusClass = 'status-danger';
    }

    const aiSummary = data.ai_analysis?.summary || 'Automated structural analysis completed.';
    const aiReason = data.ai_analysis?.reason || data.reason || 'No detailed heuristic reason provided for this scan profile.';
    const aiRecommendation = data.ai_analysis?.recommendation || (isSafe ? 'The artifact appears clean to interact with safely.' : 'Proceed with measured caution.');
    const finalVerdict = data.final_verdict || `This artifact is categorized as ${threatStatus}.`;

    const indicators = data.indicators || data.details || [];
    const securityChecks = data.security_checks || [];

    const canvasId = `riskChart-${Math.random().toString(36).substr(2, 9)}`;

    const verdictDisplay = escapeHtml(String(threatStatus));
    const engineDisplay = escapeHtml(String(engine));
    const scanTimeDisplay = escapeHtml(String(scanTime));

    const urlDisplay = escapeHtml(url);
    const urlProbe = String(data.url || data.input_data || url).trim().toLowerCase();
    let protoBadgeClass = 'scan-proto-neutral';
    let protoIcon = 'fa-link';
    let protoTitle = 'HTTPS';
    let protoSubtitle = 'Connection type';
    if (urlProbe.startsWith('https://')) {
        protoBadgeClass = 'scan-proto-secure';
        protoIcon = 'fa-lock';
        protoTitle = 'HTTPS';
        protoSubtitle = 'Encrypted';
    } else if (urlProbe.startsWith('http://')) {
        protoBadgeClass = 'scan-proto-warn';
        protoIcon = 'fa-lock-open';
        protoTitle = 'HTTP';
        protoSubtitle = 'Not encrypted';
    } else {
        protoTitle = 'Target';
        protoSubtitle = 'Scanned input';
    }

    resultWrapper.innerHTML = `
        <!-- 1. Scan Summary Header -->
        <div class="glass-card summary-header" style="border-top-color: ${statusColor}">
            <div class="summary-info">
                <div class="scan-target-banner">
                    <div class="scan-target-banner__icon" aria-hidden="true">
                        <i class="fa-solid fa-bullseye"></i>
                    </div>
                    <div class="scan-target-banner__main">
                        <div class="scan-target-banner__top">
                            <div class="scan-target-banner__heading">
                                <span class="scan-target-banner__kicker">What we analyzed</span>
                                <p class="scan-target-banner__hint">This report applies to the URL or text below — not your device, account, or a hidden “system ID”.</p>
                            </div>
                            <div class="scan-target-banner__proto ${protoBadgeClass}" title="${protoTitle}: ${protoSubtitle}">
                                <i class="fa-solid ${protoIcon}" aria-hidden="true"></i>
                                <span class="scan-target-banner__proto-text">
                                    <span class="scan-target-banner__proto-title">${protoTitle}</span>
                                    <span class="scan-target-banner__proto-sub">${protoSubtitle}</span>
                                </span>
                            </div>
                        </div>
                        <h2 class="scan-target-banner__url text-xl font-black text-white mb-3 break-all line-clamp-3 leading-snug">${urlDisplay}</h2>
                    </div>
                </div>

                <div class="scan-meta-strip" role="group" aria-label="Scan summary">
                    <div class="scan-meta-cell">
                        <span class="scan-meta-label"><i class="fa-solid fa-flag-checkered" aria-hidden="true"></i> Verdict</span>
                        <span class="status-badge scan-meta-verdict ${statusClass}">${verdictDisplay}</span>
                    </div>
                    <div class="scan-meta-cell">
                        <span class="scan-meta-label"><i class="fa-solid fa-microchip" aria-hidden="true"></i> Analysis engine</span>
                        <span class="scan-meta-value" title="${engineDisplay}">${engineDisplay}</span>
                    </div>
                    <div class="scan-meta-cell scan-meta-cell--time">
                        <span class="scan-meta-label"><i class="fa-regular fa-clock" aria-hidden="true"></i> Scan time</span>
                        <span class="scan-meta-value scan-meta-time">${scanTimeDisplay}</span>
                    </div>
                </div>
            </div>

            <!-- 2. Risk Score -->
            <div class="score-container summary-score-col">
                <div class="chart-wrapper">
                    <canvas id="${canvasId}"></canvas>
                    <div class="chart-center">
                        <!-- FIX: number and label centred with flex column -->
                        <span style="font-size: 2.25rem; font-weight: 900; color: ${statusColor}; line-height: 1; letter-spacing: -0.04em; display:block; text-align:center;">${riskScore}</span>
                        <span style="font-size: 8px; color: #64748b; font-weight: 700; text-transform: uppercase; letter-spacing: 0.15em; margin-top: 4px; display:block; text-align:center;">Risk Index</span>
                    </div>
                </div>
                <!-- FIX: confidence label centred and no scale transform -->
                <div style="text-align:center; margin-top: 8px;">
                    <span style="font-size:10px; font-weight:900; color:#64748b; text-transform:uppercase; letter-spacing:0.1em;">
                        Confidence: <span style="color:#f1f5f9;">${(confidence * 100).toFixed(1)}%</span>
                    </span>
                </div>
            </div>
        </div>

        <div class="premium-grid mt-6">
            <!-- Left Column -->
            <div class="results-grid-col results-grid-col--main">

                <!-- 3. AI Forensic Analysis -->
                <div class="glass-card ai-card result-glass-card ai-forensic-card">
                    <div class="ai-card-head flex items-center gap-3 border-b border-slate-700/50">
                        <div class="p-2 rounded-lg bg-accent/10 text-accent" style="display:flex;align-items:center;justify-content:center;">
                            <i class="fa-solid fa-brain text-xl"></i>
                        </div>
                        <h3 class="text-sm font-black text-white uppercase tracking-widest" style="margin:0;">AI Forensic Analysis</h3>
                    </div>
                    <div class="ai-content">
                        <p class="ai-summary font-bold text-white leading-snug" style="font-size:0.95rem;">${aiSummary}</p>
                        <p class="ai-reason text-slate-400 text-sm leading-relaxed font-medium whitespace-pre-line">${aiReason}</p>
                        <div class="recommendation-box p-4 rounded-xl bg-slate-900 border border-slate-700/50 relative overflow-hidden">
                            <div class="absolute left-0 top-0 bottom-0 w-1 bg-accent"></div>
                            <!-- FIX: label and value vertically separated cleanly -->
                            <span class="text-[10px] text-slate-500 uppercase font-black tracking-widest block mb-1.5">Recommendation Directive</span>
                            <span class="text-sm font-semibold text-slate-200">${aiRecommendation}</span>
                        </div>
                    </div>
                </div>

            </div>

            <!-- Right Column -->
            <div class="results-grid-col results-grid-col--side">

                <!-- 5. Security Checks -->
                ${securityChecks.length > 0 ? `
                <div class="glass-card result-glass-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3" style="margin:0 0 1rem 0;">Security Parameter Checks</h3>
                    <div class="checklist" style="display:flex; flex-direction:column; gap:0.5rem;">
                        ${securityChecks.map(chk => {
                            let bg    = 'rgba(16,185,129,0.05)';
                            let border= 'rgba(16,185,129,0.18)';
                            let iconColor = '#34d399';
                            let icon  = '<i class="fa-solid fa-circle-check"></i>';
                            let statusColor2 = '#34d399';
                            if (chk.status === 'failed') {
                                bg='rgba(239,68,68,0.05)'; border='rgba(239,68,68,0.18)';
                                iconColor='#f87171'; statusColor2='#f87171';
                                icon='<i class="fa-solid fa-circle-xmark"></i>';
                            } else if (chk.status === 'warning') {
                                bg='rgba(245,158,11,0.05)'; border='rgba(245,158,11,0.18)';
                                iconColor='#fbbf24'; statusColor2='#fbbf24';
                                icon='<i class="fa-solid fa-triangle-exclamation"></i>';
                            }
                            return `
                            <div style="
                                display:flex; align-items:center; gap:0.75rem;
                                padding:0.7rem 0.875rem;
                                border-radius:8px;
                                border:1px solid ${border};
                                background:${bg};
                                transition:opacity 0.15s;
                            ">
                                <!-- FIX: icon fixed width so labels stay aligned -->
                                <span style="color:${iconColor}; font-size:1rem; flex-shrink:0; width:18px; text-align:center;">${icon}</span>
                                <span style="font-size:0.82rem; font-weight:600; color:#e2e8f0; flex:1;">${chk.name}</span>
                                <!-- FIX: status badge pill instead of raw text for better readability -->
                                <span style="
                                    font-size:0.6rem; font-weight:800; letter-spacing:0.12em;
                                    text-transform:uppercase; color:${statusColor2};
                                    background:${bg}; border:1px solid ${border};
                                    padding:0.15rem 0.5rem; border-radius:999px;
                                    flex-shrink:0; white-space:nowrap;
                                ">${chk.status}</span>
                            </div>`;
                        }).join('')}
                    </div>
                </div>
                ` : ''}

                ${renderPremiumTechnicalIndicatorsCard(indicators)}
            </div>
        </div>

        <!-- 7. Action Buttons — FIX: align-items center -->
        <div class="action-buttons-grid mt-6" style="display:flex; flex-wrap:wrap; gap:0.5rem; align-items:center;">
            ${(url && url.startsWith('http')) ? `
                <a href="${url}" target="_blank" class="neon-btn btn-primary"><i class="fa-solid fa-arrow-up-right-from-square"></i> Sandbox Access</a>
            ` : ''}
            <button class="neon-btn btn-secondary" onclick="window.print()"><i class="fa-solid fa-file-pdf"></i> Export Report</button>
            <button class="neon-btn btn-secondary" onclick="triggerRescan('${scanType}', '${(data.url || data.input_data || url).replace(/'/g, "\\'")}')"><i class="fa-solid fa-rotate-right"></i> Rescan Artifact</button>
            <button class="neon-btn btn-secondary" id="btn-share-evidence-${canvasId}"><i class="fa-solid fa-share-nodes"></i> Share Evidence</button>
            <button class="neon-btn btn-danger" onclick="addToBlacklist('${(data.url || data.input_data || url).replace(/'/g, "\\'")}', '${scanType.replace(/'/g, "\\'")}')"><i class="fa-solid fa-ban"></i> Add to Blacklist</button>
            <button class="neon-btn btn-success" style="border-color:rgba(16,185,129,0.3);color:#10b981;" onclick="addToWhitelist('${(data.url || data.input_data || url).replace(/'/g, "\\'")}', '${scanType.replace(/'/g, "\\'")}')"><i class="fa-solid fa-shield-check"></i> Add to Whitelist</button>
        </div>

        <!-- 8. Final Verdict Banner -->
        <div class="verdict-banner mt-6 ${statusClass}">
            <div class="flex items-center gap-5 relative z-10">
                <i class="fa-solid ${isSafe ? 'fa-shield-check' : (isHighRisk ? 'fa-triangle-exclamation' : 'fa-circle-info')}" style="font-size:2rem; flex-shrink:0;"></i>
                <div style="min-width:0;">
                    <!-- FIX: verdict label and text vertically spaced cleanly -->
                    <h2 style="font-size:0.6rem; font-weight:900; text-transform:uppercase; letter-spacing:0.2em; opacity:0.65; margin-bottom:0.375rem;">Official Verdict Declaration</h2>
                    <p style="font-size:1rem; font-weight:800; line-height:1.4; letter-spacing:-0.01em; color:#f1f5f9;">${finalVerdict}</p>
                </div>
            </div>
            <div class="banner-bg-glow"></div>
        </div>
    `;

    container.appendChild(resultWrapper);

    // Link Share Button
    const shareBtn = document.getElementById(`btn-share-evidence-${canvasId}`);
    if (shareBtn) {
        shareBtn.onclick = () => shareEvidence({
            url: data.url || data.input_data || url,
            threat_status: threatStatus,
            confidence: confidence,
            scan_time: scanTime
        });
    }

    // Chart.js Doughnut
    const ctx = document.getElementById(canvasId);
    if (ctx) {
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [riskScore, 100 - riskScore],
                    backgroundColor: [statusColor, 'rgba(255,255,255,0.05)'],
                    borderWidth: 0,
                    borderRadius: 6,
                    cutout: '82%'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { animateScale: true, animateRotate: true, duration: 1500, easing: 'easeOutQuart' },
                plugins: { tooltip: { enabled: false }, legend: { display: false } }
            }
        });
    }
}function showToast(title, message, type = 'info', duration = 4000) {
    const toast = document.getElementById('toast');
    if (!toast) return;

    const body = toast.querySelector('.toast-body');
    const line = toast.querySelector('.toast-line');
    
    if (body) {
        body.innerHTML = `<strong>${title}</strong><p>${message}</p>`;
    }

    // Reset classes
    toast.className = 'toast';
    toast.classList.add(`toast-${type}`);
    
    // Show toast
    toast.classList.add('show');
    toast.classList.remove('hidden');

    if (line) {
        line.style.width = '100%';
        line.style.transition = `width ${duration}ms linear`;
        setTimeout(() => { line.style.width = '0%'; }, 10);
    }

    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => { toast.classList.add('hidden'); }, 500);
    }, duration);
}

function showConfirm(title, message, onConfirm) {
    const modal = document.getElementById('confirmation-modal');
    const titleEl = document.getElementById('confirm-title');
    const msgEl = document.getElementById('confirm-message');
    const cancelBtn = document.getElementById('confirm-cancel-btn');
    const actionBtn = document.getElementById('confirm-proceed-btn');

    if (!modal || !titleEl || !msgEl || !cancelBtn || !actionBtn) return;

    titleEl.innerText = title;
    msgEl.innerText = message;

    modal.classList.remove('hidden');

    // Remove old listeners
    const newCancelBtn = cancelBtn.cloneNode(true);
    const newActionBtn = actionBtn.cloneNode(true);
    cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);
    actionBtn.parentNode.replaceChild(newActionBtn, actionBtn);

    newCancelBtn.onclick = () => {
        modal.classList.add('hidden');
    };

    newActionBtn.onclick = () => {
        modal.classList.add('hidden');
        if (onConfirm) onConfirm();
    };

    // Close on overlay click
    document.getElementById('confirm-overlay').onclick = () => {
        modal.classList.add('hidden');
    };
}

// === UI UTILITIES ===

function toggleUserMenu() {
    const menu = document.getElementById('user-dropdown');
    if (menu) menu.classList.toggle('hidden');
}

// Helper to get auth headers
function getAuthHeaders() {
    const userId = localStorage.getItem('user_id');
    return {
        'Content-Type': 'application/json',
        'X-User-Id': userId || ''
    };
}

// === DOM CONTENT LOADED ===

function setupDragAndDrop(zoneId, inputId, textId) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const text = document.getElementById(textId);

    if (!zone || !input) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        zone.addEventListener(eventName, e => {
            e.preventDefault();
            e.stopPropagation();
        }, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        zone.addEventListener(eventName, () => zone.classList.add('dragover'), false);
    });

    ['dragleave', 'dragend'].forEach(eventName => {
        zone.addEventListener(eventName, () => zone.classList.remove('dragover'), false);
    });

    zone.addEventListener('drop', e => {
        zone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            input.files = files;
            if (text) text.innerText = `File selected: ${files[0].name}`;
        }
    }, false);

    input.addEventListener('change', () => {
        if (input.files.length > 0 && text) {
            text.innerText = `File selected: ${input.files[0].name}`;
        }
    });
}

// === REUSABLE SCAN FUNCTIONS ===

async function performUrlScan(url = null) {
    const btn = document.getElementById('url-scan-btn');
    const input = document.getElementById('url-input');
    const resultDiv = document.getElementById('url-result');
    if (!btn || !resultDiv) return;

    const targetUrl = url || (input ? input.value.trim() : null);
    if (!targetUrl) { showToast('Scan Error', 'Please enter a URL to proceed', 'warning'); return; }
    if (input && url) input.value = url;

    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Initializing Scan...';
    btn.disabled = true;
    resultDiv.classList.add('hidden');

    try {
        const response = await fetch('/api/scan-url', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ url: targetUrl })
        });
        const data = await response.json();
        renderScanResult('url-result', data, 'URL');
    } catch (err) {
        console.error(err);
        renderScanResult('url-result', { error: 'Network connection failed' }, 'URL');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function performSmsScan(text = null) {
    const btn = document.getElementById('sms-scan-btn');
    const input = document.getElementById('sms-input');
    const resultDiv = document.getElementById('sms-result');
    if (!btn || !resultDiv) return;

    const targetText = text || (input ? input.value.trim() : null);
    if (!targetText) { showToast('Scan Error', 'Please enter SMS content for analysis', 'warning'); return; }
    if (input && text) input.value = text;

    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Deep Analysis...';
    btn.disabled = true;
    resultDiv.classList.add('hidden');

    try {
        const response = await fetch('/api/scan-sms', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ text: targetText })
        });
        const data = await response.json();
        renderScanResult('sms-result', data, 'SMS');
    } catch (err) {
        console.error(err);
        renderScanResult('sms-result', { error: 'Failed to analyze message' }, 'SMS');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function performEmailScan(text = null) {
    const btn = document.getElementById('email-scan-btn');
    const input = document.getElementById('email-input');
    const resultDiv = document.getElementById('email-result');
    if (!btn || !resultDiv) return;

    const targetText = text || (input ? input.value.trim() : null);
    if (!targetText) { showToast('Scan Error', 'Please enter email content for forensic analysis', 'warning'); return; }
    if (input && text) input.value = text;

    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Intelligence Scan...';
    btn.disabled = true;
    resultDiv.classList.add('hidden');

    try {
        const response = await fetch('/analyze-email', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ text: targetText })
        });
        const data = await response.json();
        renderEmailResult('email-result', data);
    } catch (err) {
        console.error(err);
        renderEmailResult('email-result', { error: 'Analysis failed' });
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function performDomainScan(domain = null) {
    const btn = document.getElementById('domain-check-btn');
    const input = document.getElementById('domain-input');
    const resultDiv = document.getElementById('domain-result');
    if (!btn || !resultDiv) return;

    const targetDomain = domain || (input ? input.value.trim() : null);
    if (!targetDomain) { showToast('Lookup Error', 'Please enter a domain name', 'warning'); return; }
    if (input && domain) input.value = domain;

    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Checking WHOIS...';
    btn.disabled = true;
    resultDiv.classList.add('hidden');

    try {
        const response = await fetch('/api/check-domain', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ domain: targetDomain })
        });
        const data = await response.json();
        renderDomainResult('domain-result', data);
    } catch (err) {
        console.error(err);
        renderDomainResult('domain-result', { error: 'Domain lookup failed' });
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function performFileScan() {
    const btn = document.getElementById('file-scan-btn');
    const input = document.getElementById('file-input');
    const resultDiv = document.getElementById('file-result');
    if (!btn || !input || !resultDiv) return;

    if (input.files.length === 0) { showToast('Upload Error', 'Please select a file to inspect', 'warning'); return; }
    const file = input.files[0];

    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Malware Inspection...';
    btn.disabled = true;
    resultDiv.classList.add('hidden');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/scan-file', {
            method: 'POST',
            headers: { 'X-User-Id': localStorage.getItem('user_id') || '' },
            body: formData
        });
        const data = await response.json();
        renderFileResult('file-result', data);
    } catch (err) {
        console.error(err);
        renderFileResult('file-result', { error: 'File analysis failed' });
    } finally {
        btn.innerHTML = 'Analyze File';
        btn.disabled = false;
    }
}

async function performQrScan() {
    const btn = document.getElementById('qr-scan-btn');
    const input = document.getElementById('qr-input');
    const resultDiv = document.getElementById('qr-result');
    if (!btn || !input || !resultDiv) return;

    if (input.files.length === 0) { showToast('Input Error', 'Please select a QR code image', 'warning'); return; }
    const file = input.files[0];

    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Extracting Data...';
    btn.disabled = true;
    resultDiv.classList.add('hidden');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/scan-qr', {
            method: 'POST',
            headers: { 'X-User-Id': localStorage.getItem('user_id') || '' },
            body: formData
        });
        const data = await response.json();

        if (data.is_url && data.threat_analysis) {
            const combinedData = {
                ...data.threat_analysis,
                content: data.content,
                input_data: data.content
            };
            renderScanResult('qr-result', combinedData, 'QR');
        } else {
            renderScanResult('qr-result', data, 'QR');
        }
    } catch (err) {
        console.error(err);
        renderScanResult('qr-result', { error: 'QR Scan failed' }, 'QR');
    } finally {
        btn.innerHTML = 'Scan QR Code';
        btn.disabled = false;
    }
}

async function performWebScan(url = null) {
    const btn = document.getElementById('web-scan-btn');
    const input = document.getElementById('web-input');
    const resultDiv = document.getElementById('web-result');
    if (!btn || !resultDiv) return;

    const targetUrl = url || (input ? input.value.trim() : null);
    if (!targetUrl) { alert('Please enter a URL'); return; }
    if (input && url) input.value = url;

    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Forensic Audit...';
    btn.disabled = true;
    resultDiv.classList.add('hidden');

    try {
        const response = await fetch('/api/inspect-web', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ url: targetUrl })
        });
        const data = await response.json();
        renderWebsiteResult('web-result', data);
    } catch (err) {
        console.error(err);
        renderWebsiteResult('web-result', { error: 'Website inspection failed' });
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function triggerRescan(type, input = null) {
    console.log(`Rescanning ${type} with input:`, input);
    switch (type) {
        case 'URL': performUrlScan(input); break;
        case 'SMS': performSmsScan(input); break;
        case 'Email': performEmailScan(input); break;
        case 'Domain': performDomainScan(input); break;
        case 'File': performFileScan(); break;
        case 'QR': performQrScan(); break;
        case 'Web': performWebScan(input); break;
        default: console.error('Unknown scan type for rescan:', type);
    }
}


document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    restoreDashboardTab();

    setupDragAndDrop('file-upload-zone', 'file-input', 'file-upload-text');
    setupDragAndDrop('qr-upload-zone', 'qr-input', 'qr-upload-text');

    window.addEventListener('hashchange', () => {
        if (!document.getElementById('tab-dashboard')) return;
        const t = (window.location.hash || '').replace(/^#/, '').toLowerCase();
        if (DASHBOARD_TAB_IDS.includes(t)) switchTab(t);
    });

    // --- URL Scanner Logic ---
    const scanBtn = document.getElementById('url-scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', () => performUrlScan());
    }

    // --- SMS Scanner Logic ---
    const smsScanBtn = document.getElementById('sms-scan-btn');
    if (smsScanBtn) {
        smsScanBtn.addEventListener('click', () => performSmsScan());
    }

    // --- Email Scanner Logic ---
    const emailScanBtn = document.getElementById('email-scan-btn');
    if (emailScanBtn) {
        emailScanBtn.addEventListener('click', () => performEmailScan());
    }

    // --- Domain Check Logic ---
    const domainCheckBtn = document.getElementById('domain-check-btn');
    if (domainCheckBtn) {
        domainCheckBtn.addEventListener('click', () => performDomainScan());
    }

    // --- File Scanner Logic ---
    const fileScanBtn = document.getElementById('file-scan-btn');
    if (fileScanBtn) {
        fileScanBtn.addEventListener('click', () => performFileScan());
    }

    // --- QR Scanner Logic ---
    const qrScanBtn = document.getElementById('qr-scan-btn');
    if (qrScanBtn) {
        qrScanBtn.addEventListener('click', () => performQrScan());
    }

    // --- Website Inspector Logic ---
    const webScanBtn = document.getElementById('web-scan-btn');
    if (webScanBtn) {
        webScanBtn.addEventListener('click', () => performWebScan());
    }

    // History search listener
    const historySearch = document.getElementById('history-search');
    if (historySearch) {
        historySearch.addEventListener('input', () => {
            fetchHistory();
        });
    }

    // Dropdown listener
    window.addEventListener('click', function (e) {
        if (!e.target.closest('.user-menu-container')) {
            const menu = document.getElementById('user-dropdown');
            if (menu) menu.classList.add('hidden');
        }
    });
});

// === DOMAIN SCANNER SPECIFIC UI RENDERING ===
function renderDomainResult(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.classList.remove('hidden');
    container.innerHTML = '';

    const wrapper = document.createElement('div');
    wrapper.className = 'domain-result-container';

    if (data.error) {
        wrapper.innerHTML = `<div class="domain-card border-red-500"><h3 class="text-red-500 text-lg font-bold">Error</h3><p>${data.error}</p></div>`;
        container.appendChild(wrapper);
        return;
    }

    const domain = data.domain || 'Unknown Domain';
    const threatStatus = data.threat_status || data.result || 'Unknown';
    const confidence = parseFloat(data.confidence) || 0.0;
    const riskScore = data.risk_score || 0;
    const scanTime = data.scan_time || new Date().toLocaleString();
    const engine = data.engine || 'Domain Intelligence Engine';
    const finalVerdict = data.final_verdict || `Domain classified as ${threatStatus}`;

    // Styling based on risk
    const isSafe = threatStatus.toLowerCase().includes('safe') || threatStatus.toLowerCase().includes('benign');
    const isThreat = threatStatus.toLowerCase().includes('malware') || threatStatus.toLowerCase().includes('phishing');
    const statusClass = isSafe ? 'domain-status-safe' : (isThreat ? 'domain-status-danger' : 'domain-status-warning');
    const statusIcon = isSafe ? 'fa-shield-check' : (isThreat ? 'fa-skull-crossbones' : 'fa-triangle-exclamation');

    const dInfo = data.domain_info || {};
    const hInfo = data.hosting_info || {};
    const dns = data.dns_records || {};
    const checks = data.security_checks || [];
    let indicators = data.indicators || [];
    if (!indicators.length) {
        indicators = [
            { name: 'Threat Status', value: threatStatus, status: isThreat ? 'danger' : (isSafe ? 'safe' : 'warning') },
            { name: 'Registrar', value: dInfo.registrar || 'N/A', status: 'warning' },
            { name: 'DNS NS', value: dns.NS || 'N/A', status: 'safe' }
        ];
    }

    wrapper.innerHTML = `
        <!-- 1. Summary Card -->
        <div class="domain-card domain-summary border-l-4 ${statusClass}">
            <div class="flex justify-between items-start flex-wrap gap-4">
                <div>
                    <h2 class="text-2xl font-black mb-2">${domain}</h2>
                    <div class="flex gap-4 items-center flex-wrap">
                        <span class="domain-badge ${statusClass} uppercase tracking-widest text-[10px] font-bold px-3 py-1 rounded-full"><i class="fa-solid ${statusIcon} mr-1"></i> ${threatStatus}</span>
                        <span class="text-sm opacity-80"><i class="fa-solid fa-microchip mr-1"></i> ${engine}</span>
                        <span class="text-sm opacity-80"><i class="fa-regular fa-clock mr-1"></i> ${scanTime}</span>
                    </div>
                </div>
                <div class="text-right">
                    <div class="text-3xl font-black ${statusClass}">${riskScore}/100</div>
                    <div class="text-[10px] uppercase tracking-widest opacity-70">Risk Score (Conf: ${(confidence * 100).toFixed(0)}%)</div>
                </div>
            </div>
        </div>

        <div class="domain-grid mt-6">
            <div class="domain-grid-column">
                <!-- 2. Domain Information -->
                <div class="domain-card">
                    <h3 class="domain-heading"><i class="fa-solid fa-globe mr-2"></i> Domain Information</h3>
                    <div class="domain-kv-list">
                        <div class="domain-kv"><span class="k">Registrar:</span><span class="v">${dInfo.registrar || 'N/A'}</span></div>
                        <div class="domain-kv"><span class="k">Creation Date:</span><span class="v">${dInfo.creation_date || 'N/A'}</span></div>
                        <div class="domain-kv"><span class="k">Expiry Date:</span><span class="v">${dInfo.expiry_date || 'N/A'}</span></div>
                        <div class="domain-kv"><span class="k">Domain Age:</span><span class="v">${dInfo.domain_age || 'N/A'}</span></div>
                        <div class="domain-kv"><span class="k">WHOIS Hidden:</span><span class="v">${dInfo.whois_hidden ? '<span class="text-amber-400">Yes</span>' : '<span class="text-emerald-400">No</span>'}</span></div>
                    </div>
                </div>

                <!-- 3. Hosting Information -->
                <div class="domain-card mt-4">
                    <h3 class="domain-heading"><i class="fa-solid fa-server mr-2"></i> Hosting Information</h3>
                    <div class="domain-kv-list">
                        <div class="domain-kv"><span class="k">IP Address:</span><span class="v">${hInfo.ip_address || 'N/A'}</span></div>
                        <div class="domain-kv"><span class="k">Provider:</span><span class="v">${hInfo.hosting_provider || 'N/A'}</span></div>
                        <div class="domain-kv"><span class="k">Country:</span><span class="v">${hInfo.country || 'N/A'}</span></div>
                    </div>
                </div>

                <!-- 4. DNS Records -->
                <div class="domain-card mt-4">
                    <h3 class="domain-heading"><i class="fa-solid fa-network-wired mr-2"></i> DNS Records Matrix</h3>
                    <div class="domain-dns-grid">
                        ${Object.entries(dns).map(([type, status]) => `
                            <div class="domain-dns-box">
                                <span class="type">${type}</span>
                                <span class="status ${status.toLowerCase() === 'present' ? 'text-emerald-400' : 'text-red-400'}">${status}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>

            <div class="domain-grid-column">
                <!-- 5. Security Checks -->
                <div class="domain-card">
                    <h3 class="domain-heading"><i class="fa-solid fa-shield-halved mr-2"></i> Infrastructure Security Checks</h3>
                    <div class="domain-checklist">
                        ${checks.map(chk => {
        let cl = 'domain-chk-pass';
        let i = '<i class="fa-solid fa-check"></i>';
        if (chk.status === 'failed') { cl = 'domain-chk-fail'; i = '<i class="fa-solid fa-xmark"></i>'; }
        if (chk.status === 'warning') { cl = 'domain-chk-warn'; i = '<i class="fa-solid fa-exclamation"></i>'; }
        return `
                                <div class="domain-chk-item ${cl}">
                                    <div class="icon">${i}</div>
                                    <div class="name">${chk.name}</div>
                                    <div class="status">${chk.status}</div>
                                </div>
                            `;
    }).join('')}
                    </div>
                </div>

                <div class="domain-card mt-4">
                    <h3 class="domain-heading"><i class="fa-solid fa-gauge-high mr-2"></i>Technical Indicators</h3>
                    <div style="display:grid; grid-template-columns:repeat(2,1fr); gap:0.625rem;">
                        ${renderIndicatorGridCells(indicators)}
                    </div>
                </div>
            </div>
        </div>

        <!-- 8. Verdict Banner -->
        <div class="domain-verdict mt-6 ${statusClass}">
            <div class="flex items-center gap-4">
                <i class="fa-solid ${statusIcon} text-3xl"></i>
                <div>
                    <h4 class="text-[10px] uppercase tracking-widest opacity-80 mb-1">Final Intelligence Verdict</h4>
                    <p class="text-lg font-bold">${finalVerdict}</p>
                </div>
            </div>
        </div>

        <!-- 9. Actions -->
        <div class="mt-6 flex gap-3">
             <button class="domain-badge domain-status-warning px-4 py-2 rounded-lg" onclick="triggerRescan('Domain', '${domain.replace(/'/g, "\\'")}')"><i class="fa-solid fa-rotate-right mr-2"></i> Rescan Domain</button>
             <button class="domain-badge domain-status-safe px-4 py-2 rounded-lg" onclick="window.print()"><i class="fa-solid fa-file-pdf mr-2"></i> Print Report</button>
        </div>
    `;

    container.appendChild(wrapper);
}

// === WEBSITE INSPECTOR SPECIFIC UI RENDERING ===
function renderWebsiteResult(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.classList.remove('hidden');
    container.innerHTML = '';
    const wrapper = document.createElement('div');
    wrapper.className = 'website-result-container';

    if (data.error) {
        wrapper.innerHTML = `<div class="website-card"><h3 class="text-red-400 font-bold text-lg mb-2">Inspection Error</h3><p>${data.error}</p></div>`;
        container.appendChild(wrapper);
        return;
    }

    const url = data.url || 'Unknown Target';
    const threatStatus = data.threat_status || data.result || 'Unknown';
    const confidence = parseFloat(data.confidence) || 0.0;
    const riskScore = data.risk_score || 0;
    const scanTime = data.scan_time || new Date().toLocaleString();
    const engine = data.engine || 'Website Inspection Engine';
    const finalVerdict = data.final_verdict || `Website classified as ${threatStatus}.`;

    const isSafe = threatStatus.toLowerCase().includes('safe') || threatStatus.toLowerCase().includes('benign');
    const isThreat = threatStatus.toLowerCase().includes('malware') || threatStatus.toLowerCase().includes('phishing');
    const wClass = isSafe ? 'ws-safe' : (isThreat ? 'ws-danger' : 'ws-warning');
    const wIcon = isSafe ? 'fa-shield-check' : (isThreat ? 'fa-skull-crossbones' : 'fa-triangle-exclamation');

    const pInfo = data.page_info || {};
    const secAna = data.security_analysis || {};
    const techs = data.technologies || [];
    const extRes = data.external_resources || [];
    const checks = data.security_checks || [];
    let indicators = data.indicators || [];
    if (!indicators.length && Object.keys(secAna).length) {
        indicators = [
            { name: 'HTTPS', value: secAna.https ? 'Yes' : 'No', status: secAna.https ? 'safe' : 'danger' },
            { name: 'Suspicious JS', value: secAna.suspicious_js ? 'Flagged' : 'No', status: secAna.suspicious_js ? 'warning' : 'safe' },
            { name: 'Hidden Forms', value: secAna.hidden_forms ? 'Yes' : 'No', status: secAna.hidden_forms ? 'warning' : 'safe' },
            { name: 'External Scripts', value: secAna.external_scripts ? 'Yes' : 'No', status: secAna.external_scripts ? 'warning' : 'safe' }
        ];
    }

    const boolRow = (label, val) => `
        <div class="ws-kv">
            <span class="ws-k">${label}</span>
            <span class="ws-v ${val ? 'ws-yes' : 'ws-no'}">${val ? '✔ Yes' : '✖ No'}</span>
        </div>`;

    wrapper.innerHTML = `
        <!-- 1. Summary -->
        <div class="website-card ws-summary ${wClass}">
            <div class="flex justify-between items-start flex-wrap gap-4">
                <div>
                    <div class="text-[10px] text-slate-400 uppercase tracking-[0.18em] font-bold mb-2">Website Inspector Result</div>
                    <h2 class="text-2xl font-black mb-3 break-all">${url}</h2>
                    <div class="flex gap-3 flex-wrap items-center">
                        <span class="ws-badge ${wClass}"><i class="fa-solid ${wIcon} mr-1"></i>${threatStatus}</span>
                        <span class="text-sm opacity-70"><i class="fa-solid fa-microchip mr-1"></i>${engine}</span>
                        <span class="text-sm opacity-70"><i class="fa-regular fa-clock mr-1"></i>${scanTime}</span>
                    </div>
                </div>
                <div class="text-right">
                    <div class="text-4xl font-black ${wClass}">${riskScore}/100</div>
                    <div class="text-[10px] uppercase tracking-widest opacity-60 mt-1">Risk Score · Conf ${(confidence * 100).toFixed(0)}%</div>
                </div>
            </div>
        </div>

        <div class="website-grid mt-5">
            <!-- Left Column -->
            <div class="ws-col">
                <!-- 2. Page Information -->
                <div class="website-card">
                    <h3 class="ws-heading"><i class="fa-solid fa-file-code mr-2"></i>Page Information</h3>
                    <div class="ws-kv-list">
                        <div class="ws-kv"><span class="ws-k">Title:</span><span class="ws-v">${pInfo.title || 'N/A'}</span></div>
                        <div class="ws-kv"><span class="ws-k">Page Size:</span><span class="ws-v">${pInfo.page_size || 'N/A'}</span></div>
                        <div class="ws-kv"><span class="ws-k">Load Time:</span><span class="ws-v">${pInfo.load_time || 'N/A'}</span></div>
                        <div class="ws-kv"><span class="ws-k">Scripts:</span><span class="ws-v">${pInfo.scripts ?? 0}</span></div>
                        <div class="ws-kv"><span class="ws-k">External Links:</span><span class="ws-v">${pInfo.external_links ?? 0}</span></div>
                        <div class="ws-kv"><span class="ws-k">Forms:</span><span class="ws-v">${pInfo.forms ?? 0}</span></div>
                        <div class="ws-kv"><span class="ws-k">iFrames:</span><span class="ws-v">${pInfo.iframes ?? 0}</span></div>
                    </div>
                </div>

                <!-- 3. Security Analysis -->
                <div class="website-card mt-4">
                    <h3 class="ws-heading"><i class="fa-solid fa-lock mr-2"></i>Security Analysis</h3>
                    <div class="ws-kv-list">
                        ${boolRow('HTTPS Enabled', secAna.https)}
                        ${boolRow('SSL Certificate Valid', secAna.ssl_valid)}
                        ${boolRow('Mixed Content', secAna.mixed_content)}
                        ${boolRow('Suspicious JavaScript', secAna.suspicious_js)}
                        ${boolRow('Hidden Forms', secAna.hidden_forms)}
                        ${boolRow('iFrames Present', secAna.iframes_present)}
                        ${boolRow('External Scripts', secAna.external_scripts)}
                        ${boolRow('Redirect Detected', secAna.redirect_detected)}
                    </div>
                </div>

                <!-- 4. Technologies -->
                <div class="website-card mt-4">
                    <h3 class="ws-heading"><i class="fa-solid fa-layer-group mr-2"></i>Technology Detection</h3>
                    <div class="ws-tags">${techs.map(t => `<span class="ws-tag">${t}</span>`).join('')}</div>
                </div>

                <!-- 5. External Resources -->
                <div class="website-card mt-4">
                    <h3 class="ws-heading"><i class="fa-solid fa-arrow-up-right-from-square mr-2"></i>External Resources</h3>
                    <div class="ws-tags">${extRes.map(r => `<span class="ws-tag ws-tag-ext">${r}</span>`).join('')}</div>
                </div>
            </div>

            <!-- Right Column -->
            <div class="ws-col">
                <!-- 6. Security Checklist -->
                <div class="website-card">
                    <h3 class="ws-heading"><i class="fa-solid fa-shield-halved mr-2"></i>Security Checklist</h3>
                    <div class="website-checklist">
                        ${checks.map(chk => {
        let cl = 'ws-chk-pass', ic = '<i class="fa-solid fa-check"></i>';
        if (chk.status === 'failed') { cl = 'ws-chk-fail'; ic = '<i class="fa-solid fa-xmark"></i>'; }
        if (chk.status === 'warning') { cl = 'ws-chk-warn'; ic = '<i class="fa-solid fa-exclamation"></i>'; }
        return `
                            <div class="ws-chk-item ${cl}">
                                <div class="icon">${ic}</div>
                                <div class="name">${chk.name}</div>
                                <div class="status">${chk.status}</div>
                            </div>`;
    }).join('')}
                    </div>
                </div>

                <div class="website-card mt-4">
                    <h3 class="ws-heading"><i class="fa-solid fa-gauge-high mr-2"></i>Technical Indicators</h3>
                    <div style="display:grid; grid-template-columns:repeat(2,1fr); gap:0.625rem;">
                        ${renderIndicatorGridCells(indicators)}
                    </div>
                </div>
            </div>
        </div>

        <!-- 8. Verdict Banner -->
        <div class="website-verdict mt-5 ${wClass}">
            <div class="flex items-center gap-4">
                <i class="fa-solid ${wIcon} text-3xl"></i>
                <div>
                    <h4 class="text-[10px] uppercase tracking-widest opacity-75 mb-1">Final Security Verdict</h4>
                    <p class="text-lg font-bold">${finalVerdict}</p>
                </div>
            </div>
        </div>

        <!-- 9. Actions -->
        <div class="mt-5 flex gap-3">
             <button class="ws-badge ws-warning px-4 py-2 rounded-lg" onclick="triggerRescan('Web', '${url.replace(/'/g, "\\'")}')"><i class="fa-solid fa-rotate-right mr-2"></i> Rescan Website</button>
             <button class="ws-badge ws-safe px-4 py-2 rounded-lg" onclick="window.print()"><i class="fa-solid fa-file-pdf mr-2"></i> Export PDF</button>
        </div>
    `;

    container.appendChild(wrapper);
}

// === FILE SCANNER SPECIFIC UI RENDERING ===
function renderFileResult(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.classList.remove('hidden');
    container.innerHTML = '';
    const wrapper = document.createElement('div');
    wrapper.className = 'file-result-container';

    if (data.error) {
        wrapper.innerHTML = `<div class="file-card"><h3 class="text-red-400 font-bold mb-2">Scan Error</h3><p>${data.error}</p></div>`;
        container.appendChild(wrapper);
        return;
    }

    const filename = data.filename || 'Unknown File';
    const fileType = data.file_type || 'Unknown';
    const fileSize = data.file_size || 'N/A';
    const threat = data.threat_status || data.result || 'Unknown';
    const confidence = parseFloat(data.confidence) || 0.0;
    const riskScore = data.risk_score || 0;
    const scanTime = data.scan_time || new Date().toLocaleString();
    const engine = data.engine || 'AI Deep File Analysis Engine';
    const verdict = data.final_verdict || `File classified as ${threat}.`;

    const isSafe = threat.toLowerCase().includes('safe') || threat.toLowerCase().includes('benign');
    const isThreat = threat.toLowerCase().includes('malware');
    const fClass = isSafe ? 'ff-safe' : (isThreat ? 'ff-danger' : 'ff-warning');
    const fIcon = isSafe ? 'fa-shield-check' : (isThreat ? 'fa-biohazard' : 'fa-triangle-exclamation');

    const hash = data.hash_info || {};
    const mal = data.malware_analysis || {};
    const stat = data.static_analysis || {};
    const checks = data.security_checks || [];
    const tl = data.timeline || [];

    const boolCell = (val) => val
        ? '<span class="ff-yes">✔ Yes</span>'
        : '<span class="ff-no">✖ No</span>';

    wrapper.innerHTML = `
        <!-- 1. Summary -->
        <div class="file-card ff-summary ${fClass}">
            <div class="flex justify-between items-start flex-wrap gap-4">
                <div>
                    <div class="text-[10px] text-slate-400 uppercase tracking-[0.18em] font-bold mb-2">File Scanner Result</div>
                    <h2 class="text-2xl font-black mb-1">${filename}</h2>
                    <div class="text-sm text-slate-400 mb-3">${fileType} &nbsp;·&nbsp; ${fileSize}</div>
                    <div class="flex gap-3 flex-wrap items-center">
                        <span class="ff-badge ${fClass}"><i class="fa-solid ${fIcon} mr-1"></i>${threat}</span>
                        <span class="text-sm opacity-70"><i class="fa-solid fa-microchip mr-1"></i>${engine}</span>
                        <span class="text-sm opacity-70"><i class="fa-regular fa-clock mr-1"></i>${scanTime}</span>
                    </div>
                </div>
                <div class="text-right">
                    <div class="text-4xl font-black ${fClass}">${riskScore}/100</div>
                    <div class="text-[10px] uppercase tracking-widest opacity-60 mt-1">Risk Score · Conf ${(confidence * 100).toFixed(0)}%</div>
                </div>
            </div>
        </div>

        <div class="file-grid mt-5">
            <!-- Left Column -->
            <div class="ff-col">
                <!-- 2. Hash Information -->
                <div class="file-card">
                    <h3 class="ff-heading"><i class="fa-solid fa-fingerprint mr-2"></i>File Hash Information</h3>
                    <div class="ff-kv-list">
                        <div class="ff-kv"><span class="ff-k">MD5:</span><span class="ff-v ff-mono">${hash.md5 || 'N/A'}</span></div>
                        <div class="ff-kv"><span class="ff-k">SHA1:</span><span class="ff-v ff-mono">${hash.sha1 || 'N/A'}</span></div>
                        <div class="ff-kv"><span class="ff-k">SHA256:</span><span class="ff-v ff-mono ff-small">${hash.sha256 || 'N/A'}</span></div>
                        <div class="ff-kv"><span class="ff-k">Entropy:</span><span class="ff-v">${hash.entropy || 'N/A'}</span></div>
                        <div class="ff-kv"><span class="ff-k">MIME Type:</span><span class="ff-v">${hash.mime_type || 'N/A'}</span></div>
                    </div>
                </div>

                <!-- 3. Malware Analysis -->
                <div class="file-card mt-4">
                    <h3 class="ff-heading"><i class="fa-solid fa-biohazard mr-2"></i>Malware Analysis</h3>
                    <div class="ff-kv-list">
                        <div class="ff-kv"><span class="ff-k">Malware Detected:</span><span class="ff-v">${boolCell(mal.malware_detected)}</span></div>
                        <div class="ff-kv"><span class="ff-k">Malware Type:</span><span class="ff-v">${mal.malware_type || 'N/A'}</span></div>
                        <div class="ff-kv"><span class="ff-k">Suspicious Behavior:</span><span class="ff-v">${boolCell(mal.suspicious_behavior)}</span></div>
                        <div class="ff-kv"><span class="ff-k">Packed File:</span><span class="ff-v">${boolCell(mal.packed_file)}</span></div>
                        <div class="ff-kv"><span class="ff-k">Obfuscation:</span><span class="ff-v">${boolCell(mal.obfuscation)}</span></div>
                        <div class="ff-kv"><span class="ff-k">Permissions:</span><span class="ff-v">${mal.permissions_requested || 'N/A'}</span></div>
                        ${mal.suspicious_strings && mal.suspicious_strings.length > 0 ? `
                        <div class="ff-kv ff-kv-col"><span class="ff-k">Suspicious Strings:</span><div class="ff-tags mt-1">${mal.suspicious_strings.map(s => `<span class="ff-tag ff-tag-warn">${s}</span>`).join('')}</div></div>` : ''}
                    </div>
                </div>

                <!-- 4. Static Analysis -->
                <div class="file-card mt-4">
                    <h3 class="ff-heading"><i class="fa-solid fa-code mr-2"></i>Static Analysis</h3>
                    <div class="ff-kv-list">
                        <div class="ff-kv"><span class="ff-k">Strings Found:</span><span class="ff-v">${stat.strings_found ?? 'N/A'}</span></div>
                        <div class="ff-kv"><span class="ff-k">Suspicious Keywords:</span><span class="ff-v ${stat.suspicious_keywords > 0 ? 'ff-warn-text' : ''}">${stat.suspicious_keywords ?? 0}</span></div>
                        <div class="ff-kv"><span class="ff-k">File Sections:</span><span class="ff-v">${stat.file_sections || 'N/A'}</span></div>
                        <div class="ff-kv"><span class="ff-k">Digital Signature:</span><span class="ff-v">${stat.digital_signature || 'N/A'}</span></div>
                        ${stat.embedded_urls && stat.embedded_urls.length > 0 ? `
                        <div class="ff-kv ff-kv-col"><span class="ff-k">Embedded URLs:</span><div class="ff-tags mt-1">${stat.embedded_urls.map(u => `<span class="ff-tag ff-tag-ext">${u}</span>`).join('')}</div></div>` : ''}
                    </div>
                </div>
            </div>

            <!-- Right Column -->
            <div class="ff-col">
                <!-- 5. Security Checks -->
                <div class="file-card">
                    <h3 class="ff-heading"><i class="fa-solid fa-shield-halved mr-2"></i>Security Checks</h3>
                    <div class="file-checklist">
                        ${checks.map(chk => {
        let cl = 'fc-pass', ic = '<i class="fa-solid fa-check"></i>';
        if (chk.status === 'failed') { cl = 'fc-fail'; ic = '<i class="fa-solid fa-xmark"></i>'; }
        if (chk.status === 'warning') { cl = 'fc-warn'; ic = '<i class="fa-solid fa-exclamation"></i>'; }
        return `
                            <div class="fc-item ${cl}">
                                <div class="icon">${ic}</div>
                                <div class="name">${chk.name}</div>
                                <div class="status">${chk.status}</div>
                            </div>`;
    }).join('')}
                    </div>
                </div>

                <!-- 6. Scan Timeline -->
                <div class="file-card mt-4">
                    <h3 class="ff-heading"><i class="fa-solid fa-timeline mr-2"></i>Scan Timeline</h3>
                    <div class="file-timeline">
                        ${tl.map((t, idx) => `
                            <div class="ft-item ${idx === tl.length - 1 ? 'ft-active' : ''}">
                                <div class="ft-dot"></div>
                                <div class="ft-text">${t}</div>
                            </div>`).join('')}
                    </div>
                </div>

                <!-- 7. Action Buttons -->
                <div class="file-card mt-4">
                    <h3 class="ff-heading"><i class="fa-solid fa-bolt mr-2"></i>Actions</h3>
                    <div class="ff-actions">
                        <button class="ff-btn ff-btn-sec" onclick="window.print()"><i class="fa-solid fa-file-pdf"></i> Download Report</button>
                        <button class="ff-btn ff-btn-sec" onclick="triggerRescan('File')"><i class="fa-solid fa-rotate-right"></i> Rescan File</button>
                        <button class="ff-btn ff-btn-sec"><i class="fa-solid fa-magnifying-glass"></i> Hash Intelligence</button>
                        <button class="ff-btn ff-btn-danger"><i class="fa-solid fa-ban"></i> Blacklist Hash</button>
                        <button class="ff-btn ff-btn-sec"><i class="fa-solid fa-share-nodes"></i> Share Report</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- 8. Verdict Banner -->
        <div class="file-verdict mt-5 ${fClass}">
            <div class="flex items-center gap-4">
                <i class="fa-solid ${fIcon} text-3xl"></i>
                <div>
                    <h4 class="text-[10px] uppercase tracking-widest opacity-75 mb-1">Final Analysis Verdict</h4>
                    <p class="text-lg font-bold">${verdict}</p>
                </div>
            </div>
        </div>
    `;

    container.appendChild(wrapper);
}

// === EMAIL ANALYZER SPECIFIC UI RENDERING ===
function renderEmailResult(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.classList.remove('hidden');
    container.innerHTML = '';
    const wrapper = document.createElement('div');
    wrapper.className = 'email-result-container';

    if (data.error) {
        wrapper.innerHTML = `<div class="email-card"><h3 class="text-red-400 font-bold mb-2">Analysis Error</h3><p>${data.error}</p></div>`;
        container.appendChild(wrapper);
        return;
    }

    // Normalize — support both old and new payload shapes
    const meta = data.email_meta || {};
    const hdr = data.header_analysis || {};
    const snd = data.sender_info || {};
    const cnt = data.content_analysis || {};
    const lnk = data.links_analysis || {};
    const att = data.attachments_analysis || {};
    const checks = data.security_checks || [];
    const timeline = data.timeline || [];

    const threat = data.threat_status || (data.label === 'phishing' ? 'Phishing' : 'Legitimate');
    const confidence = parseFloat(data.confidence) || 0.0;
    const riskScore = parseFloat(data.risk_score) || 0.0;
    const scanTime = data.scan_time || new Date().toLocaleString();
    const engine = data.engine || 'ML + AI Email Analysis Engine';
    const verdict = data.final_verdict || data.reason || `Email classified as ${threat}.`;

    const isPhish = threat.toLowerCase().includes('phishing');
    const isSusp = threat.toLowerCase().includes('suspicious');
    const eClass = isPhish ? 'em-danger' : (isSusp ? 'em-warning' : 'em-safe');
    const eIcon = isPhish ? 'fa-fish' : (isSusp ? 'fa-triangle-exclamation' : 'fa-envelope-circle-check');

    const boolCell = (val) => val
        ? `<span class="em-yes">✔ Yes</span>`
        : `<span class="em-no">✖ No</span>`;
    const passCell = (val, yes = 'Pass', no = 'Fail') =>
        val === 'Pass' || val === true
            ? `<span class="em-yes">${yes}</span>`
            : `<span class="em-no">${no}</span>`;

    wrapper.innerHTML = `
        <!-- 1. Summary Card -->
        <div class="email-card em-summary ${eClass}">
            <div class="flex justify-between items-start flex-wrap gap-4">
                <div>
                    <div class="text-[10px] text-slate-400 uppercase tracking-[0.18em] font-bold mb-2">Email Analyzer Result</div>
                    <h2 class="text-2xl font-black mb-1">${meta.subject || 'No Subject'}</h2>
                    <div class="text-sm text-slate-400 mb-3">
                        <span><i class="fa-solid fa-paper-plane mr-1"></i>${meta.sender || 'Unknown'}</span>
                        <span class="mx-2">&rarr;</span>
                        <span>${meta.recipient || 'Unknown'}</span>
                    </div>
                    <div class="flex gap-3 flex-wrap items-center">
                        <span class="em-badge ${eClass}"><i class="fa-solid ${eIcon} mr-1"></i>${threat}</span>
                        <span class="text-sm opacity-70"><i class="fa-solid fa-microchip mr-1"></i>${engine}</span>
                        <span class="text-sm opacity-70"><i class="fa-regular fa-clock mr-1"></i>${scanTime}</span>
                    </div>
                </div>
                <div class="text-right">
                    <div class="text-4xl font-black ${eClass}">${riskScore.toFixed(0)}/100</div>
                    <div class="text-[10px] uppercase tracking-widest opacity-60 mt-1">Risk Score &middot; Conf ${(confidence * 100).toFixed(0)}%</div>
                </div>
            </div>
        </div>

        <div class="email-grid mt-5">
            <!-- Left Column -->
            <div class="em-col">
                <!-- 2. Header Analysis -->
                <div class="email-card">
                    <h3 class="em-heading"><i class="fa-solid fa-file-lines mr-2"></i>Email Header Analysis</h3>
                    <div class="em-kv-list">
                        <div class="em-kv"><span class="em-k">SPF:</span><span class="em-v">${passCell(hdr.spf)}</span></div>
                        <div class="em-kv"><span class="em-k">DKIM:</span><span class="em-v">${passCell(hdr.dkim)}</span></div>
                        <div class="em-kv"><span class="em-k">DMARC:</span><span class="em-v">${passCell(hdr.dmarc)}</span></div>
                        <div class="em-kv"><span class="em-k">Return Path:</span><span class="em-v em-trunc">${hdr.return_path || 'N/A'}</span></div>
                        <div class="em-kv"><span class="em-k">Reply-To:</span><span class="em-v em-trunc">${hdr.reply_to || 'N/A'}</span></div>
                        <div class="em-kv"><span class="em-k">Message ID:</span><span class="em-v em-trunc">${hdr.message_id || 'N/A'}</span></div>
                        <div class="em-kv"><span class="em-k">Received Servers:</span><span class="em-v">${hdr.received_servers ?? 'N/A'}</span></div>
                        <div class="em-kv"><span class="em-k">Header Anomalies:</span><span class="em-v">${boolCell(hdr.header_anomalies)}</span></div>
                    </div>
                </div>

                <!-- 3. Sender Information -->
                <div class="email-card mt-4">
                    <h3 class="em-heading"><i class="fa-solid fa-user-shield mr-2"></i>Sender Information</h3>
                    <div class="em-kv-list">
                        <div class="em-kv"><span class="em-k">Sender Domain:</span><span class="em-v">${snd.sender_domain || 'N/A'}</span></div>
                        <div class="em-kv"><span class="em-k">Domain Age:</span><span class="em-v">${snd.domain_age || 'N/A'}</span></div>
                        <div class="em-kv"><span class="em-k">WHOIS Hidden:</span><span class="em-v">${boolCell(snd.whois_hidden)}</span></div>
                        <div class="em-kv"><span class="em-k">Sender IP:</span><span class="em-v">${snd.sender_ip || 'N/A'}</span></div>
                        <div class="em-kv"><span class="em-k">Country:</span><span class="em-v">${snd.sender_country || 'N/A'}</span></div>
                        <div class="em-kv"><span class="em-k">Mail Server:</span><span class="em-v">${snd.mail_server || 'N/A'}</span></div>
                    </div>
                </div>

                <!-- 4. Content Analysis -->
                <div class="email-card mt-4">
                    <h3 class="em-heading"><i class="fa-solid fa-magnifying-glass-chart mr-2"></i>Content Analysis</h3>
                    <div class="em-kv-list">
                        <div class="em-kv"><span class="em-k">Phishing Keywords:</span><span class="em-v ${cnt.phishing_keywords > 0 ? 'em-warn-text' : ''}">${cnt.phishing_keywords ?? 0}</span></div>
                        <div class="em-kv"><span class="em-k">Suspicious Links:</span><span class="em-v ${cnt.suspicious_links > 0 ? 'em-warn-text' : ''}">${cnt.suspicious_links ?? 0}</span></div>
                        <div class="em-kv"><span class="em-k">Attachments:</span><span class="em-v">${boolCell(cnt.attachments_present)}</span></div>
                        <div class="em-kv"><span class="em-k">HTML Email:</span><span class="em-v">${boolCell(cnt.html_email)}</span></div>
                        <div class="em-kv"><span class="em-k">Urgent Language:</span><span class="em-v">${boolCell(cnt.urgent_language)}</span></div>
                        <div class="em-kv"><span class="em-k">Spoofed Domain:</span><span class="em-v">${boolCell(cnt.spoofed_domain)}</span></div>
                        <div class="em-kv"><span class="em-k">Mismatched URLs:</span><span class="em-v">${boolCell(cnt.mismatched_urls)}</span></div>
                        <div class="em-kv"><span class="em-k">Shortened Links:</span><span class="em-v">${boolCell(cnt.shortened_links)}</span></div>
                    </div>
                </div>

                <!-- 5. Links Analysis -->
                <div class="email-card mt-4">
                    <h3 class="em-heading"><i class="fa-solid fa-link mr-2"></i>Links Analysis</h3>
                    <div class="em-kv-list">
                        <div class="em-kv"><span class="em-k">Total Links:</span><span class="em-v">${lnk.total_links ?? 0}</span></div>
                        <div class="em-kv"><span class="em-k">Suspicious Domains:</span><span class="em-v ${lnk.suspicious_domains > 0 ? 'em-warn-text' : ''}">${lnk.suspicious_domains ?? 0}</span></div>
                        <div class="em-kv"><span class="em-k">Redirect Links:</span><span class="em-v">${lnk.redirect_links ?? 0}</span></div>
                        <div class="em-kv"><span class="em-k">IP Address URLs:</span><span class="em-v ${lnk.ip_address_urls > 0 ? 'em-warn-text' : ''}">${lnk.ip_address_urls ?? 0}</span></div>
                        ${lnk.external_domains && lnk.external_domains.length > 0 ? `
                        <div class="em-kv em-kv-col"><span class="em-k">External Domains:</span>
                        <div class="em-tags mt-1">${lnk.external_domains.map(d => `<span class="em-tag em-tag-ext">${d}</span>`).join('')}</div></div>` : ''}
                    </div>
                </div>
            </div>

            <!-- Right Column -->
            <div class="em-col">
                <!-- 6. Attachments Analysis -->
                <div class="email-card">
                    <h3 class="em-heading"><i class="fa-solid fa-paperclip mr-2"></i>Attachments Analysis</h3>
                    <div class="em-kv-list">
                        <div class="em-kv"><span class="em-k">Attachments Present:</span><span class="em-v">${boolCell(att.attachment_names && att.attachment_names.length > 0)}</span></div>
                        <div class="em-kv"><span class="em-k">Suspicious:</span><span class="em-v">${boolCell(att.suspicious_attachments)}</span></div>
                        <div class="em-kv"><span class="em-k">Malware Risk:</span><span class="em-v ${att.malware_risk === 'High' ? 'em-danger' : ''}">${att.malware_risk || 'Low'}</span></div>
                        <div class="em-kv"><span class="em-k">Macro Enabled:</span><span class="em-v">${boolCell(att.macro_enabled)}</span></div>
                    </div>
                </div>

                <!-- 7. Security Checks -->
                <div class="email-card mt-4">
                    <h3 class="em-heading"><i class="fa-solid fa-shield-halved mr-2"></i>Security Checks</h3>
                    <div class="email-checklist">
                        ${checks.map(chk => {
        let cl = 'ec-pass', ic = '<i class="fa-solid fa-check"></i>';
        if (chk.status === 'failed') { cl = 'ec-fail'; ic = '<i class="fa-solid fa-xmark"></i>'; }
        if (chk.status === 'warning') { cl = 'ec-warn'; ic = '<i class="fa-solid fa-exclamation"></i>'; }
        return `
                            <div class="ec-item ${cl}">
                                <div class="icon">${ic}</div>
                                <div class="name">${chk.name}</div>
                                <div class="status">${chk.status}</div>
                            </div>`;
    }).join('')}
                    </div>
                </div>

                <!-- 8. Scan Timeline -->
                <div class="email-card mt-4">
                    <h3 class="em-heading"><i class="fa-solid fa-timeline mr-2"></i>Analysis Timeline</h3>
                    <div class="email-timeline">
                        ${timeline.map((t, idx) => `
                            <div class="et-item ${idx === timeline.length - 1 ? 'et-active' : ''}">
                                <div class="et-dot"></div>
                                <div class="et-text">${t}</div>
                            </div>`).join('')}
                    </div>
                </div>

                <!-- 9. Action Buttons -->
                <div class="email-card mt-4">
                    <h3 class="em-heading"><i class="fa-solid fa-bolt mr-2"></i>Actions</h3>
                    <div class="em-actions">
                        <button class="em-btn em-btn-sec" onclick="window.print()"><i class="fa-solid fa-file-pdf"></i> Download Report</button>
                        <button class="em-btn em-btn-sec" onclick="triggerRescan('Email', '${(meta.body || meta.text || data.text || '').replace(/'/g, "\\'").replace(/\n/g, "\\n")}')"><i class="fa-solid fa-rotate-right"></i> Rescan Email</button>
                        <button class="em-btn em-btn-sec"><i class="fa-solid fa-code"></i> View Full Headers</button>
                        <button class="em-btn em-btn-sec"><i class="fa-solid fa-link"></i> Extract Links</button>
                        <button class="em-btn em-btn-danger"><i class="fa-solid fa-ban"></i> Blacklist Sender</button>
                        <button class="em-btn em-btn-sec"><i class="fa-solid fa-share-nodes"></i> Share Report</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- 10. Verdict Banner -->
        <div class="email-verdict mt-5 ${eClass}">
            <div class="flex items-center gap-4">
                <i class="fa-solid ${eIcon} text-3xl"></i>
                <div>
                    <h4 class="text-[10px] uppercase tracking-widest opacity-75 mb-1">Final Email Verdict</h4>
                    <p class="text-lg font-bold">${verdict}</p>
                </div>
            </div>
        </div>
    `;

    container.appendChild(wrapper);
}