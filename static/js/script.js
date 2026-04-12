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
            if (data.user_name || data.full_name || data.name) {
                localStorage.setItem('user_name', data.user_name || data.full_name || data.name);
            }

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

function isNotificationsEnabled() {
    const stored = localStorage.getItem('sentinel-shield-notifications');
    return stored === null ? true : stored === 'true';
}

function setNotificationsEnabled(enabled) {
    localStorage.setItem('sentinel-shield-notifications', String(enabled));
    refreshProfileSettingsState();
}

function toggleNotificationsPreference() {
    const nextValue = !isNotificationsEnabled();
    setNotificationsEnabled(nextValue);
    showToast(
        nextValue ? 'Notifications Enabled' : 'Notifications Disabled',
        nextValue ? 'In-app alerts are now visible.' : 'In-app alerts are now muted from profile settings.',
        nextValue ? 'success' : 'info',
        4000,
        true
    );
}

function toggleProfileTheme() {
    toggleTheme();
    refreshProfileSettingsState();
}

function refreshProfileSettingsState() {
    const notificationStatus = document.getElementById('notifications-status');
    if (notificationStatus) {
        notificationStatus.innerText = isNotificationsEnabled() ? 'On' : 'Off';
    }

    const themeStatus = document.getElementById('theme-status');
    const profileThemeIcon = document.getElementById('profile-theme-icon');
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';

    if (themeStatus) {
        themeStatus.innerText = currentTheme === 'light' ? 'Light' : 'Dark';
    }

    if (profileThemeIcon) {
        profileThemeIcon.classList.toggle('fa-sun', currentTheme === 'light');
        profileThemeIcon.classList.toggle('fa-moon', currentTheme !== 'light');
    }
}

window.syncThemePreferences = refreshProfileSettingsState;

function openChangePasswordModal() {
    const modal = document.getElementById('change-password-modal');
    const form = document.getElementById('change-password-form');
    if (!modal || !form) return;

    form.reset();
    modal.classList.remove('hidden');

    const firstInput = document.getElementById('current-password-input');
    if (firstInput) {
        setTimeout(() => firstInput.focus(), 50);
    }
}

function closeChangePasswordModal() {
    const modal = document.getElementById('change-password-modal');
    if (modal) modal.classList.add('hidden');
}

async function submitChangePassword(e) {
    e.preventDefault();

    const currentPassword = document.getElementById('current-password-input')?.value?.trim() || '';
    const newPassword = document.getElementById('new-password-input')?.value?.trim() || '';
    const confirmPassword = document.getElementById('confirm-password-input')?.value?.trim() || '';
    const submitBtn = document.getElementById('change-password-submit');

    if (!currentPassword || !newPassword || !confirmPassword) {
        showToast('Validation Error', 'All password fields are required.', 'warning');
        return;
    }

    if (newPassword.length < 8) {
        showToast('Validation Error', 'New password must be at least 8 characters long.', 'warning');
        return;
    }

    if (newPassword !== confirmPassword) {
        showToast('Validation Error', 'New password and confirmation do not match.', 'warning');
        return;
    }

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Updating...';
    }

    try {
        const response = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });

        const data = await response.json();

        if (!response.ok || data.error) {
            showToast('Password Update Failed', data.error || 'Unable to update password.', 'error');
            return;
        }

        closeChangePasswordModal();
        showToast('Password Updated', 'Please sign in again with your new password.', 'success', 4000, true);
        setTimeout(() => {
            handleLogout();
        }, 1200);
    } catch (err) {
        console.error('Password update failed:', err);
        showToast('Network Error', 'Could not update the password right now.', 'error');
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerText = 'Update Password';
        }
    }
}

function checkAuth() {
    const userId = localStorage.getItem('user_id');
    const isLoginPage = window.location.pathname.includes('login.html') || window.location.pathname.includes('signup.html') || window.location.pathname === '/' || window.location.pathname === '';

    if (!userId && !isLoginPage) {
        window.location.href = 'login.html';
    } else if (userId) {
        // Update UI if needed
        const userNameDisplay = document.getElementById('user-name-display');
        if (userNameDisplay) {
            const storedName = localStorage.getItem('user_name');
            const fallbackFromProfile = document.getElementById('profile-name')?.innerText?.trim();
            const fallbackName = storedName || fallbackFromProfile || 'User';
            userNameDisplay.innerText = fallbackName;
        }
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
    const joinedMetricEl = document.getElementById('profile-joined-metric');
    const initialsEl = document.getElementById('profile-avatar-initials');

    if (data.user_name) {
        localStorage.setItem('user_name', data.user_name);
        nameEls.forEach(el => el.innerText = data.user_name);
        const userNameDisplay = document.getElementById('user-name-display');
        if (userNameDisplay) userNameDisplay.innerText = data.user_name;
        // Set initials
        const parts = data.user_name.split(' ');
        const initials = parts.map(p => p[0]).join('').toUpperCase().substring(0, 2);
        if (initialsEl) initialsEl.innerText = initials;
    }

    const email = localStorage.getItem('user_email');
    if (email) {
        emailEls.forEach(el => el.innerText = email);
    }

    if (data.joined_date) {
        if (joinedEl) joinedEl.innerText = data.joined_date;
        if (joinedMetricEl) joinedMetricEl.innerText = data.joined_date;
    }

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
            <div class="indicator-card">
                <div class="indicator-label">${label}</div>
                <div class="indicator-value-row">
                    <span class="indicator-value">${val}</span>
                    <span class="indicator-icon">${icon}</span>
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

    const isSmsScan = String(scanType || '').toUpperCase() === 'SMS';

    container.classList.remove('hidden');
    container.innerHTML = '';

    const resultWrapper = document.createElement('div');
    resultWrapper.className = `premium-dashboard-container${isSmsScan ? ' sms-result-full' : ''}`;

    if (data.error) {
        resultWrapper.innerHTML = `
            <div class="glass-card" style="border-top: 4px solid #ef4444;">
                <div style="display:flex; align-items:center; gap:1rem; color:#ef4444;">
                    <i class="fa-solid fa-triangle-exclamation" style="font-size:1.875rem;"></i>
                    <div>
                        <h3 style="font-weight:700; font-size:1.125rem; margin-bottom:0.25rem;">Analysis Error</h3>
                        <p style="font-size:0.875rem; opacity:0.8; margin:0;">${data.error}</p>
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
                        <h2 class="scan-target-banner__url" style="font-size:1.25rem; font-weight:900; color:#fff; margin-bottom:0.75rem; word-break:break-all; line-height:1.375;">${urlDisplay}</h2>
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
                        <span style="font-size: 8px; color: var(--text-secondary); font-weight: 700; text-transform: uppercase; letter-spacing: 0.15em; margin-top: 4px; display:block; text-align:center;">Risk Index</span>
                    </div>
                </div>
                <!-- FIX: confidence label centred and no scale transform -->
                <div style="text-align:center; margin-top: 8px;">
                    <span style="font-size:10px; font-weight:900; color: var(--text-secondary); text-transform: uppercase; letter-spacing:0.1em;">
                        Confidence: <span style="color: var(--text-primary);">${(confidence * 100).toFixed(1)}%</span>
                    </span>
                </div>
            </div>
        </div>
        <div class="premium-grid mt-4">
            <!-- Left Column -->
            <div class="results-grid-col results-grid-col--main">

                <!-- 3. AI Forensic Analysis -->
                <div class="glass-card ai-card result-glass-card ai-forensic-card">
                    <div class="ai-card-head" style="display:flex; align-items:center; gap:0.75rem; border-bottom:1px solid rgba(148,163,184,0.2); margin-bottom:1rem; padding-bottom:0.75rem;">
                        <div style="display:flex; align-items:center; justify-content:center; padding:0.5rem; background:rgba(6,182,212,0.1); color:var(--accent); border-radius:0.5rem;">
                            <i class="fa-solid fa-brain" style="font-size:1.25rem;"></i>
                        </div>
                        <h3 style="margin:0; font-size:0.875rem; font-weight:900; color:#fff; text-transform:uppercase; letter-spacing:0.1em;">AI Forensic Analysis</h3>
                    </div>
                    <div class="ai-content">
                        <p class="ai-summary" style="font-size:0.95rem; font-weight:700; color:var(--text-primary); line-height:1.4; margin-bottom:0.5rem;">${aiSummary}</p>
                        <p class="ai-reason" style="color:var(--text-secondary); font-size:0.875rem; line-height:1.625; font-weight:500; white-space:pre-line;">${aiReason}</p>
                        <div class="recommendation-box" style="padding:1rem; border-radius:0.75rem; background:var(--bg-surface-alt); border:1px solid var(--border-dim); position:relative; overflow:hidden; margin-top:1rem;">
                            <div style="position:absolute; left:0; top:0; bottom:0; width:0.25rem; background:var(--accent);"></div>
                            <span style="opacity:0.6; font-size:10px; color:var(--text-secondary); text-transform:uppercase; font-weight:900; letter-spacing:0.1em; display:block; margin-bottom:0.375rem;">Recommendation Directive</span>
                            <span style="font-size:0.875rem; font-weight:600; color:var(--text-primary);">${aiRecommendation}</span>
                        </div>
                    </div>
                </div>
            </div>

            ${isSmsScan ? '' : `
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
                                iconColor='#ef4444'; statusColor2='#ef4444';
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
                                <span style="font-size:0.82rem; font-weight:600; color: var(--text-primary); flex:1;">${chk.name}</span>
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
            </div>
            `}
        </div>


        <!-- 7. Action Buttons — FIX: align-items center -->
        <div class="action-buttons-grid mt-4" style="display:flex; flex-wrap:wrap; gap:0.5rem; align-items:center;">
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
        <div class="verdict-banner ${statusClass}">
            <div style="display:flex; align-items:center; gap:1.25rem; position:relative; z-index:10;">
                <i class="fa-solid ${isSafe ? 'fa-shield-check' : (isHighRisk ? 'fa-triangle-exclamation' : 'fa-circle-info')}" style="font-size:2rem; flex-shrink:0;"></i>
                <div style="min-width:0;">
                    <!-- FIX: verdict label and text vertically spaced cleanly -->
                    <h2 style="font-size:0.6rem; font-weight:900; text-transform:uppercase; letter-spacing:0.2em; opacity:0.65; margin-bottom:0.375rem;">Official Verdict Declaration</h2>
                    <p style="font-size:1rem; font-weight:800; line-height:1.4; letter-spacing:-0.01em; color:${statusColor}; margin:0;">${finalVerdict}</p>
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
                    backgroundColor: [statusColor, 'var(--bg-surface-alt)'],
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
}function showToast(title, message, type = 'info', duration = 4000, force = false) {
    const toast = document.getElementById('toast');
    if (!toast) return;

    if (!force && typeof isNotificationsEnabled === 'function' && !isNotificationsEnabled() && type !== 'error') {
        return;
    }

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
    const userEmail = localStorage.getItem('user_email');
    return {
        'Content-Type': 'application/json',
        'X-User-Id': userId || '',
        'X-User-Email': userEmail || ''
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

function triggerActiveToolPrimaryAction() {
    const activePanel = document.querySelector('.tool-panel:not(.hidden)');
    if (!activePanel) return false;

    const primaryButton = activePanel.querySelector(
        '#url-scan-btn, #domain-check-btn, #web-scan-btn, #file-scan-btn, #email-scan-btn, #sms-scan-btn, #qr-scan-btn'
    );

    if (!primaryButton || primaryButton.disabled) return false;
    primaryButton.click();
    return true;
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
    refreshProfileSettingsState();

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

    // Enter key should trigger the primary action button for the active scanner module.
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' || e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;

        const activePanel = document.querySelector('.tool-panel:not(.hidden)');
        if (!activePanel) return;

        const activeEl = document.activeElement;
        if (!activeEl || !activePanel.contains(activeEl)) return;

        const tag = (activeEl.tagName || '').toLowerCase();
        const isTypingControl = tag === 'input' || tag === 'textarea';
        const isButtonLike = tag === 'button' || tag === 'a';

        if (!isTypingControl || isButtonLike) return;

        e.preventDefault();
        triggerActiveToolPrimaryAction();
    });

    // History search listener
    const historySearch = document.getElementById('history-search');
    if (historySearch) {
        historySearch.addEventListener('input', () => {
            fetchHistory();
        });
    }

    const changePasswordForm = document.getElementById('change-password-form');
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', submitChangePassword);
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
        wrapper.innerHTML = `
            <div class="glass-card" style="border-top: 4px solid #ef4444;">
                <div style="display:flex; align-items:center; gap:1rem; color:#ef4444;">
                    <i class="fa-solid fa-triangle-exclamation" style="font-size:1.875rem;"></i>
                    <div>
                        <h3 style="font-weight:700; font-size:1.125rem; margin-bottom:0.25rem;">Domain Lookup Error</h3>
                        <p style="font-size:0.875rem; opacity:0.8; margin:0;">${data.error}</p>
                    </div>
                </div>
            </div>
        `;
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
    const isSafe = threatStatus.toLowerCase().includes('safe') || threatStatus.toLowerCase().includes('benign');
    const isThreat = threatStatus.toLowerCase().includes('malware') || threatStatus.toLowerCase().includes('phishing');
    const statusClass = isSafe ? 'status-safe' : (isThreat ? 'status-danger' : 'status-warning');
    const statusColor = isSafe ? '#10b981' : (isThreat ? '#ef4444' : '#f59e0b');
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

    // Keep domain forensic indicators concise and relevant for UI density.
    indicators = indicators.filter((ind) => {
        const label = String(ind.name || ind.label || '').toLowerCase().trim();
        return label !== 'dns ns' && label !== 'dns ns record' && label !== 'hosting country';
    });

    if (!indicators.length) {
        indicators = [
            { name: 'Threat Status', value: threatStatus, status: isThreat ? 'danger' : (isSafe ? 'safe' : 'warning') },
            { name: 'Registrar', value: dInfo.registrar || 'N/A', status: 'warning' },
            { name: 'Domain Age', value: dInfo.domain_age || 'N/A', status: 'safe' }
        ];
    }

    wrapper.className = 'premium-dashboard-container domain-result-container animate-fade-in';
    wrapper.innerHTML = `
        <!-- 1. Summary Header -->
        <div class="glass-card summary-header" style="border-top: 4px solid ${statusColor};">
            <div class="summary-info">
                <div class="scan-target-banner" style="background:transparent; border:none; padding:0; margin:0; box-shadow:none;">
                    <div class="scan-target-banner__top">
                        <div class="scan-target-banner__heading">
                            <span class="scan-target-banner__kicker">Intelligence Analysis Target</span>
                            <p class="scan-target-banner__hint">Deep-scanning domain records and hosting reputation. This report is isolated to the asset below.</p>
                        </div>
                        <div class="scan-target-banner__proto" style="background:rgba(255,255,255,0.05); border-color:rgba(255,255,255,0.1); color:#fff; padding: 0.5rem 1rem;">
                            <i class="fa-solid fa-globe" aria-hidden="true"></i>
                            <span class="scan-target-banner__proto-text">
                                <span class="scan-target-banner__proto-title">Domain</span>
                                <span class="scan-target-banner__proto-sub">Architecture</span>
                            </span>
                        </div>
                    </div>
                    <h2 class="scan-target-banner__url" style="font-size:1.5rem; font-weight:900; color:#fff; margin-bottom:0.75rem; margin-top:1rem; word-break:break-all; line-height:1.375; letter-spacing:-0.02em;">${domain}</h2>
                </div>
                <div class="summary-meta-row">
                    <div class="meta-item">
                        <i class="fa-solid fa-microchip"></i>
                        <span>${engine}</span>
                    </div>
                    <div class="meta-item">
                        <i class="fa-regular fa-clock"></i>
                        <span>${scanTime}</span>
                    </div>
                    <div class="meta-item">
                        <span class="status-badge ${statusClass}">${threatStatus}</span>
                    </div>
                </div>
            </div>
            <div class="score-container summary-score-col">
                <div class="chart-wrapper">
                    <canvas id="domain-chart-${Date.now()}"></canvas>
                    <div class="chart-center">
                        <span style="font-size: 2.25rem; font-weight: 900; color: ${statusColor}; line-height: 1; letter-spacing: -0.04em; display:block; text-align:center;">${riskScore}</span>
                        <span style="font-size: 8px; color: var(--text-secondary); font-weight: 700; text-transform: uppercase; letter-spacing: 0.15em; margin-top: 4px; display:block; text-align:center;">Risk Index</span>
                    </div>
                </div>
                <div style="text-align:center; margin-top: 8px;">
                     <span style="font-size:10px; font-weight:900; color: var(--text-secondary); text-transform: uppercase; letter-spacing:0.1em;">
                        Confidence: <span style="color: var(--text-primary);">${(confidence * 100).toFixed(1)}%</span>
                     </span>
                </div>
            </div>
        </div>

        <div class="premium-grid">
            <div class="results-grid-col">
                <!-- 2. Domain Information -->
                <div class="glass-card result-glass-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-globe mr-2"></i> Infrastructure Profile</h3>
                    <div style="display:flex; flex-direction:column; gap:0.75rem;">
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Registrar:</span><span style="color:#e2e8f0; font-size:0.85rem; font-weight:700;">${dInfo.registrar || 'N/A'}</span></div>
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Creation:</span><span style="color:#e2e8f0; font-size:0.85rem; font-weight:700;">${dInfo.creation_date || 'N/A'}</span></div>
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Age:</span><span style="color:#10b981; font-size:0.85rem; font-weight:700;">${dInfo.domain_age || 'N/A'}</span></div>
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">WHOIS:</span><span style="font-size:0.85rem; font-weight:700;">${dInfo.whois_hidden ? '<span class="text-amber-400">Hidden</span>' : '<span class="text-emerald-400">Public</span>'}</span></div>
                    </div>
                </div>

                <!-- 3. Hosting Details -->
                <div class="glass-card result-glass-card domain-hosting-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-server mr-2"></i> Hosting Architecture</h3>
                    <div style="display:flex; flex-direction:column; gap:0.75rem;">
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Primary IP:</span><span style="color:#3b82f6; font-size:0.85rem; font-weight:700; font-family:monospace;">${hInfo.ip_address || 'N/A'}</span></div>
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Provider:</span><span style="color:#e2e8f0; font-size:0.85rem; font-weight:700; font-family:monospace;">${hInfo.hosting_provider || 'N/A'}</span></div>
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Country:</span><span style="color:#e2e8f0; font-size:0.85rem; font-weight:700;">${hInfo.country || 'N/A'}</span></div>
                    </div>
                </div>
            </div>

            <div class="results-grid-col">
                <!-- 4. DNS Matrix -->
                <div class="glass-card result-glass-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-network-wired mr-2"></i> DNS Records Matrix</h3>
                    <div style="display:grid; grid-template-columns:repeat(2,1fr); gap:0.5rem;">
                        ${Object.entries(dns).map(([type, status]) => `
                            <div style="background:rgba(255,255,255,0.03); padding:0.5rem; border-radius:8px; border:1px solid rgba(255,255,255,0.05); text-align:center;">
                                <div style="font-size:0.6rem; font-weight:800; opacity:0.5; text-transform:uppercase;">${type}</div>
                                <div style="font-size:0.8rem; font-weight:700; color:${status.toLowerCase() === 'present' ? '#10b981' : '#ef4444'};">${status}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- 5. Technical Indicators -->
                <div class="glass-card result-glass-card domain-forensic-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-gauge-high mr-2"></i> Forensic Indicators</h3>
                    <div class="result-indicators-grid domain-indicators-grid">
                        ${renderIndicatorGridCells(indicators)}
                    </div>
                </div>
            </div>
        </div>

        <!-- 6. Action Buttons -->
        <div class="action-buttons-grid" style="display:flex; flex-wrap:wrap; gap:0.5rem; align-items:center;">
            <button class="neon-btn btn-secondary" onclick="triggerRescan('Domain', '${domain.replace(/'/g, "\\'")}')"><i class="fa-solid fa-rotate-right"></i> Rescan Artifact</button>
            <button class="neon-btn btn-secondary" onclick="window.print()"><i class="fa-solid fa-file-pdf"></i> Download Report</button>
            <button class="neon-btn btn-danger" onclick="addToBlacklist('${domain.replace(/'/g, "\\'")}', 'Domain')"><i class="fa-solid fa-ban"></i> Add to Blacklist</button>
            <button class="neon-btn btn-success" style="border-color:rgba(16,185,129,0.3);color:#10b981;" onclick="addToWhitelist('${domain.replace(/'/g, "\\'")}', 'Domain')"><i class="fa-solid fa-shield-check"></i> Add to Whitelist</button>
        </div>

        <!-- 7. Verdict Banner -->
        <div class="verdict-banner ${statusClass}">
            <div style="display:flex; align-items:center; gap:1.25rem; position:relative; z-index:10;">
                <i class="fa-solid ${statusIcon}" style="font-size:2rem; flex-shrink:0;"></i>
                <div style="min-width:0;">
                    <h2 style="font-size:0.6rem; font-weight:900; text-transform:uppercase; letter-spacing:0.2em; opacity:0.65; margin-bottom:0.375rem;">Official Intelligence Verdict</h2>
                    <p style="font-size:1rem; font-weight:800; line-height:1.4; letter-spacing:-0.01em; color:${statusColor}; margin:0;">${finalVerdict}</p>
                </div>
            </div>
            <div class="banner-bg-glow"></div>
        </div>
    `;

    container.appendChild(wrapper);

    // Initialise Chart if in DOM
    setTimeout(() => {
        const canvas = wrapper.querySelector('canvas');
        if (canvas) {
            new Chart(canvas, {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [riskScore, 100 - riskScore],
                        backgroundColor: [statusColor, 'var(--bg-surface-alt)'],
                        borderWidth: 0,
                        borderRadius: 6,
                        cutout: '82%'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { tooltip: { enabled: false }, legend: { display: false } }
                }
            });
        }
    }, 100);
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
        wrapper.innerHTML = `
            <div class="glass-card" style="border-top: 4px solid #ef4444;">
                <div style="display:flex; align-items:center; gap:1rem; color:#ef4444;">
                    <i class="fa-solid fa-triangle-exclamation" style="font-size:1.875rem;"></i>
                    <div>
                        <h3 style="font-weight:700; font-size:1.125rem; margin-bottom:0.25rem;">Website Inspection Error</h3>
                        <p style="font-size:0.875rem; opacity:0.8; margin:0;">${data.error}</p>
                    </div>
                </div>
            </div>
        `;
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
    const wIcon = isSafe ? 'fa-shield-check' : (isThreat ? 'fa-skull-crossbones' : 'fa-triangle-exclamation');
    const statusColor = isSafe ? '#10b981' : (isThreat ? '#ef4444' : '#f59e0b');
    const statusClass = isSafe ? 'status-safe' : (isThreat ? 'status-danger' : 'status-warning');

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
            { name: 'Hidden Forms', value: secAna.hidden_forms ? 'Yes' : 'No', status: secAna.hidden_forms ? 'warning' : 'safe' }
        ];
    }

    // Keep behavioral indicators concise and avoid noisy infra-only values.
    indicators = indicators.filter((ind) => {
        const label = String(ind.name || ind.label || '').toLowerCase().trim();
        return label !== 'dns ns'
            && label !== 'dns ns record'
            && label !== 'hosting country'
            && label !== 'password field'
            && label !== 'external script domains';
    });

    if (!indicators.length) {
        indicators = [
            { name: 'HTTPS', value: secAna.https ? 'Yes' : 'No', status: secAna.https ? 'safe' : 'danger' },
            { name: 'Suspicious JS', value: secAna.suspicious_js ? 'Flagged' : 'No', status: secAna.suspicious_js ? 'warning' : 'safe' },
            { name: 'Hidden Forms', value: secAna.hidden_forms ? 'Yes' : 'No', status: secAna.hidden_forms ? 'warning' : 'safe' }
        ];
    }

    wrapper.className = 'premium-dashboard-container website-result-container animate-fade-in';
    wrapper.innerHTML = `
        <!-- 1. Summary Header -->
        <div class="glass-card summary-header" style="border-top: 4px solid ${statusColor};">
            <div class="summary-info">
                <div class="scan-target-banner" style="background:transparent; border:none; padding:0; margin:0; box-shadow:none;">
                    <div class="scan-target-banner__top">
                        <div class="scan-target-banner__heading">
                            <span class="scan-target-banner__kicker">Website Content Analysis</span>
                            <p class="scan-target-banner__hint">Analyzing page source, script behaviors, and 3rd-party resource integrations.</p>
                        </div>
                        <div class="scan-target-banner__proto" style="background:rgba(255,255,255,0.05); border-color:rgba(255,255,255,0.1); color:#fff; padding: 0.5rem 1rem;">
                            <i class="fa-solid fa-code" aria-hidden="true"></i>
                            <span class="scan-target-banner__proto-text">
                                <span class="scan-target-banner__proto-title">Static</span>
                                <span class="scan-target-banner__proto-sub">Intelligence</span>
                            </span>
                        </div>
                    </div>
                    <h2 class="scan-target-banner__url" style="font-size:1.5rem; font-weight:900; color:#fff; margin-bottom:0.75rem; margin-top:1rem; word-break:break-all; line-height:1.375; letter-spacing:-0.02em;">${url}</h2>
                </div>
                <div class="summary-meta-row mt-4">
                    <div class="meta-item">
                        <i class="fa-solid fa-microchip"></i>
                        <span>${engine}</span>
                    </div>
                    <div class="meta-item">
                        <i class="fa-regular fa-clock"></i>
                        <span>${scanTime}</span>
                    </div>
                    <div class="meta-item">
                        <span class="status-badge ${statusClass}">${threatStatus}</span>
                    </div>
                </div>
            </div>
            <div class="score-container summary-score-col">
                <div class="chart-wrapper">
                    <canvas id="web-chart-${Date.now()}"></canvas>
                    <div class="chart-center">
                        <span style="font-size: 2.25rem; font-weight: 900; color: ${statusColor}; line-height: 1; letter-spacing: -0.04em; display:block; text-align:center;">${riskScore}</span>
                        <span style="font-size: 8px; color: var(--text-secondary); font-weight: 700; text-transform: uppercase; letter-spacing: 0.15em; margin-top: 4px; display:block; text-align:center;">Risk Index</span>
                    </div>
                </div>
                <div style="text-align:center; margin-top: 8px;">
                     <span style="font-size:10px; font-weight:900; color: var(--text-secondary); text-transform: uppercase; letter-spacing:0.1em;">
                        Confidence: <span style="color: var(--text-primary);">${(confidence * 100).toFixed(1)}%</span>
                     </span>
                </div>
            </div>
        </div>

        <div class="premium-grid mt-4">
            <div class="results-grid-col">
                <!-- 2. Page Profile -->
                <div class="glass-card result-glass-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-file-invoice mr-2"></i> Document Fingerprint</h3>
                    <div style="display:flex; flex-direction:column; gap:0.75rem;">
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Page Title:</span><span style="color:#e2e8f0; font-size:0.85rem; font-weight:700; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${pInfo.title || 'N/A'}</span></div>
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Payload Size:</span><span style="color:#e2e8f0; font-size:0.85rem; font-weight:700;">${pInfo.page_size || 'N/A'}</span></div>
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Load Latency:</span><span style="color:#10b981; font-size:0.85rem; font-weight:700;">${pInfo.load_time || 'N/A'}</span></div>
                        <div style="display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;"><span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">Active Scripts:</span><span style="color:#e2e8f0; font-size:0.85rem; font-weight:700;">${pInfo.scripts ?? 0}</span></div>
                    </div>
                </div>

                <!-- 3. Security Hardening -->
                <div class="glass-card result-glass-card mt-4">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-shield-virus mr-2"></i> Security Posture</h3>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
                        ${Object.entries(secAna).map(([k, v]) => `
                            <div style="background:rgba(255,255,255,0.03); padding:0.6rem; border-radius:8px; border:1px solid rgba(255,255,255,0.05); display:flex; justify-content:space-between; align-items:center;">
                                <span style="font-size:0.65rem; font-weight:700; color:#94a3b8; text-transform:uppercase;">${k.replace(/_/g, ' ')}</span>
                                <i class="fa-solid ${v ? 'fa-circle-check text-emerald-400' : 'fa-circle-xmark text-slate-600'}" style="font-size:0.85rem;"></i>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- 4 & 5. Tech & Resources (SIDE BY SIDE) -->
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:1.25rem;" class="mt-4">
                    <div class="glass-card result-glass-card" style="margin:0; padding:1.25rem;">
                        <h3 class="text-[10px] font-black text-slate-400 mb-3 uppercase tracking-widest"><i class="fa-solid fa-layer-group mr-1.5"></i> Platform Stack</h3>
                        <div style="display:flex; flex-wrap:wrap; gap:0.4rem;">
                            ${techs.map(t => `<span style="background:rgba(6,182,212,0.1); color:#22d3ee; border:1px solid rgba(6,182,212,0.2); border-radius:4px; padding:2px 6px; font-size:10px; font-weight:700;">${t}</span>`).join('')}
                            ${techs.length === 0 ? '<span style="opacity:0.4; font-size:10px;">None Detected</span>' : ''}
                        </div>
                    </div>
                    <div class="glass-card result-glass-card" style="margin:0; padding:1.25rem;">
                        <h3 class="text-[10px] font-black text-slate-400 mb-3 uppercase tracking-widest"><i class="fa-solid fa-link-slash mr-1.5"></i> External Deps</h3>
                        <div style="display:flex; flex-wrap:wrap; gap:0.4rem;">
                            ${extRes.map(r => `<span style="background:rgba(251,191,36,0.1); color:#fbbf24; border:1px solid rgba(251,191,36,0.2); border-radius:4px; padding:2px 6px; font-size:10px; font-weight:700;">${r}</span>`).join('')}
                            ${extRes.length === 0 ? '<span style="opacity:0.4; font-size:10px;">None Detected</span>' : ''}
                        </div>
                    </div>
                </div>
            </div>

            <div class="results-grid-col">
                <!-- 6. Diagnostic Checklist -->
                <div class="glass-card result-glass-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-clipboard-check mr-2"></i> Integrity Checklist</h3>
                    <div style="display:flex; flex-direction:column; gap:0.5rem;">
                        ${checks.map(chk => {
                            let statusColor2 = chk.status === 'success' || chk.status === 'passed' ? '#10b981' : (chk.status === 'failed' ? '#ef4444' : '#f59e0b');
                            let statusIcon2 = chk.status === 'success' || chk.status === 'passed' ? 'fa-circle-check' : (chk.status === 'failed' ? 'fa-circle-xmark' : 'fa-triangle-exclamation');
                            return `
                                <div style="display:flex; align-items:center; gap:0.75rem; padding:0.6rem 0.8rem; background:var(--bg-surface-alt); border-radius:10px; border:1px solid var(--border-dim);">
                                    <i class="fa-solid ${statusIcon2}" style="color:${statusColor2}; font-size:1rem;"></i>
                                    <div style="flex-grow:1;">
                                        <div style="font-size:0.8rem; font-weight:700; color:var(--text-primary);">${chk.name}</div>
                                        <div style="font-size:0.65rem; color:var(--text-secondary); font-weight:600;">${chk.status.toUpperCase()}</div>
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>

                <!-- 7. Forensic Indicators -->
                <div class="glass-card result-glass-card mt-4 website-behavior-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-gauge-high mr-2"></i> Behavioral Indicators</h3>
                    <div class="result-indicators-grid website-behavior-indicators-grid">
                        ${renderIndicatorGridCells(indicators)}
                    </div>
                </div>
            </div>
        </div>

        <!-- 8. Actions -->
        <div class="action-buttons-grid mt-4" style="display:flex; flex-wrap:wrap; gap:0.5rem; align-items:center;">
            <button class="neon-btn btn-secondary" onclick="triggerRescan('Website', '${url.replace(/'/g, "\\'")}')"><i class="fa-solid fa-rotate-right"></i> Rescan Page</button>
            <button class="neon-btn btn-secondary" onclick="window.print()"><i class="fa-solid fa-file-pdf"></i> Download Report</button>
            <button class="neon-btn btn-danger" onclick="addToBlacklist('${url.replace(/'/g, "\\'")}', 'Website')"><i class="fa-solid fa-ban"></i> Add to Blacklist</button>
            <button class="neon-btn btn-success" style="border-color:rgba(16,185,129,0.3);color:#10b981;" onclick="addToWhitelist('${url.replace(/'/g, "\\'")}', 'Website')"><i class="fa-solid fa-shield-check"></i> Add to Whitelist</button>
        </div>

        <!-- 9. Verdict Banner -->
        <div class="verdict-banner ${statusClass}">
            <div style="display:flex; align-items:center; gap:1.25rem; position:relative; z-index:10;">
                <i class="fa-solid ${wIcon}" style="font-size:2rem; flex-shrink:0;"></i>
                <div style="min-width:0;">
                    <h2 style="font-size:0.6rem; font-weight:900; text-transform:uppercase; letter-spacing:0.2em; opacity:0.65; margin-bottom:0.375rem;">Final Security Verdict</h2>
                    <p style="font-size:1rem; font-weight:800; line-height:1.4; letter-spacing:-0.01em; color:${statusColor}; margin:0;">${finalVerdict}</p>
                </div>
            </div>
            <div class="banner-bg-glow"></div>
        </div>
    `;

    container.appendChild(wrapper);

    // Initialise Chart if in DOM
    setTimeout(() => {
        const canvas = wrapper.querySelector('canvas');
        if (canvas) {
            new Chart(canvas, {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [riskScore, 100 - riskScore],
                        backgroundColor: [statusColor, 'var(--bg-surface-alt)'],
                        borderWidth: 0,
                        borderRadius: 6,
                        cutout: '82%'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { tooltip: { enabled: false }, legend: { display: false } }
                }
            });
        }
    }, 100);
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
    const hash = data.hash_info || {};
    const mal = data.malware_analysis || {};
    const stat = data.static_analysis || {};
    const checks = data.security_checks || [];

    const isSafe = threat.toLowerCase().includes('safe') || threat.toLowerCase().includes('benign');
    const isThreat = threat.toLowerCase().includes('malware');
    const statusColor = isSafe ? '#10b981' : (isThreat ? '#ef4444' : '#f59e0b');
    const statusClass = isSafe ? 'status-safe' : (isThreat ? 'status-danger' : 'status-warning');
    const fIcon = isSafe ? 'fa-shield-check' : (isThreat ? 'fa-biohazard' : 'fa-triangle-exclamation');

    wrapper.className = 'premium-dashboard-container email-result-modern animate-fade-in';
    wrapper.innerHTML = `
        <!-- 1. Summary Header -->
        <div class="glass-card summary-header" style="border-top: 4px solid ${statusColor};">
            <div class="summary-info">
                <div class="scan-target-banner" style="background:transparent; border:none; padding:0; margin:0; box-shadow:none;">
                    <div class="scan-target-banner__top">
                        <div class="scan-target-banner__heading">
                            <span class="scan-target-banner__kicker">Binary Asset Analysis</span>
                            <p class="scan-target-banner__hint">Analyzing file structure, entropy, and embedded code patterns for malicious indicators.</p>
                        </div>
                        <div class="scan-target-banner__proto" style="background:rgba(255,255,255,0.05); border-color:rgba(255,255,255,0.1); color:#fff; padding: 0.5rem 1rem;">
                            <i class="fa-solid fa-file-shield" aria-hidden="true"></i>
                            <span class="scan-target-banner__proto-text">
                                <span class="scan-target-banner__proto-title">${fileType}</span>
                                <span class="scan-target-banner__proto-sub">${fileSize}</span>
                            </span>
                        </div>
                    </div>
                    <h2 class="scan-target-banner__url text-2xl font-black text-white mb-2 mt-4 break-all leading-tight tracking-tight">${filename}</h2>
                </div>
                <div class="summary-meta-row mt-4">
                    <div class="meta-item">
                        <i class="fa-solid fa-microchip"></i>
                        <span>${engine}</span>
                    </div>
                    <div class="meta-item">
                        <i class="fa-regular fa-clock"></i>
                        <span>${scanTime}</span>
                    </div>
                    <div class="meta-item">
                        <span class="status-badge ${statusClass}">${threat}</span>
                    </div>
                </div>
            </div>
            <div class="summary-score-col">
                <div class="chart-wrapper">
                    <canvas id="file-chart-${Date.now()}"></canvas>
                    <div class="chart-center">
                        <span style="font-size:1.5rem; font-weight:800; color:${statusColor};">${riskScore}</span>
                        <span style="font-size:0.5rem; font-weight:700; opacity:0.6; text-transform:uppercase;">Risk</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="premium-grid mt-4">
            <div class="results-grid-col">
                <!-- 2. Hash & Integrity -->
                <div class="glass-card result-glass-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-fingerprint mr-2"></i> Integrity Signatures</h3>
                    <div style="display:flex; flex-direction:column; gap:0.75rem;">
                        <div style="display:flex; flex-direction:column; gap:0.25rem; border-bottom:1px solid rgba(255,255,255,0.03); padding-bottom:0.5rem;">
                            <span style="color:var(--text-secondary); font-size:0.7rem; font-weight:700; text-transform:uppercase;">MD5 Hash</span>
                            <span style="color:var(--text-primary); font-size:0.8rem; font-family:monospace; word-break:break-all;">${hash.md5 || 'N/A'}</span>
                        </div>
                        <div style="display:flex; flex-direction:column; gap:0.25rem;">
                            <span style="color:var(--text-secondary); font-size:0.7rem; font-weight:700; text-transform:uppercase;">SHA-256 Signature</span>
                            <span style="color:var(--text-primary); font-size:0.8rem; font-family:monospace; word-break:break-all;">${hash.sha256 || 'N/A'}</span>
                        </div>
                    </div>
                </div>

                <!-- 3. Malware Investigation -->
                <div class="glass-card result-glass-card mt-4">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-virus-slash mr-2"></i> Malware Analysis</h3>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
                        ${Object.entries(mal).map(([k, v]) => `
                            <div style="background:var(--bg-surface-alt); padding:0.6rem; border-radius:8px; border:1px solid var(--border-dim); display:flex; justify-content:space-between; align-items:center;">
                                <span style="font-size:0.6rem; font-weight:700; color:var(--text-secondary); text-transform:uppercase;">${k.replace(/_/g, ' ')}</span>
                                <i class="fa-solid ${v ? 'fa-circle-xmark text-red-400' : 'fa-circle-check text-emerald-400'}" style="font-size:0.85rem;"></i>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>

            <div class="results-grid-col">
                <!-- 4. Security Verification -->
                <div class="glass-card result-glass-card">
                    <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-clipboard-check mr-2"></i> Security Verification</h3>
                    <div style="display:flex; flex-direction:column; gap:0.5rem;">
                        ${checks.map(chk => {
                            let statusColor2 = chk.status === 'success' || chk.status === 'passed' ? '#10b981' : (chk.status === 'failed' ? '#ef4444' : '#f59e0b');
                            let statusIcon2 = chk.status === 'success' || chk.status === 'passed' ? 'fa-circle-check' : (chk.status === 'failed' ? 'fa-circle-xmark' : 'fa-triangle-exclamation');
                            return `
                                <div style="display:flex; align-items:center; gap:0.75rem; padding:0.6rem 0.8rem; background:var(--bg-surface-alt); border-radius:10px; border:1px solid var(--border-dim);">
                                    <i class="fa-solid ${statusIcon2}" style="color:${statusColor2}; font-size:1rem;"></i>
                                    <div style="flex-grow:1;">
                                        <div style="font-size:0.8rem; font-weight:700; color:var(--text-primary);">${chk.name}</div>
                                        <div style="font-size:0.65rem; color:var(--text-secondary); font-weight:600;">${chk.status.toUpperCase()}</div>
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>

            </div>
        </div>

        <div class="glass-card result-glass-card file-static-indicators-card">
            <h3 class="text-sm font-black text-white mb-4 uppercase tracking-widest border-b border-slate-700/50 pb-3"><i class="fa-solid fa-microscope mr-2"></i> Static Indicators</h3>
            <div class="file-static-indicators-grid">
                 ${Object.entries(stat).map(([k, v]) => `
                    <div class="file-static-indicator-item">
                        <span class="file-static-indicator-label">${k.replace(/_/g, ' ')}</span>
                        <span class="file-static-indicator-value">${Array.isArray(v) ? v.join(', ') : v}</span>
                    </div>
                `).join('')}
                <div class="file-static-indicator-item">
                    <span class="file-static-indicator-label">Risk Score</span>
                    <span class="file-static-indicator-value">${riskScore}</span>
                </div>
            </div>
        </div>

        <!-- 6. Actions -->
        <div class="action-buttons-grid mt-4" style="display:flex; flex-wrap:wrap; gap:0.5rem; align-items:center;">
            <button class="neon-btn btn-secondary" onclick="document.getElementById('file-input').click()"><i class="fa-solid fa-rotate-right"></i> Rescan Artifact</button>
            <button class="neon-btn btn-secondary" onclick="window.print()"><i class="fa-solid fa-file-pdf"></i> Download Report</button>
            <button class="neon-btn btn-danger" onclick="addToBlacklist('${filename.replace(/'/g, "\\'")}', 'File')"><i class="fa-solid fa-ban"></i> Add to Blacklist</button>
            <button class="neon-btn btn-success" style="border-color:rgba(16,185,129,0.3);color:#10b981;" onclick="addToWhitelist('${filename.replace(/'/g, "\\'")}', 'File')"><i class="fa-solid fa-shield-check"></i> Add to Whitelist</button>
        </div>

        <!-- 7. Verdict Banner -->
        <div class="verdict-banner ${statusClass}">
            <div class="flex items-center gap-5 relative z-10">
                <i class="fa-solid ${fIcon}" style="font-size:2rem; flex-shrink:0;"></i>
                <div style="min-width:0;">
                    <h2 style="font-size:0.6rem; font-weight:900; text-transform:uppercase; letter-spacing:0.2em; opacity:0.65; margin-bottom:0.375rem;">Official Security Verdict</h2>
                    <p style="font-size:1rem; font-weight:800; line-height:1.4; letter-spacing:-0.01em; color:${statusColor};">${verdict}</p>
                </div>
            </div>
            <div class="banner-bg-glow"></div>
        </div>
    `;

    container.appendChild(wrapper);

    // Initialise Chart if in DOM
    setTimeout(() => {
        const canvas = wrapper.querySelector('canvas');
        if (canvas) {
            new Chart(canvas, {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [riskScore, 100 - riskScore],
                        backgroundColor: [statusColor, 'var(--bg-surface-alt)'],
                        borderWidth: 0,
                        borderRadius: 6,
                        cutout: '82%'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { tooltip: { enabled: false }, legend: { display: false } }
                }
            });
        }
    }, 100);
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

    const threat = data.threat_status || (data.label === 'phishing' ? 'Phishing' : 'Legitimate');
    const riskScore = parseFloat(data.risk_score) || 0.0;
    const scanTime = data.scan_time || new Date().toLocaleString();
    const engine = data.engine || 'AI Neural Email Intelligence Engine';
    const verdict = data.final_verdict || data.reason || `Analysis suggests this email is likely ${threat.toLowerCase()}.`;

    const isPhish = threat.toLowerCase().includes('phishing');
    const isSusp = threat.toLowerCase().includes('suspicious');
    const statusColor = isPhish ? '#ef4444' : (isSusp ? '#f59e0b' : '#10b981');
    const statusClass = isPhish ? 'status-danger' : (isSusp ? 'status-warning' : 'status-safe');
    const eIcon = isPhish ? 'fa-fish' : (isSusp ? 'fa-triangle-exclamation' : 'fa-envelope-circle-check');

    const passCell = (val, yes = 'Valid', no = 'Invalid') =>
        val === 'Pass' || val === true
            ? `<span class="status-badge status-safe">${yes}</span>`
            : `<span class="status-badge status-danger">${no}</span>`;

    const filteredContentAnalysis = Object.fromEntries(
        Object.entries(cnt).filter(([k]) => k !== 'phishing_keywords' && k !== 'html_email')
    );

    wrapper.className = 'premium-dashboard-container animate-fade-in';
    wrapper.innerHTML = `
        <!-- 1. Forensic Summary Header -->
        <div class="glass-card summary-header" style="border-top: 4px solid ${statusColor};">
            <div class="summary-info">
                <div class="scan-target-banner" style="background:transparent; border:none; padding:0; margin:0; box-shadow:none;">
                    <div class="scan-target-banner__top">
                        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:1rem;">
                            <div class="scan-target-banner__heading">
                                <span class="scan-target-banner__kicker" style="color:${statusColor}; opacity:1; font-size:0.7rem;">Neural Email Forensics</span>
                                <p class="scan-target-banner__hint" style="font-size:0.75rem; line-height:1.4; margin-top:0.3rem;">Analyzing deep-header authenticity, linguistic intent analysis, and malicious linkage patterns.</p>
                            </div>
                            <div class="scan-target-banner__proto" style="background:var(--bg-surface-alt); border-color:var(--border-dim); color:var(--text-primary); border-width: 1px; border-style: solid; padding: 0.4rem 0.7rem; border-radius:8px; flex-shrink:0;">
                                <i class="fa-solid ${eIcon}" aria-hidden="true" style="font-size:0.85rem;"></i>
                                <span class="scan-target-banner__proto-text" style="font-size:0.65rem;">
                                    <span class="scan-target-banner__proto-title">Mime</span>
                                    <span class="scan-target-banner__proto-sub">Intel</span>
                                </span>
                            </div>
                        </div>
                    </div>
                    <h2 class="scan-target-banner__url" style="font-size:1.5rem; font-weight:900; color:var(--text-primary); margin:1rem 0 0.5rem 0; word-break:break-word;">${meta.subject || 'No Subject'}</h2>
                    <div class="flex items-center gap-2 mt-1" style="flex-wrap:wrap; font-size:0.65rem;">
                        <div class="glass-tag" style="background:rgba(255,255,255,0.03); padding:0.25rem 0.6rem; border-radius:100px; border:1px solid rgba(255,255,255,0.05);">
                            <i class="fa-solid fa-paper-plane mr-1" style="font-size:0.6rem;"></i>From: <span class="font-bold">${meta.sender || 'Unknown'}</span>
                        </div>
                        <div class="glass-tag" style="background:var(--bg-surface-alt); padding:0.25rem 0.6rem; border-radius:100px; border:1px solid var(--border-dim);">
                            <i class="fa-solid fa-at mr-1" style="font-size:0.6rem;"></i>Envelope: <span class="font-bold">${meta.sender_domain || 'Unknown'}</span>
                        </div>
                    </div>
                </div>
                <div class="summary-meta-row mt-3">
                    <div class="meta-item">
                        <i class="fa-solid fa-microchip"></i>
                        <span>${engine}</span>
                    </div>
                    <div class="meta-item">
                        <i class="fa-regular fa-clock"></i>
                        <span>${scanTime}</span>
                    </div>
                    <div class="meta-item">
                        <span class="status-badge ${statusClass}" style="padding: 0.25rem 0.75rem; font-size: 0.65rem;">VERDICT: ${threat}</span>
                    </div>
                </div>
            </div>
            <div class="summary-score-col">
                <div class="chart-wrapper">
                    <canvas id="email-chart-${Date.now()}"></canvas>
                    <div class="chart-center">
                        <span style="font-size:1.8rem; font-weight:950; color:${statusColor}; letter-spacing:-1px;">${riskScore.toFixed(0)}</span>
                        <span style="font-size:0.5rem; font-weight:800; opacity:0.6; text-transform:uppercase; letter-spacing:1px;">Threat Index</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="premium-grid mt-4">
            <div class="results-grid-col">
                <!-- 2. Authentication protocol -->
                <div class="glass-card result-glass-card hover-glow">
                    <h3 class="text-xs font-black text-primary mb-5 uppercase tracking-[0.2em] border-b border-dim pb-4 flex justify-between items-center">
                        <span><i class="fa-solid fa-shield-halved mr-2 text-cyan-400"></i> Authentication</span>
                        <span class="text-[0.6rem] opacity-40">Protocol Verification</span>
                    </h3>
                    <div style="display:flex; flex-direction:column; gap:1rem;">
                        <div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-surface-alt); border: 1px solid var(--border-dim); padding:0.75rem; border-radius:12px;">
                            <span style="color:#94a3b8; font-size:0.75rem; font-weight:700;">DKIM Signature:</span>
                            ${passCell(hdr.dkim_valid)}
                        </div>
                        <div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-surface-alt); border: 1px solid var(--border-dim); padding:0.75rem; border-radius:12px;">
                            <span style="color:#94a3b8; font-size:0.75rem; font-weight:700;">SPF Alignment:</span>
                            ${passCell(hdr.spf_pass, 'Pass', 'Fail')}
                        </div>
                        <div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-surface-alt); border: 1px solid var(--border-dim); padding:0.75rem; border-radius:12px;">
                            <span style="color:#94a3b8; font-size:0.75rem; font-weight:700;">DMARC Policy:</span>
                            ${passCell(hdr.dmarc_pass, 'Enforced', 'None')}
                        </div>
                    </div>
                </div>

                <!-- 3. Sender Intelligence -->
                <div class="glass-card result-glass-card mt-4 hover-glow">
                    <h3 class="text-xs font-black text-primary mb-5 uppercase tracking-[0.2em] border-b border-dim pb-4"><i class="fa-solid fa-id-card-clip mr-2 text-indigo-400"></i> Sender Intel</h3>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
                         <div style="background:var(--bg-surface-alt); padding:1rem; border-radius:12px; border:1px solid var(--border-dim);">
                            <span style="font-size:0.6rem; font-weight:900; color:var(--text-secondary); text-transform:uppercase; letter-spacing:1px;">Reputation</span>
                            <div style="font-size:1.1rem; font-weight:800; color:var(--text-primary); margin-top:0.25rem;">${snd.reputation || 'N/A'}</div>
                        </div>
                         <div style="background:var(--bg-surface-alt); padding:1rem; border-radius:12px; border:1px solid var(--border-dim);">
                            <span style="font-size:0.6rem; font-weight:900; color:var(--text-secondary); text-transform:uppercase; letter-spacing:1px;">Domain Age</span>
                            <div style="font-size:1.1rem; font-weight:800; color:var(--text-primary); margin-top:0.25rem;">${snd.domain_age || 'N/A'}</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="results-grid-col">
                <!-- 4. Content Risk Assessment -->
                <div class="glass-card result-glass-card hover-glow h-full">
                    <h3 class="text-xs font-black text-primary mb-5 uppercase tracking-[0.2em] border-b border-dim pb-4"><i class="fa-solid fa-brain mr-2 text-emerald-400"></i> Deep Content Forensic</h3>
                    <div style="display:flex; flex-direction:column; gap:0.6rem;">
                        ${Object.entries(filteredContentAnalysis).map(([k, v]) => `
                            <div class="premium-list-item" style="display:flex; align-items:center; gap:0.8rem; padding:0.8rem; background:rgba(255,255,255,0.02); border-radius:12px; border:1px solid rgba(255,255,255,0.05);">
                                <div style="width:32px; height:32px; border-radius:8px; background:${v ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)'}; display:flex; align-items:center; justify-content:center;">
                                    <i class="fa-solid ${v ? 'fa-triangle-exclamation text-red-400' : 'fa-check text-emerald-400'}" style="font-size:0.8rem;"></i>
                                </div>
                                <div style="flex-grow:1;">
                                    <div style="font-size:0.75rem; font-weight:800; color:var(--text-primary); text-transform:capitalize; letter-spacing:0.02em;">${k.replace(/_/g, ' ')}</div>
                                    <div style="font-size:0.55rem; color:var(--text-secondary); font-weight:900; text-transform:uppercase;">${v ? 'Threat Detected' : 'Clean / Neutral'}</div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>

        <!-- 5. Interactive Actions -->
        <div class="action-buttons-grid mt-6" style="display:flex; flex-wrap:wrap; gap:0.75rem; align-items:center;">
            <button class="neon-btn btn-secondary" onclick="document.getElementById('email-input').focus()"><i class="fa-solid fa-rotate-right mr-2"></i> RE-FORENSIC</button>
            <button class="neon-btn btn-secondary" onclick="window.print()"><i class="fa-solid fa-file-export mr-2"></i> EXPORT REPORT</button>
            <button class="neon-btn btn-danger" onclick="addToBlacklist('${(meta.sender || 'Unknown').replace(/'/g, "\\'")}', 'Email')"><i class="fa-solid fa-ban mr-2"></i> QUARANTINE SENDER</button>
            <button class="neon-btn btn-success" style="border-color:rgba(16,185,129,0.3);color:#10b981;" onclick="addToWhitelist('${(meta.sender || 'Unknown').replace(/'/g, "\\'")}', 'Email')"><i class="fa-solid fa-shield-check mr-2"></i> WHITELIST</button>
        </div>

        <!-- 6. Upgraded Verdict Banner -->
        <div class="verdict-banner ${statusClass}" style="padding: 1.5rem; margin-top: 2rem;">
            <div class="flex items-start gap-4 relative z-10 w-full">
                <div style="width:56px; height:56px; border-radius:16px; background:var(--bg-surface-alt); border:1px solid var(--border-dim); display:flex; align-items:center; justify-content:center; flex-shrink:0;">
                    <i class="fa-solid ${eIcon}" style="font-size:1.8rem; color:${statusColor};"></i>
                </div>
                <div style="flex-grow:1; min-width:0;">
                    <div style="margin-bottom:0.5rem;">
                        <span style="font-size:0.55rem; font-weight:900; text-transform:uppercase; letter-spacing:0.2em; color:${statusColor}; opacity:0.9;">Intelligence Verdict</span>
                    </div>
                    <h3 style="font-size:1rem; font-weight:800; line-height:1.4; color:var(--text-primary); margin:0.2rem 0 0.5rem 0;">${verdict}</h3>
                    <div style="font-size:0.65rem; font-weight:700; color:var(--text-secondary); letter-spacing:0.05em;">CONFIDENCE: ${(riskScore > 50 ? riskScore : 100 - riskScore).toFixed(0)}%</div>
                </div>
            </div>
            <div class="banner-bg-glow" style="background:${statusColor}; opacity:0.1;"></div>
        </div>
    `;

    container.appendChild(wrapper);

    // Initialize Chart
    setTimeout(() => {
        const canvas = wrapper.querySelector('canvas');
        if (canvas) {
            new Chart(canvas, {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [riskScore, 100 - riskScore],
                        backgroundColor: [statusColor, 'var(--bg-surface-alt)'],
                        borderWidth: 0,
                        borderRadius: 10,
                        cutout: '84%'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { tooltip: { enabled: false }, legend: { display: false } },
                    animation: { duration: 1500, easing: 'easeOutQuart' }
                }
            });
        }
    }, 100);
}
// === INIT ===
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    if (window.location.pathname.includes('dashboard')) {
        restoreDashboardTab();
    }
});