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
            alert('Login Failed: ' + data.error);
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
        alert('Network Error connecting to Auth server.');
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
        alert("Passwords do not match!");
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
            alert('Signup Failed: ' + data.error);
        } else {
            // Show Success Modal instead of alert
            const modal = document.getElementById('signup-success-modal');
            if (modal) {
                modal.classList.remove('hidden');
            } else {
                // Fallback in case modal isn't in DOM
                alert('Confirmation mail sent to your mail please confirm and revisit');
                window.location.href = 'login.html';
            }
        }
    } catch (err) {
        console.error(err);
        alert('Network Error during Signup.');
    } finally {
        btn.innerHTML = 'Create Account';
        btn.disabled = false;
    }
}

function handleLogout() {
    localStorage.clear();
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
    // 1. Update Navbar Buttons
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('onclick').includes(`'${tabId}'`)) {
            item.classList.add('active');
        }
    });

    // 2. Update Tab Visibility
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => {
        tab.classList.add('hidden');
        tab.classList.remove('active');
    });

    const activeTab = document.getElementById(`tab-${tabId}`);
    if (activeTab) {
        activeTab.classList.remove('hidden');
        activeTab.classList.add('active');
    }

    // 3. Tab Specific Logic
    if (tabId === 'dashboard') {
        refreshDashboard();
    } else if (tabId === 'history') {
        loadScanHistory();
    } else if (tabId === 'profile') {
        if (lastDashboardData) updateProfileInfo(lastDashboardData);
        else refreshDashboard();
    }

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
}function updateCharts(data) {
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
        reasonEl.innerText = scan.reason || 'AI Intelligence Engine: No critical structural vulnerabilities or malicious signatures detected in this specific artifact fingerprint.';
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
    resultWrapper.className = 'premium-result-container';
    
    if (data.error) {
        resultWrapper.innerHTML = `
            <div class="result-card-premium" style="border-color: #ef444433;">
                <div class="flex items-center gap-4 text-red-400">
                    <i class="fa-solid fa-triangle-exclamation text-3xl"></i>
                    <div>
                        <h3 class="font-bold text-lg">Structural Analysis Error</h3>
                        <p class="text-sm opacity-80">${data.error}</p>
                    </div>
                </div>
            </div>
        `;
        container.appendChild(resultWrapper);
        return;
    }

    // Determine Risk Level
    let risk = { label: 'UNKNOWN', color: '#64748b', class: 'risk-low', badge: 'bg-slate-500/20 text-slate-400' };
    const res = (data.result || '').toString().toLowerCase();
    const conf = parseFloat(data.confidence) || 0;
    
    const isSafe = res.includes('safe') || res.includes('benign') || res.includes('good') || res.includes('secure');
    const isThreat = res.includes('malware') || res.includes('phishing') || res.includes('scam') || res.includes('threat') || (conf > 0.8 && !isSafe);
    
    if (isSafe) {
        risk = { label: 'SECURE', color: '#10b981', class: 'risk-safe', badge: 'bg-emerald-500/20 text-emerald-400' };
    } else if (isThreat) {
        risk = { label: 'THREAT DETECTED', color: '#ef4444', class: 'risk-high', badge: 'bg-red-500/20 text-red-400' };
    } else if (conf > 0.4) {
        risk = { label: 'SUSPICIOUS', color: '#f59e0b', class: 'risk-medium', badge: 'bg-amber-500/20 text-amber-400' };
    }

    // Gauge Offset Calculation
    const radius = 70;
    const circumf = Math.PI * radius; // Half circumf
    const offset = circumf - (conf * circumf);

    resultWrapper.innerHTML = `
        <div class="result-card-premium">
            <div class="intelligence-grid">
                <div class="gauge-wrapper">
                    <div class="gauge-container">
                        <svg class="gauge-svg" viewBox="0 0 160 80">
                            <path class="gauge-background" d="M 10 75 A 70 70 0 0 1 150 75" />
                            <path class="gauge-fill" d="M 10 75 A 70 70 0 0 1 150 75" 
                                  style="stroke: ${risk.color}; stroke-dashoffset: ${offset};" />
                        </svg>
                        <div class="gauge-text">
                            <span class="gauge-value" style="color: ${risk.color}">${(conf * 100).toFixed(0)}%</span>
                            <span class="gauge-label">Certainty</span>
                        </div>
                    </div>
                    <div class="mt-4 px-4 py-1.5 rounded-full ${risk.badge} text-[10px] font-black tracking-widest uppercase">
                        ${risk.label}
                    </div>
                </div>

                <div class="diagnostic-panel">
                    <div class="panel-accent"></div>
                    <span class="result-tag-premium" style="background: ${risk.color}; color: #000;">Diagnostic Output</span>
                    
                    <h3 class="text-xl font-black mb-4 tracking-tight">AI FORENSIC ANALYSIS</h3>
                    <div style="background: rgba(0,0,0,0.3); padding: 1.5rem; border-radius: 16px; border: 1px solid rgba(255,255,255,0.05); position: relative;">
                        <i class="fa-solid fa-quote-left absolute -top-2 -left-2 text-accent opacity-20 text-2xl"></i>
                        <p class="italic text-sm leading-relaxed text-slate-300 font-medium">
                            ${data.reason || 'Structural patterns analyzed. No immediate indicators of compromise detected in the primary artifact layers.'}
                        </p>
                    </div>

                    <div class="mt-6 flex items-center gap-6">
                        <div class="flex flex-col">
                            <label class="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-1">Fingerprint</label>
                            <span class="text-xs font-mono text-accent opacity-80 truncate max-w-[200px]">${data.input_data || 'Verified Sequence'}</span>
                        </div>
                        <div class="h-8 w-[1px] bg-white/5"></div>
                        <div class="flex flex-col">
                            <label class="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-1">Audit Status</label>
                            <span class="text-xs text-slate-300 font-bold">COMPLETED</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="action-bar-premium">
                ${(data.url || data.input_data?.startsWith('http')) ? `
                    <a href="${data.url || data.input_data}" target="_blank" class="premium-action-btn bg-accent text-black">
                        <i class="fa-solid fa-arrow-up-right-from-square"></i> Visit Target Safely
                    </a>
                ` : ''}
                <button onclick="navigator.clipboard.writeText('${data.input_data || ''}')" class="premium-action-btn bg-white/5 border border-white/10 text-white hover:bg-white/10">
                    <i class="fa-solid fa-copy"></i> Copy Fingerprint
                </button>
            </div>
        </div>
    `;

    container.appendChild(resultWrapper);
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

document.addEventListener('DOMContentLoaded', () => {
    checkAuth();

    // ... other initializations ...
    setupDragAndDrop('file-upload-zone', 'file-input', 'file-upload-text');
    setupDragAndDrop('qr-upload-zone', 'qr-input', 'qr-upload-text');

    // Initial Dashboard Load
    if (!document.getElementById('tab-dashboard').classList.contains('hidden')) {
        refreshDashboard();
    }    // --- URL Scanner Logic ---
    const scanBtn = document.getElementById('url-scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', async () => {
            const input = document.getElementById('url-input');
            const resultDiv = document.getElementById('url-result');
            const url = input.value.trim();

            if (!url) { alert('Please enter a URL'); return; }

            const originalText = scanBtn.innerHTML;
            scanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Initializing Scan...';
            scanBtn.disabled = true;
            resultDiv.classList.add('hidden');

            try {
                const response = await fetch('/api/scan-url', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();
                renderScanResult('url-result', data, 'URL');
            } catch (err) {
                console.error(err);
                renderScanResult('url-result', { error: 'Network connection failed' }, 'URL');
            } finally {
                scanBtn.innerHTML = originalText;
                scanBtn.disabled = false;
            }
        });
    }

    // --- SMS Scanner Logic ---
    const smsScanBtn = document.getElementById('sms-scan-btn');
    if (smsScanBtn) {
        smsScanBtn.addEventListener('click', async () => {
            const input = document.getElementById('sms-input');
            const resultDiv = document.getElementById('sms-result');
            const text = input.value.trim();

            if (!text) { alert('Please enter SMS content'); return; }

            const originalText = smsScanBtn.innerHTML;
            smsScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Deep Analysis...';
            smsScanBtn.disabled = true;
            resultDiv.classList.add('hidden');

            try {
                const response = await fetch('/api/scan-sms', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ text: text })
                });
                const data = await response.json();
                renderScanResult('sms-result', data, 'SMS');
            } catch (err) {
                console.error(err);
                renderScanResult('sms-result', { error: 'Failed to analyze message' }, 'SMS');
            } finally {
                smsScanBtn.innerHTML = originalText;
                smsScanBtn.disabled = false;
            }
        });
    }

    // History filter listener
    const historyTypeFilter = document.getElementById('history-type-filter');
    if (historyTypeFilter) {
        historyTypeFilter.addEventListener('change', () => {
            fetchHistory();
        });
    }

    // --- Email Scanner Logic ---
    const emailScanBtn = document.getElementById('email-scan-btn');
    if (emailScanBtn) {
        emailScanBtn.addEventListener('click', async () => {
            const input = document.getElementById('email-input');
            const resultDiv = document.getElementById('email-result');
            const text = input.value.trim();

            if (!text) { alert('Please enter email content'); return; }

            const originalText = emailScanBtn.innerHTML;
            emailScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Intelligence Scan...';
            emailScanBtn.disabled = true;
            resultDiv.classList.add('hidden');

            try {
                const response = await fetch('/analyze-email', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ text: text })
                });
                const data = await response.json();
                renderScanResult('email-result', data, 'Email');
            } catch (err) {
                console.error(err);
                renderScanResult('email-result', { error: 'Analysis failed' }, 'Email');
            } finally {
                emailScanBtn.innerHTML = originalText;
                emailScanBtn.disabled = false;
            }
        });
    }

    // --- Domain Check Logic ---
    const domainCheckBtn = document.getElementById('domain-check-btn');
    if (domainCheckBtn) {
        domainCheckBtn.addEventListener('click', async () => {
            const input = document.getElementById('domain-input');
            const resultDiv = document.getElementById('domain-result');
            const domain = input.value.trim();

            if (!domain) { alert('Please enter a domain'); return; }

            const originalText = domainCheckBtn.innerHTML;
            domainCheckBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Checking WHOIS...';
            domainCheckBtn.disabled = true;
            resultDiv.classList.add('hidden');

            try {
                const response = await fetch('/api/check-domain', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ domain: domain })
                });
                const data = await response.json();
                renderScanResult('domain-result', data, 'Domain');
            } catch (err) {
                console.error(err);
                renderScanResult('domain-result', { error: 'Domain lookup failed' }, 'Domain');
            } finally {
                domainCheckBtn.innerHTML = originalText;
                domainCheckBtn.disabled = false;
            }
        });
    }

    // --- File Scanner Logic ---
    const fileScanBtn = document.getElementById('file-scan-btn');
    const fileInput = document.getElementById('file-input');
    if (fileScanBtn && fileInput) {
        fileScanBtn.addEventListener('click', async () => {
            if (fileInput.files.length === 0) { alert('Please select a file'); return; }
            const resultDiv = document.getElementById('file-result');
            const file = fileInput.files[0];

            fileScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Malware Inspection...';
            fileScanBtn.disabled = true;
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
                renderScanResult('file-result', data, 'File');
            } catch (err) {
                console.error(err);
                renderScanResult('file-result', { error: 'File analysis failed' }, 'File');
            } finally {
                fileScanBtn.innerHTML = 'Analyze File';
                fileScanBtn.disabled = false;
            }
        });
    }

    // --- QR Scanner Logic ---
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}

// ... inside DOMContentLoaded, QR logic ...
    const qrScanBtn = document.getElementById('qr-scan-btn');
    const qrInput = document.getElementById('qr-input');
    if (qrScanBtn && qrInput) {
        qrScanBtn.addEventListener('click', async () => {
            if (qrInput.files.length === 0) { alert('Please select a QR image'); return; }
            const resultDiv = document.getElementById('qr-result');
            const file = qrInput.files[0];

            qrScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Extracting Data...';
            qrScanBtn.disabled = true;
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
                
                // Special handling for QR because it might return sub-analysis
                if (data.is_url && data.threat_analysis) {
                    const combinedData = {
                        ...data.threat_analysis,
                        content: data.content,
                        input_data: data.content // Use the extracted URL as input_data
                    };
                    renderScanResult('qr-result', combinedData, 'QR');
                } else {
                    renderScanResult('qr-result', data, 'QR');
                }
            } catch (err) {
                console.error(err);
                renderScanResult('qr-result', { error: 'QR Scan failed' }, 'QR');
            } finally {
                qrScanBtn.innerHTML = 'Scan QR Code';
                qrScanBtn.disabled = false;
            }
        });
    }

    // --- Website Inspector Logic ---
    const webScanBtn = document.getElementById('web-scan-btn');
    if (webScanBtn) {
        webScanBtn.addEventListener('click', async () => {
            const input = document.getElementById('web-input');
            const resultDiv = document.getElementById('web-result');
            const url = input.value.trim();

            if (!url) { alert('Please enter a URL'); return; }

            const originalText = webScanBtn.innerHTML;
            webScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Forensic Audit...';
            webScanBtn.disabled = true;
            resultDiv.classList.add('hidden');
            try {
                const response = await fetch('/api/inspect-web', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();
                renderScanResult('web-result', data, 'Web');
            } catch (err) {
                console.error(err);
                renderScanResult('web-result', { error: 'Website inspection failed' }, 'Web');
            } finally {
                webScanBtn.innerHTML = originalText;
                webScanBtn.disabled = false;
            }
        });
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