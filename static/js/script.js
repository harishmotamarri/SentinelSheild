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
            alert('confirmation mail sent to your mail please confirm and revisit');
            window.location.href = 'login.html';
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
    } catch (err) {
        console.error('Failed to refresh dashboard:', err);
    }
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

function openScanDetailModal(scan) {
    const modal = document.getElementById('scan-detail-modal');
    if (!modal) return;

    const risk = getRiskLevel(scan.result, scan.confidence);
    const date = new Date(scan.created_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

    document.getElementById('modal-title').innerText = `${scan.scan_type} Scan Details`;
    document.getElementById('modal-date').innerText = date;
    document.getElementById('modal-input').innerText = scan.input_data;
    document.getElementById('modal-result').innerText = scan.result;
    document.getElementById('modal-result').className = `detail-value font-bold uppercase ${risk.class === 'badge-safe' ? 'text-success' : 'text-danger'}`;
    document.getElementById('modal-confidence').innerText = `${(scan.confidence * 100).toFixed(1)}%`;
    document.getElementById('modal-reason').innerText = scan.reason || 'Detailed analysis not provided.';

    // Icon box color
    const iconBox = document.getElementById('modal-type-icon');
    let color = '#3b82f6'; // Default blue
    if (scan.scan_type === 'URL') color = '#3b82f6';
    if (scan.scan_type === 'File') color = '#a855f7';
    if (scan.scan_type === 'Email') color = '#22c55e';
    if (scan.scan_type === 'SMS') color = '#eab308';
    
    iconBox.style.background = `${color}1A`; // 10% opacity
    iconBox.style.color = color;

    modal.classList.remove('hidden');
}

function closeScanModal() {
    const modal = document.getElementById('scan-detail-modal');
    if (modal) modal.classList.add('hidden');
}

function updateCharts(data) {
    const typeCanvas = document.getElementById('typeChart');
    const threatCanvas = document.getElementById('threatChart');
    if (!typeCanvas || !threatCanvas) return;

    const typeCtx = typeCanvas.getContext('2d');
    const threatCtx = threatCanvas.getContext('2d');

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
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 10 } } }
            }
        }
    });

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
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 10 } } }
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
    const userId = localStorage.getItem('user_id');
    const container = document.getElementById('history-container');
    const loading = document.getElementById('history-loading');
    const empty = document.getElementById('history-empty');
    const searchInput = document.getElementById('history-search');
    const typeFilter = document.getElementById('history-type-filter');

    if (!container || !userId) return;

    loading.classList.remove('hidden');
    empty.classList.add('hidden');
    
    // Keep the header, remove only rows
    const existingRows = container.querySelectorAll('.history-row');
    existingRows.forEach(row => row.remove());

    try {
        const response = await fetch(`/api/user-scans?user_id=${userId}`);
        const scans = await response.json();

        loading.classList.add('hidden');

        if (!scans || scans.length === 0) {
            empty.classList.remove('hidden');
        } else {
            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            const selectedType = typeFilter ? typeFilter.value : 'all';

            const filteredScans = scans.filter(scan => {
                const matchesSearch = scan.input_data.toLowerCase().includes(searchTerm) || 
                                     scan.scan_type.toLowerCase().includes(searchTerm) ||
                                     scan.result.toLowerCase().includes(searchTerm);
                const matchesType = selectedType === 'all' || scan.scan_type === selectedType;
                return matchesSearch && matchesType;
            });

            if (filteredScans.length === 0) {
                empty.classList.remove('hidden');
                empty.innerText = 'No matches found for your filter.';
            } else {
                filteredScans.forEach(scan => {
                    const date = new Date(scan.created_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
                    const risk = getRiskLevel(scan.result, scan.confidence);
                    
                    const row = document.createElement('div');
                    row.className = 'history-row';
                    row.innerHTML = `
                        <div class="history-type">
                            <span class="type-tag">${scan.scan_type}</span>
                        </div>
                        <div class="history-input" title="${scan.input_data}">
                            ${scan.input_data}
                            <span class="scan-date">${date}</span>
                        </div>
                        <div class="history-result font-bold">${scan.result}</div>
                        <div class="history-confidence">${(scan.confidence * 100).toFixed(1)}%</div>
                        <div class="history-risk">
                            <span class="badge ${risk.class}">${risk.label}</span>
                        </div>
                    `;
                    container.appendChild(row);
                });
            }
        }
    } catch (err) {
        console.error(err);
        loading.classList.add('hidden');
        const errorMsg = document.createElement('div');
        errorMsg.className = 'p-4 text-red-500 text-center history-row';
        errorMsg.innerText = 'Failed to load history data.';
        container.appendChild(errorMsg);
    }
}

// === SCAN TOOLS SWITCHER ===

function openTool(element, toolId) {
    document.querySelectorAll('.tool-item').forEach(item => {
        item.classList.remove('active');
    });
    element.classList.add('active');

    document.querySelectorAll('.tool-panel').forEach(panel => {
        panel.classList.add('hidden');
    });
    document.getElementById(`tool-${toolId}`).classList.remove('hidden');
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
    }

    // --- URL Scanner Logic ---
    const scanBtn = document.getElementById('url-scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', async () => {
            const input = document.getElementById('url-input');
            const resultDiv = document.getElementById('url-result');
            const url = input.value.trim();

            if (!url) { alert('Please enter a URL'); return; }

            const originalText = scanBtn.innerHTML;
            scanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...';
            scanBtn.disabled = true;
            resultDiv.classList.add('hidden');

            try {
                const response = await fetch('/api/scan-url', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();
                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Error: ${data.error}</div>`;
                } else {
                    const resStr = data.result.toString().toLowerCase();
                    const isSafe = resStr.includes('good') || resStr.includes('safe') || data.result == '0' || resStr.includes('benign');
                    const isMalicious = resStr.includes('malware') || resStr.includes('phishing');
                    
                    let statusClass = 'badge-medium';
                    if (isMalicious) statusClass = 'badge-high';
                    if (isSafe) statusClass = 'badge-safe';

                    resultDiv.innerHTML = `
                        <div class="qr-result-card">
                            <div class="result-header">
                                <div class="flex items-center gap-3">
                                    <i class="fa-solid fa-link-slash text-2xl text-blue-400"></i>
                                    <div>
                                        <h3 class="font-bold text-lg">URL Security Clearance</h3>
                                        <p class="text-xs text-gray-500 truncate" style="max-width: 200px;">${data.url}</p>
                                    </div>
                                </div>
                                <span class="badge ${statusClass}">${data.result.toUpperCase()}</span>
                            </div>
                            <div class="result-main">
                                <div class="result-data-box">
                                    <label class="text-xs text-gray-500 uppercase font-bold">Risk Assessment</label>
                                    <div class="mt-2">
                                        <div class="flex justify-between text-xs mb-1">
                                            <span>Detection Confidence</span>
                                            <span class="font-bold ${isSafe ? 'text-success' : 'text-danger'}">${(data.confidence * 100).toFixed(1)}%</span>
                                        </div>
                                        <div class="confidence-outer">
                                            <div class="confidence-inner" style="width: ${data.confidence * 100}%; background: ${isSafe ? '#4ade80' : '#f87171'}"></div>
                                        </div>
                                    </div>
                                    <div class="mt-4 p-2 bg-black/20 rounded border border-white/5">
                                        <label class="text-[10px] text-gray-500 uppercase block">Engine Context</label>
                                        <span class="text-xs font-bold text-blue-300">Multi-Layer ML + LLaMA AI</span>
                                    </div>
                                </div>
                                <div class="ai-insight">
                                    <label class="text-xs text-accent uppercase font-bold flex items-center gap-1">
                                        <i class="fa-solid fa-robot"></i> AI Expert Analysis
                                    </label>
                                    <p class="mt-2 leading-relaxed text-sm">${data.reason || 'URL structure verified.'}</p>
                                </div>
                            </div>
                        </div>
                    `;
                }
            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Network Error</div>`;
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
            smsScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...';
            smsScanBtn.disabled = true;
            resultDiv.classList.add('hidden');

            try {
                const response = await fetch('/api/scan-sms', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ text: text })
                });
                const data = await response.json();
                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Error: ${data.error}</div>`;
                } else {
                    const isScam = data.label === 'scam' || data.label === 'spam' || data.risk_score > 50;
                    const statusClass = isScam ? 'badge-high' : 'badge-safe';
                    const resultLabel = isScam ? 'SCAM / THREAT' : 'SECURE / HAM';
                    
                    resultDiv.innerHTML = `
                        <div class="qr-result-card">
                            <div class="result-header">
                                <div class="flex items-center gap-3">
                                    <i class="fa-solid fa-comment-slash text-2xl text-blue-400"></i>
                                    <div>
                                        <h3 class="font-bold text-lg">SMS Threat Analysis</h3>
                                        <p class="text-xs text-gray-500">Message Content Scan</p>
                                    </div>
                                </div>
                                <span class="badge ${statusClass}">${resultLabel}</span>
                            </div>
                            <div class="result-main">
                                <div class="result-data-box">
                                    <label class="text-xs text-gray-500 uppercase font-bold">Risk Assessment</label>
                                    <div class="mt-2">
                                        <div class="flex justify-between text-xs mb-1">
                                            <span>Likelihood of Scam</span>
                                            <span class="font-bold ${isScam ? 'text-danger' : 'text-success'}">${data.risk_score}%</span>
                                        </div>
                                        <div class="confidence-outer">
                                            <div class="confidence-inner" style="width: ${data.risk_score}%; background: ${isScam ? '#f87171' : '#4ade80'}"></div>
                                        </div>
                                    </div>
                                    <div class="mt-4">
                                        <label class="text-xs text-gray-500 uppercase font-bold">Detection Confidence</label>
                                        <p class="text-sm font-bold text-blue-300">${(data.confidence * 100).toFixed(1)}%</p>
                                    </div>
                                </div>
                                <div class="ai-insight">
                                    <label class="text-xs text-accent uppercase font-bold flex items-center gap-1">
                                        <i class="fa-solid fa-robot"></i> AI Expert Analysis
                                    </label>
                                    <p class="mt-2 leading-relaxed text-sm">${data.reason || 'Detailed analysis complete.'}</p>
                                </div>
                            </div>
                        </div>
                    `;
                }
            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Network Error during analysis</div>`;
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
            emailScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...';
            emailScanBtn.disabled = true;
            resultDiv.classList.add('hidden');

            try {
                const response = await fetch('/analyze-email', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ text: text })
                });
                const data = await response.json();
                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Error: ${data.error}</div>`;
                } else {
                    const isPhishing = data.label === 'phishing' || data.risk_score > 70;
                    const statusClass = isPhishing ? 'badge-high' : 'badge-safe';
                    const resultLabel = isPhishing ? 'PHISHING / THREAT' : 'SECURE / HAM';
                    const features = data.engineered_features || {};
                    
                    resultDiv.innerHTML = `
                        <div class="qr-result-card">
                            <div class="result-header">
                                <div class="flex items-center gap-3">
                                    <i class="fa-solid fa-envelope-open-text text-2xl text-blue-400"></i>
                                    <div>
                                        <h3 class="font-bold text-lg">Email Security Analysis</h3>
                                        <p class="text-xs text-gray-500">Content Integrity Scan</p>
                                    </div>
                                </div>
                                <span class="badge ${statusClass}">${resultLabel}</span>
                            </div>
                            <div class="result-main">
                                <div class="result-data-box">
                                    <label class="text-xs text-gray-500 uppercase font-bold">Threat Indicator</label>
                                    <div class="mt-2">
                                        <div class="flex justify-between text-xs mb-1">
                                            <span>Phishing Likelihood</span>
                                            <span class="font-bold ${isPhishing ? 'text-danger' : 'text-success'}">${data.risk_score}%</span>
                                        </div>
                                        <div class="confidence-outer">
                                            <div class="confidence-inner" style="width: ${data.risk_score}%; background: ${isPhishing ? '#ef4444' : '#22c55e'}"></div>
                                        </div>
                                    </div>
                                    
                                    <div class="mt-4 grid grid-cols-2 gap-3">
                                        <div class="p-2 bg-black/20 rounded border border-white/5">
                                            <label class="text-[10px] text-gray-500 uppercase block">URLs Detected</label>
                                            <span class="text-sm font-bold">${features.url_count || 0}</span>
                                        </div>
                                        <div class="p-2 bg-black/20 rounded border border-white/5">
                                            <label class="text-[10px] text-gray-500 uppercase block">Suspicious Keywords</label>
                                            <span class="text-sm font-bold">${features.suspicious_keywords || 0}</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="ai-insight">
                                    <label class="text-xs text-accent uppercase font-bold flex items-center gap-1">
                                        <i class="fa-solid fa-robot"></i> AI Expert Insight
                                    </label>
                                    <p class="mt-2 leading-relaxed text-sm">${data.reason || 'AI analysis complete.'}</p>
                                </div>
                            </div>
                        </div>
                    `;
                }
            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Network Error during analysis</div>`;
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
            domainCheckBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Checking...';
            domainCheckBtn.disabled = true;
            resultDiv.classList.add('hidden');

            try {
                const response = await fetch('/api/check-domain', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ domain: domain })
                });
                const data = await response.json();
                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Error: ${data.error}</div>`;
                } else {
                    const resStr = data.result.toLowerCase();
                    const isMalicious = resStr.includes('malware') || resStr.includes('suspicious') || resStr.includes('phishing');
                    const isSafe = resStr.includes('safe') || resStr.includes('benign');

                    let statusClass = 'badge-medium';
                    if (isMalicious) statusClass = 'badge-high';
                    if (isSafe) statusClass = 'badge-safe';

                    const nsStr = Array.isArray(data.name_servers) ? data.name_servers.slice(0, 2).join(', ') : 'Unknown';

                    resultDiv.innerHTML = `
                        <div class="qr-result-card">
                            <div class="result-header">
                                <div class="flex items-center gap-3">
                                    <i class="fa-solid fa-file-signature text-2xl text-blue-400"></i>
                                    <div>
                                        <h3 class="font-bold text-lg">Domain Reputation Report</h3>
                                        <p class="text-xs text-gray-500">${data.domain}</p>
                                    </div>
                                </div>
                                <span class="badge ${statusClass}">${data.result.toUpperCase()}</span>
                            </div>
                            <div class="result-main">
                                <div class="result-data-box">
                                    <label class="text-xs text-gray-500 uppercase font-bold">Registration Profile</label>
                                    <div class="mt-2">
                                        <div class="flex justify-between text-xs mb-1">
                                            <span>Reputation Confidence</span>
                                            <span class="font-bold ${isMalicious ? 'text-danger' : 'text-success'}">${(data.confidence * 100).toFixed(1)}%</span>
                                        </div>
                                        <div class="confidence-outer">
                                            <div class="confidence-inner" style="width: ${data.confidence * 100}%; background: ${isMalicious ? '#f87171' : '#4ade80'}"></div>
                                        </div>
                                    </div>
                                    <div class="mt-4 grid grid-cols-2 gap-2">
                                        <div class="p-2 bg-black/20 rounded border border-white/5">
                                            <label class="text-[10px] text-gray-500 uppercase block">Registrar</label>
                                            <span class="text-[11px] font-bold text-blue-300 truncate block">${data.registrar || 'Unknown'}</span>
                                        </div>
                                        <div class="p-2 bg-black/20 rounded border border-white/5">
                                            <label class="text-[10px] text-gray-500 uppercase block">Created</label>
                                            <span class="text-[11px] font-bold text-blue-300">${data.creation_date ? data.creation_date.split('T')[0] : 'Unknown'}</span>
                                        </div>
                                        <div class="p-2 bg-black/20 rounded border border-white/5">
                                            <label class="text-[10px] text-gray-500 uppercase block">Expires</label>
                                            <span class="text-[11px] font-bold text-blue-300">${data.expiration_date ? data.expiration_date.split('T')[0] : 'Unknown'}</span>
                                        </div>
                                        <div class="p-2 bg-black/20 rounded border border-white/5">
                                            <label class="text-[10px] text-gray-500 uppercase block">N-Servers</label>
                                            <span class="text-[11px] font-bold text-blue-300 truncate block">${nsStr}</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="ai-insight">
                                    <label class="text-xs text-accent uppercase font-bold flex items-center gap-1">
                                        <i class="fa-solid fa-robot"></i> AI Risk Insight
                                    </label>
                                    <p class="mt-2 leading-relaxed text-sm">${data.reason || 'Domain verification complete.'}</p>
                                </div>
                            </div>
                        </div>
                    `;
                }
            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Network Error</div>`;
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

            fileScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...';
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
                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Error: ${data.error}</div>`;
                } else {
                    const resStr = data.result.toLowerCase();
                    const isMalware = resStr.includes('malware') || resStr.includes('suspicious');
                    const isSafe = resStr.includes('safe') || resStr.includes('benign');
                    
                    let statusClass = 'badge-medium';
                    if (isMalware) statusClass = 'badge-high';
                    if (isSafe) statusClass = 'badge-safe';

                    resultDiv.innerHTML = `
                        <div class="qr-result-card">
                            <div class="result-header">
                                <div class="flex items-center gap-3">
                                    <i class="fa-solid fa-file-shield text-2xl text-blue-400"></i>
                                    <div>
                                        <h3 class="font-bold text-lg">File Integrity Analysis</h3>
                                        <p class="text-xs text-gray-500">${file.name}</p>
                                    </div>
                                </div>
                                <span class="badge ${statusClass}">${data.result.toUpperCase()}</span>
                            </div>
                            <div class="result-main">
                                <div class="result-data-box">
                                    <label class="text-xs text-gray-500 uppercase font-bold">Analysis Verdict</label>
                                    <div class="mt-2">
                                        <div class="flex justify-between text-xs mb-1">
                                            <span>Detection Confidence</span>
                                            <span class="font-bold ${(isMalware && !isSafe) ? 'text-danger' : 'text-success'}">${(data.confidence * 100).toFixed(1)}%</span>
                                        </div>
                                        <div class="confidence-outer">
                                            <div class="confidence-inner" style="width: ${data.confidence * 100}%; background: ${isMalware ? '#f87171' : '#4ade80'}"></div>
                                        </div>
                                    </div>
                                    <div class="mt-4 p-2 bg-black/20 rounded border border-white/5">
                                        <label class="text-[10px] text-gray-500 uppercase block">Expert System</label>
                                        <span class="text-xs font-bold text-blue-300">LLaMA 3.1 8B Cyber-Expert</span>
                                    </div>
                                </div>
                                <div class="ai-insight">
                                    <label class="text-xs text-accent uppercase font-bold flex items-center gap-1">
                                        <i class="fa-solid fa-robot"></i> AI Expert Insight
                                    </label>
                                    <p class="mt-2 leading-relaxed text-sm">${data.reason || 'Deep file inspection complete.'}</p>
                                </div>
                            </div>
                        </div>
                    `;
                }
            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Network Error during file analysis</div>`;
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

            qrScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Processing...';
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
                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Error: ${data.error}</div>`;
                } else {
                    let resultHtml = '';
                    
                    if (data.is_url && data.threat_analysis) {
                        const threat = data.threat_analysis;
                        const isSafe = threat.result.toLowerCase().includes('safe') || threat.result.toLowerCase().includes('benign');
                        const statusClass = isSafe ? 'text-success' : 'text-danger';
                        const icon = isSafe ? 'fa-shield-check' : 'fa-triangle-exclamation';
                        
                        resultHtml = `
                            <div class="qr-result-card">
                                <div class="result-header">
                                    <div class="flex items-center gap-3">
                                        <i class="fa-solid fa-qrcode text-2xl text-blue-400"></i>
                                        <div>
                                            <h3 class="font-bold text-lg">QR URL Analysis</h3>
                                            <p class="text-xs text-gray-500">Embedded Link Detected</p>
                                        </div>
                                    </div>
                                    <span class="badge ${isSafe ? 'badge-safe' : 'badge-high'}">${threat.result.toUpperCase()}</span>
                                </div>
                                <div class="result-main">
                                    <div class="result-data-box">
                                        <label class="text-xs text-gray-500 uppercase font-bold">Embedded URL</label>
                                        <p class="mt-1 break-all font-mono text-sm text-blue-300">${data.content}</p>
                                        
                                        <div class="mt-4">
                                            <label class="text-xs text-gray-500 uppercase font-bold">AI Confidence</label>
                                            <div class="confidence-outer">
                                                <div class="confidence-inner" style="width: ${threat.confidence * 100}%"></div>
                                            </div>
                                            <p class="text-right text-xs font-bold">${(threat.confidence * 100).toFixed(1)}%</p>
                                        </div>
                                    </div>
                                    <div class="ai-insight">
                                        <label class="text-xs text-accent uppercase font-bold flex items-center gap-1">
                                            <i class="fa-solid fa-robot"></i> AI Expert Insight
                                        </label>
                                        <p class="mt-2 leading-relaxed">${threat.reason || 'No detailed analysis available.'}</p>
                                    </div>
                                </div>
                                <div class="action-bar">
                                    <button class="btn btn-accent btn-sm" onclick="window.open('${data.content}', '_blank')">
                                        <i class="fa-solid fa-external-link"></i> Safely Visit URL
                                    </button>
                                    <button class="btn btn-dark-outline btn-sm" onclick="copyToClipboard('${data.content}')">
                                        <i class="fa-regular fa-copy"></i> Copy Link
                                    </button>
                                </div>
                            </div>
                        `;
                    } else {
                        resultHtml = `
                            <div class="qr-result-card">
                                <div class="result-header">
                                    <div class="flex items-center gap-3">
                                        <i class="fa-solid fa-qrcode text-2xl text-blue-400"></i>
                                        <div>
                                            <h3 class="font-bold text-lg">QR Data Extracted</h3>
                                            <p class="text-xs text-gray-500">Plain Text / Content</p>
                                        </div>
                                    </div>
                                    <span class="badge badge-low">INFO</span>
                                </div>
                                <div class="result-data-box">
                                    <label class="text-xs text-gray-500 uppercase font-bold">Raw Content</label>
                                    <div class="mt-2 p-3 bg-black/30 rounded font-mono text-sm border border-white/5 whitespace-pre-wrap">${data.content}</div>
                                </div>
                                <div class="action-bar">
                                    <button class="btn btn-accent btn-sm" onclick="copyToClipboard('${data.content}')">
                                        <i class="fa-regular fa-copy"></i> Copy to Clipboard
                                    </button>
                                </div>
                            </div>
                        `;
                    }
                    resultDiv.innerHTML = resultHtml;
                }
            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Network error processing QR</div>`;
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
            webScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Inspecting...';
            webScanBtn.disabled = true;
            resultDiv.classList.add('hidden');
            try {
                const response = await fetch('/api/inspect-web', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();
                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Error: ${data.error}</div>`;
                } else {
                    const resStr = data.result.toLowerCase();
                    const isVulnerable = resStr.includes('vulnerable') || resStr.includes('suspicious') || resStr.includes('malware');
                    const isSafe = resStr.includes('safe') || resStr.includes('benign');

                    let statusClass = 'badge-medium';
                    if (isVulnerable) statusClass = 'badge-high';
                    if (isSafe) statusClass = 'badge-safe';
                    
                    const meta = data.site_metadata || {};

                    resultDiv.innerHTML = `
                        <div class="qr-result-card">
                            <div class="result-header">
                                <div class="flex items-center gap-3">
                                    <i class="fa-solid fa-globe text-2xl text-blue-400"></i>
                                    <div>
                                        <h3 class="font-bold text-lg">Website Content Report</h3>
                                        <p class="text-xs text-gray-500">${meta.title || 'Live Website Scan'}</p>
                                    </div>
                                </div>
                                <span class="badge ${statusClass}">${data.result.toUpperCase()}</span>
                            </div>
                            <div class="result-main">
                                <div class="result-data-box">
                                    <label class="text-xs text-gray-500 uppercase font-bold">Security Posture</label>
                                    <div class="mt-2">
                                        <div class="flex justify-between text-xs mb-1">
                                            <span>Scan Confidence</span>
                                            <span class="font-bold ${isVulnerable ? 'text-danger' : 'text-success'}">${(data.confidence * 100).toFixed(1)}%</span>
                                        </div>
                                        <div class="confidence-outer">
                                            <div class="confidence-inner" style="width: ${data.confidence * 100}%; background: ${isVulnerable ? '#f87171' : '#4ade80'}"></div>
                                        </div>
                                    </div>
                                    
                                    <div class="mt-4 grid grid-cols-2 gap-3">
                                        <div class="p-2 bg-black/20 rounded border border-white/5 text-center">
                                            <label class="text-[10px] text-gray-500 uppercase block">Active Forms</label>
                                            <span class="text-sm font-bold text-blue-300">${meta.form_count || 0}</span>
                                        </div>
                                        <div class="p-2 bg-black/20 rounded border border-white/5 text-center">
                                            <label class="text-[10px] text-gray-500 uppercase block">Ext. Scripts</label>
                                            <span class="text-sm font-bold text-blue-300">${meta.script_count || 0}</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="ai-insight">
                                    <label class="text-xs text-accent uppercase font-bold flex items-center gap-1">
                                        <i class="fa-solid fa-robot"></i> AI Forensic Analysis
                                    </label>
                                    <p class="mt-2 leading-relaxed text-sm">${data.reason || 'Structural analysis complete.'}</p>
                                </div>
                            </div>
                        </div>
                    `;
                }
            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-100">Network Error during inspection</div>`;
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