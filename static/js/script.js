// === AUTHENTICATION LOGIC ===

function handleLogin(e) {
    e.preventDefault();
    const btn = document.getElementById('login-btn');
    const originalText = btn.innerText;

    // 1. Loading State
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Signing in...';
    btn.disabled = true;

    // 2. Simulate Network Delay (1.5s)
    setTimeout(() => {
        // 3. Redirect to Dashboard
        window.location.href = 'dashboard.html';

    }, 1500);
}

function handleSignup(e) {
    e.preventDefault();
    // Simulate signup
    const btn = e.target.querySelector('button');
    const originalText = btn.innerText;

    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Creating Account...';
    btn.disabled = true;

    setTimeout(() => {
        window.location.href = 'dashboard.html';
    }, 1500);
}

function handleLogout() {
    // Redirect to Login
    window.location.href = 'login.html';
}

// === NAVIGATION TABS (Dashboard / Scan / History) ===

function switchTab(tabName) {
    // 1. Update Navbar Buttons
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.classList.remove('active');
        // Simple text matching for the active class logic
        if (btn.innerText.toLowerCase().includes(tabName)) {
            btn.classList.add('active');
        }
    });

    // 2. Hide All Tab Content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });

    // 3. Show Selected Tab
    // Check if element exists before removing hidden class
    const tabElement = document.getElementById(`tab-${tabName}`);
    if (tabElement) {
        tabElement.classList.remove('hidden');
    }

    // 4. Special logic for History Tab (Simulate Loading)
    if (tabName === 'history') {
        const loading = document.getElementById('history-loading');
        const empty = document.getElementById('history-empty');

        if (loading && empty) {
            loading.classList.remove('hidden');
            empty.classList.add('hidden');

            setTimeout(() => {
                loading.classList.add('hidden');
                empty.classList.remove('hidden');
            }, 1200);
        }
    }
}

// === SCAN TOOLS SWITCHER ===

function openTool(element, toolId) {
    // 1. Sidebar Active State
    document.querySelectorAll('.tool-item').forEach(item => {
        item.classList.remove('active');
    });
    element.classList.add('active');

    // 2. Show Tool Panel
    document.querySelectorAll('.tool-panel').forEach(panel => {
        panel.classList.add('hidden');
    });
    document.getElementById(`tool-${toolId}`).classList.remove('hidden');
}

// === UI UTILITIES ===

function toggleUserMenu() {
    const menu = document.getElementById('user-dropdown');
    if (menu) {
        menu.classList.toggle('hidden');
    }
}

function showToast() {
    const toast = document.getElementById('toast');
    if (toast) {
        toast.classList.remove('hidden');

        // Auto hide after 4 seconds
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 4000);
    }
}

// Close dropdown if clicked outside
window.addEventListener('click', function (e) {
    if (!e.target.closest('.user-menu-container')) {
        const menu = document.getElementById('user-dropdown');
        if (menu) {
            menu.classList.add('hidden');
        }
    }
});

// Run this on page load to handle initial state if needed
document.addEventListener('DOMContentLoaded', () => {
    // Optional: Check current URL to set active tab if on dashboard
    if (window.location.pathname.includes('dashboard.html')) {
        // Ensure default tab is shown? It's already hardcoded in HTML as active.
    }

    // URL Scanner Logic
    const scanBtn = document.getElementById('url-scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', async () => {
            const input = document.getElementById('url-input');
            const resultDiv = document.getElementById('url-result');
            const url = input.value.trim();

            if (!url) {
                alert('Please enter a URL');
                return;
            }

            // UI Loading State
            const originalText = scanBtn.innerHTML;
            scanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...';
            scanBtn.disabled = true;
            resultDiv.classList.add('hidden');
            resultDiv.innerHTML = '';

            try {
                // Call API
                // Adjust port if running on different port
                const response = await fetch('/api/scan-url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });

                const data = await response.json();

                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Error: ${data.error}</div>`;
                } else {
                    // Determine color based on result
                    // Assuming 'good' or 'safe' -> green, else red
                    const isSafe = data.result.toString().toLowerCase().includes('good') || data.result.toString().toLowerCase().includes('safe') || data.result == '0';
                    const colorClass = isSafe ? 'text-green-400' : 'text-red-400';
                    const bgClass = isSafe ? 'bg-green-900/30 border-green-700' : 'bg-red-900/30 border-red-700';
                    const icon = isSafe ? '<i class="fa-solid fa-check-circle"></i>' : '<i class="fa-solid fa-triangle-exclamation"></i>';

                    resultDiv.innerHTML = `
                        <div class="p-4 ${bgClass} border rounded">
                            <h3 class="text-xl font-bold ${colorClass} mb-2">${icon} ${data.result}</h3>
                            <p class="text-sm text-gray-300">Confidence: ${(data.confidence * 100).toFixed(2)}%</p>
                        </div>
                    `;
                }

            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Network Error: Is the backend running?</div>`;
            } finally {
                scanBtn.innerHTML = originalText;
                scanBtn.disabled = false;
            }
        });
    }
});