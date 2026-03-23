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

function createReasonElement(parent) {
    const reasonDiv = document.createElement('div');
    reasonDiv.className = 'analysis-reason mt-3';
    reasonDiv.innerHTML = '<p class="text-sm opacity-80"><i class="fa-solid fa-robot mr-1"></i> AI Analysis: <span class="reason-text"></span></p>';
    parent.appendChild(reasonDiv);
    return reasonDiv.querySelector('.reason-text');
}

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

    // SMS Scanner Logic
    const smsScanBtn = document.getElementById('sms-scan-btn');
    if (smsScanBtn) {
        smsScanBtn.addEventListener('click', async () => {
            const input = document.getElementById('sms-input');
            const resultDiv = document.getElementById('sms-result');
            const text = input.value.trim();

            if (!text) {
                alert('Please enter SMS/message content');
                return;
            }

            // UI Loading State
            const originalText = smsScanBtn.innerHTML;
            smsScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...';
            smsScanBtn.disabled = true;
            resultDiv.classList.add('hidden');
            resultDiv.innerHTML = '';

            try {
                // Call API
                const response = await fetch('/api/scan-sms', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: text })
                });

                const data = await response.json();

                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Error: ${data.error}</div>`;
                } else {
                    const isScam = data.label === 'scam' || data.label === 'spam';
                    const colorClass = isScam ? 'text-red-400' : 'text-green-400';
                    const bgClass = isScam ? 'bg-red-900/30 border-red-700' : 'bg-green-900/30 border-green-700';
                    const icon = isScam ? '<i class="fa-solid fa-triangle-exclamation"></i>' : '<i class="fa-solid fa-check-circle"></i>';

                    resultDiv.innerHTML = `
                        <div class="p-4 ${bgClass} border rounded">
                            <h3 class="text-xl font-bold ${colorClass} mb-2">${icon} ${data.label.toUpperCase()}</h3>
                            <p class="text-sm text-gray-300">Confidence: ${(data.confidence * 100).toFixed(2)}%</p>
                            <p class="text-xs text-gray-400 mt-2">Risk Score: ${data.risk_score}</p>
                            <div class="mt-3 p-2 bg-black/20 rounded text-xs text-gray-400">
                                <strong>AI Analysis:</strong> ${data.reason}
                            </div>
                        </div>
                    `;
                }

            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Network Error: Is the backend running?</div>`;
            } finally {
                smsScanBtn.innerHTML = originalText;
                smsScanBtn.disabled = false;
            }
        });
    }

    // QR Scanner Logic
    const qrInput = document.getElementById('qr-input');
    const qrUploadText = document.getElementById('qr-upload-text');
    
    if (qrInput && qrUploadText) {
        qrInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                qrUploadText.innerText = `Selected: ${e.target.files[0].name}`;
                qrUploadText.classList.add('text-accent');
            } else {
                qrUploadText.innerText = 'Click to upload QR code image';
                qrUploadText.classList.remove('text-accent');
            }
        });
    }

    const qrScanBtn = document.getElementById('qr-scan-btn');
    if (qrScanBtn) {
        qrScanBtn.addEventListener('click', async () => {
            const resultDiv = document.getElementById('qr-result');
            if (!qrInput || qrInput.files.length === 0) {
                alert('Please select a QR code image to scan');
                return;
            }

            const file = qrInput.files[0];

            // UI Loading State
            const originalText = qrScanBtn.innerHTML;
            qrScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...';
            qrScanBtn.disabled = true;
            resultDiv.classList.add('hidden');
            resultDiv.innerHTML = '';

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('/api/scan-qr', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Error: ${data.error}</div>`;
                } else {
                    let analysisHtml = '';
                    if (data.threat_analysis) {
                        const isSafe = data.threat_analysis.result.toString().toLowerCase().includes('good') || 
                                       data.threat_analysis.result.toString().toLowerCase().includes('safe') || 
                                       data.threat_analysis.result == '0' ||
                                       data.threat_analysis.result.toString().toLowerCase().includes('benign');
                        
                        const colorClass = isSafe ? 'text-green-400' : 'text-red-400';
                        const icon = isSafe ? '<i class="fa-solid fa-check-circle"></i>' : '<i class="fa-solid fa-triangle-exclamation"></i>';
                        
                        analysisHtml = `
                            <div class="mt-3 p-3 bg-black/20 rounded border border-white/10">
                                <p class="text-xs uppercase tracking-wider text-gray-500 mb-1">Threat Analysis</p>
                                <p class="font-bold ${colorClass}">${icon} ${data.threat_analysis.result}</p>
                                <p class="text-xs text-gray-400">Confidence: ${(data.threat_analysis.confidence * 100).toFixed(2)}%</p>
                            </div>
                        `;
                    }

                    resultDiv.innerHTML = `
                        <div class="p-4 bg-blue-900/30 border border-blue-700 rounded">
                            <h3 class="text-lg font-bold text-blue-400 mb-2"><i class="fa-solid fa-qrcode"></i> QR Content Extracted</h3>
                            <div class="p-2 bg-black/30 rounded mb-2 break-all font-mono text-sm">
                                ${data.content}
                            </div>
                            <p class="text-xs text-gray-400">${data.is_url ? 'Link detected and analyzed' : 'Text content detected'}</p>
                            ${analysisHtml}
                        </div>
                    `;
                }

            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Network Error</div>`;
            } finally {
                qrScanBtn.innerHTML = originalText;
                qrScanBtn.disabled = false;
            }
        });
    }

    // Domain Check Logic
    const domainCheckBtn = document.getElementById('domain-check-btn');
    if (domainCheckBtn) {
        domainCheckBtn.addEventListener('click', async () => {
            const input = document.getElementById('domain-input');
            const resultDiv = document.getElementById('domain-result');
            const domain = input.value.trim();

            if (!domain) {
                alert('Please enter a domain name');
                return;
            }

            // UI Loading State
            const originalText = domainCheckBtn.innerHTML;
            domainCheckBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Checking...';
            domainCheckBtn.disabled = true;
            resultDiv.classList.add('hidden');
            resultDiv.innerHTML = '';

            try {
                const response = await fetch('/api/check-domain', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: domain })
                });

                const data = await response.json();
                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Error: ${data.error}</div>`;
                } else {
                    const isSafe = data.result.toLowerCase().includes('safe') || data.result.toLowerCase().includes('benign');
                    const colorClass = isSafe ? 'text-green-400' : 'text-red-400';
                    const bgClass = isSafe ? 'bg-green-900/30 border-green-700' : 'bg-red-900/30 border-red-700';
                    const icon = isSafe ? '<i class="fa-solid fa-check-circle"></i>' : '<i class="fa-solid fa-triangle-exclamation"></i>';

                    resultDiv.innerHTML = `
                        <div class="p-4 ${bgClass} border rounded">
                            <h3 class="text-xl font-bold ${colorClass} mb-2">${icon} ${data.result.toUpperCase()}</h3>
                            <p class="text-sm text-gray-300"><strong>Domain:</strong> ${data.domain}</p>
                            <p class="text-sm text-gray-300"><strong>Registrar:</strong> ${data.registrar}</p>
                            <p class="text-sm text-gray-300"><strong>Created:</strong> ${data.creation_date}</p>
                            <div class="mt-3 p-2 bg-black/20 rounded text-xs text-gray-400">
                                <strong>Analysis:</strong> ${data.reason}
                            </div>
                            <p class="text-xs text-gray-500 mt-2">Confidence: ${(data.confidence * 100).toFixed(2)}%</p>
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
                            <div class="mt-3 p-2 bg-black/20 rounded text-xs text-gray-400">
                                <strong>AI Analysis:</strong> ${data.reason}
                            </div>
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

    // Email Scanner Logic
    const emailScanBtn = document.getElementById('email-scan-btn');
    console.log("Email Scan Button found:", emailScanBtn);
    if (emailScanBtn) {
        emailScanBtn.addEventListener('click', async () => {
            console.log("Email scan button clicked");
            const input = document.getElementById('email-input');
            const resultDiv = document.getElementById('email-result');
            const text = input.value.trim();

            if (!text) {
                alert('Please enter email content');
                return;
            }

            // UI Loading State
            const originalText = emailScanBtn.innerHTML;
            emailScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...';
            emailScanBtn.disabled = true;
            resultDiv.classList.add('hidden');
            resultDiv.innerHTML = '';

            try {
                // Call API
                const response = await fetch('/analyze-email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: text })
                });

                const data = await response.json();

                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Error: ${data.error}</div>`;
                } else {
                    const isPhishing = data.label === 'phishing';
                    const colorClass = isPhishing ? 'text-red-400' : 'text-green-400';
                    const bgClass = isPhishing ? 'bg-red-900/30 border-red-700' : 'bg-green-900/30 border-green-700';
                    const icon = isPhishing ? '<i class="fa-solid fa-triangle-exclamation"></i>' : '<i class="fa-solid fa-check-circle"></i>';

                    let featuresHtml = '';
                    if (data.engineered_features) {
                        featuresHtml = `
                            <div class="mt-3 text-sm text-gray-400">
                                <p><strong>Analysis Details:</strong></p>
                                <ul class="list-disc pl-5 mt-1">
                                    <li>Suspicious Keywords: ${data.engineered_features.suspicious_keywords}</li>
                                    <li>URLs Found: ${data.engineered_features.url_count}</li>
                                    <li>Risk Score: ${data.risk_score}</li>
                                </ul>
                            </div>
                        `;
                    }

                    resultDiv.innerHTML = `
                        <div class="p-4 ${bgClass} border rounded">
                            <h3 class="text-xl font-bold ${colorClass} mb-2">${icon} ${data.label.toUpperCase()}</h3>
                            <p class="text-sm text-gray-300">Confidence: ${(data.confidence * 100).toFixed(2)}%</p>
                            <div class="mt-3 p-2 bg-black/20 rounded text-xs text-gray-400">
                                <strong>AI Analysis:</strong> ${data.reason}
                            </div>
                            ${featuresHtml}
                        </div>
                    `;
                }

            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Network Error: Is the backend running?</div>`;
            } finally {
                emailScanBtn.innerHTML = originalText;
                emailScanBtn.disabled = false;
            }
        });
    }

    // File Scanner Logic
    const fileInput = document.getElementById('file-input');
    const fileUploadText = document.getElementById('file-upload-text');
    
    if (fileInput && fileUploadText) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                fileUploadText.innerText = `Selected: ${e.target.files[0].name}`;
                fileUploadText.classList.add('text-accent');
            } else {
                fileUploadText.innerText = 'Click to upload or drag and drop';
                fileUploadText.classList.remove('text-accent');
            }
        });
    }

    const fileScanBtn = document.getElementById('file-scan-btn');
    if (fileScanBtn) {
        fileScanBtn.addEventListener('click', async () => {
             const resultDiv = document.getElementById('file-result');
             if (!fileInput || fileInput.files.length === 0) {
                 alert('Please select a file to scan');
                 return;
             }

             const file = fileInput.files[0];

             // UI Loading State
             const originalText = fileScanBtn.innerHTML;
             fileScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...';
             fileScanBtn.disabled = true;
             resultDiv.classList.add('hidden');
             resultDiv.innerHTML = '';

             const formData = new FormData();
             formData.append('file', file);

             try {
                 // Call API
                 const response = await fetch('/api/scan-file', {
                     method: 'POST',
                     body: formData
                 });

                 const data = await response.json();

                 resultDiv.classList.remove('hidden');

                 if (data.error) {
                     resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Error: ${data.error}</div>`;
                 } else {
                     const isScam = data.result.toLowerCase() === 'malware' || data.result.toLowerCase() === 'suspicious';
                     const colorClass = isScam ? 'text-red-400' : 'text-green-400';
                     const bgClass = isScam ? 'bg-red-900/30 border-red-700' : 'bg-green-900/30 border-green-700';
                     const icon = isScam ? '<i class="fa-solid fa-triangle-exclamation"></i>' : '<i class="fa-solid fa-check-circle"></i>';

                     resultDiv.innerHTML = `
                         <div class="p-4 ${bgClass} border rounded">
                             <h3 class="text-xl font-bold ${colorClass} mb-2">${icon} ${data.result.toUpperCase()}</h3>
                             <p class="text-sm text-gray-300">Confidence: ${(data.confidence * 100).toFixed(2)}%</p>
                             <p class="text-sm text-gray-300 mt-2"><strong>Reason:</strong> ${data.reason}</p>
                         </div>
                     `;
                 }

             } catch (err) {
                 console.error(err);
                 resultDiv.classList.remove('hidden');
                 resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Network Error: Is the backend running?</div>`;
             } finally {
                 fileScanBtn.innerHTML = originalText;
                 fileScanBtn.disabled = false;
             }
        });
    }

    // Website Inspector Logic
    const webScanBtn = document.getElementById('web-scan-btn');
    if (webScanBtn) {
        webScanBtn.addEventListener('click', async () => {
            const input = document.getElementById('web-input');
            const resultDiv = document.getElementById('web-result');
            const url = input.value.trim();

            if (!url) {
                alert('Please enter a website URL to inspect');
                return;
            }

            // UI Loading State
            const originalText = webScanBtn.innerHTML;
            webScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Inspecting...';
            webScanBtn.disabled = true;
            resultDiv.classList.add('hidden');
            resultDiv.innerHTML = '';

            try {
                // Call API
                const response = await fetch('/api/inspect-web', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });

                const data = await response.json();

                resultDiv.classList.remove('hidden');

                if (data.error) {
                    resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Error: ${data.error}</div>`;
                } else {
                    const isScam = data.result.toLowerCase() === 'malware' || data.result.toLowerCase() === 'suspicious';
                    const colorClass = isScam ? 'text-red-400' : 'text-green-400';
                    const bgClass = isScam ? 'bg-red-900/30 border-red-700' : 'bg-green-900/30 border-green-700';
                    const icon = isScam ? '<i class="fa-solid fa-triangle-exclamation"></i>' : '<i class="fa-solid fa-check-circle"></i>';

                    resultDiv.innerHTML = `
                        <div class="p-4 ${bgClass} border rounded">
                            <h3 class="text-xl font-bold ${colorClass} mb-2">${icon} ${data.result.toUpperCase()}</h3>
                            <p class="text-sm text-gray-300">Confidence: ${(data.confidence * 100).toFixed(2)}%</p>
                            <p class="text-sm text-gray-300 mt-2"><strong>Reason:</strong> ${data.reason}</p>
                        </div>
                    `;
                }

            } catch (err) {
                console.error(err);
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-700 rounded text-red-200">Network Error: Is the backend running?</div>`;
            } finally {
                webScanBtn.innerHTML = originalText;
                webScanBtn.disabled = false;
            }
        });
    }
});