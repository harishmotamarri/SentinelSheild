import { auth } from './auth.js';

export const ui = {
    init() {
        this.initTheme();
        this.renderNavbar();
        this.renderSidebar();
        lucide.createIcons();
    },

    initTheme() {
        // Default to dark mode
        if (localStorage.getItem('theme') === 'light') {
            document.documentElement.classList.remove('dark');
        } else {
            document.documentElement.classList.add('dark');
        }
    },

    toggleTheme() {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        this.renderNavbar();
    },

    getPath(target) {
        const depth = window.location.pathname.split('/').filter(Boolean).length;
        // If we are in a subfolder like 'scan/', we need to go up one level
        // Note: this assumes we are only max 1 level deep (which is true for this project)
        const inSubfolder = window.location.pathname.includes('/scan/');
        if (inSubfolder && !target.startsWith('scan/')) {
            return '../' + target;
        }
        if (!inSubfolder && target.startsWith('scan/')) {
            return target;
        }
        return target.replace('scan/', '');
    },

    async renderSidebar() {
        const sidebarContainer = document.getElementById('sidebar-container');
        if (!sidebarContainer) return;

        const isSubfolder = window.location.pathname.includes('/scan/');
        const prefix = isSubfolder ? '' : 'scan/';

        const scanLinks = [
            { href: prefix + 'url.html', label: 'URL Scanner', icon: 'link' },
            { href: prefix + 'email.html', label: 'Email Analyzer', icon: 'mail' },
            { href: prefix + 'message.html', label: 'SMS Detector', icon: 'message-square' },
            { href: prefix + 'file.html', label: 'File Scanner', icon: 'file' },
            { href: prefix + 'website.html', label: 'Website Inspector', icon: 'globe' },
            { href: prefix + 'qr.html', label: 'QR Scanner', icon: 'qr-code' },
            { href: (isSubfolder ? '../' : '') + 'domain-check.html', label: 'Domain Check', icon: 'server' },
        ];

        const linksHtml = scanLinks.map(link => {
            const isActive = window.location.pathname.includes(link.href.split('/').pop());
            return `
                <a href="${link.href}" class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${isActive ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-secondary'}">
                    <i data-lucide="${link.icon}" class="h-4 w-4"></i>
                    ${link.label}
                </a>
            `;
        }).join('');

        sidebarContainer.innerHTML = `
            <aside class="w-64 shrink-0 border-r border-border bg-card/50 hidden lg:block h-[calc(100vh-65px)] sticky top-[65px]">
                <div class="p-4">
                    <h2 class="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-4">Scan Tools</h2>
                    <nav class="space-y-1">
                        ${linksHtml}
                    </nav>
                </div>
            </aside>
        `;
        lucide.createIcons();
    },

    async renderNavbar() {
        const navbarContainer = document.getElementById('navbar-container');
        if (!navbarContainer) return;

        const user = await auth.getUser();
        const isAdmin = await auth.isAdmin();

        const isDark = document.documentElement.classList.contains('dark');
        const themeIcon = isDark ? 'sun' : 'moon';

        const isSubfolder = window.location.pathname.includes('/scan/');
        const up = isSubfolder ? '../' : '';

        const navLinks = user ? `
            <div class="hidden md:flex items-center gap-1">
                <a href="${up}dashboard.html" class="px-4 py-2 rounded-lg text-sm font-medium ${window.location.pathname.includes('dashboard') ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-secondary'}">Dashboard</a>
                <a href="${up}scan/url.html" class="px-4 py-2 rounded-lg text-sm font-medium ${window.location.pathname.includes('scan') ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-secondary'}">Scan</a>
                <a href="${up}history.html" class="px-4 py-2 rounded-lg text-sm font-medium ${window.location.pathname.includes('history') ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-secondary'}">History</a>
                ${isAdmin ? `<a href="${up}admin.html" class="px-4 py-2 rounded-lg text-sm font-medium ${window.location.pathname.includes('admin') ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-secondary'}">Admin</a>` : ''}
            </div>
        ` : '';

        const rightSide = user ? `
            <div class="flex items-center gap-2">
                <button id="themeToggle" class="p-2 rounded-lg text-muted-foreground hover:bg-secondary">
                    <i data-lucide="${themeIcon}" class="h-5 w-5"></i>
                </button>
                <div class="relative group">
                    <button class="p-2 rounded-full text-muted-foreground hover:bg-secondary border border-border">
                        <i data-lucide="user" class="h-5 w-5"></i>
                    </button>
                    <div class="absolute right-0 top-full mt-2 w-56 bg-card border border-border rounded-lg shadow-lg opacity-0 pointer-events-none group-hover:opacity-100 group-hover:pointer-events-auto transition-opacity z-50">
                        <div class="px-4 py-3 border-b border-border">
                            <p class="text-sm font-medium truncate">${user.email}</p>
                            <p class="text-xs text-muted-foreground">${isAdmin ? 'Administrator' : 'User'}</p>
                        </div>
                        <a href="${up}dashboard.html" class="flex items-center px-4 py-2 text-sm hover:bg-secondary">
                            <i data-lucide="settings" class="mr-2 h-4 w-4"></i> Dashboard
                        </a>
                        <button id="logoutBtn" class="w-full flex items-center px-4 py-2 text-sm text-destructive hover:bg-secondary text-left">
                            <i data-lucide="log-out" class="mr-2 h-4 w-4"></i> Sign Out
                        </button>
                    </div>
                </div>
            </div>
        ` : `
            <div class="flex items-center gap-2">
                <button id="themeToggle" class="p-2 rounded-lg text-muted-foreground hover:bg-secondary mr-2">
                    <i data-lucide="${themeIcon}" class="h-5 w-5"></i>
                </button>
                <a href="${up}login.html" class="px-4 py-2 rounded-lg text-sm font-medium text-muted-foreground hover:text-foreground">Sign In</a>
                <a href="${up}register.html" class="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90">Get Started</a>
            </div>
        `;

        navbarContainer.innerHTML = `
            <nav class="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-lg">
                <div class="container mx-auto px-4">
                    <div class="flex h-16 items-center justify-between">
                        <a href="${up}index.html" class="flex items-center gap-2 text-xl font-bold">
                            <i data-lucide="shield" class="h-8 w-8 text-primary"></i>
                            <span class="hidden sm:inline">CyberGuard</span>
                        </a>
                        ${navLinks}
                        ${rightSide}
                    </div>
                </div>
            </nav>
        `;

        lucide.createIcons();

        document.getElementById('themeToggle')?.addEventListener('click', () => this.toggleTheme());
        document.getElementById('logoutBtn')?.addEventListener('click', async () => {
            await auth.signOut();
            window.location.href = up + 'index.html';
        });
    }
};
