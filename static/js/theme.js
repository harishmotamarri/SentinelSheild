// Theme handling logic
const STORAGE_KEY = 'sentinel-shield-theme';
const THEME_ATTR = 'data-theme';

// 1. Initialize Theme on Load
function initTheme() {
    const savedTheme = localStorage.getItem(STORAGE_KEY);
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    // Default to dark if nothing saved
    if (savedTheme) {
        document.documentElement.setAttribute(THEME_ATTR, savedTheme);
        updateToggleIcon(savedTheme);
    } else {
        // Enforce dark mode as default for this app "premium" look, unless user explicitly wants light
        // or respect system? Let's default to dark as per design.
        document.documentElement.setAttribute(THEME_ATTR, 'dark');
        updateToggleIcon('dark');
    }
}

// 2. Toggle Function
window.toggleTheme = function () {
    const currentTheme = document.documentElement.getAttribute(THEME_ATTR);
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';

    document.documentElement.setAttribute(THEME_ATTR, newTheme);
    localStorage.setItem(STORAGE_KEY, newTheme);
    updateToggleIcon(newTheme);
}

// 3. Update Icon UI (if exists)
function updateToggleIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
        if (theme === 'light') {
            icon.classList.remove('fa-sun');
            icon.classList.add('fa-moon');
        } else {
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun');
        }
    }
}

// Run immediately
initTheme();
