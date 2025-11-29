/* ==========================================
   NETEASE - Main Application JavaScript
   ========================================== */

// ==================== Configuration ====================
const API_URL = 'http://localhost:8000';

// ==================== State ====================
let currentPage = 'dashboard';
let permissions = {};
let userInfo = {};

// ==================== Initialization ====================
function initApp() {
    // Check authentication
    const token = localStorage.getItem('access_token');
    if (!token) {
        window.location.href = 'index.html';
        return;
    }

    // Load user info
    userInfo = {
        username: localStorage.getItem('username') || 'User',
        role: localStorage.getItem('role') || 'user'
    };

    // Load permissions
    try {
        permissions = JSON.parse(localStorage.getItem('permissions')) || {};
    } catch (e) {
        permissions = {};
    }

    // Initialize UI
    initializeUI();
    applyPermissions();
    
    // Load default page or from hash
    const hash = window.location.hash.slice(1);
    showPage(hash || 'dashboard');

    // Set current date
    const dateEl = document.getElementById('currentDate');
    if (dateEl) {
        dateEl.textContent = new Date().toLocaleDateString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    }
}

// ==================== UI Initialization ====================
function initializeUI() {
    // Set user info
    const userNameEl = document.getElementById('userName');
    const userRoleEl = document.getElementById('userRole');
    const userAvatarEl = document.getElementById('userAvatar');
    const welcomeNameEl = document.getElementById('welcomeName');

    if (userNameEl) userNameEl.textContent = userInfo.username;
    if (userRoleEl) userRoleEl.textContent = userInfo.role;
    if (userAvatarEl) userAvatarEl.textContent = userInfo.username.charAt(0).toUpperCase();
    if (welcomeNameEl) welcomeNameEl.textContent = userInfo.username;

    // Add click listeners to nav items
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
        item.addEventListener('click', function() {
            const page = this.getAttribute('data-page');
            showPage(page);
        });
    });
}

// ==================== Permission Management ====================
function applyPermissions() {
    // Define which nav items correspond to which permission modules
    const navPermissionMap = {
        'nav-dashboard': 'dashboard',
        'nav-asset_requirement': 'asset_requirement',
        'nav-asset_list': 'asset_list',
        'nav-asset_auto_discovery': 'asset_auto_discovery',
        'nav-auditing': 'auditing',
        'nav-hardening': 'hardening',
        'nav-user_management': 'user_management',
        'nav-logs': 'logs'
    };

    // Hide nav items based on read permission
    for (const [navId, module] of Object.entries(navPermissionMap)) {
        const navElement = document.getElementById(navId);
        if (navElement) {
            const hasReadPermission = permissions[module]?.read === true;
            if (!hasReadPermission) {
                navElement.classList.add('hidden');
            }
        }
    }

    // Hide entire sections if all items are hidden
    hideEmptySections();
}

function hideEmptySections() {
    // Check Asset Management section
    const assetItems = ['nav-asset_requirement', 'nav-asset_list', 'nav-asset_auto_discovery'];
    const hasVisibleAsset = assetItems.some(id => {
        const el = document.getElementById(id);
        return el && !el.classList.contains('hidden');
    });
    const assetSection = document.getElementById('nav-asset-management');
    if (assetSection && !hasVisibleAsset) {
        assetSection.classList.add('hidden');
    }

    // Check Security section
    const securityItems = ['nav-auditing', 'nav-hardening'];
    const hasVisibleSecurity = securityItems.some(id => {
        const el = document.getElementById(id);
        return el && !el.classList.contains('hidden');
    });
    const securitySection = document.getElementById('nav-security');
    if (securitySection && !hasVisibleSecurity) {
        securitySection.classList.add('hidden');
    }

    // Check Admin section
    const adminItems = ['nav-user_management', 'nav-logs'];
    const hasVisibleAdmin = adminItems.some(id => {
        const el = document.getElementById(id);
        return el && !el.classList.contains('hidden');
    });
    const adminSection = document.getElementById('nav-admin');
    if (adminSection && !hasVisibleAdmin) {
        adminSection.classList.add('hidden');
    }
}

function hasPermission(module, action = 'read') {
    return permissions[module]?.[action] === true;
}

// ==================== Page Navigation ====================
function showPage(pageName) {
    // Check permission
    if (!hasPermission(pageName, 'read')) {
        pageName = 'access_denied';
    }

    // Update URL hash
    if (pageName !== 'access_denied') {
        window.location.hash = pageName;
    }

    // Hide all pages
    document.querySelectorAll('[id^="page-"]').forEach(page => {
        page.classList.add('hidden');
    });

    // Show selected page
    const pageElement = document.getElementById(`page-${pageName}`);
    if (pageElement) {
        pageElement.classList.remove('hidden');
    }

    // Update active nav item
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    const activeNav = document.querySelector(`.nav-item[data-page="${pageName}"]`);
    if (activeNav) {
        activeNav.classList.add('active');
    }

    // Update page title
    const pageTitles = {
        'dashboard': 'Dashboard',
        'asset_requirement': 'Asset Requirement',
        'asset_list': 'Asset List',
        'asset_auto_discovery': 'Auto Discovery',
        'auditing': 'Auditing',
        'hardening': 'Hardening',
        'user_management': 'User Management',
        'logs': 'System Logs',
        'access_denied': 'Access Denied'
    };
    const titleEl = document.getElementById('pageTitle');
    if (titleEl) {
        titleEl.textContent = pageTitles[pageName] || pageName;
    }

    currentPage = pageName;

    // Trigger page-specific initialization
    if (typeof window[`init_${pageName}`] === 'function') {
        window[`init_${pageName}`]();
    }
}

// ==================== Sidebar Functions ====================
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('collapsed');
}

function toggleUserMenu() {
    document.getElementById('userDropdown').classList.toggle('show');
}

// Close dropdown when clicking outside
document.addEventListener('click', function(e) {
    const dropdown = document.getElementById('userDropdown');
    const menuBtn = document.querySelector('.user-menu-btn');
    if (dropdown && menuBtn && !dropdown.contains(e.target) && !menuBtn.contains(e.target)) {
        dropdown.classList.remove('show');
    }
});

// ==================== User Actions ====================
function changePassword() {
    alert('Change password functionality coming soon!');
    document.getElementById('userDropdown').classList.remove('show');
}

function logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
    localStorage.removeItem('permissions');
    window.location.href = 'index.html';
}

// ==================== API Helper ====================
async function apiRequest(endpoint, options = {}) {
    const token = localStorage.getItem('access_token');
    
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        }
    };

    const response = await fetch(`${API_URL}${endpoint}`, {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers
        }
    });

    if (response.status === 401) {
        logout();
        throw new Error('Unauthorized');
    }

    return response;
}

// ==================== Initialize on DOM Ready ====================
document.addEventListener('DOMContentLoaded', initApp);

// Handle browser back/forward
window.addEventListener('hashchange', function() {
    const hash = window.location.hash.slice(1);
    if (hash && hash !== currentPage) {
        showPage(hash);
    }
});


// ==================== Dashboard Stats ====================
async function init_dashboard() {
    try {
        // Load assets count
        const assetsRes = await apiRequest('/api/assets/');
        if (assetsRes.ok) {
            const assets = await assetsRes.json();
            document.getElementById('stat-total-assets').textContent = assets.length;
            
            const activeAssets = assets.filter(a => a.status === 'active').length;
            document.getElementById('stat-active-assets').textContent = activeAssets;
        }

        // Load users count (if has permission)
        if (hasPermission('user_management', 'read')) {
            const usersRes = await apiRequest('/api/users/');
            if (usersRes.ok) {
                const users = await usersRes.json();
                document.getElementById('stat-total-users').textContent = users.length;
            }
        }

        // Pending issues (placeholder - can be customized)
        document.getElementById('stat-pending-issues').textContent = '0';
        
    } catch (error) {
        console.error('Error loading dashboard stats:', error);
    }
}

// ==================== Dashboard Stats ====================
async function init_dashboard() {
    try {
        // Load assets count
        const assetsRes = await apiRequest('/api/assets/');
        if (assetsRes.ok) {
            const assets = await assetsRes.json();
            document.getElementById('stat-total-assets').textContent = assets.length;
            
            const activeAssets = assets.filter(a => a.status === 'active').length;
            document.getElementById('stat-active-assets').textContent = activeAssets;
        }

        // Load users count (if has permission)
        if (hasPermission('user_management', 'read')) {
            const usersRes = await apiRequest('/api/users/');
            if (usersRes.ok) {
                const users = await usersRes.json();
                document.getElementById('stat-total-users').textContent = users.length;
            }
        }

        // Pending issues (placeholder)
        document.getElementById('stat-pending-issues').textContent = '0';
        
    } catch (error) {
        console.error('Error loading dashboard stats:', error);
    }
}