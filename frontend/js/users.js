/* ==========================================
   NETEASE - User Management JavaScript
   ========================================== */

// ==================== State ====================
let usersData = [];
let editingUserId = null;
let deletingUserId = null;

// ==================== Initialize ====================
function init_user_management() {
    loadUsers();
    updateCreateButtonVisibility();
    setupRoleChangeListener();
}

function updateCreateButtonVisibility() {
    const createBtn = document.getElementById('btn-create-user');
    if (createBtn) {
        if (hasPermission('user_management', 'write')) {
            createBtn.classList.remove('hidden');
        } else {
            createBtn.classList.add('hidden');
        }
    }
}

function setupRoleChangeListener() {
    const roleSelect = document.getElementById('user-role');
    if (roleSelect) {
        roleSelect.addEventListener('change', function() {
            const permSection = document.getElementById('permissions-section');
            if (this.value === 'admin') {
                permSection.classList.add('hidden');
            } else {
                permSection.classList.remove('hidden');
            }
        });
    }
}

// ==================== Load Users ====================
async function loadUsers() {
    const tbody = document.getElementById('users-table-body');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">Loading users...</td></tr>';

    try {
        const response = await apiRequest('/api/users/');

        if (!response.ok) {
            throw new Error('Failed to load users');
        }

        usersData = await response.json();
        renderUsersTable();
    } catch (error) {
        console.error('Error loading users:', error);
        tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">Error loading users</td></tr>';
    }
}

function renderUsersTable() {
    const tbody = document.getElementById('users-table-body');
    if (!tbody) return;
    
    if (usersData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">No users found</td></tr>';
        return;
    }

    const canWrite = hasPermission('user_management', 'write');
    const canDelete = hasPermission('user_management', 'delete');

    tbody.innerHTML = usersData.map(user => `
        <tr>
            <td>${user.id}</td>
            <td><strong>${user.username}</strong></td>
            <td>${user.email}</td>
            <td><span class="role-badge ${user.role}">${user.role}</span></td>
            <td><span class="status-badge ${user.is_active ? 'active' : 'inactive'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
            <td class="actions-cell">
                ${canWrite ? `
                    <button class="btn btn-icon edit" onclick="editUser(${user.id})" title="Edit">
                        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                    </button>
                ` : ''}
                ${canDelete ? `
                    <button class="btn btn-icon delete" onclick="deleteUser(${user.id}, '${user.username}')" title="Delete">
                        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                    </button>
                ` : ''}
            </td>
        </tr>
    `).join('');
}

// ==================== Create User ====================
function showCreateUserModal() {
    editingUserId = null;
    document.getElementById('modal-title').textContent = 'Create User';
    document.getElementById('btn-save-user').textContent = 'Create User';
    document.getElementById('user-form').reset();
    document.getElementById('user-password').required = true;
    document.getElementById('password-hint').textContent = '(min 4 chars) *';
    document.getElementById('permissions-section').classList.remove('hidden');
    document.getElementById('form-error').classList.add('hidden');
    
    // Reset permissions to defaults
    resetPermissions();
    
    document.getElementById('user-modal').classList.remove('hidden');
}

// ==================== Edit User ====================
async function editUser(userId) {
    editingUserId = userId;
    document.getElementById('modal-title').textContent = 'Edit User';
    document.getElementById('btn-save-user').textContent = 'Update User';
    document.getElementById('user-password').required = false;
    document.getElementById('password-hint').textContent = '(leave empty to keep current)';
    document.getElementById('form-error').classList.add('hidden');

    try {
        const response = await apiRequest(`/api/users/${userId}`);

        if (!response.ok) throw new Error('Failed to load user');

        const user = await response.json();
        
        document.getElementById('user-id').value = user.id;
        document.getElementById('user-username').value = user.username;
        document.getElementById('user-email').value = user.email;
        document.getElementById('user-password').value = '';
        document.getElementById('user-role').value = user.role;
        document.getElementById('user-active').checked = user.is_active;

        // Handle permissions section visibility
        if (user.role === 'admin') {
            document.getElementById('permissions-section').classList.add('hidden');
        } else {
            document.getElementById('permissions-section').classList.remove('hidden');
            loadPermissions(user.permissions || []);
        }

        document.getElementById('user-modal').classList.remove('hidden');
    } catch (error) {
        console.error('Error loading user:', error);
        alert('Error loading user details');
    }
}

// ==================== Permission Helpers ====================
function resetPermissions() {
    document.querySelectorAll('.permission-row').forEach(row => {
        const module = row.dataset.module;
        row.querySelector('.perm-read').checked = (module === 'dashboard' || module === 'asset_list');
        row.querySelector('.perm-write').checked = false;
        row.querySelector('.perm-delete').checked = false;
    });
}

function loadPermissions(permissions) {
    // Reset all first
    document.querySelectorAll('.permission-row').forEach(row => {
        row.querySelector('.perm-read').checked = false;
        row.querySelector('.perm-write').checked = false;
        row.querySelector('.perm-delete').checked = false;
    });

    // Set from data
    permissions.forEach(perm => {
        const row = document.querySelector(`.permission-row[data-module="${perm.module}"]`);
        if (row) {
            row.querySelector('.perm-read').checked = perm.can_read;
            row.querySelector('.perm-write').checked = perm.can_write;
            row.querySelector('.perm-delete').checked = perm.can_delete;
        }
    });
}

function getPermissionsFromForm() {
    const permissions = [];
    document.querySelectorAll('.permission-row').forEach(row => {
        permissions.push({
            module: row.dataset.module,
            can_read: row.querySelector('.perm-read').checked,
            can_write: row.querySelector('.perm-write').checked,
            can_delete: row.querySelector('.perm-delete').checked
        });
    });
    return permissions;
}

// ==================== Save User ====================
function closeUserModal() {
    document.getElementById('user-modal').classList.add('hidden');
    editingUserId = null;
}

async function saveUser() {
    const saveBtn = document.getElementById('btn-save-user');
    const errorDiv = document.getElementById('form-error');
    
    const username = document.getElementById('user-username').value.trim();
    const email = document.getElementById('user-email').value.trim();
    const password = document.getElementById('user-password').value;
    const role = document.getElementById('user-role').value;
    const isActive = document.getElementById('user-active').checked;

    // Validation
    if (!username || !email) {
        errorDiv.textContent = 'Username and email are required';
        errorDiv.classList.remove('hidden');
        return;
    }

    if (!editingUserId && (!password || password.length < 4)) {
        errorDiv.textContent = 'Password must be at least 4 characters';
        errorDiv.classList.remove('hidden');
        return;
    }

    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';
    errorDiv.classList.add('hidden');

    try {
        const userData = {
            username,
            email,
            role,
            is_active: isActive
        };

        // Add password only if provided
        if (password) {
            userData.password = password;
        }

        // Add permissions only if not admin
        if (role !== 'admin') {
            userData.permissions = getPermissionsFromForm();
        }

        const url = editingUserId 
            ? `/api/users/${editingUserId}`
            : `/api/users/`;

        const response = await apiRequest(url, {
            method: editingUserId ? 'PUT' : 'POST',
            body: JSON.stringify(userData)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Failed to save user');
        }

        closeUserModal();
        loadUsers();
    } catch (error) {
        console.error('Error saving user:', error);
        errorDiv.textContent = error.message;
        errorDiv.classList.remove('hidden');
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = editingUserId ? 'Update User' : 'Create User';
    }
}

// ==================== Delete User ====================
function deleteUser(userId, username) {
    deletingUserId = userId;
    document.getElementById('delete-username').textContent = username;
    document.getElementById('delete-modal').classList.remove('hidden');
}

function closeDeleteModal() {
    document.getElementById('delete-modal').classList.add('hidden');
    deletingUserId = null;
}

async function confirmDeleteUser() {
    if (!deletingUserId) return;

    const deleteBtn = document.getElementById('btn-confirm-delete');
    deleteBtn.disabled = true;
    deleteBtn.textContent = 'Deleting...';

    try {
        const response = await apiRequest(`/api/users/${deletingUserId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.detail || 'Failed to delete user');
        }

        closeDeleteModal();
        loadUsers();
    } catch (error) {
        console.error('Error deleting user:', error);
        alert(error.message);
    } finally {
        deleteBtn.disabled = false;
        deleteBtn.textContent = 'Delete';
    }
}
