/* ==========================================
   NETEASE - Asset List JavaScript
   Fixed to match actual API response
   ========================================== */

// ==================== State ====================
let assetsData = [];
let assetTypes = [];
let assetOwners = [];
let assetLocations = [];
let editingAssetId = null;
let deletingAssetId = null;

// ==================== Initialize ====================
function init_asset_list() {
    loadAssets();
    loadDropdownData();
    updateAssetCreateButtonVisibility();
}

function updateAssetCreateButtonVisibility() {
    const createBtn = document.getElementById('btn-create-asset');
    if (createBtn) {
        if (hasPermission('asset_list', 'write')) {
            createBtn.classList.remove('hidden');
        } else {
            createBtn.classList.add('hidden');
        }
    }
}

// ==================== Load Data ====================
async function loadAssets() {
    const tbody = document.getElementById('assets-table-body');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="8" class="loading-cell">Loading assets...</td></tr>';

    try {
        const response = await apiRequest('/api/assets/');

        if (!response.ok) {
            throw new Error('Failed to load assets');
        }

        assetsData = await response.json();
        console.log('Assets loaded:', assetsData.length);
        renderAssetsTable();
    } catch (error) {
        console.error('Error loading assets:', error);
        tbody.innerHTML = '<tr><td colspan="8" class="loading-cell">Error loading assets</td></tr>';
    }
}

async function loadDropdownData() {
    try {
        const [typesRes, ownersRes, locationsRes] = await Promise.all([
            apiRequest('/api/asset-types/'),
            apiRequest('/api/owners/'),
            apiRequest('/api/locations/')
        ]);

        if (typesRes.ok) assetTypes = await typesRes.json();
        if (ownersRes.ok) assetOwners = await ownersRes.json();
        if (locationsRes.ok) assetLocations = await locationsRes.json();

        populateAssetDropdowns();
    } catch (error) {
        console.error('Error loading dropdown data:', error);
    }
}

function populateAssetDropdowns() {
    // Asset Type
    const typeSelect = document.getElementById('asset-type');
    if (typeSelect && assetTypes.length) {
        typeSelect.innerHTML = '<option value="">Select Type</option>' +
            assetTypes.map(t => `<option value="${t.id}">${t.name}</option>`).join('');
    }

    // Owner
    const ownerSelect = document.getElementById('asset-owner');
    if (ownerSelect && assetOwners.length) {
        ownerSelect.innerHTML = '<option value="">Select Owner</option>' +
            assetOwners.map(o => `<option value="${o.id}">${o.name}</option>`).join('');
    }

    // Location
    const locationSelect = document.getElementById('asset-location');
    if (locationSelect && assetLocations.length) {
        locationSelect.innerHTML = '<option value="">Select Location</option>' +
            assetLocations.map(l => `<option value="${l.id}">${l.name}</option>`).join('');
    }
}

// Helper to get name from ID
function getTypeName(typeId) {
    const type = assetTypes.find(t => t.id === typeId);
    return type ? type.name : '-';
}

function getOwnerName(ownerId) {
    const owner = assetOwners.find(o => o.id === ownerId);
    return owner ? owner.name : '-';
}

function getLocationName(locationId) {
    const location = assetLocations.find(l => l.id === locationId);
    return location ? location.name : '-';
}

// ==================== Render Table ====================
function renderAssetsTable() {
    const tbody = document.getElementById('assets-table-body');
    if (!tbody) return;
    
    if (assetsData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="loading-cell">No assets found</td></tr>';
        return;
    }

    const canWrite = hasPermission('asset_list', 'write');
    const canDelete = hasPermission('asset_list', 'delete');

    tbody.innerHTML = assetsData.map(asset => `
        <tr>
            <td>${asset.id}</td>
            <td><strong>${asset.asset_name || '-'}</strong></td>
            <td>${asset.ip_address || '-'}</td>
            <td>${getTypeName(asset.asset_type_id)}</td>
            <td>${getOwnerName(asset.owner_id)}</td>
            <td>${getLocationName(asset.location_id)}</td>
            <td><span class="status-badge ${asset.status || 'inactive'}">${formatStatus(asset.status)}</span></td>
            <td class="actions-cell">
                <button class="btn btn-icon" onclick="viewAsset(${asset.id})" title="View">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>
                </button>
                ${canWrite ? `
                    <button class="btn btn-icon edit" onclick="editAsset(${asset.id})" title="Edit">
                        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                    </button>
                ` : ''}
                ${canDelete ? `
                    <button class="btn btn-icon delete" onclick="deleteAsset(${asset.id}, '${asset.asset_name}')" title="Delete">
                        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                    </button>
                ` : ''}
            </td>
        </tr>
    `).join('');
}

function formatStatus(status) {
    const statusMap = {
        'active': 'Active',
        'inactive': 'Inactive',
        'maintenance': 'Maintenance',
        'retired': 'Retired'
    };
    return statusMap[status] || status || 'Unknown';
}

// ==================== View Asset ====================
async function viewAsset(assetId) {
    try {
        const response = await apiRequest(`/api/assets/${assetId}`);
        if (!response.ok) throw new Error('Failed to load asset');

        const asset = await response.json();
        
        document.getElementById('view-asset-name').textContent = asset.asset_name || '-';
        document.getElementById('view-asset-ip').textContent = asset.ip_address || '-';
        document.getElementById('view-asset-mac').textContent = asset.mac_address || '-';
        document.getElementById('view-asset-type').textContent = getTypeName(asset.asset_type_id);
        document.getElementById('view-asset-owner').textContent = getOwnerName(asset.owner_id);
        document.getElementById('view-asset-location').textContent = getLocationName(asset.location_id);
        document.getElementById('view-asset-hostname').textContent = asset.hostname || '-';
        document.getElementById('view-asset-manufacturer').textContent = asset.manufacturer || '-';
        document.getElementById('view-asset-model').textContent = asset.model || '-';
        document.getElementById('view-asset-serial').textContent = asset.serial_number || '-';
        document.getElementById('view-asset-os').textContent = asset.os_name ? `${asset.os_name} ${asset.os_version || ''}` : '-';
        document.getElementById('view-asset-status').textContent = formatStatus(asset.status);
        document.getElementById('view-asset-description').textContent = asset.description || '-';

        document.getElementById('asset-view-modal').classList.remove('hidden');
    } catch (error) {
        console.error('Error loading asset:', error);
        alert('Error loading asset details');
    }
}

function closeAssetViewModal() {
    document.getElementById('asset-view-modal').classList.add('hidden');
}

// ==================== Create Asset ====================
function showCreateAssetModal() {
    editingAssetId = null;
    document.getElementById('asset-modal-title').textContent = 'Create Asset';
    document.getElementById('btn-save-asset').textContent = 'Create Asset';
    document.getElementById('asset-form').reset();
    document.getElementById('asset-form-error').classList.add('hidden');
    
    document.getElementById('asset-modal').classList.remove('hidden');
}

// ==================== Edit Asset ====================
async function editAsset(assetId) {
    editingAssetId = assetId;
    document.getElementById('asset-modal-title').textContent = 'Edit Asset';
    document.getElementById('btn-save-asset').textContent = 'Update Asset';
    document.getElementById('asset-form-error').classList.add('hidden');

    try {
        const response = await apiRequest(`/api/assets/${assetId}`);
        if (!response.ok) throw new Error('Failed to load asset');

        const asset = await response.json();
        
        document.getElementById('asset-id').value = asset.id;
        document.getElementById('asset-name').value = asset.asset_name || '';
        document.getElementById('asset-hostname').value = asset.hostname || '';
        document.getElementById('asset-ip').value = asset.ip_address || '';
        document.getElementById('asset-mac').value = asset.mac_address || '';
        document.getElementById('asset-type').value = asset.asset_type_id || '';
        document.getElementById('asset-owner').value = asset.owner_id || '';
        document.getElementById('asset-location').value = asset.location_id || '';
        document.getElementById('asset-manufacturer').value = asset.manufacturer || '';
        document.getElementById('asset-model').value = asset.model || '';
        document.getElementById('asset-serial').value = asset.serial_number || '';
        document.getElementById('asset-status').value = asset.status || 'active';
        document.getElementById('asset-description').value = asset.description || '';

        document.getElementById('asset-modal').classList.remove('hidden');
    } catch (error) {
        console.error('Error loading asset:', error);
        alert('Error loading asset details');
    }
}

// ==================== Save Asset ====================
function closeAssetModal() {
    document.getElementById('asset-modal').classList.add('hidden');
    editingAssetId = null;
}

async function saveAsset() {
    const saveBtn = document.getElementById('btn-save-asset');
    const errorDiv = document.getElementById('asset-form-error');
    
    const assetName = document.getElementById('asset-name').value.trim();
    
    if (!assetName) {
        errorDiv.textContent = 'Asset name is required';
        errorDiv.classList.remove('hidden');
        return;
    }

    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';
    errorDiv.classList.add('hidden');

    try {
        const assetData = {
            asset_name: assetName,
            hostname: document.getElementById('asset-hostname').value.trim() || null,
            ip_address: document.getElementById('asset-ip').value.trim() || null,
            mac_address: document.getElementById('asset-mac').value.trim() || null,
            asset_type_id: parseInt(document.getElementById('asset-type').value) || null,
            owner_id: parseInt(document.getElementById('asset-owner').value) || null,
            location_id: parseInt(document.getElementById('asset-location').value) || null,
            manufacturer: document.getElementById('asset-manufacturer').value.trim() || null,
            model: document.getElementById('asset-model').value.trim() || null,
            serial_number: document.getElementById('asset-serial').value.trim() || null,
            status: document.getElementById('asset-status').value,
            description: document.getElementById('asset-description').value.trim() || null
        };

        const url = editingAssetId 
            ? `/api/assets/${editingAssetId}`
            : `/api/assets/`;

        const response = await apiRequest(url, {
            method: editingAssetId ? 'PUT' : 'POST',
            body: JSON.stringify(assetData)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Failed to save asset');
        }

        closeAssetModal();
        loadAssets();
    } catch (error) {
        console.error('Error saving asset:', error);
        errorDiv.textContent = error.message;
        errorDiv.classList.remove('hidden');
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = editingAssetId ? 'Update Asset' : 'Create Asset';
    }
}

// ==================== Delete Asset ====================
function deleteAsset(assetId, assetName) {
    deletingAssetId = assetId;
    document.getElementById('delete-asset-name').textContent = assetName;
    document.getElementById('asset-delete-modal').classList.remove('hidden');
}

function closeAssetDeleteModal() {
    document.getElementById('asset-delete-modal').classList.add('hidden');
    deletingAssetId = null;
}

async function confirmDeleteAsset() {
    if (!deletingAssetId) return;

    const deleteBtn = document.getElementById('btn-confirm-delete-asset');
    deleteBtn.disabled = true;
    deleteBtn.textContent = 'Deleting...';

    try {
        const response = await apiRequest(`/api/assets/${deletingAssetId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.detail || 'Failed to delete asset');
        }

        closeAssetDeleteModal();
        loadAssets();
    } catch (error) {
        console.error('Error deleting asset:', error);
        alert(error.message);
    } finally {
        deleteBtn.disabled = false;
        deleteBtn.textContent = 'Delete';
    }
}

// ==================== Search ====================
function searchAssets() {
    const query = document.getElementById('asset-search').value.toLowerCase().trim();
    
    if (!query) {
        renderAssetsTable();
        return;
    }

    const filtered = assetsData.filter(asset => 
        (asset.asset_name && asset.asset_name.toLowerCase().includes(query)) ||
        (asset.ip_address && asset.ip_address.includes(query)) ||
        (asset.hostname && asset.hostname.toLowerCase().includes(query)) ||
        (asset.manufacturer && asset.manufacturer.toLowerCase().includes(query))
    );

    // Temporarily replace assetsData for rendering
    const originalData = assetsData;
    assetsData = filtered;
    renderAssetsTable();
    assetsData = originalData;
}