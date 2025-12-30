/* ==========================================
   NGCORION - Users Page (Complete with Permissions)
   ========================================== */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { fetchUsers, createUser, updateUser, deleteUser } from '../../store/slices/usersSlice';
import Button from '../../components/common/Button';
import Table from '../../components/common/Table';
import Modal from '../../components/common/Modal';
import Input from '../../components/common/Input';
import Select from '../../components/common/Select';
import SearchBox from '../../components/common/SearchBox';
import './Users.css';

// Available modules for permissions
const MODULES = [
  { name: 'dashboard', label: 'Dashboard' },
  { name: 'asset_requirement', label: 'Asset Requirement' },
  { name: 'asset_list', label: 'Asset List' },
  { name: 'asset_auto_discovery', label: 'Auto Discovery' },
  { name: 'user_management', label: 'User Management' },
  { name: 'auditing', label: 'Auditing' },
  { name: 'hardening', label: 'Hardening' },
  { name: 'logs', label: 'Logs' },
];

const Users = () => {
  const dispatch = useDispatch();
  const { users, loading } = useSelector((state) => state.users);
  const [searchQuery, setSearchQuery] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [deletingUser, setDeletingUser] = useState(null);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    role: 'user',
    is_active: true,
  });
  const [permissions, setPermissions] = useState({});
  const [formError, setFormError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  useEffect(() => {
    dispatch(fetchUsers());
  }, [dispatch]);

  // Initialize default permissions
  const getDefaultPermissions = () => {
    const perms = {};
    MODULES.forEach(mod => {
      perms[mod.name] = {
        can_read: mod.name === 'dashboard' || mod.name === 'asset_list',
        can_write: false,
        can_delete: false,
      };
    });
    return perms;
  };

  const filteredUsers = users.filter(
    (user) =>
      user.username?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.email?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.full_name?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const columns = [
    { key: 'id', title: 'ID', width: '60px' },
    { key: 'username', title: 'Username' },
    { key: 'email', title: 'Email' },
    {
      key: 'role',
      title: 'Role',
      render: (value) => <span className={`role-badge ${value}`}>{value}</span>,
    },
    {
      key: 'is_active',
      title: 'Status',
      render: (value) => (
        <span className={`status-badge ${value ? 'active' : 'decommissioned'}`}>
          {value ? 'Active' : 'Inactive'}
        </span>
      ),
    },
    {
      key: 'actions',
      title: 'Actions',
      render: (_, row) => (
        <div className="table-actions">
          <button className="btn btn-icon edit" onClick={() => handleEdit(row)}>
            <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
              <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z" />
            </svg>
          </button>
          <button className="btn btn-icon delete" onClick={() => handleDeleteClick(row)}>
            <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
              <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z" />
            </svg>
          </button>
        </div>
      ),
    },
  ];

  const roleOptions = [
    { value: 'admin', label: 'Admin' },
    { value: 'manager', label: 'Manager' },
    { value: 'user', label: 'User' },
    { value: 'guest', label: 'Guest' },
  ];

  const handleCreate = () => {
    setEditingUser(null);
    setFormData({
      username: '',
      email: '',
      full_name: '',
      password: '',
      role: 'user',
      is_active: true,
    });
    setPermissions(getDefaultPermissions());
    setFormError('');
    setIsModalOpen(true);
  };

  const handleEdit = async (user) => {
    setEditingUser(user);
    setFormData({
      username: user.username,
      email: user.email || '',
      full_name: user.full_name || '',
      password: '',
      role: user.role,
      is_active: user.is_active,
    });
    
    // Load user permissions
    if (user.role === 'admin') {
      setPermissions({});
    } else {
      // Convert permissions array to object
      const perms = getDefaultPermissions();
      if (user.permissions && Array.isArray(user.permissions)) {
        user.permissions.forEach(p => {
          if (perms[p.module]) {
            perms[p.module] = {
              can_read: p.can_read,
              can_write: p.can_write,
              can_delete: p.can_delete,
            };
          }
        });
      }
      setPermissions(perms);
    }
    
    setFormError('');
    setIsModalOpen(true);
  };

  const handleDeleteClick = (user) => {
    setDeletingUser(user);
    setDeleteError('');
    setIsDeleteModalOpen(true);
  };

  const handlePermissionChange = (module, permission, value) => {
    setPermissions(prev => ({
      ...prev,
      [module]: {
        ...prev[module],
        [permission]: value,
      }
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');

    if (!formData.username) {
      setFormError('Username is required');
      return;
    }

    if (!formData.email) {
      setFormError('Email is required');
      return;
    }

    if (!editingUser && !formData.password) {
      setFormError('Password is required');
      return;
    }

    if (formData.password && formData.password.length < 4) {
      setFormError('Password must be at least 4 characters');
      return;
    }

    try {
      const userData = {
        username: formData.username,
        email: formData.email,
        role: formData.role,
        is_active: formData.is_active,
      };

      if (formData.password) {
        userData.password = formData.password;
      }

      // Add permissions for non-admin users
      if (formData.role !== 'admin') {
        userData.permissions = MODULES.map(mod => ({
          module: mod.name,
          can_read: permissions[mod.name]?.can_read || false,
          can_write: permissions[mod.name]?.can_write || false,
          can_delete: permissions[mod.name]?.can_delete || false,
        }));
      }

      if (editingUser) {
        await dispatch(updateUser({ userId: editingUser.id, userData })).unwrap();
      } else {
        await dispatch(createUser(userData)).unwrap();
      }
      setIsModalOpen(false);
      dispatch(fetchUsers());
    } catch (err) {
      setFormError(err || 'Failed to save user');
    }
  };

  const handleDelete = async () => {
    setDeleteError('');
    try {
      await dispatch(deleteUser(deletingUser.id)).unwrap();
      setIsDeleteModalOpen(false);
      setDeletingUser(null);

      // Show success message
      setSuccessMessage(`User "${deletingUser.username}" deleted successfully!`);
      setTimeout(() => setSuccessMessage(''), 3000);

      // Refresh user list
      dispatch(fetchUsers());
    } catch (err) {
      console.error('Delete failed:', err);
      // Show error in the delete modal
      setDeleteError(typeof err === 'string' ? err : err.message || 'Failed to delete user. You may not have permission.');
    }
  };

  return (
    <div className="users-page">
      <div className="page-header">
        <h1 className="page-title">User Management</h1>
        <Button onClick={handleCreate}>
          <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
            <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
          </svg>
          Add User
        </Button>
      </div>

      {/* Success Message */}
      {successMessage && (
        <div className="success-message" style={{ marginBottom: '20px' }}>
          {successMessage}
        </div>
      )}

      <div className="users-toolbar">
        <SearchBox
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder="Search users..."
        />
      </div>

      <Table columns={columns} data={filteredUsers} loading={loading} emptyMessage="No users found" />

      {/* Create/Edit Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title={editingUser ? 'Edit User' : 'Create User'}
        size="large"
      >
        <form onSubmit={handleSubmit} className="user-form">
          {formError && <div className="error-message">{formError}</div>}

          <div className="form-row">
            <Input
              label="Username *"
              name="username"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              required
            />

            <Input
              label="Email *"
              type="email"
              name="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              required
            />
          </div>

          <div className="form-row">
            <Input
              label={editingUser ? 'Password (leave blank to keep)' : 'Password *'}
              type="password"
              name="password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              required={!editingUser}
            />

            <Select
              label="Role *"
              name="role"
              value={formData.role}
              onChange={(e) => setFormData({ ...formData, role: e.target.value })}
              options={roleOptions}
            />
          </div>

          <div className="form-group">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={formData.is_active}
                onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
              />
              <span>Active</span>
            </label>
          </div>

          {/* Permissions Section - Only show for non-admin */}
          {formData.role !== 'admin' && (
            <div className="permissions-section">
              <h4>Permissions</h4>
              <p className="permissions-hint">Set access permissions for each module</p>
              
              <div className="permissions-grid">
                <div className="permission-header">
                  <span>Module</span>
                  <span>Read</span>
                  <span>Write</span>
                  <span>Delete</span>
                </div>
                
                {MODULES.map(mod => (
                  <div className="permission-row" key={mod.name}>
                    <span>{mod.label}</span>
                    <input
                      type="checkbox"
                      checked={permissions[mod.name]?.can_read || false}
                      onChange={(e) => handlePermissionChange(mod.name, 'can_read', e.target.checked)}
                    />
                    <input
                      type="checkbox"
                      checked={permissions[mod.name]?.can_write || false}
                      onChange={(e) => handlePermissionChange(mod.name, 'can_write', e.target.checked)}
                    />
                    <input
                      type="checkbox"
                      checked={permissions[mod.name]?.can_delete || false}
                      onChange={(e) => handlePermissionChange(mod.name, 'can_delete', e.target.checked)}
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          {formData.role === 'admin' && (
            <div className="admin-notice">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/>
              </svg>
              <span>Admin users have full access to all modules</span>
            </div>
          )}

          <div className="form-actions">
            <Button variant="secondary" type="button" onClick={() => setIsModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit">{editingUser ? 'Update' : 'Create'}</Button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={isDeleteModalOpen}
        onClose={() => setIsDeleteModalOpen(false)}
        title="Delete User"
        size="small"
      >
        {deleteError && (
          <div className="error-message" style={{ marginBottom: '16px' }}>
            {deleteError}
          </div>
        )}
        <p>Are you sure you want to delete user "<strong>{deletingUser?.username}</strong>"?</p>
        <p className="warning-text">This action cannot be undone.</p>
        <div className="form-actions">
          <Button variant="secondary" onClick={() => setIsDeleteModalOpen(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={handleDelete}>
            Delete
          </Button>
        </div>
      </Modal>
    </div>
  );
};

export default Users;
