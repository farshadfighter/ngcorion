# NETEASE Frontend Documentation

## Overview

NETEASE frontend is a React-based single-page application (SPA) for enterprise IT asset management. Built with modern React practices using functional components, hooks, and Redux Toolkit for state management.

**Brand:** NGCORION  
**Color Scheme:** Cyan (#00d4ff) as primary color  
**Design:** Dark sidebar, light content area, professional enterprise UI

---

## Tech Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| React | 18.x | UI Library |
| Vite | 5.x | Build tool & dev server |
| Redux Toolkit | 2.x | State management |
| React Router DOM | 6.x | Client-side routing |
| Axios | 1.x | HTTP client |
| CSS | Custom | Styling (no framework) |

---

## Project Structure

```
frontend-react/
├── public/
│   └── favicon.ico
├── src/
│   ├── main.jsx                    # React entry point
│   ├── App.jsx                     # Main app with routes
│   ├── App.css                     # Global styles
│   │
│   ├── api/
│   │   └── axios.js                # Axios instance & interceptors
│   │
│   ├── store/
│   │   ├── index.js                # Redux store configuration
│   │   └── slices/
│   │       ├── authSlice.js        # Authentication state
│   │       ├── usersSlice.js       # User management
│   │       ├── assetsSlice.js      # Assets CRUD & views
│   │       ├── assetTypesSlice.js  # Asset types
│   │       ├── ownersSlice.js      # Asset owners
│   │       ├── locationsSlice.js   # Locations/sites
│   │       ├── zonesSlice.js       # Network zones
│   │       ├── osCatalogSlice.js   # OS catalog
│   │       ├── vendorsSlice.js     # Vendors
│   │       ├── enumsSlice.js       # Enum values (status, risk, etc.)
│   │       └── discoverySlice.js   # Auto-discovery scanning
│   │
│   ├── hooks/
│   │   └── useAuth.js              # Auth hook with role checks
│   │
│   ├── components/
│   │   ├── common/                 # Reusable UI components
│   │   │   ├── Button.jsx
│   │   │   ├── Button.css
│   │   │   ├── Input.jsx
│   │   │   ├── Input.css
│   │   │   ├── Select.jsx
│   │   │   ├── Select.css
│   │   │   ├── Table.jsx
│   │   │   ├── Table.css
│   │   │   ├── Modal.jsx
│   │   │   ├── Modal.css
│   │   │   ├── Tabs.jsx
│   │   │   ├── Tabs.css
│   │   │   ├── SearchBox.jsx
│   │   │   ├── SearchBox.css
│   │   │   ├── PrivateRoute.jsx
│   │   │   └── index.js            # Barrel export
│   │   │
│   │   └── layout/
│   │       ├── MainLayout.jsx      # Main layout wrapper
│   │       ├── MainLayout.css
│   │       ├── Sidebar.jsx         # Navigation sidebar
│   │       ├── Sidebar.css
│   │       ├── Header.jsx          # Top header bar
│   │       └── Header.css
│   │
│   └── pages/
│       ├── Login/
│       │   ├── Login.jsx
│       │   ├── Login.css
│       │   └── index.js
│       │
│       ├── Dashboard/
│       │   ├── Dashboard.jsx
│       │   ├── Dashboard.css
│       │   └── index.js
│       │
│       ├── Users/
│       │   ├── Users.jsx
│       │   ├── Users.css
│       │   ├── components/
│       │   │   └── UserForm.jsx
│       │   └── index.js
│       │
│       ├── AssetList/
│       │   ├── AssetList.jsx
│       │   ├── AssetList.css
│       │   ├── components/
│       │   │   ├── AssetForm.jsx
│       │   │   ├── AssetForm.css
│       │   │   └── index.js
│       │   └── index.js
│       │
│       ├── AssetRequirement/
│       │   ├── AssetRequirement.jsx
│       │   ├── AssetRequirement.css
│       │   └── index.js
│       │
│       ├── AutoDiscovery/
│       │   ├── AutoDiscovery.jsx
│       │   ├── AutoDiscovery.css
│       │   ├── DiscoveryResultModal.jsx
│       │   ├── DiscoveryResultModal.css
│       │   ├── ActivityLog.jsx
│       │   ├── ActivityLog.css
│       │   └── index.js
│       │
│       ├── Auditing/
│       │   ├── Auditing.jsx
│       │   ├── Auditing.css
│       │   └── index.js
│       │
│       ├── Hardening/
│       │   ├── Hardening.jsx
│       │   ├── Hardening.css
│       │   └── index.js
│       │
│       └── Logs/
│           ├── Logs.jsx
│           ├── Logs.css
│           └── index.js
│
├── package.json
├── vite.config.js
├── index.html
└── .env
```

---

## Installation & Setup

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Install Dependencies
```bash
cd frontend-react
npm install
```

### Environment Variables (.env)
```env
VITE_API_URL=http://localhost:8000
# Production:
# VITE_API_URL=http://172.16.200.90:8000
```

### Run Development Server
```bash
npm run dev
# Runs on http://localhost:3000 (configured in vite.config.js)
```

### Build for Production
```bash
npm run build
# Output: dist/
```

---

## Routing

### App.jsx Routes
```jsx
import { Routes, Route, Navigate } from 'react-router-dom';

<Routes>
  {/* Public Route */}
  <Route path="/login" element={<Login />} />
  
  {/* Protected Routes - wrapped in MainLayout */}
  <Route element={<PrivateRoute><MainLayout /></PrivateRoute>}>
    <Route path="/dashboard" element={<Dashboard />} />
    <Route path="/users" element={<Users />} />
    <Route path="/assets" element={<AssetList />} />
    <Route path="/asset-requirement" element={<AssetRequirement />} />
    <Route path="/auto-discovery" element={<AutoDiscovery />} />
    <Route path="/auditing" element={<Auditing />} />
    <Route path="/hardening" element={<Hardening />} />
    <Route path="/logs" element={<Logs />} />
  </Route>
  
  {/* Redirects */}
  <Route path="/" element={<Navigate to="/dashboard" replace />} />
  <Route path="*" element={<Navigate to="/dashboard" replace />} />
</Routes>
```

### Route Protection
```jsx
// components/common/PrivateRoute.jsx
const PrivateRoute = ({ children }) => {
  const { isAuthenticated, loading } = useSelector((state) => state.auth);
  
  if (loading) return <LoadingSpinner />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  
  return children;
};
```

---

## Redux Store

### Store Configuration
```javascript
// store/index.js
import { configureStore } from '@reduxjs/toolkit';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    users: usersReducer,
    assets: assetsReducer,
    assetTypes: assetTypesReducer,
    owners: ownersReducer,
    locations: locationsReducer,
    zones: zonesReducer,
    osCatalog: osCatalogReducer,
    vendors: vendorsReducer,
    enums: enumsReducer,
    discovery: discoveryReducer,
  },
  devTools: import.meta.env.DEV,
});
```

### State Structure
```javascript
{
  auth: {
    user: { id, username, email, full_name, role },
    token: "jwt_token_string",
    isAuthenticated: boolean,
    loading: boolean,
    error: string | null
  },
  
  users: {
    items: [...],
    selectedUser: {...},
    loading: boolean,
    error: string | null
  },
  
  assets: {
    assets: [...],
    selectedAsset: {...},
    assetTypes: [...],
    currentView: 'overview' | 'network' | 'location' | 'security',
    loading: boolean,
    error: string | null
  },
  
  assetTypes: {
    items: [...],
    loading: boolean,
    error: string | null
  },
  
  owners: {
    items: [...],
    loading: boolean,
    error: string | null
  },
  
  locations: {
    items: [...],
    loading: boolean,
    error: string | null
  },
  
  zones: {
    items: [...],
    loading: boolean,
    error: string | null
  },
  
  enums: {
    status: [{ value, label }, ...],
    confidentiality: [...],
    risk: [...],
    loading: boolean
  },
  
  discovery: {
    currentScan: {...},
    scanHistory: [...],
    discoveredHosts: [...],
    matchedAsset: {...},
    activityLog: [...],
    isScanning: boolean,
    isLoadingScans: boolean,
    isApplying: boolean,
    error: string | null
  }
}
```

---

## Slices Reference

### authSlice.js
```javascript
// Actions
export const login = createAsyncThunk('auth/login', async (credentials));
export const logout = createAsyncThunk('auth/logout', async ());
export const getCurrentUser = createAsyncThunk('auth/me', async ());

// Reducers
clearError()

// Selectors
state.auth.user
state.auth.token
state.auth.isAuthenticated
state.auth.loading
state.auth.error
```

### assetsSlice.js
```javascript
// Actions
export const fetchAssets = createAsyncThunk('assets/fetchAll');
export const fetchAsset = createAsyncThunk('assets/fetchOne');  // Full data for edit
export const createAsset = createAsyncThunk('assets/create');
export const updateAsset = createAsyncThunk('assets/update');
export const deleteAsset = createAsyncThunk('assets/delete');
export const fetchAssetTypes = createAsyncThunk('assets/fetchTypes');

// View-specific fetches
export const fetchOverviewView = createAsyncThunk('assets/fetchOverview');
export const fetchNetworkView = createAsyncThunk('assets/fetchNetwork');
export const fetchLocationView = createAsyncThunk('assets/fetchLocation');
export const fetchSecurityView = createAsyncThunk('assets/fetchSecurity');

// Reducers
clearError()
clearSelectedAsset()
setCurrentView(view)
```

### discoverySlice.js
```javascript
// Actions
export const startScan = createAsyncThunk('discovery/start');
export const checkScanStatus = createAsyncThunk('discovery/status');
export const fetchAllScans = createAsyncThunk('discovery/fetchAll');
export const deleteScan = createAsyncThunk('discovery/delete');
export const clearAllScans = createAsyncThunk('discovery/clearAll');
export const matchIpToAsset = createAsyncThunk('discovery/match');
export const applyDiscovery = createAsyncThunk('discovery/apply');
export const createAssetFromDiscovery = createAsyncThunk('discovery/createAsset');

// Reducers
clearError()
clearCurrentScan()
clearMatchedAsset()
setDiscoveredHosts(hosts)
stopScanning()
addLogEntry(entry)
clearActivityLog()
```

---

## Axios Configuration

### api/axios.js
```javascript
import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - Add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor - Handle 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;
```

---

## Custom Hooks

### useAuth.js
```javascript
import { useSelector } from 'react-redux';

export const useAuth = () => {
  const { user, isAuthenticated, loading } = useSelector((state) => state.auth);
  
  const isAdmin = user?.role === 'admin';
  const isManager = user?.role === 'manager';
  
  // Permission checks
  const canWrite = ['admin', 'manager', 'user'].includes(user?.role);
  const canDelete = ['admin', 'manager'].includes(user?.role);
  const canManageUsers = user?.role === 'admin';
  const canViewAll = ['admin', 'manager'].includes(user?.role);
  
  return {
    user,
    isAuthenticated,
    loading,
    isAdmin,
    isManager,
    canWrite,
    canDelete,
    canManageUsers,
    canViewAll,
  };
};
```

---

## Common Components

### Button
```jsx
// Usage
<Button onClick={handleClick}>Click Me</Button>
<Button variant="secondary">Cancel</Button>
<Button variant="danger">Delete</Button>
<Button variant="outline">Outline</Button>
<Button loading={true}>Saving...</Button>
<Button disabled>Disabled</Button>

// Props
{
  children: ReactNode,
  variant: 'primary' | 'secondary' | 'danger' | 'outline',
  loading: boolean,
  disabled: boolean,
  onClick: () => void,
  type: 'button' | 'submit',
  className: string
}
```

### Input
```jsx
// Usage
<Input
  label="Username"
  name="username"
  value={value}
  onChange={handleChange}
  required
  error="This field is required"
  placeholder="Enter username"
  type="text" | "password" | "email" | "number" | "date"
/>
```

### Select
```jsx
// Usage
<Select
  label="Asset Type"
  name="asset_type_id"
  value={selectedValue}
  onChange={handleChange}
  options={[
    { value: 1, label: 'Server' },
    { value: 2, label: 'Router' },
  ]}
  required
/>
```

### Table
```jsx
// Usage
<Table
  columns={[
    { key: 'id', title: 'ID', width: '70px' },
    { key: 'name', title: 'Name' },
    { 
      key: 'status', 
      title: 'Status',
      render: (value, row) => <span className={value}>{value}</span>
    },
  ]}
  data={items}
  loading={isLoading}
  emptyMessage="No data found"
  onRowClick={(row) => handleRowClick(row)}
/>
```

### Modal
```jsx
// Usage
<Modal
  isOpen={showModal}
  onClose={() => setShowModal(false)}
  title="Edit Asset"
  size="small" | "medium" | "large"
>
  <p>Modal content here</p>
</Modal>
```

### Tabs
```jsx
// Usage
<Tabs
  tabs={[
    { key: 'overview', label: 'Overview' },
    { key: 'network', label: 'Network' },
    { key: 'security', label: 'Security' },
  ]}
  activeTab={currentTab}
  onChange={(tab) => setCurrentTab(tab)}
/>
```

### SearchBox
```jsx
// Usage
<SearchBox
  value={searchQuery}
  onChange={setSearchQuery}
  placeholder="Search..."
/>
```

---

## Page Components

### AssetList Page
Main page for viewing and managing assets with multiple views.

**Features:**
- Four views: Overview, Network, Location, Security
- Search filtering
- Create/Edit/Delete functionality
- Multi-step form for asset creation
- Full data fetch before editing

**Key State:**
```javascript
const [searchQuery, setSearchQuery] = useState('');
const [isFormOpen, setIsFormOpen] = useState(false);
const [editingAsset, setEditingAsset] = useState(null);
const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
```

### AutoDiscovery Page
Network scanning and host discovery page.

**Features:**
- Start network scans (basic, detailed, full)
- Real-time scan status polling
- Activity log with color-coded entries
- View discovered hosts
- Match hosts to existing assets
- Create new assets from discovery
- Apply discovery data to assets
- Stop scan functionality
- Clear history

**Key State:**
```javascript
const [showScanModal, setShowScanModal] = useState(false);
const [target, setTarget] = useState('');
const [scanType, setScanType] = useState('basic');
const [showResultModal, setShowResultModal] = useState(false);
const [selectedHost, setSelectedHost] = useState(null);
```

**Polling Logic:**
```javascript
const pollIntervalRef = useRef(null);

useEffect(() => {
  if (isScanning && currentScan?.scan_id) {
    pollIntervalRef.current = setInterval(() => {
      dispatch(checkScanStatus(currentScan.scan_id));
    }, 3000);
  }
  return () => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
    }
  };
}, [isScanning, currentScan?.scan_id]);
```

---

## Layout Components

### MainLayout
```jsx
// Wraps protected pages with sidebar and header
<div className="main-layout">
  <Sidebar />
  <div className="main-content">
    <Header />
    <div className="page-content">
      <Outlet />  {/* React Router renders child routes here */}
    </div>
  </div>
</div>
```

### Sidebar
```jsx
// Navigation menu items
const menuItems = [
  { path: '/dashboard', icon: '📊', label: 'Dashboard' },
  { path: '/users', icon: '👥', label: 'Users', adminOnly: true },
  { path: '/assets', icon: '🖥️', label: 'Asset List' },
  { path: '/asset-requirement', icon: '📋', label: 'Asset Requirement' },
  { path: '/auto-discovery', icon: '🔍', label: 'Auto Discovery' },
  { path: '/auditing', icon: '✅', label: 'Auditing' },
  { path: '/hardening', icon: '🛡️', label: 'Hardening' },
  { path: '/logs', icon: '📜', label: 'Logs' },
];
```

### Header
```jsx
// Shows user info and logout button
<header className="header">
  <div className="header-title">NGCORION</div>
  <div className="header-user">
    <span>{user?.full_name}</span>
    <span className="role-badge">{user?.role}</span>
    <button onClick={handleLogout}>Logout</button>
  </div>
</header>
```

---

## CSS Variables (Global)

```css
/* App.css or index.css */
:root {
  /* Colors */
  --color-primary: #00d4ff;
  --color-primary-dark: #00b8e6;
  --color-secondary: #6c757d;
  --color-success: #22c55e;
  --color-danger: #ef4444;
  --color-warning: #f59e0b;
  --color-info: #3b82f6;
  
  /* Grays */
  --color-gray-100: #f3f4f6;
  --color-gray-200: #e5e7eb;
  --color-gray-300: #d1d5db;
  --color-gray-400: #9ca3af;
  --color-gray-500: #6b7280;
  --color-gray-600: #4b5563;
  --color-gray-700: #374151;
  --color-gray-800: #1f2937;
  --color-gray-900: #111827;
  
  /* Text */
  --text-primary: #111827;
  --text-secondary: #4b5563;
  --text-muted: #9ca3af;
  
  /* Backgrounds */
  --bg-primary: #ffffff;
  --bg-secondary: #f9fafb;
  --bg-sidebar: #0f172a;
  
  /* Borders */
  --border-color: #e5e7eb;
  --border-radius: 8px;
  --border-radius-lg: 12px;
  
  /* Spacing */
  --spacing-xs: 4px;
  --spacing-sm: 8px;
  --spacing-md: 16px;
  --spacing-lg: 24px;
  --spacing-xl: 32px;
  
  /* Typography */
  --font-size-xs: 12px;
  --font-size-sm: 14px;
  --font-size-md: 16px;
  --font-size-lg: 18px;
  --font-size-xl: 24px;
  
  /* Shadows */
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
  --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.1);
  --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.1);
  
  /* Sidebar */
  --sidebar-width: 260px;
  --header-height: 64px;
}
```

---

## Common Patterns

### Fetching Data on Mount
```jsx
useEffect(() => {
  dispatch(fetchAssets());
  dispatch(fetchAssetTypes());
}, [dispatch]);
```

### Form Handling
```jsx
const [formData, setFormData] = useState({
  name: '',
  email: '',
});

const handleChange = (e) => {
  const { name, value } = e.target;
  setFormData(prev => ({ ...prev, [name]: value }));
};

const handleSubmit = async (e) => {
  e.preventDefault();
  try {
    await dispatch(createItem(formData)).unwrap();
    onClose();
  } catch (err) {
    setError(err);
  }
};
```

### Conditional Rendering by Role
```jsx
const { canWrite, canDelete, isAdmin } = useAuth();

return (
  <>
    {canWrite && <Button onClick={handleCreate}>Add</Button>}
    {canDelete && <Button variant="danger" onClick={handleDelete}>Delete</Button>}
    {isAdmin && <Link to="/users">Manage Users</Link>}
  </>
);
```

### Loading & Error States
```jsx
if (loading) return <div className="loading">Loading...</div>;
if (error) return <div className="error">{error}</div>;

return (
  <div>
    {/* Content */}
  </div>
);
```

---

## API Endpoints Used

### Authentication
```javascript
POST /api/auth/login     // { username, password } → { access_token, user }
POST /api/auth/logout    // Logout
GET  /api/auth/me        // Get current user
```

### Assets
```javascript
GET    /api/assets/          // List all assets
POST   /api/assets/          // Create asset
GET    /api/assets/{id}      // Get single asset (full data)
PUT    /api/assets/{id}      // Update asset
DELETE /api/assets/{id}      // Delete asset

// Views (different columns)
GET /api/asset-views/overview
GET /api/asset-views/network-system
GET /api/asset-views/location-ownership
GET /api/asset-views/security-audit
```

### Reference Data
```javascript
GET /api/asset-types/
GET /api/owners/
GET /api/locations/
GET /api/zones/
GET /api/vendors/
GET /api/os-catalog/
GET /api/enums/
```

### Discovery
```javascript
POST   /api/discovery/scan           // { target, scan_type }
GET    /api/discovery/scan/{scan_id} // Get status & results
GET    /api/discovery/scans          // List all scans
DELETE /api/discovery/scan/{scan_id} // Delete scan

POST /api/discovery/match         // Match IP to asset
POST /api/discovery/apply         // Apply to existing asset
POST /api/discovery/create-asset  // Create new from discovery
```

### Users (Admin)
```javascript
GET    /api/users/
POST   /api/users/
GET    /api/users/{id}
PUT    /api/users/{id}
DELETE /api/users/{id}
```

---

## Error Handling

### In Slices
```javascript
export const fetchAssets = createAsyncThunk(
  'assets/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/assets/');
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.detail || 'Failed to fetch assets'
      );
    }
  }
);
```

### In Components
```jsx
const handleSubmit = async () => {
  setError('');
  setLoading(true);
  try {
    await dispatch(createAsset(formData)).unwrap();
    onClose();
  } catch (err) {
    setError(typeof err === 'string' ? err : err.message || 'Operation failed');
  } finally {
    setLoading(false);
  }
};
```

---

## Development Tips

### 1. Adding a New Page
1. Create folder in `src/pages/NewPage/`
2. Create `NewPage.jsx`, `NewPage.css`, `index.js`
3. Add route in `App.jsx`
4. Add menu item in `Sidebar.jsx`

### 2. Adding a New Slice
1. Create `src/store/slices/newSlice.js`
2. Import and add to `store/index.js`
3. Use in components with `useSelector` and `useDispatch`

### 3. Import Conventions
```javascript
// Always use relative imports
import Button from '../../components/common/Button';
import { fetchAssets } from '../../store/slices/assetsSlice';

// Use index.js barrel exports
import { Button, Input, Select } from '../../components/common';
```

### 4. File Naming
- Components: PascalCase (`AssetForm.jsx`)
- Slices: camelCase (`assetsSlice.js`)
- CSS: Match component name (`AssetForm.css`)
- Folders: PascalCase for pages, camelCase for utilities

---

## Known Issues / TODOs

1. **Asset Edit Modal Header** - UI needs improvement
2. **Port Information Page** - Not implemented
3. **CSV Import/Export** - Planned
4. **Dashboard Charts** - Basic, needs enhancement
5. **Mobile Responsiveness** - Partial support
6. **Dark Mode** - Not implemented

---

## Build & Deploy

### Development
```bash
npm run dev
```

### Production Build
```bash
npm run build
npm run preview  # Preview production build locally
```

### Deploy to Server
```bash
# Build locally
npm run build

# Copy dist folder to server
scp -r dist/* user@server:/var/www/netease/

# Or serve with Nginx
```

### Nginx Config (Example)
```nginx
server {
    listen 80;
    server_name netease.local;
    
    root /var/www/netease;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Contact / Notes

- **Developer:** Sina
- **Repository:** Private GitHub
- **Server:** 172.16.200.90 (via VPN)
