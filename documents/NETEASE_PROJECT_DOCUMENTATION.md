# NETEASE (NGCORION) - Project Documentation

## Overview

NETEASE is an enterprise IT Asset Management System developed for tracking and managing IT infrastructure including firewalls, routers, switches, servers, and other network devices. The brand name is **NGCORION**.

**Developer:** Sina  
**Environment:** AntiX Linux (development), Ubuntu 24 (production server at 172.16.200.90)  
**Status:** Working deployment with ongoing feature development

---

## Tech Stack

### Backend
- **Framework:** FastAPI (Python)
- **Database:** PostgreSQL
- **ORM:** SQLAlchemy
- **Migrations:** Alembic
- **Authentication:** JWT (python-jose)
- **Password Hashing:** bcrypt (passlib)
- **Network Scanning:** python-nmap

### Frontend
- **Framework:** React 18 + Vite
- **State Management:** Redux Toolkit
- **HTTP Client:** Axios
- **Routing:** React Router DOM v6
- **Styling:** CSS (custom, no framework)

### Deployment
- **Server:** Ubuntu 24
- **Process Manager:** systemd services
- **Reverse Proxy:** Nginx (optional)

---

## Project Structure

```
netease/
├── backend/
│   ├── main.py                 # FastAPI app entry point
│   ├── database.py             # Database connection & session
│   ├── models.py               # SQLAlchemy models
│   ├── schemas.py              # Pydantic schemas
│   ├── auth.py                 # JWT authentication
│   ├── dependencies.py         # FastAPI dependencies
│   ├── routers/
│   │   ├── auth.py             # Login/logout endpoints
│   │   ├── users.py            # User management
│   │   ├── assets.py           # Asset CRUD
│   │   ├── asset_types.py      # Asset type management
│   │   ├── asset_views.py      # Different asset views
│   │   ├── owners.py           # Asset owners
│   │   ├── locations.py        # Locations/sites
│   │   ├── zones.py            # Network zones
│   │   ├── os_catalog.py       # OS catalog
│   │   ├── vendors.py          # Vendor management
│   │   ├── discovery.py        # Auto-discovery (nmap)
│   │   └── logs.py             # Audit logs
│   ├── alembic/                # Database migrations
│   └── requirements.txt
│
├── frontend-react/
│   ├── src/
│   │   ├── main.jsx            # React entry point
│   │   ├── App.jsx             # Main app with routes
│   │   ├── App.css             # Global styles
│   │   ├── api/
│   │   │   └── axios.js        # Axios instance with interceptors
│   │   ├── store/
│   │   │   ├── index.js        # Redux store configuration
│   │   │   └── slices/
│   │   │       ├── authSlice.js
│   │   │       ├── usersSlice.js
│   │   │       ├── assetsSlice.js
│   │   │       ├── assetTypesSlice.js
│   │   │       ├── ownersSlice.js
│   │   │       ├── locationsSlice.js
│   │   │       ├── zonesSlice.js
│   │   │       ├── osCatalogSlice.js
│   │   │       ├── vendorsSlice.js
│   │   │       ├── enumsSlice.js
│   │   │       └── discoverySlice.js
│   │   ├── hooks/
│   │   │   └── useAuth.js      # Auth hook with role checks
│   │   ├── components/
│   │   │   ├── common/         # Reusable components
│   │   │   │   ├── Button.jsx
│   │   │   │   ├── Input.jsx
│   │   │   │   ├── Select.jsx
│   │   │   │   ├── Table.jsx
│   │   │   │   ├── Modal.jsx
│   │   │   │   ├── Tabs.jsx
│   │   │   │   ├── SearchBox.jsx
│   │   │   │   └── PrivateRoute.jsx
│   │   │   └── layout/
│   │   │       ├── MainLayout.jsx
│   │   │       ├── Sidebar.jsx
│   │   │       └── Header.jsx
│   │   └── pages/
│   │       ├── Login/
│   │       ├── Dashboard/
│   │       ├── Users/
│   │       ├── AssetList/
│   │       │   ├── AssetList.jsx
│   │       │   ├── AssetList.css
│   │       │   └── components/
│   │       │       ├── AssetForm.jsx
│   │       │       └── AssetForm.css
│   │       ├── AssetRequirement/
│   │       ├── AutoDiscovery/
│   │       │   ├── AutoDiscovery.jsx
│   │       │   ├── AutoDiscovery.css
│   │       │   ├── DiscoveryResultModal.jsx
│   │       │   ├── DiscoveryResultModal.css
│   │       │   ├── ActivityLog.jsx
│   │       │   └── ActivityLog.css
│   │       ├── Auditing/
│   │       ├── Hardening/
│   │       └── Logs/
│   ├── package.json
│   └── vite.config.js
```

---

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',  -- admin, manager, user, guest
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);
```

### Assets Table
```sql
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    asset_name VARCHAR(100) NOT NULL,
    hostname VARCHAR(100),
    asset_type_id INTEGER REFERENCES asset_types(id),
    asset_role VARCHAR(100),
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    serial_number VARCHAR(100),
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    ip_address VARCHAR(45),
    mac_address VARCHAR(17),
    location_id INTEGER REFERENCES locations(id),
    zone_id INTEGER REFERENCES zones(id),
    owner_id INTEGER REFERENCES owners(id),
    status VARCHAR(20) DEFAULT 'active',
    confidentiality_level VARCHAR(20),
    risk_level VARCHAR(20),
    last_audit_date DATE,
    last_patch_date DATE,
    asset_value DECIMAL(15,2),
    description TEXT,
    user_id INTEGER REFERENCES users(id),  -- Row-level isolation
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);
```

### Asset Types Table
```sql
CREATE TABLE asset_types (
    id SERIAL PRIMARY KEY,
    type_name VARCHAR(50) NOT NULL,
    category VARCHAR(50),
    description TEXT,
    icon VARCHAR(50)
);
```

### Locations Table
```sql
CREATE TABLE locations (
    id SERIAL PRIMARY KEY,
    site_name VARCHAR(100) NOT NULL,
    address TEXT,
    city VARCHAR(50),
    country VARCHAR(50),
    building VARCHAR(50),
    floor VARCHAR(20),
    room VARCHAR(50)
);
```

### Zones Table
```sql
CREATE TABLE zones (
    id SERIAL PRIMARY KEY,
    zone_name VARCHAR(50) NOT NULL,
    zone_type VARCHAR(50),  -- DMZ, Internal, External, etc.
    vlan_id INTEGER,
    subnet VARCHAR(18),
    description TEXT
);
```

### Owners Table
```sql
CREATE TABLE owners (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    department VARCHAR(100),
    phone VARCHAR(20),
    position VARCHAR(100)
);
```

### Discovery Scans Table
```sql
CREATE TABLE discovery_scans (
    id SERIAL PRIMARY KEY,
    scan_id UUID UNIQUE NOT NULL,
    target VARCHAR(100) NOT NULL,
    scan_type VARCHAR(20),  -- basic, detailed, full
    status VARCHAR(20),     -- pending, running, completed, failed
    hosts_total INTEGER DEFAULT 0,
    hosts_up INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT,
    user_id INTEGER REFERENCES users(id)
);
```

### Discovery Hosts Table
```sql
CREATE TABLE discovery_hosts (
    id SERIAL PRIMARY KEY,
    scan_id UUID REFERENCES discovery_scans(scan_id),
    ip_address VARCHAR(45) NOT NULL,
    hostname VARCHAR(100),
    mac_address VARCHAR(17),
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    os_accuracy INTEGER,
    status VARCHAR(20),
    ports JSONB,  -- Array of {port, protocol, state, service, version}
    discovered_at TIMESTAMP DEFAULT NOW()
);
```

### Login Logs Table
```sql
CREATE TABLE login_logs (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN,
    failure_reason VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

## API Endpoints

### Authentication
```
POST /api/auth/login          # Login, returns JWT token
POST /api/auth/logout         # Logout
GET  /api/auth/me             # Get current user info
```

### Users (Admin only)
```
GET    /api/users/            # List all users
POST   /api/users/            # Create user
GET    /api/users/{id}        # Get user by ID
PUT    /api/users/{id}        # Update user
DELETE /api/users/{id}        # Delete user
```

### Assets
```
GET    /api/assets/           # List assets (filtered by user_id for non-admins)
POST   /api/assets/           # Create asset
GET    /api/assets/{id}       # Get asset by ID (full data)
PUT    /api/assets/{id}       # Update asset
DELETE /api/assets/{id}       # Delete asset
```

### Asset Views (Read-only, specific columns)
```
GET /api/asset-views/overview           # Basic info view
GET /api/asset-views/network-system     # Network & system info
GET /api/asset-views/location-ownership # Location & owner info
GET /api/asset-views/security-audit     # Security info
```

### Reference Data
```
GET /api/asset-types/         # List asset types
GET /api/owners/              # List owners
GET /api/locations/           # List locations
GET /api/zones/               # List network zones
GET /api/vendors/             # List vendors
GET /api/os-catalog/          # List OS options
GET /api/enums/               # Get all enum values (status, risk, etc.)
```

### Auto Discovery
```
POST /api/discovery/scan              # Start new scan
GET  /api/discovery/scan/{scan_id}    # Get scan status & results
GET  /api/discovery/scans             # List all scans
DELETE /api/discovery/scan/{scan_id}  # Delete scan

POST /api/discovery/match             # Match IP to existing asset
POST /api/discovery/apply             # Apply discovery data to asset
POST /api/discovery/create-asset      # Create new asset from discovery
```

### Logs
```
GET /api/logs/login           # Get login logs (admin only)
GET /api/logs/audit           # Get audit logs
```

---

## User Roles & Permissions

| Role | View Assets | Create/Edit | Delete | Manage Users | View All Assets |
|------|-------------|-------------|--------|--------------|-----------------|
| admin | ✅ | ✅ | ✅ | ✅ | ✅ |
| manager | ✅ | ✅ | ✅ | ❌ | ✅ |
| user | ✅ (own) | ✅ | ❌ | ❌ | ❌ |
| guest | ✅ (own) | ❌ | ❌ | ❌ | ❌ |

---

## Frontend Routes

```javascript
/login              → Login page (public)
/dashboard          → Dashboard (protected)
/users              → User management (admin only)
/assets             → Asset list with views
/asset-requirement  → Asset requirements
/auto-discovery     → Network scanning
/auditing           → Audit page
/hardening          → Hardening page
/logs               → System logs
```

---

## Key Features Implemented

### 1. Authentication & Authorization
- JWT-based authentication
- Role-based access control (RBAC)
- Login attempt logging
- Token refresh handling

### 2. Asset Management
- Multi-step asset creation form (4 steps)
- Multiple views (Overview, Network, Location, Security)
- Search and filter
- Edit with full data fetch
- Delete with confirmation

### 3. Auto Discovery
- Network scanning using nmap
- Three scan types: Basic, Detailed, Full
- Real-time status polling
- Activity log with color-coded entries
- Match discovered hosts to existing assets
- Create new assets from discovery
- Apply discovery data to update assets
- Stop scan functionality
- Clear history functionality

### 4. Reference Data Management
- Asset Types
- Locations/Sites
- Network Zones
- Owners
- Vendors
- OS Catalog

---

## Redux Store Structure

```javascript
{
  auth: {
    user: { id, username, email, role, ... },
    token: "jwt_token",
    isAuthenticated: boolean,
    loading: boolean,
    error: string
  },
  assets: {
    assets: [...],
    selectedAsset: {...},
    assetTypes: [...],
    currentView: 'overview',
    loading: boolean,
    error: string
  },
  discovery: {
    currentScan: {...},
    scanHistory: [...],
    discoveredHosts: [...],
    activityLog: [...],
    isScanning: boolean,
    isLoadingScans: boolean,
    error: string
  },
  // ... other slices
}
```

---

## Axios Configuration

```javascript
// Base URL
baseURL: 'http://172.16.200.90:8000'  // Production
baseURL: 'http://localhost:8000'       // Development

// Interceptors
- Request: Adds Authorization header with JWT token
- Response: Handles 401 errors, redirects to login
```

---

## Auto Discovery Scan Types

| Type | Ports | Service Detection | OS Detection | Scripts | Time |
|------|-------|-------------------|--------------|---------|------|
| basic | 100 | ❌ | ❌ | ❌ | 30s-2min |
| detailed | 1000 | ✅ | ✅ | ❌ | 2-10min |
| full | 65535 | ✅ | ✅ | ✅ Aggressive | 10-60+min |

---

## Known Issues / TODOs

1. **Asset Edit Modal Header** - UI needs improvement, header not visible properly
2. **Port Information Page** - Not yet implemented
3. **CSV Import/Export** - Planned but not implemented
4. **Asset Dependencies** - Table exists but UI not implemented
5. **Dashboard Charts** - Basic implementation, needs enhancement

---

## Environment Variables

### Backend (.env)
```
DATABASE_URL=postgresql://user:password@localhost:5432/netease
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Frontend (.env)
```
VITE_API_URL=http://172.16.200.90:8000
```

---

## Running the Project

### Backend
```bash
cd backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend
```bash
cd frontend-react
npm install
npm run dev          # Development
npm run build        # Production build
```

### Production Deployment
```bash
# Backend service: /etc/systemd/system/netease-backend.service
# Frontend: Served by Nginx or as static files
```

---

## File Locations on Server

```
/home/user/netease/backend/          # Backend code
/home/user/netease/frontend-react/   # Frontend code
/var/www/netease/                    # Built frontend (optional)
```

---

## Recent Changes

1. Added Auto Discovery with Activity Log
2. Fixed Asset Edit - now fetches complete data before editing
3. Added Stop Scan and Clear History buttons
4. Added discovered field highlighting in Asset Form
5. Fixed import path issues (assetsSlice vs assetSlice)

---

## Developer Notes

- Sina prefers step-by-step explanations with educational guidance
- Code comments should be in English
- Conversation language is Persian
- Focus on maintainable, team-friendly code
- Using modular architecture with separate routers
- RESTful API design principles followed
