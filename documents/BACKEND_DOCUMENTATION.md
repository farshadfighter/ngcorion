# Netease Backend Documentation

A comprehensive backend documentation for the Netease Asset Management System.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Technology Stack](#2-technology-stack)
3. [Project Structure](#3-project-structure)
4. [Getting Started](#4-getting-started)
5. [Configuration](#5-configuration)
6. [Database Architecture](#6-database-architecture)
7. [Authentication & Authorization](#7-authentication--authorization)
8. [API Modules](#8-api-modules)
9. [Services](#9-services)
10. [Database Migrations](#10-database-migrations)

---

## 1. Overview

Netease is a professional asset management and security auditing system built with FastAPI. It provides:

- **Asset Inventory Management** - Comprehensive tracking with 23+ fields per asset
- **Network Auto-Discovery** - Nmap-based scanning with approval workflow
- **Security Auditing** - Cisco CIS benchmark compliance checking via SSH
- **User Management** - Multi-role access control with granular permissions
- **Audit Trails** - Complete logging of all system operations

---

## 2. Technology Stack

| Category | Technology | Version |
|----------|-----------|---------|
| Framework | FastAPI | 0.121.2 |
| Server | Uvicorn | 0.38.0 |
| Database ORM | SQLAlchemy | 2.0.44 |
| Database | PostgreSQL | - |
| Migrations | Alembic | 1.17.2 |
| Authentication | PyJWT | 2.10.1 |
| Cryptography | python-jose | 3.5.0 |
| Password Hashing | passlib + bcrypt | 1.7.4 / 3.2.2 |
| Validation | Pydantic | 2.12.4 |
| Network Scanning | python-nmap | 0.7.1 |
| SSH Client | asyncssh | 2.21.1 |
| Excel Export | openpyxl | 3.1.5 |

---

## 3. Project Structure

```
netease/
├── app/                           # Main FastAPI application
│   ├── main.py                   # Application entry point
│   ├── core/                     # Core functionality
│   │   ├── config.py            # Configuration management
│   │   ├── database.py          # Database setup & sessions
│   │   ├── security.py          # JWT & password hashing
│   │   ├── dependencies.py      # FastAPI dependencies
│   │   └── rate_limiter.py      # Rate limiting
│   ├── models/                   # SQLAlchemy ORM models
│   │   ├── user.py              # User model
│   │   ├── user_permission.py   # Permissions
│   │   ├── asset.py             # Asset inventory
│   │   ├── audit.py             # Audit models
│   │   ├── discovery.py         # Discovery models
│   │   ├── port.py              # Port models
│   │   ├── enums.py             # Enumerations
│   │   └── ...                  # Other models
│   ├── modules/                  # Feature modules
│   │   ├── auth/                # Authentication
│   │   ├── users/               # User management
│   │   ├── assets/              # Asset management
│   │   ├── discovery/           # Network discovery
│   │   ├── audit/               # Security auditing
│   │   └── logs/                # Logging
│   ├── schemas/                  # Pydantic schemas
│   └── utils/                    # Utilities
├── alembic/                      # Database migrations
│   └── versions/                # Migration files
├── scripts/                      # Utility scripts
│   └── init_db.py               # Database initialization
├── .env                          # Environment variables
├── alembic.ini                   # Alembic configuration
└── requirement.txt               # Python dependencies
```

---

## 4. Getting Started

### Prerequisites

- Python 3.10+
- PostgreSQL
- Nmap (for network discovery)

### Installation

1. **Clone the repository**
   ```bash
   cd /home/sina/main_app/netease
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirement.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

5. **Initialize database**
   ```bash
   python scripts/init_db.py
   ```

6. **Run migrations**
   ```bash
   alembic upgrade head
   ```

7. **Start the server**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### Default Credentials

- **Username:** `admin`
- **Password:** `123456`

---

## 5. Configuration

### Environment Variables (`.env`)

```ini
# Project Info
PROJECT_NAME=Netease
VERSION=1.0.1
DESCRIPTION=Asset Management System

# Database
DATABASE_URL=postgresql://netease:1234@localhost/login_db

# Security
SECRET_KEY=your-super-secret-key-min-32-chars
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Server
HOST=0.0.0.0
PORT=8000

# CORS
BACKEND_CORS_ORIGINS=["*"]
```

### Configuration Class (`app/core/config.py`)

The `Settings` class uses Pydantic for validation and loads values from `.env`:

```python
class Settings(BaseSettings):
    PROJECT_NAME: str
    VERSION: str
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    # ...
```

---

## 6. Database Architecture

### Entity Relationship Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           USER DOMAIN                                │
├─────────────────────────────────────────────────────────────────────┤
│  User ──────────< UserPermission                                    │
│    │                                                                 │
│    ├──────────< Asset                                               │
│    ├──────────< AssetOwner                                          │
│    ├──────────< AssetLocation                                       │
│    ├──────────< DiscoveryScan ────< DiscoveredHost                  │
│    └──────────< AuditSession ─────< AuditResult                     │
├─────────────────────────────────────────────────────────────────────┤
│                         ASSET DOMAIN                                 │
├─────────────────────────────────────────────────────────────────────┤
│  Asset >─────── AssetType                                           │
│    │   >─────── AssetOwner                                          │
│    │   >─────── AssetLocation                                       │
│    │                                                                 │
│    ├──────────< Port >────── Protocol                               │
│    ├──────────< AssetDependency                                     │
│    └──────────< AssetSecurityStatus                                 │
├─────────────────────────────────────────────────────────────────────┤
│                        REFERENCE DATA                                │
├─────────────────────────────────────────────────────────────────────┤
│  NetworkZone    OSCatalog    VendorCatalog    Protocol              │
└─────────────────────────────────────────────────────────────────────┘
```

### Core Models

#### User Model

```python
class User(Base):
    __tablename__ = "users"

    id: int (PK)
    username: str (unique)
    email: str (unique)
    hashed_password: str
    is_active: bool
    role: RoleEnum  # admin, manager, user, guest
    created_at: datetime
```

#### Asset Model

```python
class Asset(Base):
    __tablename__ = "assets"

    # Identity
    id: int (PK)
    asset_name: str
    hostname: str

    # Classification
    asset_type_id: FK -> AssetType
    asset_role: str

    # Hardware
    manufacturer: str
    model: str
    serial_number: str

    # Software
    os_name: str
    os_version: str

    # Network
    ip_address: str
    mac_address: str

    # Organization
    location_id: FK -> AssetLocation
    owner_id: FK -> AssetOwner
    status: StatusEnum

    # Security
    confidentiality_level: ConfidentialityLevelEnum
    risk_level: RiskLevelEnum
    last_audit_date: datetime
    last_patch_date: datetime

    # Value
    asset_value: Numeric(12, 2)

    # Ownership
    user_id: FK -> User
```

#### Audit Models

```python
class AuditTemplate(Base):
    __tablename__ = "audit_templates"

    id: int (PK)
    name: str
    device_type: DeviceTypeEnum  # cisco, linux, windows, fortinet
    version: str
    profile: str  # L1, L2, FULL

class AuditSession(Base):
    __tablename__ = "audit_sessions"

    id: int (PK)
    template_id: FK -> AuditTemplate
    asset_id: FK -> Asset
    target_ip: str
    status: str  # running, completed, failed
    compliance_pct: float
    total_checks: int
    passed_checks: int
    failed_checks: int

class AuditResult(Base):
    __tablename__ = "audit_results"

    id: int (PK)
    session_id: FK -> AuditSession
    check_number: str  # e.g., "IOS-L1-001"
    status: CheckStatusEnum  # pass, fail, not_applicable, error
    evidence_snippet: str
```

### Enumerations

```python
class RoleEnum(str, Enum):
    admin = "admin"
    manager = "manager"
    user = "user"
    guest = "guest"

class StatusEnum(str, Enum):
    ACTIVE = "active"
    STANDBY = "standby"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"

class ConfidentialityLevelEnum(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CRITICAL = "critical"

class RiskLevelEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DeviceTypeEnum(str, Enum):
    CISCO = "cisco"
    LINUX = "linux"
    WINDOWS = "windows"
    FORTINET = "fortinet"

class CheckStatusEnum(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
```

---

## 7. Authentication & Authorization

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     AUTHENTICATION FLOW                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Client sends POST /auth/login                               │
│     ├── Body: { username, password }                            │
│                                                                  │
│  2. Server validates credentials                                │
│     ├── Query user by username                                  │
│     ├── Verify password with bcrypt                             │
│     ├── Check user is_active                                    │
│                                                                  │
│  3. Server generates JWT token                                  │
│     ├── Subject: username                                       │
│     ├── Role: user.role                                         │
│     ├── Expiration: 30 minutes                                  │
│     ├── Algorithm: HS256                                        │
│                                                                  │
│  4. Server returns token                                        │
│     ├── { access_token, token_type, username, role, permissions }│
│                                                                  │
│  5. Client includes token in requests                           │
│     ├── Header: Authorization: Bearer <token>                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### JWT Token Structure

```python
{
    "sub": "admin",           # Username
    "role": "admin",          # User role
    "exp": 1703001234         # Expiration timestamp
}
```

### Role-Based Access Control (RBAC)

| Role | Description |
|------|-------------|
| `admin` | Full access to all modules |
| `manager` | Configurable permissions |
| `user` | Configurable permissions |
| `guest` | Read-only (configurable) |

### Module-Based Permissions

Permissions are stored in the `user_permissions` table:

| Module | can_read | can_write | can_delete |
|--------|----------|-----------|------------|
| dashboard | ✓ | ✓ | ✓ |
| asset_requirement | ✓ | ✓ | ✓ |
| asset_list | ✓ | ✓ | ✓ |
| asset_auto_discovery | ✓ | ✓ | ✓ |
| user_management | ✓ | ✓ | ✓ |
| auditing | ✓ | ✓ | ✓ |
| hardening | ✓ | ✓ | ✓ |
| logs | ✓ | ✓ | ✓ |

### Dependency Functions

```python
# app/core/dependencies.py

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Validates JWT and returns authenticated user"""

def require_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """Enforces admin-only access"""

def require_permission(module: str, action: str):
    """Factory for fine-grained permission checking"""
    def checker(current_user: User, db: Session):
        # Check permission in database
        return current_user
    return checker
```

### Usage in Routes

```python
@router.get("/users/")
async def get_users(
    current_user: User = Depends(require_permission("user_management", "read")),
    db: Session = Depends(get_db)
):
    # Only users with user_management.read permission can access
    ...
```

---

## 8. API Modules

### Authentication (`/auth`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | User login |

**Login Request:**
```json
{
    "username": "admin",
    "password": "123456"
}
```

**Login Response:**
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "bearer",
    "username": "admin",
    "role": "admin",
    "permissions": {
        "dashboard": {"read": true, "write": true, "delete": true},
        ...
    }
}
```

---

### Users (`/api/users`)

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/users/` | user_management.read | List all users |
| GET | `/api/users/{id}` | user_management.read | Get user by ID |
| POST | `/api/users/` | user_management.write | Create user |
| PUT | `/api/users/{id}` | user_management.write | Update user |
| DELETE | `/api/users/{id}` | user_management.delete | Delete user |
| GET | `/api/users/modules` | authenticated | List available modules |

**Create User Request:**
```json
{
    "username": "john",
    "email": "john@example.com",
    "password": "secure123",
    "role": "user",
    "is_active": true,
    "permissions": {
        "dashboard": {"read": true, "write": false, "delete": false},
        "asset_list": {"read": true, "write": true, "delete": false}
    }
}
```

---

### Assets (`/api/assets`)

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/assets/` | asset_list.read | List assets (paginated) |
| GET | `/api/assets/{id}` | asset_list.read | Get asset by ID |
| POST | `/api/assets/` | asset_list.write | Create asset |
| PUT | `/api/assets/{id}` | asset_list.write | Update asset |
| DELETE | `/api/assets/{id}` | asset_list.delete | Delete asset |

**Create Asset Request:**
```json
{
    "asset_name": "Core Router 1",
    "hostname": "router-core-01",
    "asset_type_id": 1,
    "asset_role": "Core Network Device",
    "manufacturer": "Cisco",
    "model": "ISR 4451",
    "serial_number": "FHK123456",
    "os_name": "Cisco IOS",
    "os_version": "15.7",
    "ip_address": "192.168.1.1",
    "mac_address": "00:11:22:33:44:55",
    "location_id": 1,
    "owner_id": 1,
    "status": "active",
    "confidentiality_level": "confidential",
    "risk_level": "high",
    "asset_value": 15000.00,
    "description": "Main core router"
}
```

---

### Asset Types (`/api/asset-types`)

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/asset-types/` | asset_list.read | List asset types |
| POST | `/api/asset-types/` | asset_list.write | Create type |
| PUT | `/api/asset-types/{id}` | asset_list.write | Update type |
| DELETE | `/api/asset-types/{id}` | asset_list.delete | Delete type |

**Default Asset Types:**
- Firewall
- Router
- Switch
- Server
- Workstation
- Laptop
- Printer
- Access Point
- Storage
- Other

---

### Asset Owners (`/api/asset-owners`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/asset-owners/` | List owners (user-scoped) |
| POST | `/api/asset-owners/` | Create owner |
| PUT | `/api/asset-owners/{id}` | Update owner |
| DELETE | `/api/asset-owners/{id}` | Delete owner |

**Owner Fields:**
- full_name
- department
- role
- email
- phone
- responsibility_level

---

### Asset Locations (`/api/asset-locations`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/asset-locations/` | List locations (user-scoped) |
| POST | `/api/asset-locations/` | Create location |
| PUT | `/api/asset-locations/{id}` | Update location |
| DELETE | `/api/asset-locations/{id}` | Delete location |

**Location Fields:**
- site_name
- rack_name
- room
- floor
- network_zone
- vlan_id
- subnet
- description

---

### Reference Data

| Endpoint | Description |
|----------|-------------|
| GET `/api/network-zones/` | List network zones |
| GET `/api/os-catalog/` | List OS options |
| GET `/api/vendor-catalog/` | List vendors |
| GET `/api/enums/` | List enum values |

---

### Network Discovery (`/api/discovery`)

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| POST | `/api/discovery/scan` | asset_auto_discovery.write | Start network scan |
| GET | `/api/discovery/scans/{id}` | asset_auto_discovery.read | Get scan status |
| GET | `/api/discovery/pending-hosts` | asset_auto_discovery.read | List pending hosts |
| POST | `/api/discovery/apply-discovery` | asset_auto_discovery.write | Apply to asset |
| POST | `/api/discovery/create-asset-from-discovery` | asset_auto_discovery.write | Create new asset |
| POST | `/api/discovery/manage-ports` | asset_auto_discovery.write | Manage ports |

**Start Scan Request:**
```json
{
    "target": "192.168.1.0/24",
    "scan_type": "well_known_ports",
    "protocol": "tcp",
    "job_name": "Network Scan Q4"
}
```

**Scan Types:**
- `all_ports` - Scan all 65535 ports
- `well_known_ports` - Scan ports 1-1024
- `custom_ports` - Specify custom port range

**Discovered Host Response:**
```json
{
    "id": 1,
    "scan_id": "abc12345",
    "ip_address": "192.168.1.100",
    "mac_address": "00:11:22:33:44:55",
    "hostname": "server-01",
    "os_info": "Linux 5.4",
    "os_accuracy": 95,
    "open_ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh"},
        {"port": 80, "protocol": "tcp", "service": "http"}
    ],
    "status": "pending",
    "discovered_at": "2024-01-15T10:30:00Z"
}
```

---

### Security Auditing (`/api/audit`)

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| POST | `/api/audit/cisco/execute` | auditing.write | Execute Cisco audit |
| GET | `/api/audit/sessions/{id}` | auditing.read | Get session details |
| GET | `/api/audit/results/{id}` | auditing.read | Get result details |

**Execute Cisco Audit Request:**
```json
{
    "asset_id": 1,
    "ssh_username": "admin",
    "ssh_password": "password123",
    "ssh_secret": "enable_secret",
    "profile": "L1"
}
```

**Audit Profiles:**
- `L1` - Level 1 checks only (basic security)
- `FULL` - All checks including Level 2

**Audit Session Response:**
```json
{
    "session_id": 1,
    "status": "completed",
    "compliance_pct": 85.5,
    "total_checks": 40,
    "passed_checks": 34,
    "failed_checks": 6,
    "results": [
        {
            "check_number": "IOS-L1-001",
            "title": "Set 'hostname'",
            "status": "pass",
            "severity": "medium",
            "evidence_snippet": "hostname router-core-01"
        },
        {
            "check_number": "IOS-L1-002",
            "title": "Set 'enable secret'",
            "status": "fail",
            "severity": "high",
            "evidence_snippet": "No 'enable secret' found",
            "remediation": "Configure enable secret: enable secret <password>"
        }
    ]
}
```

---

### Logs (`/api/logs`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/logs/` | List login logs |
| GET | `/api/logs/user/{username}` | User-specific logs |

**Query Parameters:**
- `limit` - Number of records (default: 50)
- `success_only` - Filter by success status

**Log Entry:**
```json
{
    "id": 1,
    "username": "admin",
    "success": true,
    "ip_address": "192.168.1.50",
    "user_agent": "Mozilla/5.0...",
    "message": "Login successful",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 9. Services

### AuthService (`app/modules/auth/service.py`)

Handles user authentication:

```python
class AuthService:
    def authenticate_user(db: Session, username: str, password: str) -> User | bool:
        """
        Validates username/password combination.
        Returns User object on success, False on failure.
        """
```

### UserService (`app/modules/users/service.py`)

Manages users and permissions:

```python
class UserService:
    def get_users(db: Session) -> List[User]
    def get_user(db: Session, user_id: int) -> User
    def create_user(db: Session, user_data: dict) -> User
    def update_user(db: Session, user_id: int, user_data: dict) -> User
    def delete_user(db: Session, user_id: int) -> bool
    def get_user_permissions(db: Session, user_id: int) -> dict
    def update_user_permissions(db: Session, user_id: int, permissions: dict)
```

### AssetService (`app/modules/assets/service.py`)

Manages assets and related data:

```python
class AssetService:
    # Asset CRUD
    def get_assets(db: Session, user_id: int, skip: int, limit: int)
    def get_asset(db: Session, asset_id: int, user_id: int)
    def create_asset(db: Session, asset_data: dict, user_id: int)
    def update_asset(db: Session, asset_id: int, asset_data: dict)
    def delete_asset(db: Session, asset_id: int)

    # Asset Types
    def get_asset_types(db: Session)
    def create_asset_type(db: Session, type_data: dict)

    # Owners & Locations
    def get_asset_owners(db: Session, user_id: int)
    def get_asset_locations(db: Session, user_id: int)
```

### DiscoveryService (`app/modules/discovery/service.py`)

Handles network discovery:

```python
class DiscoveryService:
    def start_scan(db: Session, target: str, scan_type: str, ...) -> DiscoveryScan
    def get_scan(db: Session, scan_id: str) -> DiscoveryScan
    def get_pending_hosts(db: Session, user_id: int) -> List[DiscoveredHost]
    def apply_discovery(db: Session, host_id: int, asset_id: int, ...)
    def create_asset_from_discovery(db: Session, host_id: int, ...)
    def manage_ports(db: Session, asset_id: int, ports: List[dict])
```

### AuditService (`app/modules/audit/service.py`)

Manages security auditing:

```python
class AuditService:
    def execute_cisco_audit(
        db: Session,
        asset_id: int,
        ssh_credentials: dict,
        profile: str
    ) -> AuditSession

    def get_session(db: Session, session_id: int) -> AuditSession
    def get_result(db: Session, result_id: int) -> AuditResult
```

### CiscoSSHClient (`app/modules/audit/ssh_client.py`)

SSH connection handler for Cisco devices:

```python
class CiscoSSHClient:
    async def connect(host: str, username: str, password: str, secret: str)
    async def execute_command(command: str) -> str
    async def get_running_config() -> str
    async def close()
```

---

## 10. Database Migrations

### Using Alembic

**Create new migration:**
```bash
alembic revision --autogenerate -m "Description of changes"
```

**Apply migrations:**
```bash
alembic upgrade head
```

**Rollback one migration:**
```bash
alembic downgrade -1
```

**View migration history:**
```bash
alembic history
```

**Check current version:**
```bash
alembic current
```

### Migration Files

Located in `alembic/versions/`. Key migrations include:

1. Initial tables (users, permissions)
2. Asset management tables
3. Discovery models
4. Audit models
5. Port and protocol tables
6. Reference data tables

---

## Appendix

### Default Data Created by `init_db.py`

**Admin User:**
- Username: `admin`
- Password: `123456`
- Role: `admin`

**Asset Types:**
- Firewall, Router, Switch, Server, Workstation, Laptop, Printer, Access Point, Storage, Other

**Network Zones:**
- DMZ, Internal, Management, Guest, External

**OS Catalog:**
- Windows Server, Windows Desktop, Linux (Ubuntu/CentOS/RHEL/Debian), Cisco IOS, FortiOS, etc.

**Vendor Catalog:**
- Cisco, Fortinet, HP, Dell, Juniper, Microsoft, VMware, etc.

### Security Considerations

1. **Change default credentials** in production
2. **Use strong SECRET_KEY** (minimum 32 characters)
3. **Configure CORS origins** properly (don't use `["*"]` in production)
4. **Enable HTTPS** via reverse proxy
5. **Regular database backups**
6. **Audit log monitoring**

### Process Management

**Using runit (local):**
```bash
sv status netease
sv restart netease
```

**Using systemd (server):**
```bash
systemctl status netease
systemctl restart netease
```

---
