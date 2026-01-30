# Ngicorn - Complete Project Guide

**Version:** 1.0.8
**Project Name:** Ngicorn (Network Monitoring and Asset Management System)
**Last Updated:** January 29, 2026
**Status:** Production Ready

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Installation & Setup](#installation--setup)
5. [Project Structure](#project-structure)
6. [Modules](#modules)
7. [Database Schema](#database-schema)
8. [API Documentation](#api-documentation)
9. [Security](#security)
10. [Configuration](#configuration)
11. [Development Guide](#development-guide)
12. [Deployment](#deployment)
13. [Troubleshooting](#troubleshooting)
14. [Appendix](#appendix)

---

## 📖 Project Overview

### What is Ngicorn?

Ngicorn is a comprehensive network monitoring and asset management system built with FastAPI and Python. It provides enterprise-grade capabilities for:

- **Asset Inventory Management** - Track network devices, servers, and infrastructure
- **Network Discovery** - Automated device discovery using Nmap
- **Security Auditing** - CIS compliance auditing for Cisco and FortiGate devices
- **Hardening** - Automated security hardening configurations
- **User Management** - Role-based access control (RBAC)
- **Audit Logging** - Complete audit trail of all system activities

### Technology Stack

**Backend:**
- **Framework:** FastAPI (Python 3.13)
- **Database:** PostgreSQL
- **ORM:** SQLAlchemy
- **Authentication:** JWT (JSON Web Tokens)
- **API Documentation:** OpenAPI/Swagger
- **SSH Automation:** Netmiko, AsyncSSH

**Frontend:**
- Located in `/front` directory
- Integration with backend via REST API

**Infrastructure:**
- **Web Server:** Uvicorn (ASGI)
- **Database Migrations:** Alembic
- **Environment Management:** Python venv

### Key Statistics

- **15,682+** lines of Python code in modules
- **20** database models
- **100+** API endpoints
- **6** main modules
- **65+** FortiGate security controls
- **50+** Cisco CIS checks

---

## 🏗️ Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend                             │
│                    (React/Vue - /front)                     │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP/HTTPS (REST API)
┌──────────────────────────▼──────────────────────────────────┐
│                    FastAPI Application                      │
│                      (app/main.py)                          │
├─────────────────────────────────────────────────────────────┤
│  Middleware: CORS, Authentication, Rate Limiting            │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌───────▼───────┐  ┌──────▼──────┐  ┌───────▼────────┐
│   Modules     │  │    Core     │  │    Models      │
│  (Business    │  │ (Config,    │  │  (Database)    │
│   Logic)      │  │  Security)  │  │                │
└───────┬───────┘  └─────────────┘  └───────┬────────┘
        │                                    │
        │                                    │
        └────────────────┬───────────────────┘
                         │
                ┌────────▼─────────┐
                │   PostgreSQL     │
                │    Database      │
                └──────────────────┘

External Integrations:
  ├─ Network Devices (SSH) ─────► Cisco Routers/Switches
  ├─ Network Devices (SSH) ─────► FortiGate Firewalls
  └─ Network Scanner (Nmap) ────► Network Discovery
```

### Application Flow

```
Client Request
    ↓
CORS Middleware
    ↓
Authentication (JWT)
    ↓
Rate Limiting
    ↓
Router (Endpoint Matching)
    ↓
Dependencies (DB Session, User Permissions)
    ↓
Service Layer (Business Logic)
    ↓
Database Models (SQLAlchemy ORM)
    ↓
PostgreSQL Database
    ↓
Response (JSON)
```

### Module Architecture

```
app/
├── core/               # Core functionality
│   ├── config.py       # Application configuration
│   ├── database.py     # Database connection
│   ├── security.py     # JWT, password hashing
│   └── dependencies.py # Dependency injection
│
├── models/             # Database models (20 models)
│   ├── user.py
│   ├── audit.py
│   ├── asset.py
│   └── ...
│
└── modules/            # Business logic modules
    ├── auth/           # Authentication
    ├── users/          # User management
    ├── assets/         # Asset inventory
    ├── discovery/      # Network discovery
    ├── audit/          # Cisco auditing
    ├── fortinet/       # FortiGate auditing
    ├── hardening/      # Security hardening
    └── logs/           # Audit logging
```

---

## ✨ Features

### 1. Asset Inventory Management

**Capabilities:**
- Centralized asset database
- Asset types, owners, locations, zones
- Operating system catalog
- Vendor management
- Security status tracking
- Dependency mapping
- Compliance requirements

**Key Features:**
- Bulk import/export (Excel)
- Asset views and filtering
- Custom fields support
- Relationship tracking
- Audit logging per asset

### 2. Network Discovery

**Automated Discovery:**
- Nmap-based scanning
- Port detection (TCP/UDP)
- Service identification
- OS fingerprinting
- Subnet scanning
- Scheduled scans

**Discovery Features:**
- Real-time scan status
- Discovered device auto-import
- Port service mapping
- Network topology insights

### 3. Security Auditing

#### Cisco CIS Auditing
- **50+ CIS Benchmark checks**
- Router and Switch support
- IOS/IOS-XE compatibility
- L1 and FULL audit profiles
- Automated SSH connection
- Configuration analysis
- Compliance reporting

**Audit Workflow:**
1. Select Cisco asset
2. Enter SSH credentials (not stored)
3. Execute audit (2-3 minutes)
4. Review compliance results
5. Export findings

#### FortiGate Auditing (New!)
- **65+ security controls**
- VDOM support
- CIS Benchmark mapping
- Multiple audit profiles (L1, L2, FULL)
- Sensitive data redaction
- VDOM discovery

**FortiGate Features:**
- Management plane security
- Identity & access controls
- Cryptography checks
- Logging & monitoring
- Firewall policy validation
- VPN security (SSL/IPsec)
- UTM coverage analysis

### 4. Security Hardening

**Cisco Hardening:**
- Pre-configured templates
- CIS-aligned configurations
- Command generation
- Rollback support
- Change tracking

**Hardening Categories:**
- Management access
- Authentication
- Logging
- SNMP security
- Banner configuration
- Service hardening

### 5. User Management

**User Features:**
- User registration
- Profile management
- Role-based access control
- Permission management
- Password policies
- Session management

**Permissions:**
- ASSET (read/write)
- AUDIT (read/write)
- HARDENING (read/write)
- DISCOVERY (read/write)
- USER_MANAGEMENT (admin)

### 6. Audit Logging

**Comprehensive Logging:**
- User actions
- Asset changes
- Audit executions
- Hardening operations
- Login/logout events
- Permission changes

**Log Features:**
- Searchable logs
- Time-based filtering
- User-based filtering
- Action-based filtering
- Export capabilities

---

## 🚀 Installation & Setup

### Prerequisites

```bash
# Required
- Python 3.13+
- PostgreSQL 12+
- Git

# Optional
- Nmap (for network discovery)
- SSH access to network devices
```

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd netease
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**Key Dependencies:**
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `sqlalchemy` - ORM
- `psycopg2-binary` - PostgreSQL driver
- `python-jose` - JWT tokens
- `passlib` - Password hashing
- `netmiko` - SSH automation
- `asyncssh` - Async SSH
- `python-nmap` - Network scanning
- `alembic` - Database migrations

### Step 4: Configure Environment

Create `.env` file:

```bash
cp .env.example .env  # If example exists, or create new
```

Edit `.env`:

```ini
PROJECT_NAME=Ngicorn
VERSION=1.0.8
DESCRIPTION=Network Monitoring and Asset management system

# Database
DATABASE_URL=postgresql://netease:1234@localhost/netease_db

# Security
SECRET_KEY=netease-super-secret-key-change-this-in-production-min-32-chars
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Server
HOST=0.0.0.0
PORT=8000

# CORS (Development)
BACKEND_CORS_ORIGINS=["*"]

# Production CORS
# BACKEND_CORS_ORIGINS=["http://localhost:5176", "http://your-frontend.com"]
```

### Step 5: Setup Database

```bash
# Create PostgreSQL database
createdb netease_db

# Or using psql
psql -U postgres
CREATE DATABASE netease_db;
CREATE USER netease WITH PASSWORD '1234';
GRANT ALL PRIVILEGES ON DATABASE netease_db TO netease;
\q
```

### Step 6: Run Migrations

```bash
# Initialize Alembic (if needed)
alembic init alembic

# Run migrations
alembic upgrade head
```

### Step 7: Create Admin User

```bash
# Start Python shell
python

# Create admin user
from app.core.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

db = SessionLocal()
admin = User(
    username="admin",
    email="admin@example.com",
    full_name="System Administrator",
    hashed_password=get_password_hash("admin123"),
    is_active=True,
    is_admin=True
)
db.add(admin)
db.commit()
exit()
```

### Step 8: Start Application

```bash
# Development mode (with auto-reload)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Step 9: Access Application

- **API Documentation:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **API Endpoint:** http://localhost:8000/api

---

## 📁 Project Structure

```
netease/
├── alembic/                    # Database migrations
│   ├── versions/               # Migration scripts
│   └── env.py                  # Alembic config
│
├── app/                        # Main application
│   ├── main.py                 # FastAPI app entry point
│   │
│   ├── core/                   # Core functionality
│   │   ├── config.py           # Settings & configuration
│   │   ├── database.py         # DB connection & session
│   │   ├── security.py         # JWT, password hashing
│   │   ├── dependencies.py     # DI for auth, permissions
│   │   └── rate_limiter.py     # API rate limiting
│   │
│   ├── models/                 # SQLAlchemy models (20 files)
│   │   ├── __init__.py         # Model exports
│   │   ├── user.py             # User model
│   │   ├── audit.py            # Audit session/results
│   │   ├── asset.py            # Asset inventory
│   │   ├── discovery.py        # Discovery scans
│   │   ├── hardening.py        # Hardening configs
│   │   ├── port.py             # Network ports
│   │   └── ...                 # Other models
│   │
│   ├── modules/                # Business logic modules
│   │   │
│   │   ├── auth/               # Authentication module
│   │   │   ├── router.py       # Login/logout endpoints
│   │   │   └── service.py      # Auth business logic
│   │   │
│   │   ├── users/              # User management
│   │   │   ├── router.py       # User CRUD endpoints
│   │   │   └── service.py      # User business logic
│   │   │
│   │   ├── assets/             # Asset management
│   │   │   ├── router_with_auth.py  # Asset endpoints
│   │   │   ├── schemas.py      # Pydantic schemas
│   │   │   └── service.py      # Asset business logic
│   │   │
│   │   ├── discovery/          # Network discovery
│   │   │   ├── router.py       # Discovery endpoints
│   │   │   ├── nmap_scanner.py # Nmap integration
│   │   │   ├── service.py      # Discovery logic
│   │   │   └── schemas.py      # Discovery schemas
│   │   │
│   │   ├── audit/              # Cisco CIS auditing
│   │   │   ├── cisco_router.py      # API endpoints
│   │   │   ├── cisco_service.py     # Audit orchestration
│   │   │   ├── cisco_ssh_client.py  # SSH automation
│   │   │   ├── cisco_rules.py       # CIS controls
│   │   │   └── cisco_cis_benchmark_map.py  # CIS mapping
│   │   │
│   │   ├── fortinet/           # FortiGate auditing (NEW!)
│   │   │   ├── fortinet_router.py      # API endpoints
│   │   │   ├── fortinet_service.py     # Audit orchestration
│   │   │   ├── fortinet_ssh_client.py  # SSH with VDOM support
│   │   │   ├── fortinet_rules.py       # Security controls (65+)
│   │   │   ├── fortinet_cis_map.py     # CIS mapping
│   │   │   └── README.md               # Module documentation
│   │   │
│   │   ├── hardening/          # Security hardening
│   │   │   ├── cisco_router.py      # Hardening endpoints
│   │   │   ├── cisco_service.py     # Hardening logic
│   │   │   └── schemas.py           # Hardening schemas
│   │   │
│   │   └── logs/               # Audit logging
│   │       ├── router.py       # Log endpoints
│   │       └── service.py      # Log business logic
│   │
│   └── utils/                  # Utility functions
│       └── excel_utils.py      # Excel import/export
│
├── front/                      # Frontend application
│   └── ...                     # React/Vue files
│
├── scripts/                    # Utility scripts
│   ├── fortinet_audit_cli.py   # Standalone FortiGate auditor
│   └── ...                     # Other scripts
│
├── documents/                  # Documentation
│
├── .env                        # Environment variables
├── .env.example                # Environment template
├── requirements.txt            # Python dependencies
├── alembic.ini                 # Alembic configuration
│
├── FORTINET_IMPLEMENTATION_SUMMARY.md  # FortiGate implementation docs
├── FORTINET_QUICK_START.md             # FortiGate quick guide
├── IMPLEMENTATION_COMPLETE.md          # Implementation summary
├── IMPLEMENTATION_CHECKLIST.md         # Verification checklist
├── FORTINET_AUDIT_ORGANIZATION.md      # FortiGate organization
├── REORGANIZATION_SUMMARY.md           # Project reorganization
└── FINAL.md                            # This file
```

---

## 🧩 Modules

### 1. Authentication Module (`app/modules/auth`)

**Purpose:** User authentication and session management

**Endpoints:**
- `POST /auth/login` - User login (returns JWT)
- `POST /auth/logout` - User logout
- `POST /auth/register` - User registration
- `GET /auth/me` - Get current user

**Features:**
- JWT token generation
- Password hashing (bcrypt)
- Token validation
- Session management

**Usage:**
```python
# Login
POST /auth/login
{
  "username": "admin",
  "password": "admin123"
}

# Response
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer"
}
```

### 2. Users Module (`app/modules/users`)

**Purpose:** User management and permissions

**Endpoints:**
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `GET /api/users/{id}` - Get user
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user
- `POST /api/users/{id}/permissions` - Set permissions

**Features:**
- User CRUD operations
- Permission management
- Role assignment
- Password updates

### 3. Assets Module (`app/modules/assets`)

**Purpose:** Asset inventory management

**Endpoints:**
- `GET /api/assets` - List assets
- `POST /api/assets` - Create asset
- `GET /api/assets/{id}` - Get asset details
- `PUT /api/assets/{id}` - Update asset
- `DELETE /api/assets/{id}` - Delete asset
- `GET /api/asset-types` - List asset types
- `GET /api/locations` - List locations
- `GET /api/owners` - List owners
- `GET /api/zones` - List network zones
- `GET /api/vendors` - List vendors
- `GET /api/os-catalog` - List operating systems

**Features:**
- Complete asset lifecycle
- Asset categorization
- Location tracking
- Owner assignment
- Security status
- Compliance requirements
- Bulk import/export

### 4. Discovery Module (`app/modules/discovery`)

**Purpose:** Automated network discovery

**Endpoints:**
- `POST /api/discovery/scan` - Start network scan
- `GET /api/discovery/scans` - List scans
- `GET /api/discovery/scans/{id}` - Get scan details
- `GET /api/discovery/scans/{id}/devices` - Get discovered devices

**Features:**
- Nmap integration
- Port scanning (TCP/UDP)
- Service detection
- OS fingerprinting
- Subnet scanning
- Scan scheduling

**Usage:**
```python
# Start scan
POST /api/discovery/scan
{
  "target": "192.168.1.0/24",
  "ports": "22,80,443,3389",
  "scan_type": "quick"
}
```

### 5. Audit Module (`app/modules/audit`)

**Purpose:** Cisco CIS security compliance auditing

**Endpoints:**
- `POST /api/audit/cisco/execute` - Execute Cisco audit
- `GET /api/audit/cisco/sessions` - List audit sessions
- `GET /api/audit/cisco/sessions/{id}` - Get session details
- `GET /api/audit/cisco/sessions/{id}/results` - Get audit results
- `DELETE /api/audit/cisco/sessions/{id}` - Delete session

**Features:**
- 50+ CIS Benchmark checks
- Cisco IOS/IOS-XE support
- SSH automation
- Configuration analysis
- Compliance scoring
- Detailed findings
- Remediation guidance

**Audit Profiles:**
- **L1:** 40 checks, low impact
- **FULL:** 50+ checks, comprehensive

**Usage:**
```python
# Execute audit
POST /api/audit/cisco/execute
{
  "asset_id": 10,
  "ssh_username": "admin",
  "ssh_password": "cisco123",
  "ssh_secret": "enable123",
  "profile": "L1"
}

# Response
{
  "session_id": 45,
  "compliance_pct": 78.5,
  "total_checks": 40,
  "passed": 31,
  "failed": 9
}
```

### 6. FortiGate Module (`app/modules/fortinet`) ⭐ NEW

**Purpose:** FortiGate firewall security auditing

**Endpoints:**
- `POST /api/fortinet/audit/execute` - Execute audit
- `POST /api/fortinet/vdoms/discover` - Discover VDOMs
- `GET /api/fortinet/audit/sessions` - List sessions
- `GET /api/fortinet/audit/sessions/{id}` - Get session
- `GET /api/fortinet/audit/sessions/{id}/results` - Get results
- `DELETE /api/fortinet/audit/sessions/{id}` - Delete session

**Features:**
- 65+ security controls
- VDOM support (unique to FortiGate)
- CIS Benchmark mapping
- Multiple audit profiles (L1, L2, FULL)
- Sensitive data redaction
- Management plane security checks
- VPN security validation
- UTM coverage analysis

**Security Controls:**
- Management access (HTTPS, timeouts, TLS)
- Identity & access (trusthost, MFA, passwords)
- Cryptography (encryption, SSL/TLS)
- Logging (syslog, FortiAnalyzer)
- Firewall policies (Any/Any rules)
- VPN security (SSL-VPN, IPsec)
- UTM profiles

**VDOM Support:**
```python
# Discover VDOMs
POST /api/fortinet/vdoms/discover
{
  "asset_id": 50,
  "ssh_username": "admin",
  "ssh_password": "fortinet123"
}

# Response
{
  "vdoms": ["root", "VDOM_1", "VDOM_2"]
}

# Audit specific VDOM
POST /api/fortinet/audit/execute
{
  "asset_id": 50,
  "ssh_username": "admin",
  "ssh_password": "fortinet123",
  "vdom": "VDOM_1",
  "profile": "L1"
}
```

### 7. Hardening Module (`app/modules/hardening`)

**Purpose:** Security hardening configuration generation

**Endpoints:**
- `POST /api/hardening/cisco/generate` - Generate hardening config
- `GET /api/hardening/templates` - List templates
- `POST /api/hardening/apply` - Apply hardening

**Features:**
- CIS-aligned configurations
- Cisco IOS/IOS-XE support
- Template-based generation
- Change tracking
- Rollback support

### 8. Logs Module (`app/modules/logs`)

**Purpose:** Audit logging and activity tracking

**Endpoints:**
- `GET /api/logs` - List audit logs
- `GET /api/logs/user/{user_id}` - User activity logs
- `GET /api/logs/asset/{asset_id}` - Asset change logs

**Features:**
- Complete audit trail
- Searchable logs
- Time-based filtering
- User-based filtering
- Action-based filtering

---

## 🗄️ Database Schema

### Core Tables

#### **users**
User accounts and authentication
```sql
- id (PK)
- username (unique)
- email (unique)
- full_name
- hashed_password
- is_active
- is_admin
- created_at
```

#### **user_permissions**
Role-based access control
```sql
- id (PK)
- user_id (FK → users)
- resource (e.g., "AUDIT", "ASSET")
- permission (e.g., "read", "write")
```

### Asset Management

#### **asset_inventory**
Central asset database
```sql
- id (PK)
- asset_name
- ip_address
- asset_type_id (FK)
- owner_id (FK)
- location_id (FK)
- zone_id (FK)
- os_id (FK)
- vendor_id (FK)
- security_status_id (FK)
- created_at
- updated_at
```

#### **asset_types**
Asset categorization
```sql
- id (PK)
- type_name
- description
```

#### **asset_owners**
Asset ownership tracking
```sql
- id (PK)
- owner_name
- email
- department
```

#### **asset_locations**
Physical/logical locations
```sql
- id (PK)
- location_name
- address
- country
```

#### **network_zones**
Network segmentation
```sql
- id (PK)
- zone_name
- description
- security_level
```

### Discovery

#### **discovery_scans**
Network scan sessions
```sql
- id (PK)
- user_id (FK)
- target
- scan_type
- status
- started_at
- completed_at
```

#### **ports**
Discovered network ports
```sql
- id (PK)
- scan_id (FK)
- asset_id (FK)
- port_number
- protocol
- service
- state
```

### Auditing

#### **audit_sessions**
Audit execution records
```sql
- id (PK)
- template_id (FK)
- user_id (FK)
- asset_id (FK)
- target_ip
- device_type (cisco/fortinet)
- status
- started_at
- completed_at
- total_checks
- passed_checks
- failed_checks
- compliance_pct
- turbo_dump (redacted configs)
- connection_error
```

#### **audit_results**
Individual check results
```sql
- id (PK)
- audit_session_id (FK)
- check_number
- check_title
- severity
- level
- status (pass/fail/error)
- evidence_snippet
- checked_at
```

### Hardening

#### **hardening_templates**
Security hardening configs
```sql
- id (PK)
- template_name
- device_type
- description
- config_content
- created_by (FK → users)
```

### Logging

#### **audit_logs**
System audit trail
```sql
- id (PK)
- user_id (FK)
- action
- resource_type
- resource_id
- details
- timestamp
- ip_address
```

---

## 📡 API Documentation

### API Base URL

```
http://localhost:8000
```

### Interactive Documentation

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

### Authentication

All protected endpoints require JWT token:

```bash
# 1. Login to get token
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Response
{
  "access_token": "eyJ0eXAiOiJKV1Qi...",
  "token_type": "bearer"
}

# 2. Use token in subsequent requests
curl http://localhost:8000/api/assets \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Qi..."
```

### API Endpoints Summary

#### Authentication
```
POST   /auth/login          - User login
POST   /auth/logout         - User logout
POST   /auth/register       - User registration
GET    /auth/me             - Current user info
```

#### Users
```
GET    /api/users           - List users
POST   /api/users           - Create user
GET    /api/users/{id}      - Get user
PUT    /api/users/{id}      - Update user
DELETE /api/users/{id}      - Delete user
```

#### Assets
```
GET    /api/assets          - List assets
POST   /api/assets          - Create asset
GET    /api/assets/{id}     - Get asset
PUT    /api/assets/{id}     - Update asset
DELETE /api/assets/{id}     - Delete asset
GET    /api/asset-types     - List types
GET    /api/locations       - List locations
GET    /api/owners          - List owners
GET    /api/zones           - List zones
```

#### Discovery
```
POST   /api/discovery/scan  - Start scan
GET    /api/discovery/scans - List scans
GET    /api/discovery/scans/{id} - Get scan
```

#### Cisco Audit
```
POST   /api/audit/cisco/execute - Execute audit
GET    /api/audit/cisco/sessions - List sessions
GET    /api/audit/cisco/sessions/{id} - Get session
GET    /api/audit/cisco/sessions/{id}/results - Get results
DELETE /api/audit/cisco/sessions/{id} - Delete session
```

#### FortiGate Audit
```
POST   /api/fortinet/audit/execute - Execute audit
POST   /api/fortinet/vdoms/discover - Discover VDOMs
GET    /api/fortinet/audit/sessions - List sessions
GET    /api/fortinet/audit/sessions/{id} - Get session
GET    /api/fortinet/audit/sessions/{id}/results - Get results
DELETE /api/fortinet/audit/sessions/{id} - Delete session
```

#### Hardening
```
POST   /api/hardening/cisco/generate - Generate config
GET    /api/hardening/templates - List templates
```

#### Logs
```
GET    /api/logs            - List audit logs
GET    /api/logs/user/{id}  - User logs
GET    /api/logs/asset/{id} - Asset logs
```

---

## 🔒 Security

### Authentication & Authorization

**JWT Tokens:**
- HS256 algorithm
- 30-minute expiration
- Secure secret key (32+ characters)
- Token-based authentication

**Password Security:**
- Bcrypt hashing
- Minimum 8 characters
- Strong password policy
- Password change enforcement

**Permission Model:**
```python
Permissions = {
    "ASSET": ["read", "write"],
    "AUDIT": ["read", "write"],
    "HARDENING": ["read", "write"],
    "DISCOVERY": ["read", "write"],
    "USER_MANAGEMENT": ["admin"]
}
```

### SSH Credential Handling

**Security Policy:**
✅ Credentials passed as request parameters
✅ Never stored in database
✅ Used only during SSH session
✅ Transmitted over HTTPS/TLS
✅ Removed from error messages

**Data Redaction:**
Automatic redaction of sensitive data:
- Passwords
- Secrets
- Keys
- Community strings
- Private keys

### API Security

**Rate Limiting:**
- Configurable per endpoint
- Token bucket algorithm
- DOS protection

**CORS:**
- Configurable origins
- Credential support
- Development vs production settings

**Input Validation:**
- Pydantic schemas
- Type checking
- Length validation
- Pattern matching

### Audit Logging

**Logged Events:**
- User login/logout
- Asset changes
- Audit executions
- Permission changes
- Configuration changes
- Failed authentication attempts

---

## ⚙️ Configuration

### Environment Variables (.env)

```ini
# Application
PROJECT_NAME=Ngicorn
VERSION=1.0.8
DESCRIPTION=Network Monitoring and Asset management system

# Database
DATABASE_URL=postgresql://username:password@host:port/database

# Security
SECRET_KEY=your-secret-key-min-32-characters
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Server
HOST=0.0.0.0
PORT=8000

# CORS
BACKEND_CORS_ORIGINS=["http://localhost:5176"]
```

### Database Configuration

**PostgreSQL Setup:**
```sql
-- Create database
CREATE DATABASE netease_db;

-- Create user
CREATE USER netease WITH PASSWORD 'your_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE netease_db TO netease;
```

### Application Settings (app/core/config.py)

```python
class Settings(BaseSettings):
    PROJECT_NAME: str
    VERSION: str
    DESCRIPTION: str
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    HOST: str
    PORT: int
    BACKEND_CORS_ORIGINS: List[str]

    class Config:
        env_file = ".env"
```

---

## 💻 Development Guide

### Setting Up Development Environment

```bash
# 1. Clone repository
git clone <repository-url>
cd netease

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Setup database
createdb netease_db

# 5. Run migrations
alembic upgrade head

# 6. Start development server
uvicorn app.main:app --reload
```

### Code Structure Guidelines

**Module Structure:**
```
app/modules/your_module/
├── __init__.py         # Module exports
├── router.py           # FastAPI endpoints
├── service.py          # Business logic
├── schemas.py          # Pydantic models
└── README.md           # Module documentation
```

**Creating New Module:**

1. **Create directory:**
```bash
mkdir app/modules/your_module
```

2. **Create router.py:**
```python
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.dependencies import require_permission

router = APIRouter(prefix="/api/your-module", tags=["Your Module"])

@router.get("/")
def list_items(
    db: Session = Depends(get_db),
    current_user = Depends(require_permission("YOUR_MODULE", "read"))
):
    return {"items": []}
```

3. **Create service.py:**
```python
from sqlalchemy.orm import Session

class YourService:
    @staticmethod
    def get_items(db: Session):
        # Business logic
        return []
```

4. **Register in main.py:**
```python
from app.modules.your_module import router as your_module_router
app.include_router(your_module_router.router)
```

### Adding Database Models

1. **Create model file:**
```python
# app/models/your_model.py
from sqlalchemy import Column, Integer, String
from app.core.database import Base

class YourModel(Base):
    __tablename__ = "your_table"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
```

2. **Export in models/__init__.py:**
```python
from .your_model import YourModel
```

3. **Create migration:**
```bash
alembic revision --autogenerate -m "Add your_table"
alembic upgrade head
```

### Testing

**Manual Testing:**
```bash
# Start server
uvicorn app.main:app --reload

# Test endpoint
curl http://localhost:8000/api/your-endpoint

# Use Swagger UI
http://localhost:8000/docs
```

**Import Testing:**
```python
# Test imports
python -c "from app.modules.your_module import YourService; print('✓ Import successful')"
```

### Database Migrations

**Create Migration:**
```bash
# Auto-generate migration
alembic revision --autogenerate -m "Description"

# Manual migration
alembic revision -m "Description"
```

**Apply Migrations:**
```bash
# Upgrade to latest
alembic upgrade head

# Upgrade to specific version
alembic upgrade <revision>

# Downgrade
alembic downgrade -1
```

**Migration History:**
```bash
# Show current version
alembic current

# Show migration history
alembic history
```

---

## 🚀 Deployment

### Production Deployment

#### Option 1: Uvicorn with Systemd

**1. Create systemd service:**

`/etc/systemd/system/ngicorn.service`:
```ini
[Unit]
Description=Ngicorn API
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/netease
Environment="PATH=/var/www/netease/.venv/bin"
ExecStart=/var/www/netease/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

**2. Enable and start:**
```bash
sudo systemctl enable ngicorn
sudo systemctl start ngicorn
sudo systemctl status ngicorn
```

#### Option 2: Docker

**Dockerfile:**
```dockerfile
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://netease:1234@db:5432/netease_db
    depends_on:
      - db

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=netease_db
      - POSTGRES_USER=netease
      - POSTGRES_PASSWORD=1234
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

**Deploy:**
```bash
docker-compose up -d
```

#### Option 3: Nginx + Uvicorn

**Nginx configuration:**

`/etc/nginx/sites-available/ngicorn`:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Enable site:**
```bash
sudo ln -s /etc/nginx/sites-available/ngicorn /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Production Checklist

- [ ] Set strong SECRET_KEY (32+ characters)
- [ ] Configure production DATABASE_URL
- [ ] Set specific CORS origins (not ["*"])
- [ ] Enable HTTPS/TLS
- [ ] Configure firewall rules
- [ ] Setup database backups
- [ ] Configure log rotation
- [ ] Monitor resource usage
- [ ] Setup health checks
- [ ] Configure rate limiting
- [ ] Enable security headers

### Environment Variables for Production

```ini
PROJECT_NAME=Ngicorn
VERSION=1.0.8

# Strong secret key
SECRET_KEY=<generate-strong-random-key-32-chars-minimum>

# Production database
DATABASE_URL=postgresql://user:password@db-host:5432/netease_db

# Specific CORS origins
BACKEND_CORS_ORIGINS=["https://your-frontend.com"]

# Production server
HOST=0.0.0.0
PORT=8000
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Database Connection Error

**Error:**
```
sqlalchemy.exc.OperationalError: could not connect to server
```

**Solution:**
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -U netease -d netease_db -h localhost

# Verify DATABASE_URL in .env
DATABASE_URL=postgresql://netease:password@localhost/netease_db
```

#### 2. Import Errors

**Error:**
```
ModuleNotFoundError: No module named 'netmiko'
```

**Solution:**
```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
pip list | grep netmiko
```

#### 3. SSH Connection Failures

**Error:**
```
NetmikoTimeoutException: Connection timeout
```

**Solution:**
- Verify device IP is reachable: `ping <device-ip>`
- Check SSH is enabled on device
- Verify credentials are correct
- Check firewall rules allow SSH (port 22)
- Verify device is not rate-limiting SSH connections

#### 4. Permission Denied

**Error:**
```
403 Forbidden: Insufficient permissions
```

**Solution:**
```python
# Grant user permissions via API or database
from app.models import UserPermission
permission = UserPermission(
    user_id=user_id,
    resource="AUDIT",
    permission="write"
)
db.add(permission)
db.commit()
```

#### 5. Migration Errors

**Error:**
```
alembic.util.exc.CommandError: Target database is not up to date
```

**Solution:**
```bash
# Check current version
alembic current

# Upgrade to latest
alembic upgrade head

# If conflicts, resolve manually in versions/
```

### Logging

**Enable debug logging:**
```python
# Add to app/main.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

**View logs:**
```bash
# Systemd service logs
sudo journalctl -u ngicorn -f

# Docker logs
docker-compose logs -f api

# Application logs (if file-based)
tail -f /var/log/ngicorn.log
```

### Performance Issues

**Slow API responses:**
1. Check database query performance
2. Add database indexes
3. Implement caching
4. Increase Uvicorn workers
5. Optimize SSH command collection

**High memory usage:**
1. Reduce Uvicorn workers
2. Optimize bulk operations
3. Implement pagination
4. Clear cached data

---

## 📚 Appendix

### A. Quick Reference

**Start Server:**
```bash
source .venv/bin/activate
uvicorn app.main:app --reload
```

**Access Docs:**
- http://localhost:8000/docs

**Run Migrations:**
```bash
alembic upgrade head
```

**Create Admin User:**
```python
from app.core.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

db = SessionLocal()
admin = User(
    username="admin",
    email="admin@example.com",
    hashed_password=get_password_hash("admin123"),
    is_admin=True
)
db.add(admin)
db.commit()
```

### B. API Response Formats

**Success Response:**
```json
{
  "id": 1,
  "name": "Resource Name",
  "created_at": "2026-01-29T10:00:00Z"
}
```

**Error Response:**
```json
{
  "detail": "Error message description"
}
```

**List Response:**
```json
{
  "items": [...],
  "total": 100,
  "page": 1,
  "page_size": 50
}
```

### C. Database ER Diagram

```
users ──┬─── user_permissions
        │
        ├─── audit_sessions ──── audit_results
        │
        ├─── discovery_scans ──── ports
        │
        └─── hardening_templates

asset_inventory ──┬─── asset_types
                  ├─── asset_owners
                  ├─── asset_locations
                  ├─── network_zones
                  ├─── os_catalog
                  ├─── vendors
                  ├─── asset_security_status
                  └─── audit_sessions
```

### D. Useful Commands

**Database:**
```bash
# Backup database
pg_dump netease_db > backup.sql

# Restore database
psql netease_db < backup.sql

# Connect to database
psql -U netease -d netease_db
```

**Python:**
```bash
# Create virtual environment
python3 -m venv .venv

# Activate (Linux/Mac)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Install packages
pip install -r requirements.txt

# Freeze dependencies
pip freeze > requirements.txt
```

**Git:**
```bash
# Common workflow
git add .
git commit -m "Description"
git push origin main

# Create branch
git checkout -b feature/new-feature

# Merge branch
git checkout main
git merge feature/new-feature
```

### E. Resources

**Documentation:**
- FastAPI: https://fastapi.tiangolo.com/
- SQLAlchemy: https://docs.sqlalchemy.org/
- Pydantic: https://docs.pydantic.dev/
- Alembic: https://alembic.sqlalchemy.org/
- PostgreSQL: https://www.postgresql.org/docs/

**Security:**
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/
- OWASP Top 10: https://owasp.org/www-project-top-ten/

**Tools:**
- Netmiko: https://github.com/ktbyers/netmiko
- Nmap: https://nmap.org/
- Postman: https://www.postman.com/

### F. Change Log

**v1.0.8 (2026-01-29):**
- ✅ Added FortiGate audit module
- ✅ Implemented VDOM support
- ✅ Added 65+ FortiGate security controls
- ✅ Enhanced documentation
- ✅ Performance optimizations

**v1.0.7:**
- Added Cisco CIS auditing
- Added security hardening module
- Improved asset management

**v1.0.6:**
- Added network discovery
- Added Nmap integration
- Enhanced user permissions

**v1.0.5:**
- Initial release
- Basic asset management
- User authentication

---

## 🎯 Summary

Ngicorn is a comprehensive network monitoring and asset management platform providing:

✅ **Asset Inventory** - Complete lifecycle management
✅ **Network Discovery** - Automated device detection
✅ **Security Auditing** - Cisco & FortiGate CIS compliance
✅ **Hardening** - Automated security configurations
✅ **User Management** - Role-based access control
✅ **Audit Logging** - Complete activity tracking

**Project Statistics:**
- 15,682+ lines of code
- 20 database models
- 100+ API endpoints
- 6 main modules
- Production-ready architecture

**Getting Started:**
1. Install dependencies
2. Setup database
3. Run migrations
4. Start server
5. Access http://localhost:8000/docs

**Need Help?**
- Check Swagger UI: http://localhost:8000/docs
- Review module documentation
- Check troubleshooting section
- Enable debug logging

---

**Project:** Ngicorn
**Version:** 1.0.8
**Status:** Production Ready
**License:** [Your License]
**Last Updated:** January 29, 2026

