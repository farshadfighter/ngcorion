# Changelog

## [2.0.0] - 2025-04-23

### Added

**Security Enhancements:**
- JWT-based authentication for admin endpoints (replaces HTTP Basic Auth)
- HMAC-SHA256 request signing for `/validate` and `/consume` endpoints
- Timestamp validation to prevent replay attacks (5-minute window)
- Encrypted client-side license storage using Fernet (AES-128)
- Redis-based rate limiting (60 requests/minute per IP, configurable)

**Performance Improvements:**
- Database connection pooling (pool_size=20, max_overflow=10)
- Performance indexes on frequently queried columns:
  - `idx_license_key_active` on (license_key, is_active)
  - `idx_org_token_active` on (organization_token, is_active)
  - `idx_expires_at` on (expires_at)
  - `idx_last_heartbeat` on (last_heartbeat_at)
- Structured logging middleware for all requests

**Client SDK:**
- Complete Python client library with encrypted storage
- Automatic VM fingerprinting (cross-platform)
- Built-in request signing
- Background heartbeat service with configurable interval
- Simple API for activate, validate, consume, and heartbeat operations

**Infrastructure:**
- Centralized configuration management with Pydantic Settings
- Alembic integration for database migrations
- Middleware architecture for logging and rate limiting
- Comprehensive setup and deployment documentation

**New Endpoints:**
- `POST /api/admin/login` - Admin authentication with JWT token

**New Modules:**
- `app/core/config.py` - Centralized configuration
- `app/core/security.py` - JWT and password utilities
- `app/middleware/logging.py` - Request logging middleware
- `app/middleware/rate_limit.py` - Redis-based rate limiting
- `app/utils/signing.py` - HMAC request signing utilities
- `app/utils/fingerprint.py` - VM fingerprinting utilities
- `client/storage.py` - Encrypted license storage
- `client/license_client.py` - Main client SDK
- `client/heartbeat.py` - Background heartbeat service

### Changed

- Admin endpoints now require JWT Bearer token instead of HTTP Basic Auth
- `/validate` and `/consume` endpoints now require `X-Signature` and `X-Timestamp` headers
- Database engine now uses connection pooling for better performance
- Configuration moved from scattered `os.getenv()` calls to centralized `Settings` class
- Environment variables expanded with Redis, rate limiting, and JWT settings

### Security Notes

**Breaking Changes:**
- Admin authentication changed from HTTP Basic to JWT tokens
- `/validate` and `/consume` endpoints now require signed requests
- Clients must update to use new authentication and signing mechanisms

**Migration Guide:**
1. Update `requirements.txt` dependencies (redis, alembic, requests)
2. Update `.env` file with new configuration variables
3. Run `alembic upgrade head` to apply database indexes
4. Update admin scripts to use JWT authentication
5. Update client applications to use request signing or the new SDK

### Documentation

- Added `SETUP.md` - Comprehensive setup and deployment guide
- Added `client/README.md` - Client SDK documentation
- Added `CHANGELOG.md` - Version history
- Updated `README.md` - Enhanced with new features
- Added `.env.example` - Example environment configuration
- Added `test_client.py` - SDK test script

## [1.0.0] - 2025-04-23

### Initial Release

- Basic license management system
- Multiple plan types (Pilot, Basic1-3, Enterprise)
- VM fingerprinting for license binding
- Operation quota tracking (assets, discovery, audit, harden, monitor)
- Heartbeat mechanism with auto-downgrade to Pilot
- HTTP Basic Auth for admin endpoints
- PostgreSQL database backend
- FastAPI REST API
- Persian/Farsi language support
