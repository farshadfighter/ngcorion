# Security Recommendations

A security audit of the Netease codebase. Each item includes the file, the problematic code, and what to change.

---

## CRITICAL

### 1. Database Password is `1234`

**File:** `.env` line 5, `app/core/config.py` line 28

```python
# .env
DATABASE_URL=postgresql://netease:1234@127.0.0.1/netease_db

# app/core/config.py (fallback default)
DATABASE_URL: str = "postgresql://netease:1234@localhost/netease_db"
```

**Fix:** Use a strong, randomly generated password. Change it in PostgreSQL first, then update `.env`. Remove the hardcoded default from `config.py` — the app should fail to start if `DATABASE_URL` is not set, not fall back to an insecure default.

---

### 2. SECRET_KEY is a Placeholder String

**File:** `.env` line 7, `app/core/config.py` line 34

```python
# .env
SECRET_KEY=netease-super-secret-key-change-this-in-production-min-32-chars

# app/core/config.py (fallback default)
SECRET_KEY: str = "your-secret-key-here-change-in-production-min-32-chars"
```

**Fix:** Generate a proper key with `openssl rand -hex 32` and put it in `.env`. Remove the default from `config.py` so the app refuses to start without a real key. Anyone who can guess this key can forge any JWT token and bypass authentication entirely.

---

### 3. Default Login Credentials `admin`/`123456`

**File:** `CLAUDE.md` lines 2-3

```
username : admin
password : 123456
```

**Fix:** Change the admin password in the database. Remove credentials from `CLAUDE.md` (or any committed file). If you need test credentials, document them in a local file excluded from git.

---

### 4. CORS Allows All Origins

**File:** `app/main.py` lines 72-78, `app/core/config.py` line 42, `.env` line 17

```python
# app/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins if hasattr(settings, 'cors_origins') else settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# app/core/config.py
BACKEND_CORS_ORIGINS: List[str] = ["*"]

# .env
BACKEND_CORS_ORIGINS=["*"]
```

**Fix:** Replace `["*"]` with actual frontend origins, e.g. `["https://your-domain.com"]`. Restrict `allow_methods` to only the methods you use (e.g. `["GET", "POST", "PUT", "DELETE"]`). Restrict `allow_headers` to what you actually need (e.g. `["Authorization", "Content-Type"]`). Remove `expose_headers=["*"]` or limit it to specific headers. Using `allow_credentials=True` with `allow_origins=["*"]` is especially dangerous — browsers block this combination, but misconfigured proxies may not.

---

## HIGH

### 5. No HTTPS — All Traffic is Plaintext HTTP

**Files:**
- `front/src/config/api.js` line 3: `const API_BASE_URL = 'http://172.16.200.90:8000';`
- `front/.env`: `VITE_API_URL=http://127.0.0.1:8000`
- `front/.env.production`: `VITE_API_URL=http://172.16.200.90:8000`
- `app/main.py` lines 162-164: `uvicorn.run(app, host="0.0.0.0", port=8000)`

**Fix:** Deploy behind a reverse proxy (Nginx, Caddy) with TLS. Update all frontend URLs to `https://`. Configure uvicorn with SSL certificates or let the reverse proxy handle termination. Every login, JWT token, and SSH password currently travels in cleartext.

---

### 6. Server Binds to `0.0.0.0` (All Interfaces)

**File:** `app/core/config.py` line 55

```python
HOST: str = "0.0.0.0"
```

**Fix:** In production, bind to `127.0.0.1` and put a reverse proxy in front. Binding to `0.0.0.0` exposes the app directly to any network the server is connected to.

---

### 7. Hardcoded Internal IP in Frontend

**File:** `front/src/config/api.js` line 3

```javascript
const API_BASE_URL = 'http://172.16.200.90:8000';
```

**Fix:** Use environment variables (`import.meta.env.VITE_API_URL`) or relative URLs. The hardcoded IP exposes internal network topology and breaks when the server moves.

---

### 8. SSH Passwords Sent in HTTP Request Body

**Files:** `app/modules/cisco/hardening/router.py`, `app/modules/fortinet/hardening/router.py`, `app/modules/linux/hardening/router.py`

```python
class HardeningExecuteRequest(BaseModel):
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_secret: Optional[str] = Field(None)
```

**Fix:** At minimum, enforce HTTPS so passwords are encrypted in transit. Ideally, use SSH key-based authentication instead of passwords. If passwords must be used, consider a credential vault (HashiCorp Vault, etc.) rather than passing them per-request.

---

### 9. No Rate Limiting on Login Endpoint

**File:** `app/modules/auth/router.py` — `/auth/login` endpoint

The login endpoint has no rate limiting. The existing `rate_limiter.py` only covers discovery scans.

**Fix:** Add rate limiting to the login endpoint — e.g. 5 attempts per minute per IP. Use `slowapi` or a similar library. Also consider account lockout after N failed attempts.

---

## MEDIUM

### 10. JWT Error Details Exposed to Client

**File:** `app/core/dependencies.py` lines 55-60

```python
except JWTError as e:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"Invalid token: {str(e)}",
    )
```

**Fix:** Return a generic message: `detail="Invalid or expired token"`. The internal error details help attackers understand the token validation logic.

---

### 11. User Enumeration via "User not found"

**File:** `app/core/dependencies.py` line 66

```python
detail="User not found"
```

**Fix:** Return the same error for both "user not found" and "invalid token" — e.g. `"Invalid credentials"`. Different messages let attackers discover which usernames exist.

---

### 12. JWT Token Stored in localStorage

**File:** `front/src/config/api.js` line 13

```javascript
const token = localStorage.getItem('token');
```

**Fix:** Use `httpOnly` + `Secure` + `SameSite=Strict` cookies instead. localStorage is accessible to any JavaScript on the page, making it vulnerable to XSS attacks. If a single XSS vulnerability exists anywhere in the app, all user tokens are compromised.

---

### 13. No Token Refresh / Revocation Mechanism

**File:** `app/core/config.py` line 36

```python
ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
```

There is no refresh token endpoint, no token blacklist, and no way to revoke a stolen token.

**Fix:** Implement a refresh token flow — short-lived access tokens (5-10 min) + longer-lived refresh tokens stored in httpOnly cookies. Add a token blacklist (Redis or DB) to support logout/revocation.

---

### 14. HS256 JWT Algorithm (Symmetric)

**File:** `app/core/config.py` line 35

```python
ALGORITHM: str = "HS256"
```

**Fix:** Consider RS256 (asymmetric). With HS256, the same secret both signs and verifies tokens. If the secret leaks, attackers can forge tokens. With RS256, only the private key can sign, while the public key verifies — so leaking the public key doesn't compromise signing.

---

### 15. No Input Validation on IP Addresses

**File:** `app/modules/cisco/hardening/router.py` line 171 (and similar across modules)

```python
ip_address: str = Field(..., description="Device IP address")
```

**Fix:** Validate IP format with a regex or Pydantic's `IPvAnyAddress` type. Unvalidated strings could cause unexpected behavior in SSH connections or be used for SSRF.

---

### 16. Test Credentials in API Schema Examples

**File:** `app/modules/cisco/hardening/router.py` lines 183-184, 248-249, 374, 442

```python
"ssh_password": "cisco123"
```

**Fix:** Use placeholder values like `"ssh_password": "********"` in OpenAPI schema examples. Real-looking passwords in docs get copy-pasted into production.

---

### 17. `print()` Used for Auth Logging

**File:** `app/modules/auth/router.py` line 40

```python
print(f"[{time_str}] Login {status_text}: User '{username}' With IP {ip_address}")
```

**Fix:** Use `logging.getLogger()` with structured logging. `print()` output goes to stdout with no level control, rotation, or filtering. Also ensure you never log passwords — currently only username and IP are logged here, which is fine.

---

### 18. Dependencies Use Minimum Version Pins

**File:** `requirements.txt`

```
fastapi>=0.100.0
sqlalchemy>=2.0.0
netmiko>=4.2.0
paramiko>=3.3.0
```

**Fix:** Pin exact versions (e.g. `fastapi==0.115.0`) and update regularly. Using `>=` means `pip install` could pull in any future version, including one with breaking changes or vulnerabilities. Use `pip-audit` or `safety` to check for known CVEs.

---

### 19. `.env` Files Not in `.gitignore`

**Files:** `.env`, `front/.env`, `front/.env.production`

**Fix:** Verify these are in `.gitignore`. If they've already been committed, remove them from git history with `git filter-branch` or `BFG Repo-Cleaner`, then rotate all secrets they contained.

---

## LOW

### 20. SSH Password Stored in Object Memory

**File:** `app/modules/linux/common/ssh_client.py` lines 75-100

```python
self.password = password
self.sudo_password = sudo_password or password
```

**Fix:** For defense in depth, zero out password fields after the SSH session is established (e.g. `self.password = None` after `connect()`). This reduces the window for memory-dump attacks.

---

## Summary

| #  | Issue                                | Severity | Effort |
|----|--------------------------------------|----------|--------|
| 1  | Database password `1234`             | CRITICAL | Low    |
| 2  | SECRET_KEY is a placeholder          | CRITICAL | Low    |
| 3  | Admin password `123456` in repo      | CRITICAL | Low    |
| 4  | CORS allows all origins              | CRITICAL | Low    |
| 5  | No HTTPS                             | HIGH     | Medium |
| 6  | Server binds to `0.0.0.0`           | HIGH     | Low    |
| 7  | Hardcoded internal IP in frontend    | HIGH     | Low    |
| 8  | SSH passwords in HTTP body           | HIGH     | High   |
| 9  | No rate limiting on login            | HIGH     | Medium |
| 10 | JWT error details exposed            | MEDIUM   | Low    |
| 11 | User enumeration                     | MEDIUM   | Low    |
| 12 | Token in localStorage                | MEDIUM   | Medium |
| 13 | No token refresh/revocation          | MEDIUM   | Medium |
| 14 | HS256 symmetric JWT                  | MEDIUM   | Medium |
| 15 | No IP address validation             | MEDIUM   | Low    |
| 16 | Test credentials in API examples     | MEDIUM   | Low    |
| 17 | `print()` for auth logging           | MEDIUM   | Low    |
| 18 | Loose dependency version pins        | MEDIUM   | Low    |
| 19 | `.env` files possibly committed      | MEDIUM   | Low    |
| 20 | SSH password in object memory        | LOW      | Low    |
