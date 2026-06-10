# Forgot Password — Developer Guide

Self-service password recovery via a **time-limited, single-use numeric OTP code** sent
by email. No password is ever emailed: the user requests a code, enters it, and chooses
their own new password.

- **Audience:** backend & frontend developers, and operators configuring SMTP.
- **Auth:** both endpoints are **public** (no JWT). Registered under `/auth`.

---

## Flow at a glance

```
User                Frontend                 Backend                     Email
 |  "Forgot password?" |                         |                          |
 |-------------------->| POST /auth/forgot-password {email}                 |
 |                     |------------------------>| create OTP (store hash)  |
 |                     |                         |---- email the code ----->|
 |                     |<-- 200 generic message -|                          |
 |                     | navigate to /reset-password (carry email)          |
 |                                                                          |
 |  reads 6-digit code from the email                                       |
 |  enters code + new password                                              |
 |                     |-- POST /auth/reset-password {email, otp, new_password} ->
 |                     |                         | verify code + set password|
 |                     |<------ 200 success ------|                          |
 |  redirected to login                                                     |
```

---

## API Reference

### 1. Request a reset code

**Endpoint:** `POST /auth/forgot-password`

```bash
curl -X POST http://localhost:8000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

**Response — always `200`, always identical** (regardless of whether the email exists):
```json
{ "message": "If an account with that email exists, a password reset code has been sent." }
```

This is deliberate: a different response for known vs. unknown emails would let an
attacker enumerate registered accounts. If the email *does* belong to an **active**
account, a 6-digit code is emailed (via a FastAPI `BackgroundTask`); otherwise nothing
is sent but the response is the same.

**Errors:**
| Status | When |
|--------|------|
| `422`  | `email` missing or not a valid email address |
| `429`  | Rate limit exceeded (see [Rate limiting](#rate-limiting)) |

---

### 2. Set a new password

**Endpoint:** `POST /auth/reset-password`

```bash
curl -X POST http://localhost:8000/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "otp": "215449", "new_password": "NewPass456!"}'
```

**Success — `200`:**
```json
{ "message": "Your password has been reset. You can now log in." }
```

**Errors:**
| Status | When |
|--------|------|
| `422`  | `otp` is not exactly 6 digits, or `new_password` fails the strength rules (below) |
| `400`  | Code wrong, expired, already used, or attempt limit exceeded → `"Invalid or expired code. Please request a new one."` |

The `400` message is intentionally generic — it does not distinguish a wrong code from
an exhausted attempt count. On success the code is **consumed** (marked used) and the
user's `hashed_password` is replaced; the user can immediately log in via
`POST /auth/login`.

#### Password strength rules
Enforced by the shared `validate_password_strength()` in `app/schemas/user.py`
(same rules as user creation/update):
- ≥ 8 characters (and ≤ 72 bytes, bcrypt limit)
- at least one uppercase, one lowercase, one digit, and one special character

The frontend mirrors these rules in `ResetPassword.jsx` for instant feedback, but the
backend is the source of truth.

---

## Configuration

All settings live in `app/core/config.py` and can be overridden via `.env`
(see `.env.example`).

| Setting | Default | Purpose |
|---------|---------|---------|
| `SMTP_HOST` | `""` (empty) | SMTP server host. **Empty = console mode** (the code is logged, not emailed). |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | `""` | SMTP auth username (login skipped if empty) |
| `SMTP_PASSWORD` | `""` | SMTP auth password |
| `SMTP_USE_TLS` | `true` | `true` → STARTTLS on `SMTP_PORT`; `false` → implicit SSL (`SMTP_SSL`) |
| `SMTP_FROM_EMAIL` | `no-reply@ngcorion.local` | From address — **should match `SMTP_USERNAME`** or the mail server may reject it as spoofed |
| `SMTP_FROM_NAME` | `NGcorion` | From display name |
| `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES` | `10` | How long an OTP code stays valid |
| `PASSWORD_RESET_MAX_ATTEMPTS` | `5` | Wrong-code attempts before the code is invalidated |

> `FRONTEND_BASE_URL` still exists in config but is **no longer used** by the email
> (the OTP flow sends a code, not a link).

### Console (development) mode
When `SMTP_HOST` is empty, `app/core/email.py` **logs the full email — including the
code — to the server console** instead of sending it. This lets the whole flow be
developed and tested without a mail server. Example console output:

```
===== DEV EMAIL (SMTP not configured) =====
From: NGcorion <no-reply@ngcorion.local>
To: user@example.com
Subject: NGcorion — Password reset code

We received a request to reset the password for your account.
Your password reset code is: 215449
Enter it on the password reset page to choose a new password. This code expires in 10 minutes...
===========================================
```

### Switching to a real mail server
Fill in the `SMTP_*` values in `.env`. **No code change is required** — as soon as
`SMTP_HOST` is non-empty, `send_email()` sends via `smtplib` instead of logging. Email
sending never raises into the request (failures are logged), since it runs in a
background task. **Restart the backend after editing `.env`** — settings are read once at
startup.

Example `.env` (self-hosted mailbox / typical relay):
```env
SMTP_HOST=mail.example.com
SMTP_PORT=587
SMTP_USERNAME=support@example.com
SMTP_PASSWORD=your-mailbox-password
SMTP_USE_TLS=true
SMTP_FROM_EMAIL=support@example.com     # match SMTP_USERNAME
SMTP_FROM_NAME=NGcorion
```

> If the server log shows `Sent email to …` but the message never arrives, the SMTP
> server accepted it but delivery failed downstream — almost always a domain
> deliverability issue (SPF / DKIM / DMARC), not the application.

---

## Security model

| Property | Implementation |
|----------|----------------|
| No plaintext password in email | A one-time *code* is sent; the user chooses the password |
| Code secrecy at rest | Only the **SHA-256 hash** of the OTP is stored; the raw code exists only in the email |
| Single use | `used_at` is set on first successful reset; reused codes → `400` |
| Expiry | `expires_at` (default 10 min); expired codes → `400` |
| Brute-force limit | A 6-digit code has only 10⁶ values, so verification is **scoped to the user**, **attempt-limited** (`PASSWORD_RESET_MAX_ATTEMPTS`, then the code is burned), and uses a **constant-time** compare (`hmac.compare_digest`) |
| Newest-code-wins | Creating a new code marks the user's prior unused codes as used |
| No account enumeration | `forgot-password` always returns the same `200` message |
| Abuse protection | Rate limiting on `forgot-password` (see below) |
| Auditability | Every request/reset is written to the audit log (`log_action`, action `auth.forgot_password` / `auth.reset_password`) |

### Rate limiting
Defined in `app/core/auth_rate_limiter.py` → `check_password_reset_rate_limit()`,
counting reset codes created in a rolling window:

| Limit | Default |
|-------|---------|
| `RESET_WINDOW_MINUTES` | 15 |
| `MAX_RESET_REQUESTS_PER_IP` | 5 |
| `MAX_RESET_REQUESTS_PER_EMAIL` | 3 |

Exceeding either limit returns `429`. The per-IP limit caps probing of unknown emails;
the per-email limit prevents spamming a real user's inbox.

---

## Code map

| Concern | File |
|---------|------|
| Endpoints | `app/modules/auth/router.py` (`forgot_password`, `reset_password`) |
| OTP logic | `app/modules/auth/service.py` (`AuthService.create_password_reset_otp`, `reset_password_with_otp`, `_hash_code`) |
| Request/response schemas | `app/schemas/auth.py` (`ForgotPasswordRequest`, `ResetPasswordRequest`, `MessageResponse`) |
| Password-strength validator (shared) | `app/schemas/user.py` (`validate_password_strength`) |
| DB model | `app/models/password_reset_token.py` (`PasswordResetToken`) |
| Migrations | `alembic/versions/20260609_add_password_reset_tokens.py`, `20260610_add_attempts_to_password_reset_tokens.py` |
| Email sender | `app/core/email.py` (`send_email`, `send_password_reset_otp`) |
| Rate limiter | `app/core/auth_rate_limiter.py` (`check_password_reset_rate_limit`) |
| Config | `app/core/config.py`, `.env.example` |
| Frontend — request page | `front/src/components/ForgotPassword.jsx` (route `/forgot-password`) |
| Frontend — reset page | `front/src/components/ResetPassword.jsx` (route `/reset-password`) |
| Frontend — login link & routes | `front/src/components/Login.jsx`, `front/src/App.jsx` |

### Data model: `password_reset_tokens`
| Column | Type | Notes |
|--------|------|-------|
| `id` | int PK | |
| `user_id` | int FK → `users.id` | `ON DELETE CASCADE`, indexed |
| `token_hash` | string | SHA-256 hex of the **OTP code**, indexed |
| `expires_at` | timestamptz | |
| `used_at` | timestamptz, nullable | set when consumed (or burned after too many attempts) |
| `attempts` | int, default 0 | failed verification attempts; code invalidated past the limit |
| `created_at` | timestamptz | |
| `ip_address` | string, nullable | requester IP (audit) |

---

## Setup & testing

**Apply the migrations:**
```bash
uv run alembic upgrade head
```
> Deploy note: `app/main.py` runs `Base.metadata.create_all()` at startup, so if the app
> booted before migrating, the table/column may already exist and `alembic upgrade` will
> error with `DuplicateTable`/`DuplicateColumn`. In that case `alembic stamp head` once,
> since the schema already matches.

**Manual end-to-end test (console mode, no SMTP needed):**
1. `POST /auth/forgot-password` with a real user's email → `200`; copy the 6-digit code
   printed in the server console.
2. `POST /auth/reset-password` with `{email, otp, new_password}` → `200`.
3. `POST /auth/login` with the new password → succeeds; the old password → `401`.
4. Wrong code → `400`; after `PASSWORD_RESET_MAX_ATTEMPTS` wrong tries the code is burned.
5. Re-submit a used code, or let one expire → `400`.
6. Repeat `forgot-password` past the limit → `429`.

**Frontend:** from the login page click **Forgot password?**, submit your email (you're
taken to the reset page with the email carried over), enter the emailed code + a new
password, and confirm you can log in.

> **Note:** the reset routes render inside the license gate in `App.jsx`, so (like the
> login page) they are only reachable when the license is valid.
