# Forgot Password — Developer Guide

Self-service password recovery via a **time-limited, single-use reset link** sent by
email. No password is ever emailed in plaintext: the user requests a link, clicks it,
and chooses a new password.

- **Audience:** backend & frontend developers, and operators configuring SMTP.
- **Auth:** both endpoints are **public** (no JWT). Registered under `/auth`.

---

## Flow at a glance

```
User                Frontend                 Backend                     Email
 |  "Forgot password?" |                         |                          |
 |-------------------->| POST /auth/forgot-password {email}                 |
 |                     |------------------------>| create token (store hash)|
 |                     |                         |---- send reset link ---->|
 |                     |<-- 200 generic message -|                          |
 |                                                                          |
 |  clicks link in email:  {FRONTEND_BASE_URL}/reset-password?token=RAW     |
 |-------------------->| (reads token from URL)  |                          |
 |  enters new password|                         |                          |
 |                     |---- POST /auth/reset-password {token, new_password}->
 |                     |                         | validate + set password  |
 |                     |<------ 200 success ------|                          |
 |  redirected to login                                                     |
```

---

## API Reference

### 1. Request a reset link

**Endpoint:** `POST /auth/forgot-password`

```bash
curl -X POST http://localhost:8000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

**Response — always `200`, always identical** (regardless of whether the email exists):
```json
{ "message": "If an account with that email exists, a password reset link has been sent." }
```

This is deliberate: a different response for known vs. unknown emails would let an
attacker enumerate registered accounts. If the email *does* belong to an **active**
account, a reset email is queued (via a FastAPI `BackgroundTask`); otherwise nothing
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
  -d '{"token": "RAW_TOKEN_FROM_LINK", "new_password": "NewPass456!"}'
```

**Success — `200`:**
```json
{ "message": "Your password has been reset. You can now log in." }
```

**Errors:**
| Status | When |
|--------|------|
| `422`  | `new_password` fails the strength rules (see below) |
| `400`  | Token unknown, already used, or expired → `"Invalid or expired reset link. Please request a new one."` |

On success the token is **consumed** (marked used) and the user's `hashed_password`
is replaced. The user can immediately log in via `POST /auth/login`.

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
| `SMTP_HOST` | `""` (empty) | SMTP server host. **Empty = console mode** (emails are logged, not sent). |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | `""` | SMTP auth username (login skipped if empty) |
| `SMTP_PASSWORD` | `""` | SMTP auth password |
| `SMTP_USE_TLS` | `true` | `true` → STARTTLS on `SMTP_PORT`; `false` → implicit SSL (`SMTP_SSL`) |
| `SMTP_FROM_EMAIL` | `no-reply@ngcorion.local` | From address |
| `SMTP_FROM_NAME` | `NGcorion` | From display name |
| `FRONTEND_BASE_URL` | `http://localhost:5173` | Base URL used to build the reset link in the email |
| `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES` | `30` | How long a reset link stays valid |

### Console (development) mode
When `SMTP_HOST` is empty, `app/core/email.py` **logs the full email — including the
reset link — to the server console** instead of sending it. This lets the whole flow
be developed and tested without a mail server. Example console output:

```
===== DEV EMAIL (SMTP not configured) =====
From: NGcorion <no-reply@ngcorion.local>
To: user@example.com
Subject: NGcorion — Password reset

We received a request to reset the password for your account.
Click the link below to choose a new password. This link expires in 30 minutes...

http://localhost:5173/reset-password?token=oHtAJH05hk6Kub...
===========================================
```

### Switching to a real mail server
Fill in the `SMTP_*` values in `.env` and set `FRONTEND_BASE_URL` to your deployed
frontend origin. **No code change is required** — as soon as `SMTP_HOST` is non-empty,
`send_email()` sends via `smtplib` instead of logging. Email sending never raises into
the request (failures are logged), since it runs in a background task.

Example `.env` for Gmail (app password) / a typical relay:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-account@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
SMTP_FROM_EMAIL=no-reply@yourdomain.com
SMTP_FROM_NAME=NGcorion
FRONTEND_BASE_URL=https://app.yourdomain.com
```

---

## Security model

| Property | Implementation |
|----------|----------------|
| No plaintext password in email | A reset *link* is sent; the user chooses the password |
| Token secrecy at rest | Only the **SHA-256 hash** of the token is stored; the raw token exists only in the email/URL |
| Single use | `used_at` is set on first successful reset; reused tokens → `400` |
| Expiry | `expires_at` (default 30 min); expired tokens → `400` |
| Newest-link-wins | Creating a new token marks the user's prior unused tokens as used |
| No account enumeration | `forgot-password` always returns the same `200` message |
| Abuse protection | Rate limiting on `forgot-password` (see below) |
| Auditability | Every request/reset is written to the audit log (`log_action`, action `auth.forgot_password` / `auth.reset_password`) |

### Rate limiting
Defined in `app/core/auth_rate_limiter.py` → `check_password_reset_rate_limit()`,
counting reset tokens created in a rolling window:

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
| Token logic | `app/modules/auth/service.py` (`AuthService.create_password_reset_token`, `reset_password_with_token`, `_hash_token`) |
| Request/response schemas | `app/schemas/auth.py` (`ForgotPasswordRequest`, `ResetPasswordRequest`, `MessageResponse`) |
| Password-strength validator (shared) | `app/schemas/user.py` (`validate_password_strength`) |
| DB model | `app/models/password_reset_token.py` (`PasswordResetToken`) |
| Migration | `alembic/versions/20260609_add_password_reset_tokens.py` |
| Email sender | `app/core/email.py` (`send_email`, `send_password_reset_email`) |
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
| `token_hash` | string | SHA-256 hex of the raw token, indexed |
| `expires_at` | timestamptz | |
| `used_at` | timestamptz, nullable | set when consumed |
| `created_at` | timestamptz | |
| `ip_address` | string, nullable | requester IP (audit) |

---

## Setup & testing

**Apply the migration:**
```bash
alembic upgrade head
```

**Manual end-to-end test (console mode, no SMTP needed):**
1. `POST /auth/forgot-password` with a real user's email → `200`; copy the
   `reset-password?token=...` link printed in the server console.
2. `POST /auth/reset-password` with that `token` + a strong `new_password` → `200`.
3. `POST /auth/login` with the new password → succeeds; the old password → `401`.
4. Re-submit the same token → `400` (single use). Let a token expire → `400`.
5. Repeat `forgot-password` past the limit → `429`.

**Frontend:** from the login page click **Forgot password?**, submit an email, open the
link from the console, set a new password, and confirm you can log in.

> **Note:** the reset routes render inside the license gate in `App.jsx`, so (like the
> login page) they are only reachable when the license is valid.
