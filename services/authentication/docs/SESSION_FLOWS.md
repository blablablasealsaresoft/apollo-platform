# Session & MFA Flows

1. User authenticates with credentials → `/api/auth/login`.
2. If MFA enabled, `/api/mfa/challenge` returns OTP requirements.
3. Session issued via signed JWT stored in HttpOnly cookie.
4. Refresh tokens rotated every 24h; revocation list kept in Redis.
