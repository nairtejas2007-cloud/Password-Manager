# Secure Password Manager

A FastAPI and MySQL password manager with an original responsive browser interface.

The browser UI uses a white and lime-green design. Registration saves the account and redirects to login. Login is two-stage: the server first validates the email and master password, then emails an OTP; only a valid OTP creates the vault session and verifies the email address.

## Security model

- Master passwords use Argon2id.
- Vault keys use Argon2id with a unique 16-byte per-user salt.
- Legacy credentials and every custom field value use AES-256-GCM with fresh random 12-byte nonces.
- Encryption keys remain in the authenticated server session; they are not stored in the database.
- Email OTPs are SHA-256 hashed, expire in five minutes, and have attempt limits.
- Sessions contain the derived vault key only in server memory and expire after inactivity.
- Lost master passwords cannot recover encrypted vault data.

## Windows setup

1. Install MySQL Server and start it.
2. Open `schema.sql` in MySQL Workbench and run it. This creates the database and app tables. Then create the app user:

```sql
CREATE USER 'pm_user'@'localhost' IDENTIFIED BY 'choose_a_strong_password';
GRANT ALL PRIVILEGES ON password_manager.* TO 'pm_user'@'localhost';
FLUSH PRIVILEGES;
```

3. Create the virtual environment and install dependencies:

```powershell
cd C:\Users\Tejas\Desktop\secure-password-manager
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
```

4. Edit `.env`. Set `DB_PASSWORD`, `SMTP_USERNAME`, and `SMTP_APP_PASSWORD` before use.
   Also set `OTP_PEPPER` to a stable, private random value (for example, generate one with `python -c "import secrets; print(secrets.token_hex(32))"`). Do not change it while verification codes are active.

On startup, the app applies additive, non-destructive compatibility migrations to older databases (including the original `username`-based schema) and creates the `vault_fields` table if needed. Existing password entries are preserved; entries using the older username/password/notes columns are presented as fields and can be edited without losing their values. Review and back up your database before production migrations.

## Gmail App Password

1. Enable Google 2-Step Verification on the Gmail account.
2. Open Google Account → Security → App passwords.
3. Create an app password named `Secure Password Manager`.
4. Put that 16-character password in `SMTP_APP_PASSWORD` only; never commit `.env`.

SMTP delivery is required for login OTPs. Account creation itself does not send email; the user receives an OTP after correct login credentials are entered. Missing SMTP credentials are reported at that login step.

## Run

```powershell
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --host 127.0.0.1 --port 5000 --reload
```

Open <http://127.0.0.1:5000>.
API documentation is at <http://127.0.0.1:5000/api/docs>.

## Tests

The unit tests are designed not to use MySQL. Use a separate test database for integration tests if extending coverage.

```powershell
python -m pytest -q
```

## API overview

- `POST /register` — create account without email delivery; continue to login
- `POST /register/resend` — resend verification OTP
- `POST /register/verify` — legacy registration OTP verification endpoint
- `POST /login` — verify master password and send login OTP
- `POST /login/verify` — exchange the temporary challenge and OTP for a session cookie
- `POST /login/resend` — resend a login OTP during the challenge
- `POST /logout` — destroy the vault session
- `GET /auth/me` — validate the current session
- `GET/POST /vault`, `GET/PUT/DELETE /vault/{id}`, `PATCH /vault/{id}/favourite` — owner-scoped vault operations. Entry creation/update accepts a `title` and an ordered `fields` array; legacy `site_name` input is still accepted. Editing, favouriting, or deleting a saved entry requires a recent master-password check, and that authorization is single-use.
- `POST /vault/{id}/edit-authorize` — verify the master password before changing a saved entry.
- `GET /categories`, `POST /categories` — category operations
- `GET /dashboard` — account summary
- `GET /generate` — secure password generation
- `POST /account/change-password` — re-encrypt vault and require login again

## Operational limitations

- The app is intended for local/controlled HTTPS deployment. Run behind a TLS reverse proxy for network use.
- Sessions are in-memory and restart invalidates every session.
- The checked-in schema supports fresh databases; startup migrations add the custom-field table to existing databases without dropping saved entries.
- SMTP is external and requires valid Gmail credentials.
- OTP/login throttling and active sessions are in-memory; use a single app process locally. A multi-instance deployment needs shared, persistent rate-limit and session storage.
