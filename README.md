# CyberShield

CyberShield is a Flask web app for basic security checks, account management, and scan history. The live demo is at [cybershield-aoox.onrender.com](https://cybershield-aoox.onrender.com).

## Features

- Admin and User accounts. Admins can review all accounts and scans; users can view only their own scans.
- Users can hide scans from their own account history while Admins retain visibility until the 24-hour expiry or Admin deletion. Admins can separately clear all User scans or all Admin scans.
- Users can change their password; Admins can set a temporary password for User accounts.
- IP address format and address-range checks.
- URL structure checks plus a bounded, read-only request for public page metadata. The scanner does not run page scripts, submit forms, crawl links, or download linked files.
- File metadata and signature checks performed in memory.
- Basic keyword checks for pasted log text.
- Scan history, alerts, and downloadable reports.
- Saved scans open a detailed view with local indicators, checked facts, and suggested next steps.
- Scan detail pages can be downloaded as a single-scan PDF report.
- Scan submissions are limited to five per account per UTC minute window.
- Administrators can review a private activity log for successful sign-ins, account changes, scan-history clearing, and report exports.
- Users and Admins can reset a forgotten password using a one-time email code; the code expires after 10 minutes and allows at most five attempts.
- Risk labels are Normal, Low, High, and Critical. Critical is reserved for strong confirmed evidence and is not currently assigned by local-only checks.

These tools provide basic local indicators. They do not perform live threat-intelligence lookups, antivirus scans, or a complete security analysis. `Normal` means only that these limited checks found no warning; it does not confirm that an item is safe.

## Technology

- Python and Flask
- PostgreSQL on Supabase for hosted data; SQLite can be used for local development
- HTML templates, CSS, and JavaScript
- Render Blueprint for deployment

## Run locally on Windows

From the project folder, use PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000/`. If the selected database has no administrator account, follow the setup page to create one. Admins can create User accounts from **Users**.

By default, local development uses SQLite in `instance/cybershield.sqlite3`. To use Supabase locally, set `DATABASE_URL` in `.env` to the PostgreSQL connection string and apply `supabase_schema.sql` in the Supabase SQL Editor first. Keep `.env` private; it is excluded by `.gitignore`.

Forgot-password email delivery requires SMTP settings (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, and optionally `SMTP_FROM`). Set these values in the local `.env` or Render's private environment settings. SMTP is sent over TLS; never commit the mail password. Existing hosted databases also need `supabase_password_reset.sql` run once before deploying the password-recovery update.

For an existing hosted CyberShield Supabase database, run `supabase_app_controls.sql` once in the SQL Editor before deploying updates. It creates the private admin activity and scan-limit tables.

## Hosted deployment

The live app is deployed from the `master` branch of the public GitHub repository through the root `render.yaml` Blueprint. Render stores `DATABASE_URL` as a secret environment variable; the app uses Supabase PostgreSQL for durable account and scan data.

To deploy updates, push changes to `master`. Render syncs the Blueprint and redeploys the web service.

## Data and privacy

- Passwords are stored as hashes, not plain text.
- Password changes and administrator resets invalidate existing login sessions for that account.
- The administrator activity log records administrator actions but never stores passwords or password values.
- Scan limits are counted per signed-in account; temporary rate-limit counters older than one day are removed during scan requests.
- User scan history is scoped to the signed-in account. Admin pages are protected on the Flask server.
- Responses include browser security headers, and signed-in pages are marked not to be cached.
- Uploaded files are checked in memory and are not saved or executed. Their name, hash, type, size, and findings are stored in account history. Pasted log text is not stored; only summarized counts and findings are saved.
- URL scans contact the submitted public site and may be recorded by that site. Only selected response metadata is stored; the fetched page body is not retained.
- `.env`, `.venv/`, and `instance/` are excluded from Git.

## Configuration

See `.env.example` for local environment variable names. Production secrets belong in the Render service's environment settings, never in source files or commits.
