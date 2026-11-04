# CyberShield

CyberShield is a Flask web app for basic security checks, account management, and scan history. The live demo is at [cybershield-aoox.onrender.com](https://cybershield-aoox.onrender.com).

## Features

- Admin and User accounts. Admins can review all accounts and scans; users can view only their own scans.
- Users can clear their own scan history, and User scans expire after 24 hours. Admin scans do not expire automatically; the Admin clear action affects only Admin account scans.
- Users can change their password; Admins can set a temporary password for User accounts.
- IP address format and address-range checks.
- URL structure checks that do not open or contact the submitted site.
- File metadata and signature checks performed in memory.
- Basic keyword checks for pasted log text.
- Scan history, alerts, and downloadable reports.

These tools provide basic local indicators. They do not perform live threat-intelligence lookups, antivirus scans, or a complete security analysis. Treat `Unverified` as unknown, not safe.

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

## Hosted deployment

The live app is deployed from the `master` branch of the public GitHub repository through the root `render.yaml` Blueprint. Render stores `DATABASE_URL` as a secret environment variable; the app uses Supabase PostgreSQL for durable account and scan data.

To deploy updates, push changes to `master`. Render syncs the Blueprint and redeploys the web service.

## Data and privacy

- Passwords are stored as hashes, not plain text.
- Password changes and administrator resets invalidate existing login sessions for that account.
- User scan history is scoped to the signed-in account. Admin pages are protected on the Flask server.
- Uploaded files are checked in memory and are not saved or executed. The file name and result are stored in account history.
- `.env`, `.venv/`, and `instance/` are excluded from Git.

## Configuration

See `.env.example` for local environment variable names. Production secrets belong in the Render service's environment settings, never in source files or commits.
