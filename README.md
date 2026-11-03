# CyberShield

CyberShield is a local Flask security-analysis MVP. It currently includes first-time administrator setup, login, separate Admin/User dashboards, and account management. Analysis modules will be added one at a time.

## Run locally

From the CyberShield folder, open the VS Code terminal and run:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000/` in a browser. On the first visit, create the administrator account. Use a password with at least 12 characters. After setup, the page changes to the login screen.

The administrator can create user accounts from **Users**. Each user dashboard queries only that account's scan records. Admin pages and user creation are checked on the Flask server; a User account cannot open Admin pages.

## Local data and secrets

- SQLite data is saved in `instance/cybershield.sqlite3`.
- A local Flask session key is saved in `instance/secret_key` when `SECRET_KEY` is blank.
- `.env`, `instance/`, and `.venv/` are ignored by Git.
- Passwords are stored as password hashes, not plain text.

This local SQLite authentication is for the current MVP. Before public deployment, configure production secrets and move authentication/data storage to the planned Supabase setup.
