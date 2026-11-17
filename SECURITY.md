# Security policy

Sentryline is a local analyst workspace intended for trusted, offline use. It binds to `127.0.0.1` by default and is not a hardened multi-tenant service.

## Reporting a vulnerability

Please open a private [GitHub security advisory](../../security/advisories/new) for this repository rather than a public issue. Include the affected version (`RULESET_VERSION` in `config.py`), reproduction steps and synthetic sample input.

## Handling data

- Never commit real logs, `data/*.sqlite3` databases or upload directories — they are excluded by `.gitignore`.
- When exposing the app beyond loopback, set `SENTRYLINE_PRODUCTION=1`, `SECRET_KEY`, `SENTRYLINE_AUTH_USER` and `SENTRYLINE_AUTH_PASSWORD`, and serve it behind TLS with `SENTRYLINE_HTTPS=1`.
