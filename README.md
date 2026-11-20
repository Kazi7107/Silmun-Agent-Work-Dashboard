# Silmun launch board

A password-protected, mobile-first dashboard for the Silmun launch: days to launch, what's waiting on a decision, the road to launch, open work and risks.

**View it:** https://kazi7107.github.io/Silmun-Agent-Work-Dashboard/ (ask Kazim for the password)

## How the password works

GitHub Pages can't do logins, so the data is encrypted instead. `data/tracker.enc.json` is AES-256-GCM encrypted with a key derived from the password (PBKDF2-SHA256, 310k rounds). The page asks for the password and decrypts it in the browser. Without the password the repo only holds scrambled data, even though the repo is public.

"Keep me signed in" saves the password in that browser only. The Lock button clears it.

## Updating the data

The source of truth is the private Silmun Launch Tracker. A daily job (5pm Pacific) exports it and runs:

```
SILMUN_DASH_PASSWORD=... python3 scripts/build_public_data.py raw.json data/tracker.enc.json
```

The script also trims the data before encrypting it: no email addresses, no prices, no risks about people's personal situations. Any tracker row with `[private]` in it is left out completely.

Never commit the raw export or the password.

## Changing the password

Rebuild the data with a new `SILMUN_DASH_PASSWORD` and push. The old password stops working right away. Anyone who ticked "Keep me signed in" gets asked for the new password.
