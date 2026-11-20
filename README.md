# Silmun launch board

A password-protected, mobile-first dashboard for the Silmun launch: days to launch, what's waiting on a decision, the road to launch, open work and risks.

**View it:** https://kazi7107.github.io/Silmun-Agent-Work-Dashboard/ (ask Kazim for the password)

## How the password works

GitHub Pages can't do logins, so the data is encrypted instead, with a lock-and-key setup:

- `data/public-key.json` is the lock. The daily update uses it to encrypt the data. It can't decrypt anything, so the update job never needs the password.
- `data/private-key.enc.json` is the key, itself encrypted with the password (PBKDF2-SHA256, 600k rounds, AES-GCM).
- `data/tracker.enc.json` is the data (ECDH P-256 + HKDF + AES-256-GCM).

The page asks for the password, unlocks the key and decrypts the data, all in the browser. Without the password the public repo only holds scrambled data.

"Keep me signed in" saves the password in that browser only. The Lock button clears it.

## Updating the data

The source of truth is the private Silmun Launch Tracker. A daily job (5pm Pacific) exports it and runs:

```
python3 scripts/build_public_data.py raw.json data/tracker.enc.json
```

The script also trims the data before encrypting it: no email addresses, no prices, no risks about people's personal situations. Any tracker row with `[private]` in it is left out completely.

Never commit the raw export or the password.

## Changing the password

```
SILMUN_DASH_PASSWORD=new-password python3 scripts/make_keys.py
python3 scripts/build_public_data.py raw.json data/tracker.enc.json
```

Push both. The old password stops working right away.
