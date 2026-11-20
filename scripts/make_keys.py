#!/usr/bin/env python3
"""Create (or replace) the dashboard's key pair. Run this to set or change the password.

    SILMUN_DASH_PASSWORD=... python3 scripts/make_keys.py

Writes:
  data/public-key.json       public key. The daily update encrypts with it. It can't decrypt.
  data/private-key.enc.json  private key, encrypted with the password (PBKDF2-SHA256 + AES-GCM).

After running this, rebuild the data so it's encrypted to the new key:
    python3 scripts/build_public_data.py RAW.json data/tracker.enc.json
"""
import base64
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600000
b64 = lambda b: base64.b64encode(b).decode()


def main():
    password = os.environ.get("SILMUN_DASH_PASSWORD")
    if not password:
        sys.exit("Set SILMUN_DASH_PASSWORD.")
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    pkcs8 = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, pkcs8, None)

    os.makedirs("data", exist_ok=True)
    with open("data/public-key.json", "w") as f:
        json.dump({"v": 2, "curve": "P-256", "key": b64(pub_raw)}, f)
        f.write("\n")
    with open("data/private-key.enc.json", "w") as f:
        json.dump({"v": 2, "kdf": "PBKDF2-SHA256", "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "data": b64(ct)}, f)
        f.write("\n")
    print("New key pair written. Rebuild the data next.")


if __name__ == "__main__":
    main()
