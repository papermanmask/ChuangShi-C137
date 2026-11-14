#!/usr/bin/env python3
"""
Validate the encrypted DeepSeek key + model with a 1-token request.
Reads the DPAPI-encrypted key file, decrypts in memory, makes ONE tiny
chat completion, and prints only the HTTP status (never the key).
"""
import sys
import json
import base64
import urllib.request
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import crypto_helper  # noqa: E402

BASE_URL = "https://api.deepseek.com"
MODEL = "deepseek-v4-flash"

def main():
    keyfile = os.path.join(HERE, ".inkos_key.enc")
    with open(keyfile, "rb") as f:
        raw = f.read()
    key = crypto_helper.unprotect(base64.b64decode(raw)).decode("utf-8")

    payload = json.dumps({
        "model": MODEL,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
        "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(
        BASE_URL + "/chat/completions",
        data=payload,
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", "replace")
            # Print only the status + a short, key-free excerpt
            print("STATUS_OK", resp.status)
            print("MODEL_REACHED", MODEL)
            print("SNIPPET", body[:80].replace("\n", " "))
    except urllib.error.HTTPError as e:
        print("HTTP_ERROR", e.code, e.reason)
        print("DETAIL", e.read().decode("utf-8", "replace")[:200])
        sys.exit(1)

if __name__ == "__main__":
    main()
