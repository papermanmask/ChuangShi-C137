#!/usr/bin/env python3
"""
DPAPI-based encrypt/decrypt helper for the InkOS API key.

- `encrypt`: reads raw bytes from stdin, writes BASE64(DPAPI-encrypted) to stdout or a file.
- `decrypt`: reads BASE64(DPAPI-encrypted) from stdin or a file, writes raw bytes to stdout.

The encrypted blob is bound to the current Windows user account + machine
(Windows DPAPI, CRYPTPROTECT_UI_FORBIDDEN). It cannot be decrypted on another
machine or by another user. The plaintext key NEVER touches disk and only ever
exists in process memory.
"""
import sys
import base64
import ctypes
from ctypes import wintypes, POINTER, c_byte

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", POINTER(c_byte))]

def _blob(data: bytes) -> DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, POINTER(c_byte)))

CRYPTPROTECT_UI_FORBIDDEN = 0x01

def protect(plaintext: bytes) -> bytes:
    inp = _blob(plaintext)
    out = DATA_BLOB(0, None)
    if not crypt32.CryptProtectData(
        ctypes.byref(inp), None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)

def unprotect(cipher: bytes) -> bytes:
    inp = _blob(cipher)
    out = DATA_BLOB(0, None)
    if not crypt32.CryptUnprotectData(
        ctypes.byref(inp), None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: crypto_helper.py encrypt|decrypt [file]\n")
        sys.exit(2)
    mode = sys.argv[1]
    infile = sys.argv[2] if len(sys.argv) > 2 else None
    if mode == "encrypt":
        data = sys.stdin.buffer.read()
        enc = protect(data)
        out = base64.b64encode(enc)
        if infile:
            with open(infile, "wb") as f:
                f.write(out)
        else:
            sys.stdout.buffer.write(out)
    elif mode == "decrypt":
        if infile:
            with open(infile, "rb") as f:
                raw = f.read()
        else:
            raw = sys.stdin.buffer.read()
        enc = base64.b64decode(raw)
        dec = unprotect(enc)
        sys.stdout.buffer.write(dec)
    else:
        sys.stderr.write("unknown mode\n")
        sys.exit(2)

if __name__ == "__main__":
    main()
