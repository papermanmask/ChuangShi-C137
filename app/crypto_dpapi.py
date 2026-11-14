# -*- coding: utf-8 -*-
"""
DPAPI 加密工具（Windows 专属）
- 加密后的密文与「当前 Windows 用户 + 本机」绑定，换机器/换用户均无法解密。
- 作为模块导入时提供 encrypt_bytes / decrypt_bytes；作为 CLI 时：
    python crypto_dpapi.py encrypt  -> 从 stdin 读明文，向 stdout 输出 base64 密文
    python crypto_dpai.py decrypt <file> -> 从文件读 base64 密文，向 stdout 输出明文（二进制安全）
"""
import sys
import base64
import ctypes

try:
    _kernel32 = ctypes.windll.kernel32
    _crypt32 = ctypes.windll.crypt32
    _HAS_DPAPI = True
except Exception:  # 非 Windows 平台
    _HAS_DPAPI = False


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob_from_bytes(raw: bytes) -> DATA_BLOB:
    buf = ctypes.create_string_buffer(raw, len(raw))
    return DATA_BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))


def encrypt_bytes(plain: bytes) -> bytes:
    if not _HAS_DPAPI:
        raise RuntimeError("DPAPI unavailable (non-Windows)")
    out = DATA_BLOB()
    desc = ctypes.c_wchar_p("inkos-monitor-key")
    if not _crypt32.CryptProtectData(
        ctypes.byref(_blob_from_bytes(plain)), desc, None, None, None, 0, ctypes.byref(out)
    ):
        raise ctypes.WinError()
    try:
        size = int(out.cbData)
        return ctypes.string_at(out.pbData, size)
    finally:
        _kernel32.LocalFree(out.pbData)


def decrypt_bytes(blob: bytes) -> bytes:
    if not _HAS_DPAPI:
        raise RuntimeError("DPAPI unavailable (non-Windows)")
    out = DATA_BLOB()
    if not _crypt32.CryptUnprotectData(
        ctypes.byref(_blob_from_bytes(blob)), None, None, None, None, 0, ctypes.byref(out)
    ):
        raise ctypes.WinError()
    try:
        size = int(out.cbData)
        return ctypes.string_at(out.pbData, size)
    finally:
        _kernel32.LocalFree(out.pbData)


def _cli():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: crypto_dpapi.py encrypt | decrypt <file>\n")
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "encrypt":
        data = sys.stdin.buffer.read()
        sys.stdout.write(base64.b64encode(encrypt_bytes(data)).decode("ascii"))
    elif cmd == "decrypt":
        if len(sys.argv) < 3:
            sys.stderr.write("decrypt requires <file>\n")
            sys.exit(2)
        with open(sys.argv[2], "rb") as f:
            blob = base64.b64decode(f.read().strip())
        sys.stdout.buffer.write(decrypt_bytes(blob))
    else:
        sys.stderr.write("unknown command: %s\n" % cmd)
        sys.exit(2)


if __name__ == "__main__":
    _cli()
