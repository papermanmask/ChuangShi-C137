#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
InkOS <-> DeepSeek local proxy + live usage dashboard.

- Decrypts the DeepSeek API key IN MEMORY only (via crypto_helper / DPAPI).
  The plaintext key is never written to disk and never logged.
- Forwards /chat/completions to https://api.deepseek.com and captures the
  `usage` block from every response (streaming + non-streaming).
- Computes real cost in CNY (configurable rate) using official V4 pricing,
  splits cached vs non-cached input tokens.
- Serves a live dashboard (GET /) that shows tokens / cost / balance in real time
  via Server-Sent Events (GET /stream).
- Balance is LOCALLY computed: remaining = initial_balance - cumulative_cost.
  (DeepSeek has no API to fetch account balance with an API key.)

Run:  python proxy.py            (listens on http://127.0.0.1:8787)
"""
import sys
import os
import json
import time
import base64
import queue
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import crypto_helper  # local, contains DPAPI encrypt/decrypt

PORT = int(os.environ.get("INKOS_PROXY_PORT", "8787"))
UPSTREAM = "https://api.deepseek.com"

# Official DeepSeek-V4 pricing, per 1M tokens (USD-equivalent figures; for CN
# accounts these are billed in CNY at ~1:1, so default rate = 1).
PRICES = {
    "deepseek-v4-flash": {"cache_hit": 0.0028, "cache_miss": 0.14, "output": 0.28},
    "deepseek-v4-pro":   {"cache_hit": 0.0028, "cache_miss": 0.435, "output": 0.87},
}
FALLBACK_PRICE = {"cache_hit": 0.0028, "cache_miss": 0.14, "output": 0.28}

# --- decrypt the API key IN MEMORY (never stored on disk, never printed) ---
_KEY_ENC = open(os.path.join(HERE, ".inkos_key.enc"), "rb").read()
KEY = crypto_helper.unprotect(base64.b64decode(_KEY_ENC)).decode("utf-8")

# --- shared state ---
state = {
    "calls": 0,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "cached_tokens": 0,
    "cost": 0.0,           # cumulative cost in pricing-currency units
    "history": [],         # newest first, capped at 50
}
state_lock = threading.Lock()
sse_clients = []
sse_lock = threading.Lock()

BUDGET_FILE = os.path.join(HERE, "budget.json")
LEDGER_FILE = os.path.join(HERE, "usage_ledger.json")


def load_budget():
    try:
        with open(BUDGET_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"initial_balance": 50.0, "currency": "¥", "rate": 1.0}


budget = load_budget()


def save_budget():
    try:
        with open(BUDGET_FILE, "w", encoding="utf-8") as f:
            json.dump(budget, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def compute_cost(model, prompt, completion, cached):
    p = PRICES.get(model, FALLBACK_PRICE)
    non_cached = max(0, prompt - cached)
    return ((cached / 1e6) * p["cache_hit"]
            + (non_cached / 1e6) * p["cache_miss"]
            + (completion / 1e6) * p["output"])


def record(model, prompt, completion, cached):
    cost = compute_cost(model, prompt, completion, cached)
    entry = {
        "ts": time.strftime("%H:%M:%S"),
        "model": model,
        "prompt": prompt,
        "completion": completion,
        "cached": cached,
        "cost": round(cost, 6),
    }
    with state_lock:
        state["calls"] += 1
        state["prompt_tokens"] += prompt
        state["completion_tokens"] += completion
        state["cached_tokens"] += cached
        state["cost"] += cost
        state["history"].insert(0, entry)
        state["history"] = state["history"][:50]
    try:
        with open(LEDGER_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
    notify_sse()
    return cost


def snapshot():
    rate = float(budget.get("rate", 1.0))
    spent = state["cost"] * rate
    remaining = float(budget.get("initial_balance", 0.0)) - spent
    with state_lock:
        return {
            "calls": state["calls"],
            "prompt_tokens": state["prompt_tokens"],
            "completion_tokens": state["completion_tokens"],
            "cached_tokens": state["cached_tokens"],
            "cost": round(state["cost"], 6),
            "spent_local": round(spent, 4),
            "remaining": round(remaining, 4),
            "initial_balance": budget.get("initial_balance", 0.0),
            "currency": budget.get("currency", "¥"),
            "rate": rate,
            "history": state["history"][:20],
        }


def notify_sse():
    data = "data: " + json.dumps(snapshot(), ensure_ascii=False) + "\n\n"
    dead = []
    with sse_lock:
        for q in sse_clients:
            try:
                q.put(data)
            except Exception:
                dead.append(q)
        for q in dead:
            sse_clients.remove(q)


DASHBOARD = os.path.join(HERE, "dashboard.html")


class Handler(BaseHTTPRequestHandler):
    server_version = "InkOS-Proxy/1.0"

    def log_message(self, fmt, *args):
        # Log path/status only — NEVER log headers (they carry the API key).
        try:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))
        except Exception:
            pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                with open(DASHBOARD, "r", encoding="utf-8") as f:
                    html = f.read()
                self._send(200, html, "text/html; charset=utf-8")
            except Exception:
                self._send(500, "dashboard.html not found", "text/plain")
        elif path == "/api/state":
            self._send(200, json.dumps(snapshot(), ensure_ascii=False))
        elif path == "/api/budget":
            self._send(200, json.dumps(budget, ensure_ascii=False))
        elif path == "/stream":
            self.handle_sse()
        else:
            self._send(404, "not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/budget":
            length = int(self.headers.get("Content-Length", 0) or 0)
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                data = {}
            with state_lock:
                if "initial_balance" in data:
                    budget["initial_balance"] = float(data["initial_balance"])
                if "currency" in data:
                    budget["currency"] = data["currency"]
                if "rate" in data:
                    budget["rate"] = float(data["rate"])
            save_budget()
            notify_sse()
            self._send(200, json.dumps(budget, ensure_ascii=False))
            return
        if path == "/api/reset":
            # Start a fresh session: reset running counters but fold the already
            # spent amount into the initial balance so the remaining balance
            # stays mathematically consistent.
            with state_lock:
                spent = state["cost"] * float(budget.get("rate", 1.0))
                budget["initial_balance"] = float(budget.get("initial_balance", 0.0)) + spent
                state["calls"] = 0
                state["prompt_tokens"] = 0
                state["completion_tokens"] = 0
                state["cached_tokens"] = 0
                state["cost"] = 0.0
                state["history"] = []
            save_budget()
            try:
                open(LEDGER_FILE, "w", encoding="utf-8").close()
            except Exception:
                pass
            notify_sse()
            self._send(200, json.dumps({"ok": True}))
            return
        # default: proxy the request to DeepSeek
        self.proxy_request()

    # ---------- SSE ----------
    def handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        q = queue.Queue()
        with sse_lock:
            sse_clients.append(q)
        try:
            self.wfile.write(("data: " + json.dumps(snapshot(), ensure_ascii=False) + "\n\n").encode("utf-8"))
            while True:
                try:
                    data = q.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    continue
                self.wfile.write(data.encode("utf-8"))
        except Exception:
            pass
        finally:
            with sse_lock:
                if q in sse_clients:
                    sse_clients.remove(q)

    # ---------- proxy ----------
    def proxy_request(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/v1"):
            path = path[3:]
        upstream_url = UPSTREAM + path

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        try:
            req_json = json.loads(body) if body else {}
        except Exception:
            req_json = {}
        model = req_json.get("model", "deepseek-v4-flash")
        is_stream = bool(req_json.get("stream", False))
        # Ensure the final streaming chunk carries `usage` (DeepSeek returns it
        # only when requested). Harmless if already present.
        if is_stream and "stream_options" not in req_json:
            req_json["stream_options"] = {"include_usage": True}
            body = json.dumps(req_json).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + KEY,  # our own in-memory key
        }
        req = urllib.request.Request(upstream_url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                ctype = resp.headers.get("Content-Type", "application/json")
                self.send_response(resp.status)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                if is_stream:
                    self._pipe_stream(resp, model)
                else:
                    raw = resp.read()
                    self.wfile.write(raw)
                    self._extract_usage(raw, model)
        except urllib.error.HTTPError as e:
            raw = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(raw)
            self._extract_usage(raw, model)
        except Exception as e:  # connection error etc.
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def _pipe_stream(self, resp, model):
        """Forward SSE bytes to the client while scanning for the final usage."""
        line_buf = b""
        while True:
            chunk = resp.read(4096)
            if not chunk:
                break
            try:
                self.wfile.write(chunk)
                self.wfile.flush()
            except Exception:
                break
            line_buf += chunk
            while b"\n" in line_buf:
                line, line_buf = line_buf.split(b"\n", 1)
                line = line.strip()
                if not line.startswith(b"data:"):
                    continue
                data_str = line[5:].strip()
                if data_str in (b"[DONE]", b""):
                    continue
                try:
                    obj = json.loads(data_str)
                except Exception:
                    continue
                if obj.get("usage"):
                    self._extract_usage(json.dumps(obj).encode("utf-8"), model)

    def _extract_usage(self, raw, model):
        try:
            obj = json.loads(raw)
        except Exception:
            return
        usage = obj.get("usage")
        if not usage:
            return
        prompt = int(usage.get("prompt_tokens", 0) or 0)
        completion = int(usage.get("completion_tokens", 0) or 0)
        cached = 0
        det = usage.get("prompt_tokens_details") or {}
        cached = int(det.get("cached_tokens", 0) or 0)
        record(model, prompt, completion, cached)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    sys.stderr.write("InkOS usage proxy + dashboard on http://127.0.0.1:%d\n" % PORT)
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
