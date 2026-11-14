# -*- coding: utf-8 -*-
"""
创世 · 用量监控 —— 本地代理 + 实时仪表盘（零外部依赖，仅 Python 标准库）

职责：
  1. 作为 InkOS 与 DeepSeek 之间的本地代理，转发所有请求。
  2. 抓取每次响应的 usage（输入/输出/缓存命中 token），按 V4 官方价格实时计算 ¥ 花费。
  3. 通过 SSE 把「累计 token / 实际花费 / 同步余额」实时推送到浏览器仪表盘。
  4. API Key 仅在进程内存中由 DPAPI 解密，绝不落盘、不打印。

创世工作台（多书 / 模拟世界）：
  - 支持同一工程下多本书（book）切换：/api/books 列出全部书。
  - 世界设定文件动态发现（扫描 <book>/story 目录），不再硬编码。
  - 模拟世界增强：世界统计、角色浏览器、一致性检查、世界打包导出、新建世界文档。

安全要点：
  - 代理转发到 DeepSeek 时，始终用内存中解密出的真实 Key 覆盖 Authorization 头。
  - 即使上游（如 InkOS）发来的是占位 Key，真实 Key 也不会离开本进程内存。
  - 所有文件路径访问均经 safe_rel 校验，防目录穿越。
"""
import json
import os
import sys
import base64
import time
import queue
import threading
import datetime
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import re
import uuid
import shutil
import ipaddress
import math
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 创世执法器（反 AI 腔）与数目账对账 —— 本地规则，零 LLM 依赖
from audit_cn import scan as _audit_scan, repair as _audit_repair, \
    density_verdict as _audit_verdict, patch_prompt as _audit_patch_prompt, PATCH_SYS as _AUDIT_PATCH_SYS
from ledger_cn import parse_ledger as _ledger_parse, num_facts as _ledger_facts, \
    conflicts as _ledger_conflicts, ledger_hint as _ledger_hint, ledger_table as _ledger_table

# ----------------------------- 路径与全局 -----------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
USAGE_PATH = os.path.join(HERE, "usage.json")
KEY_FILE_ENV = os.environ.get("INKOS_KEY_FILE")
KEY_PATH = os.path.abspath(KEY_FILE_ENV) if KEY_FILE_ENV else os.path.join(HERE, "key.enc")
UPSTREAM = os.environ.get("DEEPSEEK_UPSTREAM", "https://api.deepseek.com").rstrip("/")
MAX_REQUEST_BODY = 8 * 1024 * 1024
UPSTREAM_ROUTES = {
    "GET": {"/models", "/v1/models"},
    "POST": {"/chat/completions", "/v1/chat/completions"},
}
# 上游 V4.x 模型 max_output_tokens 可达 393216；新版 inkos 的 DeepSeek 模型卡把
# maxOutput 直接当作默认 max_tokens 发过来（393216 / 兜底 24576）。代理旧的 16000
# 硬上限会把这些请求误拒成 400（表现为「采用并创作正文」失败）。这里放宽上限并
# 对超限请求做钳制改写，兼顾长章节输出与预算预留的可控性。
MAX_OUTPUT_TOKENS = 65536


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """禁止 urllib 自动把含 Authorization 的请求转发到重定向目标。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


UPSTREAM_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def _upstream_url(path):
    """构造同源 HTTPS 上游 URL；拒绝 userinfo、非 TLS、异常端口与查询片段。"""
    base = urllib.parse.urlsplit(UPSTREAM)
    if (base.scheme != "https" or not base.hostname or base.username or base.password
            or base.query or base.fragment or base.port not in (None, 443)):
        raise ValueError("invalid_upstream_config")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ValueError("invalid_upstream_path")
    target_path = base.path.rstrip("/") + path
    return urllib.parse.urlunsplit(("https", base.netloc, target_path, "", ""))

# ----------------------------- 小说工作台：路径与命令 -----------------------------
# 全部路径支持自动探测，w-136 可整体搬移：
#   1) 优先读环境变量（INKOS_BOOK_ROOT / INKOS_BIN / INKOS_NODE_DIR）
#   2) 自动从本文件位置向上定位工作区（含 inkos-monitor / inkos-smoke / inkos-3body）
#   3) 运行时（Node）探测：WorkBuddy 托管目录 → 工作区内置 runtime → PATH

def _find_workspace():
    """向上探测工作区根（父目录同时含 inkos-monitor/inkos-smoke/inkos-3body）。"""
    d = HERE
    for _ in range(5):
        parent = os.path.dirname(d)
        if not parent or parent == d:
            break
        if (os.path.isdir(os.path.join(parent, "inkos-monitor"))
                and os.path.isdir(os.path.join(parent, "inkos-smoke"))
                and os.path.isdir(os.path.join(parent, "inkos-3body"))):
            return parent
        d = parent
    return os.path.dirname(HERE)


def _find_node_dir():
    """探测 node 运行时目录（含 node.exe）。"""
    # 1) WorkBuddy 托管目录 %USERPROFILE%\.workbuddy\binaries\node\versions\*
    import glob
    home = os.path.expanduser("~")
    dirs = sorted(glob.glob(os.path.join(home, ".workbuddy", "binaries", "node", "versions", "*")),
                  key=lambda p: p.lower(), reverse=True)
    for d in dirs:
        if os.path.isfile(os.path.join(d, "node.exe")):
            return d
    # 2) 工作区内置 runtime（创世自带优先，干净拷贝场景）
    for cand in (os.path.join(SELF_DIR, "runtime", "node"),
                 os.path.join(WORKSPACE, "runtime", "node"),
                 os.path.join(WORKSPACE, "inkos-monitor", "runtime", "node"),
                 os.path.join(WORKSPACE, "c-137", "创世-C137", "runtime", "node")):
        if os.path.isfile(os.path.join(cand, "node.exe")):
            return cand
    # 3) PATH 中的 node
    try:
        n = shutil.which("node")
    except Exception:
        n = None
    if n:
        return os.path.dirname(os.path.dirname(n))
    return ""


def _resolve_self_dir():
    """创世交付包根（含 app/engine/project/runtime 的目录），基于本文件 app/ 上溯一级。"""
    return os.path.dirname(HERE)

SELF_DIR = _resolve_self_dir()
SELF_PROJECT = os.path.join(SELF_DIR, "project")
SELF_ENGINE_BIN = os.path.join(SELF_DIR, "engine", "node_modules", ".bin")

WORKSPACE = _find_workspace()
# 自包含优先：创世自带 project/ 即权威书本根；仅在缺失（开发态保留 inkos-3body 兼容）时回退。
# 自愈：若 INKOS_BOOK_ROOT 指向的目录不存在（或不含 books 子目录），忽略它，回退到 SELF_PROJECT，
# 避免旧/错误的环境变量把服务器指向一个空目录，导致 /api/books 返回空、所有 API 400。
def _resolve_book_root():
    env_root = os.environ.get("INKOS_BOOK_ROOT")
    if env_root and os.path.isdir(os.path.join(env_root, "books")):
        return os.path.abspath(env_root)
    if os.path.isdir(os.path.join(SELF_PROJECT, "books")):
        return os.path.abspath(SELF_PROJECT)
    return os.path.abspath(os.path.join(WORKSPACE, "inkos-3body", "3body"))
BOOK_ROOT = _resolve_book_root()
INKOS_BIN = os.path.abspath(os.environ.get("INKOS_BIN") or (
    SELF_ENGINE_BIN if os.path.isdir(SELF_ENGINE_BIN) else os.path.join(WORKSPACE, "inkos-smoke", "node_modules", ".bin")))
_node_env = os.environ.get("INKOS_NODE_DIR")
NODE_DIR = os.path.abspath(_node_env) if _node_env else _find_node_dir()
INKOS_CLI = os.path.abspath(os.path.join(INKOS_BIN, "..", "@actalk", "inkos", "dist", "index.js"))
NODE_EXE = os.path.join(NODE_DIR, "node.exe") if NODE_DIR else ""

# ----------------------------- 回收站（软删除 / 恢复 / 永久删除） -----------------------------
# 删除章节或书本时不直接销毁，而是移动到 BOOK_ROOT/.trash 并记录清单，
# 支持随时「恢复（回滚）」或「永久删除」。.trash 在 books/ 之外，不会被当作书扫描。
TRASH_ROOT = os.path.join(BOOK_ROOT, ".trash")
TRASH_MANIFEST = os.path.join(TRASH_ROOT, "trash.json")
trash_lock = threading.Lock()

# ---- SOP 作战室规则资产（独立流程配置，不侵入核心模拟创作引擎）----
SOP_RULES = {}
try:
    SOP_RULES = json.loads(open(os.path.join(HERE, "sop_rules.json"), "r", encoding="utf-8").read())
except Exception:
    pass

state_lock = threading.Lock()
sub_lock = threading.Lock()
subscribers = set()

# ---- 全局引擎任务锁：同一时刻只允许一个「花钱的生成任务」在跑 ----
# 防止并发触发两次创作互相竞争章节号 / 撞写文件（模拟、采用创作、生成、建书共用）。
task_lock = threading.Lock()
CURRENT_TASK = {"running": False, "kind": "", "book": "", "detail": "", "startedAt": 0}
ACTIVE_PROCESS_LOCK = threading.Lock()
ACTIVE_PROCESSES = set()
SHUTDOWN_EVENT = threading.Event()


def begin_task(kind, book, detail=""):
    # 与 snapshot() 使用相同的 state_lock -> task_lock 顺序，避免锁反转。
    with state_lock:
        with task_lock:
            if CURRENT_TASK["running"]:
                return False
            # 预算护栏：余额不足以支撑一次生成任务时拒绝启动。
            spent_currency = STATE["spent_usd"] * CFG["rate"]
            balance = CFG["initial_balance"] - spent_currency - RESERVED_CURRENCY
            if kind in ("generate", "adopt", "book_create", "simulate") and balance < 0.5:
                CURRENT_TASK["_budget_block"] = True
                return "budget"
            CURRENT_TASK["_budget_block"] = False
            CURRENT_TASK.update({
                "running": True, "kind": kind, "book": book,
                "detail": detail, "startedAt": int(time.time() * 1000),
            })
            return True


def end_task():
    with task_lock:
        snap = dict(CURRENT_TASK)
        snap["running"] = False
        snap["kind"] = ""
        snap["book"] = ""
        snap["detail"] = ""
        snap["startedAt"] = 0
        snap.pop("_budget_block", None)
        CURRENT_TASK.clear()
        CURRENT_TASK.update(snap)


def task_snapshot():
    with task_lock:
        return dict(CURRENT_TASK)


# ---- 自动推演（无人值守）：系统依据设定+历史自主生成「可能的未来」 ----
# 与上帝介入（用户引导）相对：auto 模式不需作者参与；guided 模式由作者驱动。
AUTO_SIM_STATE = {
    "enabled": False,        # 默认关闭，需用户显式开启（避免无人值守烧 token）
    "lastRunAt": 0,
    "lastBook": "",
    "lastError": "",
    "totalGenerated": 0,
}
AUTO_SIM_LOCK = threading.Lock()
AUTO_SIM_MAX_PER_CHAPTER = 2   # 每章最多保留几条「可能的未来」供挑选
AUTO_SIM_INTERVAL = 90        # 轮询间隔（秒）

DEFAULT_PRICES = {
    "deepseek-v4-flash": {"input": 0.14, "input_cached": 0.0028, "output": 0.28},
    "deepseek-v4-pro": {"input": 0.435, "input_cached": 0.0087, "output": 0.87},
    "default": {"input": 0.14, "input_cached": 0.0028, "output": 0.28},
}

CFG = {
    "port": 8787,
    "currency": "¥",
    "rate": 1.0,
    "initial_balance": 50.0,
    "key_file": "key.enc",
    "prices": dict(DEFAULT_PRICES),
}

STATE = {"input": 0, "output": 0, "cached": 0, "calls": 0, "spent_usd": 0.0}
HISTORY = []
RESERVED_CURRENCY = 0.0

API_KEY = None
KEY_STATUS = "missing"


# ----------------------------- 持久化 -----------------------------
def load_config():
    global CFG
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
        for k, v in d.items():
            if k in CFG:
                CFG[k] = v
        if "prices" in d and isinstance(d["prices"], dict):
            merged = {k: dict(v) for k, v in DEFAULT_PRICES.items()}
            for model, values in d["prices"].items():
                if isinstance(values, dict):
                    base = merged.get(model, merged["default"])
                    merged[model] = dict(base, **values)
            CFG["prices"] = merged
    except FileNotFoundError:
        save_config()
    except Exception:
        pass


def configured_port():
    raw = CFG.get("port", 8787)
    if isinstance(raw, bool):
        raise ValueError("invalid_port")
    try:
        port = int(raw)
    except (TypeError, ValueError):
        raise ValueError("invalid_port")
    if isinstance(raw, float) and raw != port:
        raise ValueError("invalid_port")
    if port < 1 or port > 65535:
        raise ValueError("invalid_port")
    return port


def _is_finite_number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(float(value)))


def validate_config():
    configured_port()
    if not _is_finite_number(CFG.get("rate")) or CFG["rate"] <= 0:
        raise ValueError("invalid_exchange_rate")
    if not _is_finite_number(CFG.get("initial_balance")) or CFG["initial_balance"] < 0:
        raise ValueError("invalid_initial_balance")
    prices = CFG.get("prices")
    if not isinstance(prices, dict) or not isinstance(prices.get("default"), dict):
        raise ValueError("invalid_price_config")
    for model, values in prices.items():
        if not isinstance(values, dict):
            raise ValueError("invalid_price_config:%s" % model)
        for key in ("input", "input_cached", "output"):
            value = values.get(key)
            if not _is_finite_number(value) or value < 0:
                raise ValueError("invalid_price_config:%s.%s" % (model, key))


def _save_json_atomic(path, value):
    """先在同目录完整写入，再原子替换，避免进程中断留下截断 JSON。"""
    tmp_path = "%s.tmp.%s.%s" % (path, os.getpid(), threading.get_ident())
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        return True
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return False


def save_config():
    return _save_json_atomic(CONFIG_PATH, CFG)


def load_usage():
    global STATE, HISTORY
    try:
        with open(USAGE_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
        for k, v in (d.get("totals") or {}).items():
            if k in STATE:
                STATE[k] = v
        HISTORY[:] = (d.get("history") or [])[:200]
    except FileNotFoundError:
        pass
    except Exception:
        pass


def save_usage():
    return _save_json_atomic(
        USAGE_PATH, {"totals": STATE, "history": HISTORY[:200]}
    )


# ----------------------------- 密钥（仅内存） -----------------------------
def load_key():
    global API_KEY, KEY_STATUS
    try:
        from crypto_dpapi import decrypt_bytes
        with open(KEY_PATH, "rb") as f:
            blob = base64.b64decode(f.read().strip())
        API_KEY = decrypt_bytes(blob).decode("utf-8").strip()
        KEY_STATUS = "ok" if API_KEY else "empty"
    except Exception as e:
        API_KEY = None
        KEY_STATUS = "error:%s" % type(e).__name__


# ----------------------------- 计费逻辑 -----------------------------
def compute_cost(model, prompt, completion, cached):
    """返回本次调用花费（美元，基于每 1M token 价格）。"""
    prices = CFG.get("prices") if isinstance(CFG.get("prices"), dict) else {}
    p = prices.get(model) if isinstance(prices.get(model), dict) else None
    if p is None:
        p = prices.get("default") if isinstance(prices.get("default"), dict) else DEFAULT_PRICES["default"]
    p = {key: p.get(key, DEFAULT_PRICES["default"][key]) for key in ("input", "input_cached", "output")}
    if any(not isinstance(value, (int, float)) or isinstance(value, bool)
           or not math.isfinite(float(value)) or value < 0 for value in p.values()):
        raise ValueError("invalid_model_price")
    prompt = max(int(prompt), 0)
    completion = max(int(completion), 0)
    cached = min(max(int(cached), 0), prompt)
    uncached = prompt - cached
    cost = (uncached * p["input"] + cached * p["input_cached"] + completion * p["output"]) / 1_000_000.0
    if not math.isfinite(cost) or cost < 0:
        raise ValueError("invalid_usage_cost")
    return cost


def reserve_request_budget(model, request_bytes, max_tokens):
    """保守预留一次请求的上限费用，避免并发调用同时越过可用余额。"""
    global RESERVED_CURRENCY
    if not isinstance(model, str):
        return None
    prices = CFG["prices"].get(model) or CFG["prices"]["default"]
    upper_input_price = max(prices["input"], prices["input_cached"])
    estimated_input_tokens = max(int(request_bytes), 0) + 256
    estimated_usd = (estimated_input_tokens * upper_input_price + max_tokens * prices["output"]) / 1_000_000.0
    estimated_currency = estimated_usd * CFG["rate"]
    if not math.isfinite(estimated_currency) or estimated_currency < 0:
        return None
    with state_lock:
        spent_currency = STATE["spent_usd"] * CFG["rate"]
        available = CFG["initial_balance"] - spent_currency - RESERVED_CURRENCY
        if estimated_currency > available:
            return None
        RESERVED_CURRENCY += estimated_currency
    return estimated_currency


def release_request_budget(reserved_currency):
    global RESERVED_CURRENCY
    if reserved_currency is None:
        return
    with state_lock:
        RESERVED_CURRENCY = max(0.0, RESERVED_CURRENCY - reserved_currency)


def extract_usage(data):
    """从响应 JSON 中抽取 (prompt, completion, cached)；无 usage 返回 None。"""
    if not isinstance(data, dict):
        return None
    u = data.get("usage")
    if not isinstance(u, dict):
        return None
    if not any(k in u for k in ("prompt_tokens", "completion_tokens", "prompt_tokens_details")):
        # 空 usage（无任何 token 字段）视为无效，不计入用量
        return None
    prompt = int(u.get("prompt_tokens", 0) or 0)
    completion = int(u.get("completion_tokens", 0) or 0)
    cached = 0
    det = u.get("prompt_tokens_details") or {}
    if isinstance(det, dict):
        cached = int(det.get("cached_tokens", 0) or 0)
    if prompt < 0 or completion < 0 or cached < 0:
        return None
    return (prompt, completion, min(cached, prompt))


# ----------------------------- 状态快照 / 广播 -----------------------------
# ---- DeepSeek 账户真实余额（区别于工作台内的「本地预算额度」）----
# 工作台的 balance = initial_balance - 本地记账，只是本地护栏额度，并非账户余额。
# 前端每 3 秒轮询 /api/state，故必须缓存，避免每轮都打上游余额接口。
ACCOUNT_BALANCE_CACHE = {"ts": 0.0, "data": None}
ACCOUNT_BALANCE_TTL = 60.0


def account_balance():
    """返回 DeepSeek 账户真实余额；查询失败时返回上次成功值（可能为 None）。"""
    now = time.time()
    cached = ACCOUNT_BALANCE_CACHE["data"]
    if now - ACCOUNT_BALANCE_CACHE["ts"] < ACCOUNT_BALANCE_TTL:
        return cached
    ACCOUNT_BALANCE_CACHE["ts"] = now  # 无论成败都冷却，避免上游慢时拖住轮询
    if KEY_STATUS != "ok" or not API_KEY:
        return None
    try:
        req = urllib.request.Request(
            _upstream_url("/user/balance"),
            headers={"Authorization": "Bearer " + API_KEY},
        )
        with UPSTREAM_OPENER.open(req, timeout=3) as resp:
            d = json.loads(resp.read().decode("utf-8", "replace"))
        infos = d.get("balance_infos") or []
        cny = next((b for b in infos if b.get("currency") == "CNY"), None)
        if not isinstance(cny, dict):
            cny = infos[0] if infos and isinstance(infos[0], dict) else None
        if not isinstance(cny, dict):
            return cached
        out = {
            "available": bool(d.get("is_available")),
            "currency": cny.get("currency") or "CNY",
            "total": float(cny.get("total_balance") or 0),
            "ts": int(now * 1000),
        }
        ACCOUNT_BALANCE_CACHE["data"] = out
        return out
    except Exception:
        return cached


def snapshot():
    account = account_balance()  # 网络 I/O 必须放在 state_lock 之外
    with state_lock:
        spent_currency = STATE["spent_usd"] * CFG["rate"]
        balance = CFG["initial_balance"] - spent_currency
        available_balance = balance - RESERVED_CURRENCY
        # 注意：花费是极小的金额（¥1e-6 量级），绝不能 round 到 6 位小数，
        # 否则 2.5256e-6 会被四舍五入成 3e-6，破坏余额数学一致性。
        # 这里保留高精度，由前端按显示需要自行格式化。
        return {
            "currency": CFG["currency"],
            "rate": CFG["rate"],
            "initial_balance": CFG["initial_balance"],
            "spent": spent_currency,
            "balance": balance,
            "reserved": RESERVED_CURRENCY,
            "available_balance": available_balance,
            "account": account,
            "totals": dict(STATE),
            "history": HISTORY[:50],
            "key_status": KEY_STATUS,
            "upstream": UPSTREAM,
            "task": task_snapshot(),
            "paths": {
                "book_root": BOOK_ROOT,
                "inkos_bin": INKOS_BIN,
                "node_dir": NODE_DIR,
                "workspace": WORKSPACE,
                "self_dir": SELF_DIR,
            },
            "time": int(time.time() * 1000),
        }


def broadcast():
    evt = json.dumps(snapshot(), ensure_ascii=False)
    with sub_lock:
        for q in list(subscribers):
            try:
                q.put_nowait(evt)
            except Exception:
                pass


def record_usage(model, prompt, completion, cached):
    with state_lock:
        # 先校验并规范化用量，再修改计数，避免留下半更新账目。
        prompt = max(int(prompt), 0)
        completion = max(int(completion), 0)
        cached = min(max(int(cached), 0), prompt)
        cost = compute_cost(model, prompt, completion, cached)
        STATE["input"] += int(prompt)
        STATE["output"] += int(completion)
        STATE["cached"] += int(cached)
        STATE["calls"] += 1
        STATE["spent_usd"] += cost
        HISTORY.insert(
            0,
            {
                "t": datetime.datetime.now().strftime("%H:%M:%S"),
                "model": model,
                "input": int(prompt),
                "output": int(completion),
                "cached": int(cached),
                "cost": round(cost * CFG["rate"], 6),
            },
        )
        if len(HISTORY) > 200:
            HISTORY[:] = HISTORY[:200]
        save_usage()
    broadcast()


# ----------------------------- 多书 / 世界设定 -----------------------------
FILENAME_LABELS = {
    "brief.md": "世界设定 · Brief",
    "story_bible.md": "世界圣经 · Story Bible",
    "author_intent.md": "作者意图",
    "book_rules.md": "书规",
    "character_matrix.md": "人物矩阵",
    "current_state.md": "当前状态",
    "pending_hooks.md": "待解钩子",
    "subplot_board.md": "支线看板",
    "emotional_arcs.md": "情绪弧",
    "chapter_summaries.md": "章节摘要",
    "story_frame.md": "大纲 · 故事框架",
    "volume_map.md": "大纲 · 卷映射",
    "world_rules.md": "世界底层逻辑 · 物质构成与物理规则",
}


# 「世界底层逻辑」是每本书最底层的世界契约：物质构成 + 底层物理规则。
# 模板带草稿标记「<!-- wl:draft -->」；在「世界设定」页编辑保存一次后标记被剥离，
# 此后 build_sim_context 才会把它注入推演上下文（避免占位模板污染生成）。
WORLD_RULES_REL = "story/world_rules.md"
WORLD_RULES_DRAFT_MARK = "<!-- wl:draft -->"
WORLD_RULES_TPL = """# 世界底层逻辑

> 本文件确立整个世界的「物质构成」与「底层物理规则」——任何设定、剧情、角色能力都不得与本节冲突。由作者审批后定稿。

## 一、物质构成
- 基础物质：（世界由什么构成，如元气 / 灵力 / 以太 / 元素…）
- 能量形态：（驱动世界运转的能量及其来源与转化）
- 介质与元素：（相生相克 / 组合规则）
- 计量口径：（灵石、金币、轮、年…与数目账对齐）

## 二、底层物理规则
- 时空规则：（位面结构 / 距离 / 时间是否可逆）
- 守恒法则：（能量、物质、寿命、气运是否守恒）
- 力量上限与代价：（至强境界、禁忌力量的代价）
- 成长法则：（境界 / 阶位如何提升、有无瓶颈）

## 三、边界与禁忌
（世界级禁忌 / 自洽死穴 — 留空由作者裁定）
"""


def world_rules_finalize(content):
    """剥离文件首行的草稿标记（作者在「世界设定」页保存一次即视为定稿）。"""
    for pre in (WORLD_RULES_DRAFT_MARK + "\n", WORLD_RULES_DRAFT_MARK):
        if content.startswith(pre):
            return content[len(pre):].lstrip("\n")
    return content


# ----------------------------- 可视化只读聚合（/api/viz） -----------------------------
# N01 规范：结构化数据只在后端解析一次，前端只负责呈现；只读、零 LLM、零写盘。
# 口径：一律以 story/state/*.json（引擎最新投影）为权威，md / memory.db 仅用于对照，
#       差异以 warnings 显式回传，禁止静默归一或前端重复解析。
VIZ_VIEWS = ("manifest", "usage", "world", "plot", "trace", "audit", "sandbox")


def _viz_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def _viz_text(bd, rel):
    p = safe_rel(bd, rel)
    if not p or not os.path.isfile(p):
        return ""
    try:
        with open(p, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def _viz_md_rows(text):
    """后端把简化 md 表格解析成结构化行；原文不回传前端。"""
    headers, rows = [], []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if cells and all((not c) or set(c) <= set("-: ") for c in cells):
            continue
        if not headers:
            headers = cells
        else:
            rows.append(cells)
    return headers, rows


def _viz_chapters(bd):
    out = []
    try:
        chs = read_chapters(bd, with_content=False)
    except Exception:
        chs = []
    for c in chs[:300]:
        words = 0
        f = c.get("file")
        if f:
            p = safe_rel(bd, "chapters/" + str(f).replace("\\", "/"))
            if p and os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8") as fh:
                        words = len(re.sub(r"\s", "", fh.read()))
                except Exception:
                    pass
        out.append({"number": c.get("number"), "title": c.get("title") or "",
                    "words": words, "file": f or ""})
    return out


def _viz_hook_warnings(bd):
    """口径差异清单：state/manifest 的迁移警告 + pending_hooks.md 的状态对照差异。"""
    warns = []
    st = _viz_json(safe_rel(bd, "story/state/manifest.json") or "", {})
    for w in (st.get("migrationWarnings") or []):
        warns.append({"scope": "state/manifest.json", "message": str(w)})
    hooks_doc = _viz_json(safe_rel(bd, "story/state/hooks.json") or "", {})
    state_status = {str(h.get("hookId")): str(h.get("status"))
                    for h in (hooks_doc.get("hooks") or [])}
    _, rows = _viz_md_rows(_viz_text(bd, "story/pending_hooks.md"))
    for r in rows:
        if len(r) < 4:
            continue
        hid, md_status = r[0], r[3]
        if hid in state_status and md_status and md_status != state_status[hid]:
            warns.append({"scope": "pending_hooks.md", "hook": hid,
                          "message": "伏笔 %s 状态口径差异：md=%s，state=%s（以 state 为准）"
                                     % (hid, md_status, state_status[hid])})
    return warns, state_status


def viz_view_audit(bd):
    text = _viz_text(bd, "story/audit_drift.md")
    issues = []
    chapter = None
    m = re.search(r"第\s*(\d+)\s*章", text or "")
    if m:
        chapter = int(m.group(1))
    for line in (text or "").splitlines():
        mm = re.match(r"^>\s*-\s*\[([^\]]+)\]\s*([^:：]+)[:：]\s*(.+)$", line.strip())
        if mm:
            issues.append({"level": mm.group(1).strip(), "type": mm.group(2).strip(),
                           "message": mm.group(3).strip(), "chapter": chapter})
    return {"available": bool(text),
            "reason": "" if text else "story/audit_drift.md 不存在",
            "warnings": [], "issues": issues, "source": "story/audit_drift.md"}


def viz_view_usage(bd):
    with state_lock:
        totals = dict(STATE)
        history = [dict(h) for h in HISTORY[:200]]
    series = [{"t": h.get("t", ""), "model": h.get("model", ""),
               "input": h.get("input", 0), "cached": h.get("cached", 0),
               "output": h.get("output", 0), "cost": h.get("cost", 0)}
              for h in history]
    return {"available": True, "reason": "", "warnings": [],
            "series": series, "totals": totals,
            "chapters": _viz_chapters(bd),
            "issues": viz_view_audit(bd).get("issues") or [],
            "sources": ["app/usage.json", "chapters/index.json", "story/audit_drift.md"]}


# ----------------------------- 世界沙盘（WorldX 式：只读世界状态 + 上帝事件） -----------------------------
def _viz_sandbox_agents(bd):
    """角色人格 / 记忆 / 说话方式 / 关系，全部来自作者既有的 character_matrix.md。"""
    text = _viz_text(bd, "story/character_matrix.md")
    raw, cur = [], None
    for line in text.splitlines():
        h = re.match(r"^##\s+(.+)$", line.strip())
        if h:
            cur = {"name": h.group(1).strip(), "fields": {}, "relations": []}
            raw.append(cur)
            continue
        m = re.match(r"^-\s*\*\*([^*]+)\*\*:\s*(.*)$", line.strip())
        if m and cur:
            k, v = m.group(1).strip(), m.group(2).strip()
            cur["fields"][k] = v
            if k == "关系":
                for seg in v.split("|"):
                    mm = re.match(r"^\s*([^()|]+?)\s*\(([^/)]+)", seg)
                    if mm:
                        cur["relations"].append({"to": mm.group(1).strip(),
                                                 "label": mm.group(2).strip()})
    _, erows = _viz_md_rows(_viz_text(bd, "story/emotional_arcs.md"))
    moods = {}
    for r in erows:
        if len(r) >= 3:
            moods[r[0]] = {"chapter": r[1], "mood": r[2],
                           "trigger": r[3] if len(r) > 3 else "",
                           "intensity": r[4] if len(r) > 4 else ""}
    out = []
    for i, a in enumerate(raw):
        f = a["fields"]
        out.append({"id": "a%d" % (i + 1), "name": a["name"],
                    "role": f.get("定位", ""), "tags": f.get("标签", ""),
                    "contrast": f.get("反差", ""), "speech": f.get("说话", ""),
                    "personality": f.get("性格", ""), "motive": f.get("动机", ""),
                    "current": f.get("当前", ""), "known": f.get("已知", ""),
                    "unknown": f.get("未知", ""), "relations": a["relations"],
                    "mood": moods.get(a["name"], {})})
    return out


def _viz_sandbox_events(bd):
    """每章世界事件 / 情绪 / 状态变化（完整原文，不截断）。"""
    d = _viz_json(safe_rel(bd, "story/state/chapter_summaries.json") or "", {})
    out = []
    for r in (d.get("rows") or []):
        out.append({"chapter": r.get("chapter"), "title": r.get("title") or "",
                    "mood": r.get("mood") or "", "type": r.get("chapterType") or "",
                    "events": r.get("events") or "",
                    "stateChanges": r.get("stateChanges") or "",
                    "hookActivity": r.get("hookActivity") or ""})
    return out


def _viz_sandbox_places(bd, facts, events):
    """地点：从世界状态、章节事件与分卷标题中结构化抽取；完整原串另存 detail，不臆造地形。"""
    places, seen = [], set()
    suffix = (r"(?:城|镇|村|山脉|山|院|阁|堂|楼|洞|崖|林|市|府|宫|殿|塔|谷|涧|坡|"
              r"台|街|域|界|峰|池|窟|庄|堡|寨|寺|观|房|间|道|路|桥|亭|轩|斋|苑)")
    bad = re.compile(r"(为|采|深入|翻墙|处理|卖|将|把|被|与|和|并|先|再|又|才|却|已|未|这|那|了|着|过)")
    time_words = re.compile(r"^(?:夜晚|清晨|午后|凌晨|黄昏|白天|夜里|同时|期间|当天|次日|当日)$")
    pat = re.compile(r"(?:前往|进入|回到|抵达|赴|在|至|到)([\u4e00-\u9fff]{2,6}?" + suffix + r")")

    def add(name, source, detail, chapter=0, strict=False):
        name = (name or "").strip()
        if not name or name in seen or time_words.match(name):
            return
        if strict and (len(name) > 10 or bad.search(name)):
            return
        seen.add(name)
        places.append({"id": "p%d" % (len(places) + 1), "name": name,
                       "source": source, "detail": detail, "chapter": chapter})

    for f in facts:
        pred = str(f.get("predicate") or "")
        if "位置" not in pred and "地点" not in pred:
            continue
        obj = str(f.get("object") or "")
        add(obj.split("（")[0].strip(), "state/current_state.json · 当前位置", obj, 0)
        m = re.search(r"（([^）]+)）", obj)
        if m:
            for part in re.split(r"[、,，]", m.group(1)):
                add(part, "state/current_state.json · 位置子区域", obj, 0)
    for e in events:
        ch = e.get("chapter") or 0
        ev = str(e.get("events") or "")
        for seg in re.split(r"[，。；、,;！？\s（）()]", ev):
            for mm in pat.finditer(seg):
                add(mm.group(1), "chapter_summaries · 第%s章事件" % ch, ev, ch, True)
    vm = _viz_text(bd, "story/outline/volume_map.md")
    for mm in re.finditer(r"^第[一二三四五六七八九十]+卷[“\"]([^”\"]+)[”\"]", vm, re.M):
        add(mm.group(1), "outline/volume_map.md · 分卷", mm.group(0), 0)
    if not places:
        add("故事现场", "fallback", "未解析到地点，使用通用场景", 0)
    return places[:40]


def viz_view_sandbox(bd):
    st = _viz_json(safe_rel(bd, "story/state/current_state.json") or "", {})
    facts = [{"subject": str(f.get("subject") or ""),
              "predicate": str(f.get("predicate") or ""),
              "object": str(f.get("object") or "")} for f in (st.get("facts") or [])]
    agents = _viz_sandbox_agents(bd)
    events = _viz_sandbox_events(bd)
    places = _viz_sandbox_places(bd, facts, events)
    snaps = _viz_world_snapshots(bd)
    hooks = _viz_json(safe_rel(bd, "story/state/hooks.json") or "", {}).get("hooks") or []
    god = []
    gp = safe_rel(bd, "world_sandbox/events.json")
    if gp and os.path.isfile(gp):
        try:
            god = json.load(open(gp, "r", encoding="utf-8"))
        except Exception:
            god = []
    if not isinstance(god, list):
        god = []
    warns, _ = _viz_hook_warnings(bd)
    return {"available": bool(agents or events),
            "reason": "" if (agents or events) else "缺少角色档案与章节事件",
            "warnings": warns,
            "agents": agents, "places": places, "events": events,
            "facts": facts, "snapshots": snaps, "hooks": hooks,
            "godEvents": god[-50:],
            "summary": {"agents": len(agents), "places": len(places),
                        "chapters": len(events), "snapshots": len(snaps),
                        "facts": len(facts), "godEvents": len(god)},
            "chapter": st.get("chapter"),
            "note": "角色自主行为为规则驱动（零 LLM 调用）；人格 / 记忆 / 关系 / 事件全部来自小说状态文件，不臆造世界设定",
            "sources": ["story/character_matrix.md", "story/emotional_arcs.md",
                        "story/state/current_state.json", "story/state/chapter_summaries.json",
                        "story/state/hooks.json", "story/snapshots/<章>/",
                        "story/outline/volume_map.md", "world_sandbox/events.json"]}


def _viz_world_files(bd):
    """世界设定文件清单（只读）：完整相对路径 + 非空白字符数，不截断。"""
    out = []
    for base in ("story", "story/outline", "story/roles"):
        d = safe_rel(bd, base)
        if not d or not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if not os.path.isfile(p) or not fn.endswith(".md"):
                continue
            try:
                words = len(re.sub(r"\s", "", open(p, "r", encoding="utf-8").read()))
            except Exception:
                words = 0
            out.append({"path": base + "/" + fn, "group": base.split("/")[-1],
                        "words": words})
    return out


def _viz_world_snapshots(bd):
    """世界状态快照演化：每章快照包含哪些设定文件（完整列表，不截断）。"""
    root = safe_rel(bd, "story/snapshots")
    if not root or not os.path.isdir(root):
        return []

    def key(n):
        return int(n) if n.isdigit() else 10 ** 9

    out = []
    for n in sorted(os.listdir(root), key=key):
        d = os.path.join(root, n)
        if not os.path.isdir(d):
            continue
        files = []
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if os.path.isdir(p):
                files.append(fn + "/")
            elif fn.endswith(".md"):
                files.append(fn)
        out.append({"chapter": n, "count": len(files), "files": files})
    return out


def viz_view_world(bd):
    st = _viz_json(safe_rel(bd, "story/state/current_state.json") or "", {})
    facts = st.get("facts") or []
    nodes, edges, seen = [], [], set()

    def add(nid, label, kind, detail=""):
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "label": label, "kind": kind, "detail": detail})

    for f in facts:
        s = str(f.get("subject") or "").strip()
        pred = str(f.get("predicate") or "").strip()
        obj = str(f.get("object") or "").strip()
        if not s:
            continue
        add("e:" + s, s, "entity")
        if pred and obj:
            fid = "f:%s:%s" % (s, pred)
            add(fid, pred, "fact", obj)  # 完整值放 detail，绝不截断
            edges.append({"source": "e:" + s, "target": fid, "label": pred,
                          "chapter": f.get("validFromChapter") or f.get("sourceChapter")})
    matrix = _viz_text(bd, "story/character_matrix.md")
    cur = ""
    for line in matrix.splitlines():
        h = re.match(r"^##\s+(.+)$", line.strip())
        if h:
            cur = h.group(1).strip()
            add("r:" + cur, cur, "role")
            continue
        r = re.match(r"^-\s*\*\*关系\*\*:\s*(.+)$", line.strip())
        if r and cur:
            for seg in r.group(1).split("|"):
                mm = re.match(r"^\s*([^()|]+?)\s*\(([^/)]+)", seg)
                if mm:
                    other, rel = mm.group(1).strip(), mm.group(2).strip()
                    if other:
                        add("r:" + other, other, "role")
                        edges.append({"source": "r:" + cur, "target": "r:" + other,
                                      "label": rel, "chapter": None})
    fact_rows = [{"subject": str(f.get("subject") or ""),
                  "predicate": str(f.get("predicate") or ""),
                  "object": str(f.get("object") or ""),
                  "validFrom": f.get("validFromChapter"),
                  "validUntil": f.get("validUntilChapter"),
                  "sourceChapter": f.get("sourceChapter")}
                 for f in facts]
    wfiles = _viz_world_files(bd)
    snaps = _viz_world_snapshots(bd)
    warns, _ = _viz_hook_warnings(bd)
    return {"available": bool(nodes or wfiles),
            "reason": "" if (nodes or wfiles) else "state/current_state.json 与 story/ 均无世界数据",
            "warnings": warns, "nodes": nodes, "edges": edges,
            "files": wfiles, "snapshots": snaps, "facts": fact_rows,
            "summary": {"files": len(wfiles),
                        "fileWords": sum(x["words"] for x in wfiles),
                        "snapshots": len(snaps), "facts": len(fact_rows),
                        "nodes": len(nodes), "edges": len(edges)},
            "chapter": st.get("chapter"),
            "sources": ["story/state/current_state.json", "story/character_matrix.md",
                        "story/*.md / outline / roles", "story/snapshots/<章>/"]}


def viz_view_plot(bd):
    hooks_doc = _viz_json(safe_rel(bd, "story/state/hooks.json") or "", {})
    hooks = [{"id": h.get("hookId"), "start": h.get("startChapter"),
              "type": h.get("type") or "", "status": h.get("status") or "",
              "advanced": h.get("lastAdvancedChapter"),
              "payoff": h.get("expectedPayoff") or "", "notes": h.get("notes") or ""}
             for h in (hooks_doc.get("hooks") or [])]
    arc = []
    _, rows = _viz_md_rows(_viz_text(bd, "story/emotional_arcs.md"))
    for r in rows:
        if len(r) >= 5:
            arc.append({"role": r[0], "chapter": r[1], "mood": r[2],
                        "trigger": r[3], "intensity": r[4],
                        "direction": r[5] if len(r) > 5 else ""})
    sums = _viz_json(safe_rel(bd, "story/state/chapter_summaries.json") or "", {}).get("rows") or []
    warns, _ = _viz_hook_warnings(bd)
    return {"available": bool(hooks or arc),
            "reason": "" if (hooks or arc) else "state/hooks.json 与 emotional_arcs.md 均无数据",
            "warnings": warns, "hooks": hooks, "arc": arc,
            "summaries": [{"chapter": s.get("chapter"), "title": s.get("title") or "",
                           "mood": s.get("mood") or "", "type": s.get("chapterType") or ""}
                          for s in sums],
            "chapters": _viz_chapters(bd),
            "sources": ["story/state/hooks.json", "story/emotional_arcs.md",
                        "story/state/chapter_summaries.json"]}


def _viz_rules(bd):
    text = (_viz_text(bd, "story/runtime/chapter-0002.rule-stack.yaml")
            or _viz_text(bd, "story/runtime/chapter-0001.rule-stack.yaml"))
    rules, cur = [], None
    for line in (text or "").splitlines():
        s = line.strip()
        m = re.match(r"^-\s*id:\s*(\S+)", s)
        if m:
            cur = {"id": m.group(1), "name": "", "precedence": 0, "scope": ""}
            rules.append(cur)
            continue
        if cur:
            m2 = re.match(r"^(name|precedence|scope):\s*(\S+)", s)
            if m2:
                k, v = m2.group(1), m2.group(2)
                cur[k] = int(v) if (k == "precedence" and v.isdigit()) else v
    return rules


def viz_view_trace(bd):
    rdir = safe_rel(bd, "story/runtime")
    files = []
    if rdir and os.path.isdir(rdir):
        files = sorted(n for n in os.listdir(rdir)
                       if re.match(r"^chapter-\d+\.trace\.json$", n))
    chapters = []
    for name in files[:20]:
        d = _viz_json(os.path.join(rdir, name), {})
        if not isinstance(d, dict) or not d.get("chapter"):
            continue

        def items(vals):
            out = []
            for v in (vals or []):
                s = str(v)
                norm = s.replace("\\", "/")
                # 绝对路径带盘符时取 story/runtime 等语义目录，避免类别退化成 "E:"
                m = re.search(r"(?:^|/)(story|runtime|chapters|roles|outline|state)(?:/|$)", norm)
                cat = m.group(1) if m else (norm.split("/")[0].split("#")[0] if "/" in norm else "other")
                out.append({"label": norm.split("/")[-1].split("#")[0] or s,
                            "category": cat,
                            "path": s})  # 完整原串另存，不截断
            return out

        tiers = d.get("contextTiers") or {}
        stages = [
            {"id": "planner", "label": "规划输入", "kind": "inputs",
             "items": items(d.get("plannerInputs"))},
            {"id": "sources", "label": "选材来源", "kind": "sources",
             "items": items(d.get("selectedSources"))},
            {"id": "tiers", "label": "上下文分层", "kind": "tiers",
             "items": [{"label": "受保护来源 %d 项" % len(tiers.get("protectedSources") or []),
                        "category": "protected", "path": ""},
                       {"label": "可压缩来源 %d 项" % len(tiers.get("compressibleSources") or []),
                        "category": "compressible", "path": ""}]},
            {"id": "skills", "label": "技能与提示包", "kind": "process",
             "items": items(list(d.get("usedSkills") or []) + list(d.get("promptPacks") or []))},
            {"id": "composer", "label": "成稿输入", "kind": "outputs",
             "items": items(d.get("composerInputs"))},
        ]
        links = [{"from": stages[i]["id"], "to": stages[i + 1]["id"],
                  "kind": "pipeline"} for i in range(len(stages) - 1)]
        chapters.append({"chapter": d.get("chapter"), "file": name,
                         "stages": stages, "links": links,
                         "contextNeeds": list(d.get("contextNeeds") or []),
                         "tokenBudget": d.get("tokenBudget") or {},
                         "notes": list(d.get("notes") or [])})
    avail = bool(chapters)
    return {"available": avail,
            "reason": "" if avail else "story/runtime/ 下无可解析的 chapter-*.trace.json",
            "warnings": [], "chapters": chapters, "rules": _viz_rules(bd),
            "note": "数据血缘 / 推演管线顺序，非模型内部推理链",
            "sources": ["story/runtime/chapter-*.trace.json",
                        "story/runtime/chapter-*.rule-stack.yaml"]}


def viz_view_manifest(bd):
    warns, _ = _viz_hook_warnings(bd)

    def has(rel):
        p = safe_rel(bd, rel)
        return bool(p and os.path.isfile(p))

    rdir = safe_rel(bd, "story/runtime")
    trace_ok = False
    if rdir and os.path.isdir(rdir):
        trace_ok = any(re.match(r"^chapter-\d+\.trace\.json$", n)
                       for n in os.listdir(rdir))
    views = {
        "usage": {"available": True, "label": "数据可视化", "library": "chart.js"},
        "world": {"available": has("story/state/current_state.json"),
                  "label": "世界可视化", "library": "cytoscape"},
        "plot": {"available": has("story/state/hooks.json"),
                 "label": "剧情可视化", "library": "chart.js"},
        "trace": {"available": trace_ok, "label": "推导可视化", "library": "cytoscape"},
        "audit": {"available": has("story/audit_drift.md"),
                  "label": "审校上屏", "library": "table"},
        "sandbox": {"available": has("story/character_matrix.md"),
                    "label": "世界沙盘", "library": "canvas2d"},
    }
    for v in views.values():
        if not v["available"]:
            v["reason"] = "缺少对应数据文件，视图将自动降级或隐藏"
    return {"available": True, "reason": "", "warnings": warns, "views": views,
            "vendors": {"chart.js": "/vendor/chart-js-4.6.1.min.js",
                        "cytoscape": "/vendor/cytoscape-3.34.4.min.js",
                        "echarts": "/vendor/echarts-6.1.0.min.js"}}


def build_viz(bd, view):
    fn = {"manifest": viz_view_manifest, "usage": viz_view_usage,
          "world": viz_view_world, "plot": viz_view_plot,
          "trace": viz_view_trace, "audit": viz_view_audit,
          "sandbox": viz_view_sandbox}.get(view)
    out = fn(bd)
    avail = bool(out.pop("available", True))
    reason = out.pop("reason", "")
    warns = out.pop("warnings", [])
    return {"view": view, "book": book_title(bd), "available": avail,
            "reason": reason, "warnings": warns, "data": out}


def list_books():
    """扫描工程下全部书，返回摘要列表。"""
    books = []
    bdir = os.path.join(BOOK_ROOT, "books")
    if not os.path.isdir(bdir):
        return books
    for name in sorted(os.listdir(bdir)):
        jp = os.path.join(bdir, name, "book.json")
        if not os.path.isfile(jp):
            continue
        try:
            d = json.load(open(jp, "r", encoding="utf-8"))
        except Exception:
            d = {}
        bid = d.get("id") or name
        cnt = 0
        try:
            idx = json.load(open(os.path.join(bdir, name, "chapters", "index.json"), "r", encoding="utf-8"))
            cnt = len(idx) if isinstance(idx, list) else 0
        except Exception:
            pass
        books.append({
            "id": bid,
            "title": d.get("title", bid),
            "genre": d.get("genre", ""),
            "platform": d.get("platform", ""),
            "status": d.get("status", ""),
            "targetChapters": d.get("targetChapters"),
            "language": d.get("language", ""),
            "chapters": cnt,
        })
    return books


def default_book():
    bs = list_books()
    if not bs:
        return None
    for b in bs:
        if "三体" in b["id"]:
            return b["id"]
    return bs[0]["id"]


def _path_is_within(root, path):
    """基于真实路径判断 path 是否位于 root 内（含符号链接解析）。"""
    try:
        root_real = os.path.normcase(os.path.realpath(root))
        path_real = os.path.normcase(os.path.realpath(path))
        return os.path.commonpath([root_real, path_real]) == root_real
    except (OSError, ValueError, TypeError):
        return False


def book_dir(book):
    """解析并校验 book 目录，确保真实路径仍位于书本根目录内。"""
    if not book:
        book = default_book()
    if (not isinstance(book, str) or not book or book in (".", "..")
            or "/" in book or "\\" in book):
        return None
    try:
        books_root = os.path.realpath(os.path.join(BOOK_ROOT, "books"))
        d = os.path.realpath(os.path.join(books_root, book))
        if not _path_is_within(books_root, d):
            return None
        marker = os.path.join(d, "book.json")
        if not _path_is_within(d, marker) or not os.path.isfile(marker):
            return None
        return d
    except (OSError, ValueError, TypeError):
        return None


def book_title(book_dir_path):
    try:
        d = json.load(open(os.path.join(book_dir_path, "book.json"), "r", encoding="utf-8"))
        return d.get("title") or d.get("id") or "未命名"
    except Exception:
        return "未命名"


def safe_file_stem(value):
    """生成 Windows 可用的单段文件名，不允许标题携带路径或设备名。"""
    stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", str(value or ""))
    stem = stem.strip(" .")[:120]
    if not stem:
        stem = "book"
    if stem.upper().split(".", 1)[0] in {
            "CON", "PRN", "AUX", "NUL",
            *("COM%d" % i for i in range(1, 10)),
            *("LPT%d" % i for i in range(1, 10)),
    }:
        stem = "_" + stem
    return stem


def safe_rel(book_dir_path, rel):
    """只允许 book_dir 内的相对路径，并拒绝经符号链接越界。"""
    if not isinstance(rel, str):
        return None
    rel = rel.replace("\\", "/")
    drive, _ = os.path.splitdrive(rel)
    if not rel or drive or os.path.isabs(rel) or rel.startswith("/"):
        return None
    if ".." in rel.split("/"):
        return None
    try:
        full = os.path.realpath(os.path.join(book_dir_path, rel))
        if not _path_is_within(book_dir_path, full):
            return None
        return full
    except (OSError, ValueError, TypeError):
        return None


def pretty_label(rel):
    rel = rel.replace("\\", "/")
    base = rel.split("/")[-1]
    if base in FILENAME_LABELS:
        return FILENAME_LABELS[base]
    if base.endswith(".md"):
        name = base[:-3]
        if rel.startswith("roles/") or "/roles/" in rel:
            return "角色 · " + name
        if rel.startswith("outline/") or "/outline/" in rel:
            return "大纲 · " + name
        if rel.startswith("story/") or "/story/" in rel:
            return name
        return name
    return base


def scan_world(book_dir_path):
    """动态发现世界设定文件（扫描 story/ 下所有 .md/.txt）。"""
    items = []
    story = os.path.join(book_dir_path, "story")
    if not os.path.isdir(story):
        return items
    for root, dirs, files in os.walk(story):
        # 排除快照备份目录：snapshots 下是每章生成时的历史备份，
        # 混进文件树会让设定列表膨胀数倍且极易误编辑旧版本。
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "snapshots"]
        for fn in sorted(files):
            if not fn.endswith((".md", ".txt")):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, book_dir_path).replace("\\", "/")
            try:
                with open(full, "r", encoding="utf-8") as fh:
                    content = fh.read()
            except Exception:
                content = ""
            items.append({
                "path": rel,
                "label": pretty_label(rel),
                "depth": rel.count("/"),
                "words": len(content),
                "exists": True,
            })
    # 稳定的展示顺序：先 brief/story_bible，再按路径
    items.sort(key=lambda i: (i["depth"], i["path"]))
    return items


def save_world_file(book_dir_path, rel, content):
    full = safe_rel(book_dir_path, rel)
    if not full:
        return False, "invalid_path"
    try:
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        return True, None
    except Exception as e:
        return False, str(e)


def read_world_file(book_dir_path, rel):
    full = safe_rel(book_dir_path, rel)
    if not full or not os.path.isfile(full):
        return None
    try:
        with open(full, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


def world_stats(book_dir_path):
    items = scan_world(book_dir_path)
    words = sum(i["words"] for i in items)
    roles = [i for i in items if ("/roles/" in i["path"] or i["path"].startswith("roles/"))]
    last = 0
    for i in items:
        try:
            last = max(last, os.path.getmtime(safe_rel(book_dir_path, i["path"])))
        except Exception:
            pass
    return {
        "files": len(items),
        "words": words,
        "roles": len(roles),
        "lastModified": int(last * 1000) if last else 0,
    }


def world_entities(book_dir_path):
    items = scan_world(book_dir_path)
    roles = []
    for i in items:
        if "/roles/" in i["path"] or i["path"].startswith("roles/"):
            name = i["path"].split("/")[-1][:-3]
            roles.append({"name": name, "path": i["path"]})
    # 人物矩阵用「## 角色名」作标题、「- **字段名**:」作字段。
    # 因此人物提及取自 H2 标题（## / ###），而非加粗文本（那些是字段标签）。
    FIELD_LABELS = {
        "定位", "标签", "反差", "说话", "性格", "动机", "当前", "关系",
        "已知", "未知", "核心矛盾", "隐藏线索", "原创", "阶级", "背景",
        "外貌", "目标", "弱点", "秘密", "弧光", "简介", "身份", "能力",
    }
    mentions = set()
    for fn in ("story/character_matrix.md", "character_matrix.md"):
        f = safe_rel(book_dir_path, fn)
        if f and os.path.isfile(f):
            try:
                txt = open(f, "r", encoding="utf-8").read()
            except Exception:
                txt = ""
            for line in txt.splitlines():
                m = re.match(r"^#{2,4}\s+(.+?)\s*$", line)
                if not m:
                    continue
                nm = m.group(1).strip().strip("*").strip()
                # 去掉小节标题类（如“主要角色/次要角色/人物关系”）与字段标签
                if not nm or nm in FIELD_LABELS:
                    continue
                if any(k in nm for k in ("角色", "人物", "关系表", "矩阵", "说明", "目录")):
                    continue
                mentions.add(nm)
    return {"roles": roles, "mentions": sorted(mentions)[:60]}


def world_check(book_dir_path):
    """启发式一致性检查：核心文件缺失 / 角色未引用 / 人物矩阵提及无档案。"""
    issues = []
    must = ["brief.md", "story_bible.md", "character_matrix.md", "current_state.md"]
    for m in must:
        cands = [m, "story/" + m]
        if not any(os.path.isfile(safe_rel(book_dir_path, c)) for c in cands if safe_rel(book_dir_path, c)):
            issues.append({"level": "warn", "msg": "缺少核心世界文件：%s（建议补全世界观地基）" % m})

    ent = world_entities(book_dir_path)
    role_names = {r["name"] for r in ent["roles"]}
    # 汇总被引用的文本（brief + current_state + chapter_summaries + 全部正文章节）。
    # 纳入正文可大幅减少“角色未引用”的误报（角色多在章节中登场）。
    ref_text = ""
    for fn in ("story/brief.md", "brief.md", "story/current_state.md", "current_state.md",
               "story/chapter_summaries.md", "chapter_summaries.md"):
        f = safe_rel(book_dir_path, fn)
        if f and os.path.isfile(f):
            try:
                ref_text += open(f, "r", encoding="utf-8").read() + "\n"
            except Exception:
                pass
    ch_dir = os.path.join(book_dir_path, "chapters")
    if os.path.isdir(ch_dir):
        for cf in os.listdir(ch_dir):
            if cf.endswith((".md", ".txt")):
                try:
                    ref_text += open(os.path.join(ch_dir, cf), "r", encoding="utf-8").read() + "\n"
                except Exception:
                    pass

    def name_variants(rn):
        # 角色档常带修饰后缀（如“启明城平民·阿苔（耕霜者代表）”）；
        # 取核心名用于宽松匹配：分隔符 ·（(・ 前的主名。
        variants = {rn}
        core = re.split(r"[·（(・\s]", rn)[0].strip()
        if core:
            variants.add(core)
        return {v for v in variants if len(v) >= 2}

    for rn in sorted(role_names):
        if rn and not any(v in ref_text for v in name_variants(rn)):
            issues.append({"level": "info", "msg": "角色「%s」在正文/世界状态中未见引用（可能尚未登场或被遗漏）" % rn})
    # 人物矩阵标题人物无独立角色档案（宽松匹配：核心名互相包含即视为有档案）
    role_cores = set()
    for rn in role_names:
        role_cores |= name_variants(rn)
    for mn in ent["mentions"]:
        mn_cores = name_variants(mn)
        covered = any(
            (mc in rc or rc in mc)
            for mc in mn_cores for rc in role_cores
        )
        if not covered:
            issues.append({"level": "info", "msg": "人物矩阵包含「%s」，但 roles/ 下无独立角色档案（次要人物可忽略）" % mn})
    if not issues:
        issues.append({"level": "good", "msg": "未发现明显一致性问题 ✓"})
    return issues


def world_bundle(book_dir_path, title):
    items = scan_world(book_dir_path)
    # 优先顺序：brief, story_bible, 其余按路径
    prio = {"brief.md": 0, "story_bible.md": 1, "author_intent.md": 2, "book_rules.md": 3}
    items.sort(key=lambda i: (prio.get(i["path"].split("/")[-1], 9), i["path"]))
    parts = ["# %s · 世界设定全集\n" % title]
    for i in items:
        content = read_world_file(book_dir_path, i["path"]) or ""
        parts.append("\n\n## %s\n\n%s\n" % (i["label"], content))
    return "\n".join(parts)


def read_chapters(book_dir_path, with_content=True):
    """读章节列表。with_content=False 时不读正文（列表瘦身：
    13 章正文全量搬运一次要 80KB+，列表场景只需元数据）。"""
    idx_path = os.path.join(book_dir_path, "chapters", "index.json")
    try:
        idx = json.load(open(idx_path, "r", encoding="utf-8"))
    except Exception:
        idx = []
    ch_dir = os.path.join(book_dir_path, "chapters")
    try:
        files = os.listdir(ch_dir)
    except Exception:
        files = []
    out = []
    for c in idx:
        n = c.get("number")
        md = None
        try:
            prefix = "%04d" % int(n)
        except Exception:
            prefix = ""
        for fn in files:
            if fn.startswith(prefix) and fn.endswith(".md"):
                md = fn
                break
        content = ""
        if md and with_content:
            try:
                content = open(os.path.join(ch_dir, md), "r", encoding="utf-8").read()
            except Exception:
                content = ""
        item = {
            "number": n, "title": c.get("title", ""), "status": c.get("status"),
            "wordCount": c.get("wordCount"), "file": md,
            "auditIssues": c.get("auditIssues", []),
        }
        if with_content:
            item["content"] = content
        out.append(item)
    return out


# ----------------------------- 回收站（软删除 / 恢复 / 永久删除） -----------------------------
def load_trash():
    """读取回收站清单，返回 items 列表。"""
    try:
        with open(TRASH_MANIFEST, "r", encoding="utf-8") as f:
            d = json.load(f)
        items = d.get("items", [])
        if isinstance(items, list):
            return items
    except Exception:
        pass
    return []


def save_trash(items):
    try:
        os.makedirs(TRASH_ROOT, exist_ok=True)
        with open(TRASH_MANIFEST, "w", encoding="utf-8") as f:
            json.dump({"items": items}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _trash_chapter(bd, number):
    """把某章正文文件移到回收站，并从 index.json 移除该条目。返回 (item, error)。"""
    chs = read_chapters(bd, with_content=False)
    target = None
    for c in chs:
        if c.get("number") == number:
            target = c
            break
    if not target:
        return None, "not_found"
    if not target.get("file"):
        return None, "no_file"
    src = os.path.join(bd, "chapters", target["file"])
    if not os.path.isfile(src):
        return None, "file_missing"
    dest_dir = os.path.join(TRASH_ROOT, "chapters", os.path.basename(bd))
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, target["file"])
    if os.path.exists(dest):
        dest = dest + ".%d" % int(time.time())
    shutil.move(src, dest)
    # 从 index.json 移除该章
    idx_path = os.path.join(bd, "chapters", "index.json")
    try:
        idx = json.load(open(idx_path, "r", encoding="utf-8"))
    except Exception:
        idx = []
    idx = [e for e in idx if int(e.get("number") or -1) != number]
    try:
        with open(idx_path, "w", encoding="utf-8") as f:
            json.dump(idx, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    item = {
        "id": uuid.uuid4().hex[:12],
        "kind": "chapter",
        "bookId": os.path.basename(bd),
        "bookTitle": book_title(bd),
        "number": number,
        "chapterTitle": target.get("title", ""),
        "file": target["file"],
        "trashPath": os.path.relpath(dest, BOOK_ROOT).replace("\\", "/"),
        "indexEntry": target,
        "deletedAt": int(time.time() * 1000),
    }
    return item, None


def _trash_book(bd):
    """把整本书目录移到回收站。返回 (item, error)。"""
    title = book_title(bd)  # 移动前先读标题：移动后原路径失效，book_title(bd) 会返回「未命名」
    dest_dir = os.path.join(TRASH_ROOT, "books")
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, os.path.basename(bd))
    if os.path.exists(dest):
        dest = dest + "_%d" % int(time.time())
    shutil.move(bd, dest)
    item = {
        "id": uuid.uuid4().hex[:12],
        "kind": "book",
        "bookId": os.path.basename(bd),
        "bookTitle": title,
        "trashPath": os.path.relpath(dest, BOOK_ROOT).replace("\\", "/"),
        "deletedAt": int(time.time() * 1000),
    }
    return item, None


def _restore_trash(tid):
    """恢复回收站条目（回滚）。返回 (ok, error)。"""
    items = load_trash()
    it = next((x for x in items if x.get("id") == tid), None)
    if not it:
        return False, "not_found"
    trash_full = os.path.join(BOOK_ROOT, it["trashPath"])
    if it["kind"] == "book":
        dest = os.path.join(BOOK_ROOT, "books", it["bookId"])
        if os.path.exists(dest):
            return False, "book_exists"
        shutil.move(trash_full, dest)
    else:  # chapter
        bd = book_dir(it["bookId"])
        if not bd:
            return False, "book_missing"
        idx_path = os.path.join(bd, "chapters", "index.json")
        try:
            idx = json.load(open(idx_path, "r", encoding="utf-8"))
        except Exception:
            idx = []
        if any(int(e.get("number") or -1) == it.get("number") for e in idx):
            return False, "chapter_exists"  # 该章号已存在（可能已重新生成），避免覆盖冲突
        dest = os.path.join(bd, "chapters", it["file"])
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.move(trash_full, dest)
        idx.append(it.get("indexEntry", {"number": it["number"], "file": it["file"]}))
        idx.sort(key=lambda e: int(e.get("number") or 0))
        try:
            with open(idx_path, "w", encoding="utf-8") as f:
                json.dump(idx, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    save_trash([x for x in items if x.get("id") != tid])
    return True, None


def _purge_trash(tid):
    """永久删除回收站条目（不可恢复）。返回 (ok, error)。"""
    items = load_trash()
    it = next((x for x in items if x.get("id") == tid), None)
    if not it:
        return False, "not_found"
    trash_full = os.path.join(BOOK_ROOT, it["trashPath"])
    if it["kind"] == "book":
        if os.path.isdir(trash_full):
            shutil.rmtree(trash_full)
        elif os.path.exists(trash_full):
            os.remove(trash_full)
    else:
        if os.path.exists(trash_full):
            os.remove(trash_full)
        parent = os.path.dirname(trash_full)
        try:
            if os.path.isdir(parent) and not os.listdir(parent):
                os.rmdir(parent)
        except Exception:
            pass
    save_trash([x for x in items if x.get("id") != tid])
    return True, None


# ----------------------------- 剧情模拟工作流 -----------------------------
# 流程：LLM 推演下一章剧情（不写正文，便宜快速）→ 用户审阅/删改 → 确认采用
# → 模拟稿经 write next --context-file 强约束注入正文创作。
def sims_dir(book_dir_path):
    d = os.path.join(book_dir_path, "simulations")
    os.makedirs(d, exist_ok=True)
    return d


def list_sims(book_dir_path):
    d = sims_dir(book_dir_path)
    out = []
    for fn in os.listdir(d):
        if not (fn.startswith("sim_") and fn.endswith(".json")):
            continue
        try:
            s = json.load(open(os.path.join(d, fn), "r", encoding="utf-8"))
            out.append(s)
        except Exception:
            pass
    out.sort(key=lambda s: s.get("createdAt", 0), reverse=True)
    return out


def sim_path(book_dir_path, sid):
    if not re.fullmatch(r"[0-9a-f]{12}", sid or ""):
        return None
    return os.path.join(sims_dir(book_dir_path), "sim_%s.json" % sid)


def load_sim(book_dir_path, sid):
    p = sim_path(book_dir_path, sid)
    if not p or not os.path.isfile(p):
        return None
    try:
        return json.load(open(p, "r", encoding="utf-8"))
    except Exception:
        return None


def save_sim(book_dir_path, sim):
    p = sim_path(book_dir_path, sim.get("id", ""))
    if not p:
        return False
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(sim, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def delete_sim(book_dir_path, sid):
    p = sim_path(book_dir_path, sid)
    if not p or not os.path.isfile(p):
        return False
    try:
        os.remove(p)
        return True
    except Exception:
        return False


def build_sim_context(book_dir_path):
    """汇集世界设定+最新进展，供剧情推演。返回 (context_text, next_chapter_num, last_title)。"""
    parts = []

    def add(rel, label, limit, tail=False):
        t = read_world_file(book_dir_path, "story/" + rel) or read_world_file(book_dir_path, rel)
        if t:
            t = t.strip()
            t = t[-limit:] if tail else t[:limit]
            parts.append("### %s\n%s" % (label, t))

    wr_ctx = world_rules_text(book_dir_path, 3500)
    if wr_ctx:
        parts.append("### 世界底层逻辑（物质构成 · 底层物理规则 · 最高约束：一切设定与剧情不得与之冲突）\n" + wr_ctx)
    add("story_bible.md", "世界圣经（权威设定）", 6000)
    add("book_rules.md", "创作书规", 2500)
    add("character_matrix.md", "人物矩阵", 3000)
    add("current_state.md", "当前世界状态", 3000)
    add("pending_hooks.md", "待解伏笔钩子", 2000)
    add("chapter_summaries.md", "已发生章节摘要（近期优先）", 4000, tail=True)
    chs = read_chapters(book_dir_path, with_content=False)
    next_num, last_title = 1, ""
    if chs:
        last = chs[-1]
        next_num = int(last.get("number") or len(chs)) + 1
        last_title = last.get("title") or ""
        tail = ""
        if last.get("file"):
            try:
                tail = open(os.path.join(book_dir_path, "chapters", last["file"]),
                            "r", encoding="utf-8").read()[-2000:]
            except Exception:
                tail = ""
        parts.append("### 上一章（第%s章《%s》）结尾原文\n%s" % (last.get("number"), last_title, tail))
    return "\n\n".join(parts), next_num, last_title


SIM_SYSTEM_PROMPT = (
    "你是一台严谨的小说世界模拟引擎。你的任务是基于给定的世界设定与故事进展，"
    "推演出下一章的完整剧情走向——只做剧情推演，绝不写正文。\n"
    "输出必须是结构化 Markdown，格式如下：\n"
    "# 第{N}章剧情模拟：{拟定章节标题}\n"
    "## 一句话概要\n（一句话说清本章发生什么）\n"
    "## 场景推演\n### 场景1：{场景名}\n- 地点：\n- 出场人物：\n- 发生什么：（具体到行动与对话意图）\n- 冲突/转折：\n- 结果与代价：\n"
    "（按需 2-5 个场景，逐场推演）\n"
    "## 人物动态\n（本章各人物的心理变化、关系变化）\n"
    "## 伏笔处理\n（回收了哪些旧钩子、埋下哪些新钩子）\n"
    "## 章末悬念\n（结尾停在哪个钩子上）\n"
    "要求：1) 严格遵守世界设定与已发生剧情，不得矛盾；2) 情节具体可执行，"
    "拒绝空泛；3) 有真实的冲突与代价；4) 保持类型风格一致。"
)


SIM_SYSTEM_PROMPT_AUTO = (
    "你是一台自主运行的小说世界推演引擎，此刻作者并未参与。你的任务：完全依据给定的"
    "世界设定与已有故事进展，自行推演出第{N}章「可能的未来」——只做剧情推演，绝不写正文。\n"
    "注意：\n"
    "- 不要等待、也不要臆测任何作者指令；一切推演只来自设定与历史。\n"
    "- 世界充满不确定性：先并列给出 2-3 条「可能的走向」（每条一句话），再从中选定你最看好的主线深入推演，并标注为何它最合理。\n"
    "输出必须是结构化 Markdown，格式如下：\n"
    "# 第{N}章剧情模拟：{拟定章节标题}\n"
    "## 可能的走向（系统自主推测）\n- 走向A：\n- 走向B：\n- 走向C：\n"
    "## 选定主线与理由\n（采用哪条、为什么）\n"
    "## 一句话概要\n（一句话说清本章发生什么）\n"
    "## 场景推演\n### 场景1：{场景名}\n- 地点：\n- 出场人物：\n- 发生什么：（具体到行动与对话意图）\n- 冲突/转折：\n- 结果与代价：\n"
    "（按需 2-5 个场景，逐场推演）\n"
    "## 人物动态\n（本章各人物的心理变化、关系变化）\n"
    "## 伏笔处理\n（回收了哪些旧钩子、埋下哪些新钩子）\n"
    "## 章末悬念\n（结尾停在哪个钩子上）\n"
    "要求：1) 严格遵守世界设定与已发生剧情，不得矛盾；2) 情节具体可执行，拒绝空泛；"
    "3) 有真实的冲突与代价；4) 保持类型风格一致；5) 这是「可能的未来」之一，作者保留否决与改写权。"
)


FIRST_CHAPTER_SYSTEM_PROMPT = (
    "你是一位资深网文开篇策划。作者刚建好一本书的世界观地基，即将动笔写【第一章】。"
    "第一章决定读者是否追读，必须由你推演出一份「首章作战方案」——只做剧情方案推演，绝不写正文。\n"
    "基于给定的世界设定（此时尚无任何已发生章节，这是开篇），推演第 1 章的完整作战方案，输出必须是结构化 Markdown：\n"
    "# 第 1 章作战方案：{拟定章节标题}\n"
    "## 开篇钩子（前 300 字怎么抓人）\n（用 1-2 句话点明：本章开头用什么强冲突 / 反转 / 悬念瞬间勾住读者，主角以什么状态登场）\n"
    "## 核心目标与冲突\n（本章主角要达成什么、最大的阻碍是什么、stakes 有多高）\n"
    "## 人物亮相\n（主角与关键配角在本章如何登场、第一印象如何立住、关系如何埋线）\n"
    "## 场景序列\n### 场景1：{场景名}\n- 地点：\n- 出场人物：\n- 发生什么：（具体到行动与对话意图）\n- 冲突/转折：\n- 结果与代价：\n"
    "（2-5 个场景，从开场钩子一路推进到章末悬念）\n"
    "## 世界观切入点\n（如何自然地把读者带入这个世界——通过主角的眼睛 / 一个具体事件，而非长篇设定说明）\n"
    "## 节奏与爽点分布\n（本章情绪曲线：哪里紧、哪里松、爽点 / 高光落在哪、预计字数区间）\n"
    "## 章末悬念\n（结尾停在哪个钩子上，逼读者翻下一章）\n"
    "## 与类型 / 平台的契合\n（针对该书的类型与发布平台，本章应突出的卖点节奏）\n"
    "要求：1) 严格遵守世界设定，不得矛盾；2) 方案具体可执行，拒绝空泛；3) 开篇必须强、主角必须有记忆点；"
    "4) 保持类型风格一致；5) 这是「首章方案」之一，作者保留否决与改写权。"
)


# ----------------------------- 创作前访谈（建书前意图澄清） -----------------------------
INTERVIEWER_SYSTEM = """你是一位资深网文策划编辑，正在帮作者做「创作前访谈」。目标：在正式开写一本书之前，通过自然、有条理的对话，充分了解作者的创作意图，避免一上来就跑偏。

规则：
1. 每次只问【一个问题】，针对当前最缺失的维度，不要一次抛出多个问题。
2. 依次覆盖这些关键维度（已了解的可跳过）：题材/类型与平台；世界观与背景基调；主角与核心人物关系；核心冲突 / 金手指 / 爽点；叙事风格与基调（虐/爽/轻松/严肃）；目标读者；篇幅与节奏预期；作者最想表达或最在乎的东西。
3. 语气像真人编辑：热情、专业、偶尔给一点小建议，但绝不啰嗦，不堆砌术语。
4. 如果用户表达含糊，先用自己的话复述理解、确认对齐，再追问。
5. 当你认为已经足够理解作者意图（主要维度已覆盖、能据此生成有灵魂的「世界观地基」）时，在回答末尾用一句话明确告诉作者「我们可以开始创作了」，并简要复述你理解的核心意图（2-3 句）。
6. 如果用户主动说「开始」「直接写」「够了」「跳过」之类，尊重其意愿，不再追问，直接表示可以开始。
7. 如果是第一次对话（用户尚未发言），先做一句简短自我介绍，然后抛出第一个、也是最开放的问题（例如：你想写一本什么样的书？先随便聊聊你的想法。）。

只输出你作为编辑应该说的话，不要加任何角色前缀或格式标记。"""


INTERVIEW_SUMMARY_SYSTEM = """你是一位网文策划。下面是一段「作者创作前访谈」的对话记录。请基于对话，提炼出可供 AI 生成世界观地基（世界圣经 / 人物矩阵 / 书规）的【结构化创作意图】。

请 ONLY 输出一个 JSON 对象（不要 markdown 代码块、不要任何多余文字），字段如下：
{
  "title": "建议书名（若对话中未明确，请据意图拟一个贴切的，4-8 字为佳）",
  "genre": "从以下枚举选一：urban/fantasy/xianxia/scifi/romance/history/mystery/game/other",
  "platform": "从以下枚举选一：tomato/qidian/feilu/other",
  "lang": "zh 或 en",
  "brief": "300-600 字的中文创作意图综述：含题材定位、世界观基调、主角与核心冲突 / 金手指、风格与爽点、目标读者与篇幅预期。语言凝练、有烟火气，能直接作为世界观地基的生成蓝本。"
}
确保 genre / platform / lang 严格落在上述枚举内；若无法确定，分别用 other / tomato / zh。"""


# ---- 角色档案工作台（UI 重构 R2）----
ROLE_TIER_CN = {"lead": "主角", "major": "主要角色", "minor": "次要角色", "extra": "路人/提及"}
ROLE_TIER_DIR = {"lead": "主要角色", "major": "主要角色", "minor": "次要角色", "extra": "次要角色"}
ROLE_SECTIONS = {
    "main": ["核心标签", "反差细节", "人物小传（过往经历）", "当前现状", "关系网络", "内在驱动", "成长弧光"],
    "sub": ["核心标签", "反差细节", "当前现状", "与主角关系"],
}
ROLE_KNOWN_RELS = ["story/brief.md", "story/book_rules.md", "story/character_matrix.md",
                   "story/story_bible.md", "story/world_rules.md", "story/brief.md"]


def role_sections_for(tier):
    return ROLE_SECTIONS["sub"] if tier in ("minor", "extra") else ROLE_SECTIONS["main"]


def role_dir_for(tier):
    return ROLE_TIER_DIR.get(tier, "主要角色")


def role_file_name(name):
    """清洗文件名（Windows 非法字符 / 路径分隔），防目录穿越。"""
    nm = re.sub(r'[\\/:*?"<>|]', "", name or "").strip()
    return nm or "未命名角色"


def role_known_ctx(bd, cap=6000):
    """汇总现有世界观已知信息，供角色访谈/精炼对齐，避免凭空发明。"""
    chunks, seen = [], set()
    for rel in ROLE_KNOWN_RELS:
        full = safe_rel(bd, rel)
        if not full or not os.path.isfile(full):
            continue
        if full in seen:
            continue
        seen.add(full)
        try:
            t = open(full, "r", encoding="utf-8").read()[:1800]
        except Exception:
            continue
        # 世界底层逻辑仅注入定稿内容；草稿模板不外泄给角色对齐上下文
        if rel.replace("\\", "/").rsplit("/", 1)[-1] == "world_rules.md" and \
                t.lstrip().startswith(WORLD_RULES_DRAFT_MARK):
            continue
        if t.strip():
            chunks.append("【%s】\n%s" % (rel.rsplit("/", 1)[-1], t))
    s = "\n\n".join(chunks)
    return s[:cap]


def _tiers_path(bd):
    return safe_rel(bd, "story/roles/.tiers.json")


def read_role_tiers(bd):
    """读取侧车 tiers.json（角色名 -> 重要程度），容错为空。"""
    p = _tiers_path(bd)
    if not p or not os.path.isfile(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def write_role_tier(bd, name, tier):
    d = read_role_tiers(bd)
    d[name] = tier
    p = _tiers_path(bd)
    if not p:
        return
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


ROLE_INTERVIEWER_SYSTEM = """你是一位专帮网文作者做人设的访谈编辑。你在为《{book}》撰写角色「{role}」的档案（重要程度：{tier_cn}；模板：{template_n} 节，分节：{sections}）。

目标：通过一问一答，把作者对这个角色的想象完整还原，尤其挖掘能区分于套路模板的细节。

规则：
1. 每次只问一个问题，按模板分节推进，不要一次抛多个问题。
2. 涉及书中已发生剧情时以「已知信息」为准，绝不编造；作者未定的地方可给 2-3 个方向让作者拍板。
3. 先问「当前处境 / 第一印象」相关的开放问题，再逐步覆盖反差、过往、动机、关系、弧光等维度。
4. 语气像真人编辑：热情、具体、不堆术语。作者答得含糊时先复述对齐再继续。
5. 当主要维度已覆盖到能成稿时，在回答末尾明确说「可以开始精炼了」。
6. 首轮（作者尚未说话）：做半句自我介绍，然后抛出第一个最开放的问题（例如：这个角色第一次出场时，你希望读者记住 TA 的哪个画面？）。

只输出你作为访谈者该说的话，不要加角色前缀或格式标记。"""


ROLE_REFINE_SYSTEM = """你是一名网文人设档案整理者。下面是为《{book}》的角色「{role}」（重要程度：{tier_cn}）准备的访谈记录与已知信息。请整理成一份结构完整的角色档案 Markdown。

输出要求：只输出如下章节标题及内容，不要任何开头语、结尾语或代码块围栏：
{sections_heads}

写作约束：
1. 忠于访谈记录与已知信息，不得发明书中未出现的事实；某章节信息不足时，在该节写「（待作者补充：具体缺什么）」而不是硬编。
2. 叙述体，凝练、有张力；「关系网络 / 与主角关系」等含多人/多条目的节用「- 」列表。
3. 核心标签一行点出（3-6 个）；反差细节给可被情节印证的场景级细节；过往/现状按时间线叙述。
4. 语言像网文创作档案：锋利、具体、有记忆点。
若完全没有任何访谈轮次，仅依据已知信息生成精简草稿，并明确标出需要作者确认的推测。"""


def build_role_refine_system(book, role, tier, ctx):
    secs = role_sections_for(tier)
    heads = "\n".join("## %s" % s for s in secs)
    sysp = ROLE_REFINE_SYSTEM.format(
        book=book, role=role, tier_cn=ROLE_TIER_CN.get(tier, tier),
        sections_heads=heads)
    if ctx.strip():
        sysp += "\n\n【已知信息（用于对齐）】\n%s" % ctx
    return sysp, secs


def extract_first_json(text):
    """从模型输出中抠出第一个 JSON 对象（兼容 ```json 围栏与前后闲聊）。失败返回 None。"""
    if not text:
        return None
    s = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", s, re.S)
    if m:
        s = m.group(1)
    else:
        i = s.find("{"); j = s.rfind("}")
        if i >= 0 and j > i:
            s = s[i:j + 1]
    try:
        return json.loads(s)
    except Exception:
        return None


def _simulate_core(book_dir_path, mode, guidance, chapter=None, on_delta=None):
    """剧情推演核心：汇集上下文->调用上游->产出模拟稿 dict。
    mode='auto'（系统自主，不参考作者指令）；mode='guided'（作者引导）。
    返回 (sim_dict, error_str)。on_delta 可选，用于流式回传增量。"""
    try:
        ctx, next_num, last_title = build_sim_context(book_dir_path)
    except Exception as e:
        return None, "上下文汇集失败: %s" % e
    if isinstance(chapter, int) and chapter > 0:
        next_num = chapter
    if mode == "auto":
        sys_prompt = SIM_SYSTEM_PROMPT_AUTO.replace("{N}", str(next_num))
    else:
        sys_prompt = SIM_SYSTEM_PROMPT.replace("{N}", str(next_num))
    user_prompt = ("以下是本书的世界设定与故事进展：\n\n%s\n\n---\n请推演第%d章的剧情走向。"
                   % (ctx, next_num))
    if mode == "auto":
        user_prompt += "\n\n（本次为系统自主推演：不参考任何作者指令，完全依据上述设定与历史自行推演可能的未来。）"
    elif guidance:
        user_prompt += "\n\n【作者导向要求（必须优先满足）】\n%s" % guidance
    try:
        text = llm_stream(
            [{"role": "system", "content": sys_prompt},
             {"role": "user", "content": user_prompt}],
            on_delta or (lambda d: None),
        )
    except Exception as e:
        return None, "推演失败: %s" % e
    title = ""
    m = re.search(r"^#\s*第?\d*章?剧情模拟[:：]\s*(.+)$", text, re.M)
    if m:
        title = m.group(1).strip()
    sim = {
        "id": uuid.uuid4().hex[:12],
        "book": os.path.basename(book_dir_path),
        "chapter": next_num,
        "title": title or ("第%d章剧情模拟" % next_num),
        "guidance": guidance if mode != "auto" else "",
        "source": "auto" if mode == "auto" else "guided",  # auto=自己推演 / guided=上帝介入
        "godTouched": False,   # 作者是否对本稿做过审阅/删改/采用（上帝介入）
        "content": text,
        "status": "draft",     # draft -> used
        "createdAt": int(time.time() * 1000),
        "updatedAt": int(time.time() * 1000),
    }
    return sim, None


def _first_chapter_core(book_dir_path, on_delta=None):
    """首章推演核心：基于世界观地基推演第 1 章作战方案，产出一份模拟稿（source='first'）。
    与 _simulate_core 的区别：固定第 1 章、使用首章专用提示词、不参考任何已发生历史。"""
    try:
        ctx, next_num, last_title = build_sim_context(book_dir_path)
    except Exception as e:
        return None, "上下文汇集失败: %s" % e
    # 首章时 book 尚无可发生章节：next_num 应为 1，last_title 为空，符合开篇预期。
    user_prompt = (
        "以下是本书的世界设定与创作意图：\n\n%s\n\n---\n"
        "请推演【第 1 章】的作战方案（本书尚无任何已发生章节，这是开篇，请据此设计立人设、抛钩子、定基调的起步）。"
        % ctx
    )
    try:
        text = llm_stream(
            [{"role": "system", "content": FIRST_CHAPTER_SYSTEM_PROMPT},
             {"role": "user", "content": user_prompt}],
            on_delta or (lambda d: None),
        )
    except Exception as e:
        return None, "首章推演失败: %s" % e
    title = ""
    m = re.search(r"^#\s*第?\d*章[作战方案剧情模拟][:：]\s*(.+)$", text, re.M)
    if m:
        title = m.group(1).strip()
    sim = {
        "id": uuid.uuid4().hex[:12],
        "book": os.path.basename(book_dir_path),
        "chapter": 1,
        "title": title or "第1章作战方案",
        "guidance": "",
        "source": "first",   # 首章推演专用来源（区别于 auto / guided）
        "godTouched": False,
        "content": text,
        "status": "draft",
        "createdAt": int(time.time() * 1000),
        "updatedAt": int(time.time() * 1000),
    }
    return sim, None


# ============================================================================
# 推演机制引擎化（drama 模式）—— 多角色隔离推演 + 既成事实锁
# 借鉴 NEST-DRAMA 视野律/信封/既成事实思路自研：角色只见「公共实录裁切 + 本人角色卡 +
# 既成事实段」，各自独立推演再合流。原 auto/guided/first 路径完全不动。
# ============================================================================

DRAMA_DIRECTOR_SYSTEM = (
    "你是一台小说世界的导演调度系统。根据给定的世界设定与故事进展，先做全局调度，"
    "绝不直接编正文。\n"
    "输出严格 JSON（不要代码块、不要多余文字）：\n"
    "{\n"
    "  \"title\": \"第{N}章拟定标题\",\n"
    "  \"summary\": \"一句话说清本章发生什么\",\n"
    "  \"scenes\": [\n"
    "    {\"id\": 1, \"name\": \"场景名\", \"place\": \"地点\", \"cast\": [\"出场角色名\"], "
    "\"goal\": \"这场戏要达成什么\", \"tension\": \"内在冲突/张力来源\", \"turn\": \"关键转折\"}\n"
    "  ]\n"
    "}\n"
    "要求：1) scenes 只取本章必需场景，2-3 个为佳，每个场景出场角色从给定角色中选、不超过 3 人；"
    "2) 严格依据世界设定与已发生剧情，不得矛盾；3) 每一场都要有真实冲突与代价；4) cast 只能使用"
    "给定角色清单里的名字；5) 角色心防、真实动机不在公共层讨论，交给各自角色独立推演。"
)


DRAMA_ROLE_SYSTEM = (
    "你是小说《{book}》中的角色【{role}】。现在你身处的世界正在推进到第 {N} 章，"
    "导演已把「公共事实」交到你手上。请你**只以这个角色身份**推演：这一章你会做什么、说什么、"
    "心里盘算什么。\n"
    "铁律：\n"
    "1. **视野律**：你只能使用下面给你的公共事实 + 你自己的角色卡。他人心理、你没看到的场景、"
    "你不知道的信息，一律不得当作你知道。\n"
    "2. **既成事实不可改写**：下面「既成事实」段里的一切（你的身份、你说过的话、已经发生的事件、"
    "数目账）都已发生，你只能在它们之上行动，绝不能推翻或改写。\n"
    "3. 你的行动必须忠于你的角色卡：内核、声纹、弧线、关系网络。若角色卡写明了你的签名小动作，"
    "那可以用；除此之外避免任何口号式套话。\n"
    "输出严格 JSON（不要代码块、不要多余文字）：\n"
    "{\n"
    "  \"intent\": \"一句话：我这一章最想要什么，愿意付什么代价\",\n"
    "  \"moves\": [\n"
    "    {\"scene\": 场景id, \"action\": \"我做什么（具体动作）\", \"speech\": \"我说出口的话（原话，口语化，若沉默则不写）\"}\n"
    "  ],\n"
    "  \"inner\": \"只有我自己知道的盘算与情绪（绝不写进公共叙事）\"\n"
    "}"
)


DRAMA_MERGE_SYSTEM = (
    "你是一台小说世界的主笔。下面是导演的调度框架，以及本章每一位出场角色以自己身份独立推演"
    "出的行动与台词。请把它们**合流成一份真实的章节剧情推演稿**（仍是推演方案，不是正文成品），"
    "输出为与既有推演一致的 Markdown：\n"
    "# 第{N}章剧情模拟：{标题}\n"
    "## 一句话概要\n"
    "## 场景推演\n### 场景1：{场景名}\n- 地点：\n- 出场人物：\n- 发生什么：（融合角色行动与台词，"
    "谁做了什么、谁说了什么、彼此如何碰撞）\n- 冲突/转折：\n- 结果与代价：\n"
    "（逐场景）\n"
    "## 人物动态\n（本章各角色的心理与关系变化，基于他们的 inner 提炼可呈现的部分）\n"
    "## 伏笔处理\n## 章末悬念\n"
    "铁律：1) 角色只做各自推演里的事、说各自推演里的话，主笔不得替角色发明他没想过的心思；"
    "2) 不得改写任何既成事实；3) 若两名角色行动冲突，保留冲突本身（真实戏剧来自碰撞），"
    "不要强行和稀泥；4) 推演必须具体可执行，拒绝空泛。"
)


def _read_story(book_dir_path, rel, limit=None, tail=False):
    """读 book/story/<rel>（兼容 book/<rel>），支持截断。不存在返回 ''。"""
    t = read_world_file(book_dir_path, "story/" + rel) or read_world_file(book_dir_path, rel)
    if not t:
        return ""
    t = t.strip()
    if limit:
        t = t[-limit:] if tail else t[:limit]
    return t


def world_rules_text(book_dir_path, limit=3500):
    """定稿后的世界底层逻辑正文；草稿模板（含 <!-- wl:draft -->）返回 ''，不污染任何上下文。"""
    t = _read_story(book_dir_path, "world_rules.md")
    if not t:
        return ""
    if t.lstrip().startswith(WORLD_RULES_DRAFT_MARK):
        return ""
    return t[:limit]


def _role_cards_text(book_dir_path, names, per_card=1800):
    """从 roles/ 下按名取角色卡全文（截断）。找不到时回退人物矩阵提及。返回 {名: 卡文本}。"""
    cards = {}
    ent = world_entities(book_dir_path)
    for r in ent["roles"]:
        if names and r["name"] not in names:
            continue
        p = os.path.join(book_dir_path, r["path"])
        try:
            t = open(p, "r", encoding="utf-8").read().strip()
        except Exception:
            t = ""
        if t:
            cards[r["name"]] = t[:per_card]
    return cards


def build_drama_pack(book_dir_path, guidance, chapter=None, cast=None, scenes_max=3):
    """汇集 drama 模式的公共事实包（=导演层可见全量 + 角色信封素材 + 数目账注入）。
    返回 (pack_text, ledger_rows, next_num, last_title)。pack_text 不含角色卡。"""
    parts = []
    add = lambda label, t: parts.append("### %s\n%s" % (label, t)) if t else None
    # 世界底层逻辑置于公共事实包最前（最高约束：任何角色/导演都不许违反物质构成与物理规则）
    wr = world_rules_text(book_dir_path, 3500)
    if wr:
        parts.append("### 世界底层逻辑（物质构成 · 底层物理规则 · 最高约束：一切设定与剧情不得与之冲突）\n" + wr)
    add("世界圣经（权威设定）", _read_story(book_dir_path, "story_bible.md", 4500))
    add("创作书规", _read_story(book_dir_path, "book_rules.md", 2000))
    add("人物矩阵（关系总览）", _read_story(book_dir_path, "character_matrix.md", 2200))
    add("当前世界状态", _read_story(book_dir_path, "current_state.md", 2600))
    add("待解伏笔钩子", _read_story(book_dir_path, "pending_hooks.md", 1500))
    add("已发生章节摘要（近期优先）", _read_story(book_dir_path, "chapter_summaries.md", 3200, tail=True))
    chs = read_chapters(book_dir_path, with_content=False)
    next_num, last_title = 1, ""
    if chs:
        last = chs[-1]
        next_num = int(last.get("number") or len(chs)) + 1
        last_title = last.get("title") or ""
        tail = ""
        if last.get("file"):
            try:
                tail = open(os.path.join(book_dir_path, "chapters", last["file"]),
                            "r", encoding="utf-8").read()[-1600:]
            except Exception:
                tail = ""
        add("上一章（第%s章《%s》）结尾原文（公共实录裁切：只取可见言行）" % (last.get("number"), last_title), tail)
    if isinstance(chapter, int) and chapter > 0:
        next_num = chapter
    # 数目账注入（既成事实的一部分）
    ledger_rows = []
    lt = _read_story(book_dir_path, "particle_ledger.md")
    if lt:
        ledger_rows = _ledger_parse(lt)
        hint = _ledger_hint(ledger_rows, 14)
        if hint:
            parts.append("### 数目账（既成事实 · 不可改数字）\n" + hint)
    if guidance:
        parts.append("### 作者导向要求（必须满足）\n" + guidance)
    return "\n\n".join(parts), ledger_rows, next_num, last_title


def _drama_core(book_dir_path, guidance, chapter=None, on_delta=None,
                cast=None, scenes_max=3):
    """多角色隔离推演（source='drama'）：导演调度 → 逐角色独立推演 → 主笔合流。
    返回 (sim_dict, error_str)。on_delta 可选，透传 LLM 增量并额外 emit 阶段事件。
    """
    def stage(name, msg):
        try:
            on_delta({"stage": "drama", "phase": name, "msg": msg})
        except Exception:
            pass

    book = os.path.basename(book_dir_path)
    try:
        pack, ledger_rows, next_num, last_title = build_drama_pack(
            book_dir_path, guidance, chapter, cast, scenes_max)
    except Exception as e:
        return None, "drama 上下文汇集失败: %s" % e
    if not pack.strip():
        return None, "drama 上下文为空：请先为这本书建设世界观文件（brief/story_bible 等）"
    # 可能出场的角色：默认主要角色优先 + 次要角色补充，可被 cast 覆盖
    ent = world_entities(book_dir_path)
    role_names = [r["name"] for r in ent["roles"]]
    if not role_names:
        return None, "drama 模式需要角色卡：请在 world 的 roles/ 下为至少一个角色建档"
    pick = [n for n in role_names if n in (cast or [])] or role_names[:6]

    try:
        # ── 阶段1 导演调度：全局框架（只见公共事实，无角色心理）────────────
        stage("direct", "导演调度中…")
        sys_p = DRAMA_DIRECTOR_SYSTEM.replace("{N}", str(next_num))
        out = llm_stream(
            [{"role": "system", "content": sys_p},
             {"role": "user", "content":
              "以下是本书世界设定与进展：\n\n%s\n\n---\n请调度第%d章的剧情框架（2-3 个场景，"
              "每场 cast ≤3 人，只能从角色清单里选：%s）。"
              % (pack, next_num, "、".join(pick))}],
            lambda d: on_delta(d) if on_delta else None,
        )
        dirj = extract_first_json(out)
        if not dirj or not dirj.get("scenes"):
            # JSON 解析失败 → 退化为单场景、默认前三角色
            dirj = {"title": "第%d章剧情模拟" % next_num, "summary": "",
                    "scenes": [{"id": 1, "name": "主场景", "place": "",
                                "cast": pick[:3], "goal": "", "tension": "", "turn": ""}]}
        scenes = (dirj.get("scenes") or [])[:scenes_max]
        cast_set = []
        for sc in scenes:
            for c in (sc.get("cast") or [])[:3]:
                if c not in cast_set:
                    cast_set.append(c)
        if not cast_set:
            cast_set = pick[:2]
        cards = _role_cards_text(book_dir_path, set(cast_set) & set(role_names))

        # ── 阶段2 逐角色隔离推演（各自只见公共事实+自己角色卡+既成事实）───────
        scene_brief = "\n".join(
            "场景%d【%s】@%s | cast:%s\n  目标：%s\n  张力：%s\n  转折：%s"
            % (sc.get("id"), sc.get("name"), sc.get("place"), "、".join(sc.get("cast") or []),
               sc.get("goal"), sc.get("tension"), sc.get("turn")) for sc in scenes)
        role_inputs = {}
        for rn in cast_set:
            card = cards.get(rn)
            if not card:
                continue
            stage("role", "%s 独立推演中…" % rn)
            sys_p = DRAMA_ROLE_SYSTEM.replace("{book}", book).replace("{role}", rn).replace("{N}", str(next_num))
            msg = [{"role": "system", "content": sys_p},
                   {"role": "user", "content":
                    "【公共事实（世界设定+已发生剧情+作者导向）】\n%s\n\n"
                    "【本场戏调度】\n%s\n\n"
                    "【你的角色卡】\n%s\n\n"
                    "你现在以 %s 的身份行动。只输出你的 JSON 推演。"
                    % (pack, scene_brief, card, rn)}]
            try:
                txt = llm_stream(msg, lambda d: on_delta(d) if on_delta else None)
                role_inputs[rn] = txt
            except Exception as e:
                role_inputs[rn] = ""  # 单角色失败不拖垮全局（下游见缺省会自行推断）
        if not role_inputs:
            return None, "drama 阶段2失败：所有角色推演都未产出"

        # ── 阶段3 主笔合流成 Markdown 推演稿 ──────────────────────
        stage("merge", "主笔合流中…")
        cast_block = "\n\n".join("### %s（角色自推演原文）\n%s" % (k, v) for k, v in role_inputs.items())
        sys_p = DRAMA_MERGE_SYSTEM.replace("{N}", str(next_num)).replace("{标题}", dirj.get("title") or "（未定）")
        user_p = ("【导演调度】\n%s\n\n【公共事实摘要】\n%s\n\n【各角色独立推演原文】\n%s\n\n"
                  "请合流为第 %d 章剧情模拟推演稿（Markdown）。"
                  % (scene_brief, pack[:3000], cast_block, next_num))
        text = llm_stream(
            [{"role": "system", "content": sys_p}, {"role": "user", "content": user_p}],
            lambda d: on_delta(d) if on_delta else None,
        )
    except Exception as e:
        return None, "drama 推演失败: %s" % e
    title = ""
    m = re.search(r"^#\s*第?\d*章剧情模拟[:：]\s*(.+)$", text, re.M)
    if m:
        title = m.group(1).strip()
    sim = {
        "id": uuid.uuid4().hex[:12],
        "book": book,
        "chapter": next_num,
        "title": title or (dirj.get("title") or "第%d章剧情模拟" % next_num),
        "guidance": guidance or "",
        "source": "drama",           # 多角色隔离推演（导演→角色→合流）
        "godTouched": False,
        "content": text,
        "status": "draft",
        "createdAt": int(time.time() * 1000),
        "updatedAt": int(time.time() * 1000),
    }
    return sim, None


# ============================================================================
# 执法器 / 数目账 后处理：对任意 sim 文本产出 police 报告，可选机修与 LLM 定点
# ============================================================================

def _police_sim(sim, level="local", on_delta=None):
    """对 sim['content'] 做反 AI 腔处理，报告写回 sim['police']。
    level: report=只报不改 / local=机修（信息量不减）写入 content / full=机修+LLM 定点补丁。
    返回 sim（原地修改）。"""
    text = sim.get("content") or ""
    hits = _audit_scan(text)
    n_all = len(hits)
    repaired, residue, log = _audit_repair(text)
    kill, n_enforce, dens = _audit_verdict(repaired if level in ("local", "full") else text)
    rep = {
        "level": level, "hits": n_all, "fixed": len(log), "sent": len(residue),
        "kill": kill, "density": dens, "log": log[:8],
        "residue": [[h[0], h[2]] for h in residue[:6]],
    }
    if level in ("local", "full") and repaired != text:
        sim["content"] = repaired
        sim["policePrevLen"] = len(text)
        rep["prevLen"] = len(text)
    if level == "full" and residue:
        try:
            llm_stream(
                [{"role": "system", "content": _AUDIT_PATCH_SYS},
                 {"role": "user", "content": _audit_patch_prompt(residue)}],
                lambda d: on_delta(d) if on_delta else None,
            )
        except Exception:
            pass  # 补丁失败不致命：保留报告
    sim["police"] = rep
    return sim


def _ledger_sim(sim, ledger_rows):
    """对 sim['content'] 抽数对账，报告写回 sim['ledger']。零 LLM。"""
    facts = _ledger_facts(sim.get("content") or "")
    cf = _ledger_conflicts(facts, ledger_rows) if ledger_rows else []
    sim["ledger"] = {
        "founds": len(facts),
        "conflicts": [{"new": "%s%s=%d" % (f["noun"], f["unit"], f["qty"]),
                       "book": "%s=%d" % (r["note"], r["qty"]),
                       "sent": f["sent"]} for f, r in cf[:8]],
    }
    return sim


def _apply_sim_quality(sim, book_dir_path, police="local"):
    """sim 产出后的统一质检（执法 + 账目），按需调用。不改 source/状态机。"""
    try:
        sim = _police_sim(sim, police)
    except Exception:
        pass
    try:
        lt = _read_story(book_dir_path, "particle_ledger.md")
        rows = _ledger_parse(lt) if lt else []
        sim = _ledger_sim(sim, rows)
    except Exception:
        pass
    return sim


def _upstream_http_msg(code):
    """把上游 HTTP 错误码翻成用户能据此行动的中文提示（原样抛英文码会让人无从下手）。"""
    if code == 401:
        return "DeepSeek API Key 无效或已失效，请在「🔑 设置 API Key」重新填写"
    if code == 402:
        return "DeepSeek 账户余额不足，请到 DeepSeek 平台充值后重试"
    if code == 429:
        return "DeepSeek 请求过于频繁或已达限流，请稍后再试"
    if 500 <= code <= 599:
        return "DeepSeek 上游服务暂时不可用（HTTP %d），请稍后重试" % code
    return "上游返回 HTTP %d，请求未完成" % code


def _llm_stream_unreserved(messages, emit_delta, model="deepseek-v4-flash", temperature=0.85, max_tokens=16000):
    """执行已预留费用的上游流式调用。"""
    if KEY_STATUS != "ok" or not API_KEY:
        raise RuntimeError("api_key_unavailable")
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or not 1 <= max_tokens <= MAX_OUTPUT_TOKENS:
        raise ValueError("invalid_max_tokens")
    target = _upstream_url("/chat/completions")
    body = json.dumps({
        "model": model,
        "messages": messages,
        "stream": True,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream_options": {"include_usage": True},
    }).encode("utf-8")
    req = urllib.request.Request(
        target, data=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + API_KEY},
    )
    try:
        resp = UPSTREAM_OPENER.open(req, timeout=300)
    except urllib.error.HTTPError as e:
        raise RuntimeError(_upstream_http_msg(e.code)) from e
    full = []
    saw_reasoning = False
    buf = b""
    try:
        with resp:
            while True:
                chunk = resp.read(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    s = line.decode("utf-8", "replace").strip()
                    if not s.startswith("data:"):
                        continue
                    payload = s[5:].strip()
                    if not payload or payload == "[DONE]":
                        continue
                    try:
                        d = json.loads(payload)
                    except Exception:
                        continue
                    u = extract_usage(d)
                    if u:
                        record_usage(d.get("model", model), *u)
                    ch = d.get("choices") or []
                    if ch:
                        dl = ch[0].get("delta") or {}
                        delta = dl.get("content") or ""
                        if dl.get("reasoning_content"):
                            saw_reasoning = True
                        if delta:
                            full.append(delta)
                            try:
                                emit_delta(delta)
                            except Exception:
                                pass
    finally:
        try:
            resp.close()
        except Exception:
            pass
    text = "".join(full)
    if not text.strip() and saw_reasoning:
        raise RuntimeError("模型把输出预算全部用于思考，未写出正文；请重试一次（或缩短上下文后重试）")
    return text


def llm_stream(messages, emit_delta, model="deepseek-v4-flash", temperature=0.85, max_tokens=16000):
    """计费入口：先预留本次请求的保守费用上限，再执行上游调用。"""
    if KEY_STATUS != "ok" or not API_KEY:
        raise RuntimeError("api_key_unavailable")
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or not 1 <= max_tokens <= MAX_OUTPUT_TOKENS:
        raise ValueError("invalid_max_tokens")
    request_body = json.dumps({
        "model": model, "messages": messages, "stream": True,
        "temperature": temperature, "max_tokens": max_tokens,
        "stream_options": {"include_usage": True},
    }).encode("utf-8")
    if len(request_body) > MAX_REQUEST_BODY:
        raise ValueError("prompt_too_large")
    reservation = reserve_request_budget(model, len(request_body), max_tokens)
    if reservation is None:
        raise RuntimeError("budget_exceeded")
    try:
        return _llm_stream_unreserved(messages, emit_delta, model, temperature, max_tokens)
    finally:
        release_request_budget(reservation)


def _terminate_active_processes(grace_seconds=3):
    SHUTDOWN_EVENT.set()
    with ACTIVE_PROCESS_LOCK:
        processes = list(ACTIVE_PROCESSES)
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=grace_seconds)
                except (OSError, subprocess.TimeoutExpired):
                    pass


def run_inkos(args, on_line):
    """运行 inkos 子命令，逐行回调 on_line(text)。返回 (returncode, combined_output)。"""
    if SHUTDOWN_EVENT.is_set():
        return -1, "[error] service shutting down"
    if not NODE_EXE or not os.path.isfile(NODE_EXE):
        try:
            on_line("[error] 未找到 Node 运行时（node.exe）。请安装 Node.js，或设置环境变量 INKOS_NODE_DIR 指向其安装目录。")
        except Exception:
            pass
        return -1, "[error] node runtime missing"
    if not os.path.isfile(INKOS_CLI):
        try:
            on_line("[error] 未找到 InkOS 引擎（%s）。请确认引擎已安装（npm install）。" % INKOS_CLI)
        except Exception:
            pass
        return -1, "[error] inkos cli missing"
    env = dict(os.environ)
    env["PATH"] = INKOS_BIN + os.pathsep + NODE_DIR + os.pathsep + env.get("PATH", "")
    env["INKOS_LLM_BASE_URL"] = "http://127.0.0.1:%d" % configured_port()
    env["INKOS_LLM_API_KEY"] = "sk-local-proxy-placeholder"
    env["INKOS_LLM_MODEL"] = "deepseek-v4-flash"
    env["INKOS_LLM_API_FORMAT"] = "chat"
    env["INKOS_LLM_STREAM"] = "true"
    cmd = [NODE_EXE, INKOS_CLI] + [str(a) for a in args]
    try:
        with ACTIVE_PROCESS_LOCK:
            if SHUTDOWN_EVENT.is_set():
                return -1, "[error] service shutting down"
            proc = subprocess.Popen(
                cmd, cwd=BOOK_ROOT, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
            ACTIVE_PROCESSES.add(proc)
    except Exception as e:
        try:
            on_line("[error] 无法启动 inkos: %s" % e)
        except Exception:
            pass
        return -1, ""
    out = []
    try:
        if proc.stdout:
            for line in proc.stdout:
                line = line.rstrip("\n")
                out.append(line)
                try:
                    on_line(line)
                except Exception:
                    pass
        rc = proc.wait()
        return rc, "\n".join(out)
    finally:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        if proc.stdout:
            try:
                proc.stdout.close()
            except OSError:
                pass
        with ACTIVE_PROCESS_LOCK:
            ACTIVE_PROCESSES.discard(proc)


# ----------------------------- 自动推演守护线程 -----------------------------
def _auto_sim_loop():
    """无人值守推演：仅在引擎空闲、且该书该章尚无足够自推稿时才生成。"""
    while not SHUTDOWN_EVENT.is_set():
        try:
            st = task_snapshot()
            with AUTO_SIM_LOCK:
                enabled = AUTO_SIM_STATE["enabled"]
            if enabled and not st["running"] and KEY_STATUS == "ok" and API_KEY:
                for b in list_books():
                    if task_snapshot()["running"]:
                        break  # 作者正在操作，本次循环让位
                    bid = b["id"]
                    bd = book_dir(bid)
                    if not bd:
                        continue
                    chs = read_chapters(bd, with_content=False)
                    next_num = (int(chs[-1].get("number") or len(chs)) + 1) if chs else 1
                    existing = [s for s in list_sims(bd)
                                if s.get("source") == "auto"
                                and int(s.get("chapter") or 0) == next_num
                                and s.get("status") != "used"]
                    if len(existing) >= AUTO_SIM_MAX_PER_CHAPTER:
                        continue
                    if not begin_task("simulate", bid, "自动推演"):
                        break
                    try:
                        sim, err = _simulate_core(bd, "auto", "", next_num, None)
                        if sim and not err:
                            save_sim(bd, sim)
                            with AUTO_SIM_LOCK:
                                AUTO_SIM_STATE["lastRunAt"] = int(time.time() * 1000)
                                AUTO_SIM_STATE["lastBook"] = bid
                                AUTO_SIM_STATE["lastError"] = ""
                                AUTO_SIM_STATE["totalGenerated"] += 1
                        elif err:
                            with AUTO_SIM_LOCK:
                                AUTO_SIM_STATE["lastError"] = err
                    finally:
                        end_task()
        except Exception as e:
            try:
                with AUTO_SIM_LOCK:
                    AUTO_SIM_STATE["lastError"] = "loop:%s" % e
            except Exception:
                pass
        if SHUTDOWN_EVENT.wait(AUTO_SIM_INTERVAL):
            break


def _api_auto_sim_state():
    with AUTO_SIM_LOCK:
        return dict(AUTO_SIM_STATE)


# ----------------------------- HTTP 处理 -----------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "InkOSMonitor/1.0"

    def log_message(self, fmt, *args):
        # 精简日志，且不打印任何请求体（避免意外泄露 Key）
        try:
            line = fmt % args
        except Exception:
            line = fmt
        if "code 4" in line or "code 5" in line:
            sys.stderr.write("[monitor] %s\n" % line)
        # 正常请求静默

    # ---- 工具 ----
    def _send_json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, code, data, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _book_param(self):
        """从查询字符串读取 book 参数。"""
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return (q.get("book") or [""])[0]

    def _is_local_request(self):
        """限制 Host/Origin，降低 DNS rebinding 与跨站请求风险。"""
        try:
            peer = ipaddress.ip_address(self.client_address[0])
            if not peer.is_loopback:
                return False
            port = configured_port()
            host = urllib.parse.urlsplit("//" + (self.headers.get("Host") or ""))
            host_port = host.port if host.port is not None else 80
            if (host.hostname not in ("localhost", "127.0.0.1")
                    or host.username or host.password or host_port != port):
                return False
            origin = self.headers.get("Origin")
            if origin:
                parsed = urllib.parse.urlsplit(origin)
                origin_port = parsed.port if parsed.port is not None else 80
                if (parsed.scheme != "http"
                        or parsed.hostname not in ("localhost", "127.0.0.1")
                        or parsed.username or parsed.password or origin_port != port):
                    return False
            return True
        except (ValueError, TypeError):
            return False

    def _reject_untrusted_request(self):
        if self._is_local_request():
            return False
        self._send_json(403, {"error": "forbidden_host_or_origin"})
        return True

    def _send_request_error(self, code, error):
        data = json.dumps({"error": error}, ensure_ascii=False).encode("utf-8")
        self.close_connection = True
        self.send_response(code)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_request_body(self):
        """读取受限大小的请求体，拒绝 chunked/畸形请求并设置读取超时。"""
        if self.headers.get("Transfer-Encoding"):
            self._send_request_error(400, "transfer_encoding_not_supported")
            return None
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length or 0)
        except (TypeError, ValueError):
            self._send_request_error(400, "invalid_content_length")
            return None
        if length < 0:
            self._send_request_error(400, "invalid_content_length")
            return None
        if length > MAX_REQUEST_BODY:
            self._send_request_error(413, "request_body_too_large")
            return None
        old_timeout = self.connection.gettimeout()
        try:
            self.connection.settimeout(15)
            body = self.rfile.read(length) if length else b""
        except (OSError, TimeoutError):
            self._send_request_error(408, "request_body_timeout")
            return None
        finally:
            try:
                self.connection.settimeout(old_timeout)
            except OSError:
                pass
        if len(body) != length:
            self._send_request_error(400, "incomplete_request_body")
            return None
        return body

    def _read_json(self):
        raw = getattr(self, "_request_body", b"{}") or b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # ---- GET ----
    def do_GET(self):
        if self._reject_untrusted_request():
            return
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            # HTTP/1.1 keep-alive 下，无响应体的重定向必须显式声明 Content-Length: 0，
            # 否则客户端会一直等待 body 直到超时（表现为首页打不开/卡住）。
            self.send_response(302)
            self.send_header("Location", "/workbench")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif p in ("/workbench", "/workbench.html"):
            self._serve_workbench()
        elif p == "/api/state":
            self._send_json(200, snapshot())
        elif p == "/api/stream":
            self._serve_sse()
        elif p == "/api/health":
            self._send_json(200, {"ok": True, "key_status": KEY_STATUS})
        elif p == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        elif p == "/api/diagnostics":
            self._api_diagnostics()
        elif p == "/api/books":
            self._api_books()
        elif p == "/api/world":
            self._api_world("GET")
        elif p == "/api/world/stats":
            self._api_world_stats()
        elif p == "/api/world/entities":
            self._api_world_entities()
        elif p == "/api/role/list":
            self._api_role_list()
        elif p == "/api/ledger/view":
            self._api_ledger_view()
        elif p == "/api/world/check":
            self._api_world_check()
        elif p == "/api/world/bundle":
            self._api_world_bundle()
        elif p == "/api/chapters":
            self._api_chapters()
        elif p == "/api/overview":
            self._api_overview()
        elif p == "/api/tree":
            self._api_tree()
        elif p == "/api/viz":
            self._api_viz()
        elif p == "/api/task":
            self._send_json(200, task_snapshot())
        elif p == "/api/auto-sim":
            self._api_auto_sim()
        elif p == "/api/simulations":
            self._api_simulations()
        elif p == "/api/book/status":
            self._api_book_status()
        elif p == "/api/book/path":
            self._api_book_path()
        elif p == "/api/trash":
            self._api_trash()
        elif p == "/api/sop/rules":
            self._api_sop_rules()
        elif p == "/api/sop/milestones":
            self._api_sop_milestones()
        elif p == "/api/sop/redline":
            self._api_sop_redline()
        elif p == "/api/file":
            self._api_file()
        elif p == "/api/chapter/versions":
            self._api_chapter_versions()
        elif p.startswith("/api/chapter/"):
            self._api_chapter(p[len("/api/chapter/"):])
        elif p.startswith("/vendor/"):
            self._serve_static(os.path.join(HERE, "vendor", p[len("/vendor/"):]),
                               os.path.join(HERE, "vendor"))
        elif p.startswith("/assets/"):
            self._serve_static(os.path.join(HERE, "assets", p[len("/assets/"):]),
                               os.path.join(HERE, "assets"))
        elif urllib.parse.urlsplit(self.path).path in UPSTREAM_ROUTES["GET"]:
            self._forward("GET", None)
        else:
            self._send_json(404, {"error": "not_found"})

    # ---- POST ----
    def do_POST(self):
        if self._reject_untrusted_request():
            return
        body = self._read_request_body()
        if body is None:
            return
        self._request_body = body
        p = self.path.split("?")[0]
        if p == "/api/budget":
            self._api_budget()
        elif p == "/api/reset":
            self._api_reset()
        elif p == "/api/world":
            self._api_world("POST")
        elif p == "/api/world/new":
            self._api_world_new()
        elif p == "/api/world/seed":
            self._api_world_seed()
        elif p == "/api/book/open-folder":
            self._api_book_open_folder()
        elif p == "/api/book/create":
            self._api_book_create()
        elif p == "/api/interview":
            self._api_interview()
        elif p == "/api/role/interview":
            self._api_role_interview()
        elif p == "/api/role/refine":
            self._api_role_refine()
        elif p == "/api/role/save":
            self._api_role_save()
        elif p == "/api/generate":
            self._api_generate()
        elif p == "/api/simulate":
            self._api_simulate()
        elif p == "/api/audit":
            self._api_audit()
        elif p == "/api/ledger-check":
            self._api_ledger_check()
        elif p == "/api/first-chapter":
            self._api_first_chapter()
        elif p == "/api/simulation/save":
            self._api_simulation_save()
        elif p == "/api/simulation/delete":
            self._api_simulation_delete()
        elif p == "/api/simulation/adopt":
            self._api_simulation_adopt()
        elif p == "/api/auto-sim":
            self._api_auto_sim()
        elif p == "/api/export":
            self._api_export()
        elif p == "/api/chapter/save":
            self._api_chapter_save()
        elif p == "/api/sandbox/event":
            self._api_sandbox_event()
        elif p == "/api/chapter/delete":
            self._api_chapter_delete()
        elif p == "/api/book/delete":
            self._api_book_delete()
        elif p == "/api/trash/restore":
            self._api_trash_restore()
        elif p == "/api/trash/purge":
            self._api_trash_purge()
        elif p == "/api/trash/empty":
            self._api_trash_empty()
        elif p == "/api/book/track":
            self._api_book_track()
        elif p == "/api/key":
            self._api_key()
        elif urllib.parse.urlsplit(self.path).path in UPSTREAM_ROUTES["POST"]:
            self._forward("POST", body)
        else:
            self._send_json(404, {"error": "not_found"})

    def do_OPTIONS(self):
        if self._reject_untrusted_request():
            return
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()

    # ---- SSE ----
    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        q = queue.Queue()
        with sub_lock:
            subscribers.add(q)
        try:
            self.wfile.write(("data: " + json.dumps(snapshot(), ensure_ascii=False) + "\n\n").encode("utf-8"))
            self.wfile.flush()
            while True:
                try:
                    evt = q.get(timeout=20)
                    self.wfile.write(("data: " + evt + "\n\n").encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    try:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                    except Exception:
                        break
        except Exception:
            pass
        finally:
            with sub_lock:
                subscribers.discard(q)

    # ---- API: 预算设置 ----
    # ---- 诊断：路径 / 运行时 / 书本根解析状态（启动异常或书本为空时排查） ----
    def _api_diagnostics(self):
        from glob import glob as _glob
        books = list_books()
        diag = {
            "book_root": BOOK_ROOT,
            "book_root_exists": os.path.isdir(BOOK_ROOT),
            "books_dir_exists": os.path.isdir(os.path.join(BOOK_ROOT, "books")),
            "self_dir": SELF_DIR,
            "self_project_exists": os.path.isdir(SELF_PROJECT),
            "inkos_bin": INKOS_BIN,
            "inkos_bin_exists": os.path.isdir(INKOS_BIN),
            "node_exe": NODE_EXE,
            "node_exe_exists": bool(NODE_EXE) and os.path.isfile(NODE_EXE),
            "inkos_cli": INKOS_CLI,
            "inkos_cli_exists": os.path.isfile(INKOS_CLI),
            "workspace": WORKSPACE,
            "key_status": KEY_STATUS,
            "book_count": len(books),
            "books": [b["id"] for b in books],
        }
        self._send_json(200, diag)

    # ---- API: 预算设置 ----
    def _api_budget(self):
        d = self._read_json()
        if not isinstance(d, dict):
            self._send_json(400, {"error": "invalid_budget_payload"})
            return
        if "initial_balance" in d:
            value = d["initial_balance"]
            if not _is_finite_number(value) or value < 0:
                self._send_json(400, {"error": "invalid_initial_balance"})
                return
        if "rate" in d:
            value = d["rate"]
            if not _is_finite_number(value) or value <= 0:
                self._send_json(400, {"error": "invalid_exchange_rate"})
                return
        with state_lock:
            old_values = {key: CFG[key] for key in ("initial_balance", "currency", "rate")}
            if "initial_balance" in d:
                CFG["initial_balance"] = float(d["initial_balance"])
            if isinstance(d.get("currency"), str) and d["currency"]:
                CFG["currency"] = d["currency"]
            if "rate" in d:
                CFG["rate"] = float(d["rate"])
            saved = save_config()
            if not saved:
                CFG.update(old_values)
        if not saved:
            self._send_json(500, {"error": "config_persist_failed"})
            return
        broadcast()
        self._send_json(200, snapshot())

    # ---- API: 清零累计（会话计数归零，已花费折入初始余额，保证数学一致） ----
    def _api_reset(self):
        with state_lock:
            spent_currency = STATE["spent_usd"] * CFG["rate"]
            CFG["initial_balance"] = round(CFG["initial_balance"] - spent_currency, 6)
            STATE["input"] = 0
            STATE["output"] = 0
            STATE["cached"] = 0
            STATE["calls"] = 0
            STATE["spent_usd"] = 0.0
            HISTORY[:] = []
            save_config()
            save_usage()
        broadcast()
        self._send_json(200, snapshot())

    # ---- 小说工作台：页面 ----
    def _serve_workbench(self):
        path = os.path.join(HERE, "workbench.html")
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send_bytes(200, data, "text/html; charset=utf-8")

    def _serve_static(self, path, allowed_root):
        path = os.path.realpath(path)
        allowed_root = os.path.realpath(allowed_root)
        if not _path_is_within(allowed_root, path):
            self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers(); return
        if not os.path.isfile(path):
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        ct = "application/octet-stream"
        if path.endswith(".js"): ct = "application/javascript; charset=utf-8"
        elif path.endswith(".mjs"): ct = "application/javascript; charset=utf-8"
        elif path.endswith(".css"): ct = "text/css; charset=utf-8"
        elif path.endswith(".png"): ct = "image/png"
        elif path.endswith(".jpg") or path.endswith(".jpeg"): ct = "image/jpeg"
        elif path.endswith(".json"): ct = "application/json; charset=utf-8"
        elif path.endswith(".gltf"): ct = "model/gltf+json"
        elif path.endswith(".glb"): ct = "model/gltf-binary"
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        self._send_bytes(200, data, ct)

    # ---- 书本列表 ----
    def _api_books(self):
        self._send_json(200, {"books": list_books(), "default": default_book()})

    # ---- 世界设定：读取 / 保存 ----
    def _api_world(self, method):
        if method == "POST":
            d = self._read_json()
            # 关键：写操作必须以请求体的 book 为准（前端 POST 不带 ?book=），
            # 否则会误写到默认书，造成跨书数据污染。
            book = d.get("book") or self._book_param()
            bd = book_dir(book)
            if not bd:
                self._send_json(400, {"error": "book_not_found", "book": book})
                return
            rel = (d.get("path") or d.get("rel") or "")
            content = d.get("content", "")
            if rel.endswith("world_rules.md"):
                content = world_rules_finalize(content)
            ok, err = save_world_file(bd, rel, content)
            if not ok:
                self._send_json(400, {"error": err or "save_failed"})
                return
            self._send_json(200, {"ok": True, "book": book, "path": rel})
        else:
            book = self._book_param()
            bd = book_dir(book)
            if not bd:
                self._send_json(400, {"error": "book_not_found", "book": book})
                return
            self._send_json(200, {
                "book": book,
                "bookTitle": book_title(bd),
                "files": scan_world(bd),
            })

    # ---- 书本本地路径（详情卡只读展示；作者机器可点开文件夹） ----
    def _api_book_path(self):
        book = self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(404, {"error": "book_not_found", "book": book})
            return
        ap = os.path.abspath(bd)
        self._send_json(200, {
            "book": book,
            "title": book_title(bd),
            "path": ap,
            "exists": os.path.isdir(ap),
        })

    def _api_book_open_folder(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd or not os.path.isdir(bd):
            self._send_json(404, {"error": "book_not_found", "book": book})
            return
        ap = os.path.abspath(bd)
        try:
            if sys.platform == "win32":
                os.startfile(ap)  # noqa: 打开资源管理器（作者本机）
            elif sys.platform == "darwin":
                subprocess.Popen(["open", ap])
            else:
                subprocess.Popen(["xdg-open", ap])
        except Exception as e:
            self._send_json(500, {"error": "open_failed", "msg": str(e)})
            return
        self._send_json(200, {"ok": True, "path": ap})

    # ---- 一键生成「世界底层逻辑」模板（幂等：已存在则只读返回，不覆盖） ----
    def _api_world_seed(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        rel = (d.get("rel") or d.get("path") or WORLD_RULES_REL).strip()
        if safe_rel(bd, rel) is None:
            self._send_json(400, {"error": "invalid_path"})
            return
        existing = read_world_file(bd, rel)
        if existing is not None:
            self._send_json(200, {
                "ok": True,
                "exists": True,
                "path": rel,
                "draft": existing.lstrip().startswith(WORLD_RULES_DRAFT_MARK),
            })
            return
        ok, err = save_world_file(bd, rel, WORLD_RULES_DRAFT_MARK + "\n\n" + WORLD_RULES_TPL)
        if not ok:
            self._send_json(400, {"error": err or "save_failed"})
            return
        self._send_json(200, {"ok": True, "exists": False, "path": rel, "draft": True})

    # ---- 新建书（Architect 生成世界观地基，走 LLM 计费） ----
    def _api_book_create(self):
        d = self._read_json()
        title = (d.get("title") or "").strip()
        if not title:
            self._send_json(400, {"error": "title_required"})
            return
        # 建书前重名校验：避免 inkos 在 rc!=0 的异常部分落盘后，下次同名撞车。
        safe_id = re.sub(r"[^\w一-龥-]", "_", title).strip("_") or "book"
        bdir_check = os.path.join(BOOK_ROOT, "books", safe_id)
        if os.path.isfile(os.path.join(bdir_check, "book.json")):
            self._send_json(409, {"error": "book_exists",
                                  "msg": "已存在同名书本《%s》，请换一个书名或先删除旧书。" % title})
            return
        genre = d.get("genre") or "other"
        platform = d.get("platform") or "tomato"
        lang = d.get("lang") or "zh"
        brief = d.get("brief") or ""
        # 唯一临时文件名：并行建书时避免同秒时间戳碰撞导致 brief 互相覆盖（跨书污染根因）。
        tmp = os.path.join(
            BOOK_ROOT, ".inkos",
            "brief_%d_%d_%s.md" % (int(time.time() * 1000), os.getpid(),
                                   uuid.uuid4().hex[:8]))
        try:
            os.makedirs(os.path.dirname(tmp), exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(brief)
        except Exception as e:
            self._send_json(500, {"error": "brief_write_failed", "detail": str(e)})
            return
        r = begin_task("book_create", "", "新建图书《%s》" % title)
        if r is not True:
            self._send_json(409, {
                "error": "budget" if r == "budget" else "busy",
                "task": task_snapshot(),
                "msg": ("余额不足 ¥0.5，无法发起生成。请在「用量花费」页重置计数（账户充值需到 DeepSeek 平台）。"
                        if r == "budget" else "已有生成任务在进行中，请等它完成"),
            })
            return
        args = ["book", "create", "--title", title, "--genre", genre,
                "--platform", platform, "--lang", lang, "--brief", tmp]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        emit({"stage": "start", "title": title, "args": args})
        try:
            rc, out = run_inkos(args, lambda line: emit({"line": line}))
        finally:
            end_task()
        try:
            os.remove(tmp)
        except Exception:
            pass
        new_id = None
        try:
            bdir = os.path.join(BOOK_ROOT, "books")
            best, bt = None, 0
            for name in os.listdir(bdir):
                jp = os.path.join(bdir, name, "book.json")
                if os.path.isfile(jp):
                    t = os.path.getmtime(jp)
                    if t > bt:
                        bt, best = t, name
            new_id = best
        except Exception:
            pass
        emit({"stage": "done", "returncode": rc, "bookId": new_id})

    # ---- 创作前访谈：意图澄清 ----
    def _api_interview(self):
        """POST /api/interview
        action='ask'      -> SSE 流式返回访谈者的下一句追问（delta 帧 + ask_done 帧）
        action='summarize'-> 一次性返回结构化创作意图 JSON {title,genre,platform,lang,brief}
        需要 LLM（DeepSeek Key）。无密钥时返回 503，前端优雅降级为「直接开始」。"""
        d = self._read_json()
        action = (d.get("action") or "ask").lower()
        turns = d.get("turns") or []
        if KEY_STATUS != "ok" or not API_KEY:
            self._send_json(503, {"error": "api_key_unavailable", "detail": KEY_STATUS})
            return

        if action == "summarize":
            convo = "\n".join(
                (("作者" if t.get("role") == "user" else "编辑") + "：" + (t.get("text") or ""))
                for t in turns
            )
            if not convo.strip():
                convo = "（作者尚未提供任何信息，请基于常识给出一份通用的玄幻/都市网文创作意图建议。）"
            try:
                full = llm_stream(
                    [{"role": "system", "content": INTERVIEW_SUMMARY_SYSTEM},
                     {"role": "user", "content": "访谈记录：\n" + convo}],
                    lambda *_: None, temperature=0.3, max_tokens=1500,
                )
            except Exception as e:
                self._send_json(502, {"error": "llm_failed", "msg": str(e)})
                return
            obj = extract_first_json(full)
            if not obj:
                self._send_json(502, {"error": "bad_json", "raw": full[:600]})
                return
            # 枚举兜底，避免下游 inkos 收到非法值
            if obj.get("genre") not in ("urban", "fantasy", "xianxia", "scifi",
                                        "romance", "history", "mystery", "game", "other"):
                obj["genre"] = "other"
            if obj.get("platform") not in ("tomato", "qidian", "feilu", "other"):
                obj["platform"] = "tomato"
            if obj.get("lang") not in ("zh", "en"):
                obj["lang"] = "zh"
            self._send_json(200, obj)
            return

        # ---- action='ask'：流式追问 ----
        messages = [{"role": "system", "content": INTERVIEWER_SYSTEM}]
        for t in turns:
            role = "user" if t.get("role") == "user" else "assistant"
            messages.append({"role": role, "content": t.get("text", "")})
        if not any(t.get("role") == "user" for t in turns):
            # 首轮：让访谈者自我介绍并抛出第一个问题
            messages.append({"role": "user",
                             "content": "（开始创作前访谈，请做简短自我介绍，然后问第一个最开放的问题。）"})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        emit({"stage": "start"})
        try:
            full = llm_stream(
                messages,
                lambda delta: emit({"stage": "delta", "text": delta}),
                temperature=0.85, max_tokens=700,
            )
            emit({"stage": "ask_done", "text": full})
        except Exception as e:
            emit({"stage": "error", "msg": str(e)})

    # ---- 世界设定：新建文档 ----
    def _api_world_new(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        rel = (d.get("path") or d.get("rel") or "").strip()
        if not rel or not rel.endswith((".md", ".txt")):
            self._send_json(400, {"error": "invalid_path", "msg": "path 须为 .md/.txt 相对路径"})
            return
        if safe_rel(bd, rel) is None:
            self._send_json(400, {"error": "invalid_path"})
            return
        ok, err = save_world_file(bd, rel, d.get("content", ""))
        if not ok:
            self._send_json(400, {"error": err or "save_failed"})
            return
        self._send_json(200, {"ok": True, "path": rel})

    # ---- 角色档案：列表（含重要程度侧车）----
    def _api_role_list(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        tiers = read_role_tiers(bd)
        roles = []
        for i in scan_world(bd):
            p = i["path"]
            if "/roles/" not in p and not p.startswith("roles/"):
                continue
            name = p.rsplit("/", 1)[-1]
            if name.endswith(".md"):
                name = name[:-3]
            roles.append({
                "name": name, "path": p,
                "tier": tiers.get(name, "major"),
                "words": i.get("words", 0),
            })
        roles.sort(key=lambda r: (r["path"], r["name"]))
        self._send_json(200, {"roles": roles})

    # ---- 角色档案：保存（作者审批后落盘）----
    def _api_role_save(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        tier = d.get("tier")
        if tier not in ROLE_TIER_DIR:
            tier = "major"
        name = role_file_name(d.get("name"))
        content = d.get("content") or ""
        if not name or not content.strip():
            self._send_json(400, {"error": "empty_fields", "msg": "角色名与内容均不能为空"})
            return
        rel = "story/roles/%s/%s.md" % (role_dir_for(tier), name)
        full = safe_rel(bd, rel)
        if full is None:
            self._send_json(400, {"error": "invalid_path"})
            return
        existed = os.path.isfile(full)
        ok, err = save_world_file(bd, rel, content)
        if not ok:
            self._send_json(400, {"error": err or "save_failed"})
            return
        write_role_tier(bd, name, tier)
        self._send_json(200, {"ok": True, "path": rel, "existed": existed, "name": name})

    # ---- 角色档案：AI 访谈（逐角色追问，SSE）----
    def _api_role_interview(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        if KEY_STATUS != "ok" or not API_KEY:
            self._send_json(503, {"error": "api_key_unavailable", "detail": KEY_STATUS})
            return
        name = role_file_name(d.get("name"))
        tier = d.get("tier")
        if tier not in ROLE_TIER_DIR:
            tier = "major"
        if tier in ("minor", "extra"):
            self._send_json(400, {"error": "interview_main_only",
                                  "msg": "AI 精谈仅对主角/主要角色开放"})
            return
        turns = d.get("turns") or []
        ctx = role_known_ctx(bd)
        secs = role_sections_for(tier)
        sysp = ROLE_INTERVIEWER_SYSTEM.format(
            book=book, role=name, tier_cn=ROLE_TIER_CN.get(tier, tier),
            template_n=len(secs), sections="、".join(secs))
        if ctx.strip():
            sysp += "\n\n【已知信息（只用于对齐，不要复述全部）】\n%s" % ctx[:3000]
        messages = [{"role": "system", "content": sysp}]
        for t in turns:
            role = "user" if t.get("role") == "user" else "assistant"
            messages.append({"role": role, "content": t.get("text", "")})
        if not any(t.get("role") == "user" for t in turns):
            messages.append({"role": "user",
                             "content": "（开始为角色「%s」做人设访谈，请自我介绍半句后抛出第一个问题。）" % name})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        emit({"stage": "start"})
        try:
            full = llm_stream(
                messages,
                lambda delta: emit({"stage": "delta", "text": delta}),
                temperature=0.85, max_tokens=700,
            )
            emit({"stage": "ask_done", "text": full})
        except Exception as e:
            emit({"stage": "error", "msg": str(e)})

    # ---- 角色档案：访谈/已知信息 精炼成 md 草稿（SSE）----
    def _api_role_refine(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        if KEY_STATUS != "ok" or not API_KEY:
            self._send_json(503, {"error": "api_key_unavailable", "detail": KEY_STATUS})
            return
        name = role_file_name(d.get("name"))
        tier = d.get("tier")
        if tier not in ROLE_TIER_DIR:
            tier = "major"
        turns = d.get("turns") or []
        ctx = role_known_ctx(bd)
        sysp, _ = build_role_refine_system(book, name, tier, ctx)
        convo = "\n".join(
            (("作者" if t.get("role") == "user" else "访谈编辑") + "：" + (t.get("text") or ""))
            for t in turns)
        if not convo.strip():
            convo = "（无访谈轮次：请仅依据已知信息为《%s》的角色「%s」生成%s节精简草稿，信息不足处标注待作者补充。）" % (
                book, name, len(role_sections_for(tier)))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        emit({"stage": "start"})
        try:
            full = llm_stream(
                [{"role": "system", "content": sysp},
                 {"role": "user", "content": "访谈记录：\n" + convo}],
                lambda delta: emit({"stage": "delta", "text": delta}),
                temperature=0.6, max_tokens=2600,
            )
            emit({"stage": "refine_done", "text": full})
        except Exception as e:
            emit({"stage": "error", "msg": str(e)})

    # ---- 世界统计 ----
    def _api_world_stats(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        self._send_json(200, world_stats(bd))

    # ---- 世界角色 / 实体 ----
    def _api_world_entities(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        self._send_json(200, world_entities(bd))

    # ---- 世界一致性检查 ----
    def _api_world_check(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        self._send_json(200, {"issues": world_check(bd)})

    # ---- 世界打包导出（单 MD 下载） ----
    def _api_world_bundle(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        title = book_title(bd)
        text = world_bundle(bd, title).encode("utf-8")
        fname = (title or "world") + "-世界设定全集.md"
        self.send_response(200)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Length", str(len(text)))
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % urllib.parse.quote(fname))
        self.end_headers()
        self.wfile.write(text)

    # ---- 章节列表（瘦身：不带正文）/ 单章（按需读单文件） ----
    def _api_chapters(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        self._send_json(200, {"book": book_title(bd),
                              "chapters": read_chapters(bd, with_content=False)})

    def _api_chapter(self, num):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        try:
            num = int(num)
        except Exception:
            self._send_json(400, {"error": "bad_num"})
            return
        for c in read_chapters(bd, with_content=False):
            if c["number"] == num:
                content = ""
                if c.get("file"):
                    try:
                        content = open(os.path.join(bd, "chapters", c["file"]),
                                       "r", encoding="utf-8").read()
                    except Exception:
                        content = ""
                c["content"] = content
                self._send_json(200, c)
                return
        self._send_json(404, {"error": "not_found"})

    # ---- 工程状态（无 LLM 花费）----
    def _api_book_status(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        rc, out = run_inkos(["status", os.path.basename(bd)], lambda line: None)
        self._send_json(200, {"returncode": rc, "raw": out})

    # ---- 文件下载 / 读取 ----
    def _api_file(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        book = (q.get("book") or [""])[0]
        rel = (q.get("rel") or [""])[0]
        bd = book_dir(book)
        if not bd:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        full = safe_rel(bd, rel)
        if not full or not os.path.isfile(full):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            with open(full, "rb") as f:
                data = f.read()
        except Exception:
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        ct = "text/plain; charset=utf-8"
        if full.endswith(".md"):
            ct = "text/markdown; charset=utf-8"
        elif full.endswith(".json"):
            ct = "application/json; charset=utf-8"
        self._send_bytes(200, data, ct)

    # ---- 聚合总览：一次请求拿齐总览页全部数据（原需 3 个请求） ----
    def _api_overview(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        chs = read_chapters(bd, with_content=False)
        sims = list_sims(bd)
        drafts = [s for s in sims if s.get("status") == "draft"]
        stats = world_stats(bd)
        # 待审稿中是否已有针对下一章的草稿（用于总览"下一步"引导）
        next_num = (int(chs[-1].get("number") or len(chs)) + 1) if chs else 1
        has_next_draft = any(int(s.get("chapter") or 0) == next_num for s in drafts)
        self._send_json(200, {
            "book": book_title(bd),
            "chapters": len(chs),
            "lastChapter": ({"number": chs[-1].get("number"), "title": chs[-1].get("title")} if chs else None),
            "nextChapter": next_num,
            "drafts": len(drafts),
            "hasNextDraft": has_next_draft,
            "world": stats,
            "task": task_snapshot(),
            "autoSim": _api_auto_sim_state(),
        })

    # ---- 可视化只读聚合（N01：后端解析、前端只呈现；零 LLM / 零写盘） ----
    def _api_viz(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        bd = book_dir((q.get("book") or [""])[0] or None)
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        view = (q.get("view") or ["manifest"])[0]
        if view not in VIZ_VIEWS:
            self._send_json(400, {"error": "bad_view", "views": list(VIZ_VIEWS)})
            return
        try:
            self._send_json(200, build_viz(bd, view))
        except Exception as e:
            # 只读端点解析异常也不抛 5xx：降级为「不可用 + 原因」，前端自动隐藏/降级视图
            self._send_json(200, {"view": view, "book": book_title(bd),
                                  "available": False,
                                  "reason": "viz_parse_error: %s" % type(e).__name__,
                                  "warnings": [], "data": {}})

    # ---- 章节就地编辑：版本列表（GET 只读） + 保存（POST，保存前自动归档旧版） ----
    def _api_chapter_versions(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        bd = book_dir((q.get("book") or [""])[0] or None)
        if not bd:
            self._send_json(400, {"error": "book_not_found"}); return
        try:
            num = int((q.get("num") or [""])[0])
        except Exception:
            self._send_json(400, {"error": "bad_number"}); return
        vdir = os.path.join(bd, "chapters", ".versions")
        prefix = "%04d_" % num
        files = []
        if os.path.isdir(vdir):
            for fn in sorted(os.listdir(vdir), reverse=True):
                if not (fn.startswith(prefix) and fn.endswith(".md")):
                    continue
                p = os.path.join(vdir, fn)
                try:
                    words = len(re.sub(r"\s", "", open(p, "r", encoding="utf-8").read()))
                except Exception:
                    words = 0
                files.append({"file": fn, "words": words, "size": os.path.getsize(p),
                              "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                                     time.localtime(os.path.getmtime(p)))})
        out = {"ok": True, "number": num, "total": len(files), "versions": files[:30]}
        want = (q.get("file") or [""])[0]
        if want:
            if (not want.startswith(prefix) or not want.endswith(".md")
                    or "/" in want or "\\" in want or ".." in want):
                self._send_json(400, {"error": "bad_version"}); return
            p = os.path.join(vdir, want)
            if (not _path_is_within(os.path.realpath(vdir), os.path.realpath(p))
                    or not os.path.isfile(p)):
                self._send_json(404, {"error": "version_not_found"}); return
            try:
                out["content"] = open(p, "r", encoding="utf-8").read()
            except Exception:
                self._send_json(500, {"error": "read_failed"}); return
        self._send_json(200, out)

    def _api_chapter_save(self):
        d = self._read_json()
        bd = book_dir(d.get("book") or "")
        if not bd:
            self._send_json(400, {"error": "book_not_found"}); return
        try:
            num = int(d.get("number"))
        except Exception:
            self._send_json(400, {"error": "bad_number"}); return
        content = d.get("content")
        if not isinstance(content, str):
            self._send_json(400, {"error": "bad_content"}); return
        idx_path = safe_rel(bd, "chapters/index.json")
        if not idx_path or not os.path.isfile(idx_path):
            self._send_json(404, {"error": "index_not_found"}); return
        try:
            idx = json.load(open(idx_path, "r", encoding="utf-8"))
        except Exception:
            self._send_json(500, {"error": "index_parse_failed"}); return
        entry = None
        for c in idx:
            try:
                if int(c.get("number") or 0) == num:
                    entry = c; break
            except Exception:
                continue
        if not entry:
            self._send_json(404, {"error": "chapter_not_found"}); return
        ch_dir = os.path.join(bd, "chapters")
        fname = None
        for fn in os.listdir(ch_dir):
            if fn.startswith("%04d" % num) and fn.endswith(".md"):
                fname = fn; break
        if not fname:
            self._send_json(404, {"error": "chapter_file_not_found"}); return
        full = safe_rel(bd, "chapters/" + fname)
        if not full or not os.path.isfile(full):
            self._send_json(400, {"error": "unsafe_path"}); return
        try:
            old = open(full, "r", encoding="utf-8").read()
        except Exception:
            self._send_json(500, {"error": "read_failed"}); return
        if old == content:
            self._send_json(200, {"ok": True, "unchanged": True, "number": num}); return
        # 先归档旧版再覆盖正文：任何情况下都不做「无备份覆盖」
        vdir = os.path.join(ch_dir, ".versions")
        stamp = time.strftime("%Y%m%d-%H%M%S")
        vname = "%04d_%s_%06d.md" % (num, stamp, int(time.time() * 1000) % 1000000)
        try:
            os.makedirs(vdir, exist_ok=True)
            with open(os.path.join(vdir, vname), "w", encoding="utf-8") as f:
                f.write(old)
        except Exception:
            self._send_json(500, {"error": "version_backup_failed"}); return
        tmp = full + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, full)
        except Exception:
            try: os.remove(tmp)
            except OSError: pass
            self._send_json(500, {"error": "write_failed"}); return
        # 引擎 wordCount 走 zh_chars 口径且与 lengthTelemetry 校验绑定，编辑端不得覆盖。
        # 只更新 updatedAt，并另存一个明确标注口径的参考值，避免两套口径混进同一字段。
        wc = len(re.sub(r"\s", "", content))
        entry["editorWordCount"] = wc
        entry["editorWordCountMode"] = "non_whitespace_chars"
        entry["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        try:
            _save_json_atomic(idx_path, idx)
        except Exception:
            pass  # 正文已落盘且旧版已归档；索引更新失败不回滚正文
        self._send_json(200, {"ok": True, "unchanged": False, "number": num,
                              "editorWordCount": wc,
                              "wordCountMode": "non_whitespace_chars (reference only)",
                              "version": vname,
                              "notice": "旧版已归档；引擎 wordCount / state/*.json / memory.db / auditIssues 未自动同步"})

    # ---- 世界沙盘：上帝模式注入事件（只写 world_sandbox/，绝不碰 story/ 与引擎数据） ----
    def _api_sandbox_event(self):
        d = self._read_json()
        bd = book_dir(d.get("book") or "")
        if not bd:
            self._send_json(400, {"error": "book_not_found"}); return
        text = str(d.get("text") or "").strip()
        if not text:
            self._send_json(400, {"error": "empty_text"}); return
        if len(text) > 500:
            self._send_json(400, {"error": "text_too_long"}); return
        root = os.path.join(bd, "world_sandbox")
        try:
            os.makedirs(root, exist_ok=True)
            path = os.path.join(root, "events.json")
            try:
                arr = json.load(open(path, "r", encoding="utf-8"))
            except Exception:
                arr = []
            if not isinstance(arr, list):
                arr = []
            arr.append({"t": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "chapter": d.get("chapter"), "text": text, "kind": "god"})
            arr = arr[-200:]
            _save_json_atomic(path, arr)
        except Exception:
            self._send_json(500, {"error": "write_failed"}); return
        self._send_json(200, {"ok": True, "total": len(arr)})

    # ---- 结构树：一次请求拿齐「世界观→角色→章节→模拟稿」的父子层级 ----
    def _api_tree(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        items = scan_world(bd)
        world_children = self._build_world_tree(items)
        ent = world_entities(bd)
        chs = read_chapters(bd, with_content=False)
        sims = list_sims(bd)
        drafts = [s for s in sims if s.get("status") != "used"]
        # 角色 = 角色档案文件 + 人物矩阵提及，去重合并（避免「登记角色=文件数」与树不一致）
        # 有档案文件者带 path，结构树点击可直达角色档案；仅矩阵提及者无 path，点击给出提示。
        role_children, _seen = [], set()
        for r in ent["roles"]:
            if r["name"] in _seen:
                continue
            _seen.add(r["name"])
            role_children.append({"type": "role", "label": r["name"], "path": r["path"]})
        for m in ent["mentions"]:
            if m in _seen:
                continue
            _seen.add(m)
            role_children.append({"type": "role", "label": m})
        role_names = [rc["label"] for rc in role_children]
        nodes = [
            {
                "type": "world", "label": "世界观地基", "icon": "🌍",
                "meta": "%d 个文件 · %dk 字" % (len(items), round(sum(i["words"] for i in items) / 1000)),
                "count": len(items), "open": True, "children": world_children,
            },
            {
                "type": "roles", "label": "角色", "icon": "👥",
                "meta": "%d 位人物" % len(role_names),
                "count": len(role_names), "open": True,
                "children": role_children,
            },
            {
                "type": "chapters", "label": "章节", "icon": "📝",
                "meta": "%d 章 · %dk 字" % (len(chs), round(sum((c.get("wordCount") or 0) for c in chs) / 1000)),
                "count": len(chs), "open": True,
                "children": [{
                    "type": "chapter", "label": ("第%d章 %s" % (c["number"], c.get("title") or "")).strip(),
                    "num": c["number"], "status": c.get("status"), "words": c.get("wordCount") or 0,
                } for c in chs],
            },
            {
                "type": "sims", "label": "模拟稿", "icon": "💡",
                "meta": "%d 份（%d 待审）" % (len(sims), len(drafts)),
                "count": len(sims), "open": True,
                "children": [{
                    "type": "sim", "label": s.get("title") or ("第%d章" % s.get("chapter")),
                    "chapter": s.get("chapter"), "status": s.get("status"),
                } for s in sims],
            },
        ]
        self._send_json(200, {"book": book_title(bd), "nodes": nodes})


    def _build_world_tree(self, items):
        """把 scan_world 的扁平文件列表（path 含 / 层级）组装成嵌套目录树。

        目录节点 type=dir（默认折叠），文件节点 type=file（携带 label/words/path）。
        """
        root = {"type": "dir", "label": "story", "children": []}
        dir_nodes = {"": root}
        for it in sorted(items, key=lambda x: x["path"]):
            rel = it["path"]
            if rel.startswith("story/"):
                rel = rel[len("story/"):]
            parts = rel.split("/")
            acc = ""
            parent = root
            for i, part in enumerate(parts):
                is_file = (i == len(parts) - 1)
                if is_file:
                    parent["children"].append({
                        "type": "file", "label": it["label"], "name": part,
                        "path": it["path"], "words": it.get("words", 0),
                    })
                else:
                    key = (acc + "/" + part) if acc else part
                    if key not in dir_nodes:
                        dn = {"type": "dir", "label": part, "name": part, "open": False, "children": []}
                        dir_nodes[key] = dn
                        parent["children"].append(dn)
                    parent = dir_nodes[key]
                    acc = key
        return root["children"]


    # ---- 剧情模拟：列表 ----
    def _api_simulations(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        sims = list_sims(bd)
        # 列表瘦身：正文截断预览，详情由前端按需展开（全文已在 content 内，前端本地即可）
        self._send_json(200, {"simulations": sims})

    # ---- 剧情模拟：生成（SSE 流式推演，不写正文）----
    def _api_simulate(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        mode = d.get("mode") or "guided"
        if mode not in ("auto", "guided", "drama"):
            mode = "guided"
        guidance = (d.get("guidance") or "").strip()  # 用户对本次推演的导向要求（可空）
        # 执法力度：report=只报不改 / local=本地机修(信息量不减) / full=机修+LLM定点补丁。
        # auto 系统自推默认只报不改，除非作者显式要求修。
        req_police = d.get("police")
        if req_police not in ("report", "local", "full"):
            police = "report" if mode == "auto" else "local"
        else:
            police = req_police
        r = begin_task("simulate", os.path.basename(bd), "剧情推演")
        if r is not True:
            self._send_json(409, {
                "error": "budget" if r == "budget" else "busy",
                "task": task_snapshot(),
                "msg": ("余额不足 ¥0.5，无法发起生成。请在「用量花费」页重置计数（账户充值需到 DeepSeek 平台）。"
                        if r == "budget" else "已有生成任务在进行中，请等它完成"),
            })
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        target = d.get("chapter")
        emit({"stage": "start",
              "chapter": target if isinstance(target, int) and target > 0 else None,
              "mode": mode})
        try:
            if mode == "drama":
                cast = d.get("cast")
                try:
                    scenes_max = max(1, min(int(d.get("scenes") or 3), 5))
                except Exception:
                    scenes_max = 3
                sim, err = _drama_core(bd, guidance, target,
                                       lambda ev: emit(ev), cast, scenes_max)
            else:
                sim, err = _simulate_core(bd, mode, guidance, target,
                                          lambda delta: emit({"delta": delta}))
            if err:
                emit({"stage": "error", "msg": err})
                return
            sim = _apply_sim_quality(sim, bd, police)
            save_sim(bd, sim)
            emit({"stage": "done", "sim": sim, "source": sim.get("source")})
        finally:
            end_task()

    # ---- 纯本地质检端点（零 LLM）：反 AI 腔执法报告 ----
    def _api_audit(self):
        d = self._read_json()
        text = d.get("text") or ""
        if not text:
            self._send_json(400, {"error": "text_required"})
            return
        hits = _audit_scan(text)
        repaired, residue, log = _audit_repair(text)
        kill, n, dens = _audit_verdict(repaired)
        self._send_json(200, {
            "hits": [[h[0], h[1], h[2]] for h in hits],
            "log": log, "residue": [[h[0], h[2]] for h in residue],
            "repaired": repaired,
            "verdict": {"kill": kill, "n": n, "density": dens},
        })

    # ---- 纯本地质检端点（零 LLM）：数目账对账 ----
    def _api_ledger_check(self):
        d = self._read_json()
        text = d.get("text") or ""
        book = d.get("book") or self._book_param()
        if not text:
            self._send_json(400, {"error": "text_required"})
            return
        rows = []
        bd = book_dir(book) if book else None
        if bd:
            try:
                lt = read_world_file(bd, "story/particle_ledger.md") or read_world_file(bd, "particle_ledger.md")
                if lt:
                    rows = _ledger_parse(lt)
            except Exception:
                rows = []
        facts = _ledger_facts(text)
        cf = _ledger_conflicts(facts, rows) if rows else []
        self._send_json(200, {
            "facts": [{"noun": f["noun"], "unit": f["unit"], "qty": f["qty"], "sent": f["sent"]} for f in facts],
            "conflicts": [{"new": "%s%s=%d" % (f["noun"], f["unit"], f["qty"]),
                           "book": "%s=%d" % (r["note"], r["qty"]),
                           "sent": f["sent"]} for f, r in cf[:10]],
            "book": book,
        })

    # ---- 数目账：只读模块化视图（零 LLM）。UI 规范 N01：数据型信息必须结构化呈现，
    #      前端禁止把 particle_ledger.md 原文整段直糊；本端点提供行级结构。 ----
    def _api_ledger_view(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        path = "story/particle_ledger.md"
        lt = read_world_file(bd, path) or read_world_file(bd, "particle_ledger.md")
        if not lt:
            self._send_json(200, {"rows": [], "total": 0, "path": path, "exists": False})
            return
        try:
            rows = _ledger_table(lt)
        except Exception:
            rows = []
        self._send_json(200, {"rows": rows, "total": len(rows), "path": path, "exists": True})

    # ---- 首章推演：建书后、动笔前的第 1 章作战方案 ----
    def _api_first_chapter(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        if KEY_STATUS != "ok" or not API_KEY:
            self._send_json(503, {"error": "api_key_unavailable", "detail": KEY_STATUS})
            return
        r = begin_task("simulate", os.path.basename(bd), "首章推演")
        if r is not True:
            self._send_json(409, {
                "error": "budget" if r == "budget" else "busy",
                "task": task_snapshot(),
                "msg": ("余额不足 ¥0.5，无法发起推演。请在「用量花费」页重置计数（账户充值需到 DeepSeek 平台）。"
                        if r == "budget" else "已有生成任务在进行中，请等它完成"),
            })
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        emit({"stage": "start", "chapter": 1, "mode": "first"})
        try:
            sim, err = _first_chapter_core(bd, lambda delta: emit({"delta": delta}))
            if err:
                emit({"stage": "error", "msg": err})
                return
            save_sim(bd, sim)
            emit({"stage": "done", "sim": sim, "source": "first"})
        finally:
            end_task()

    # ---- 剧情模拟：保存（实时删改）----
    def _api_simulation_save(self):
        d = self._read_json()
        bd = book_dir(d.get("book") or "")
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        sim = load_sim(bd, d.get("id") or "")
        if not sim:
            self._send_json(404, {"error": "sim_not_found"})
            return
        if sim.get("status") == "used":
            self._send_json(400, {"error": "sim_locked", "msg": "已采用的模拟稿不可再编辑"})
            return
        if isinstance(d.get("content"), str):
            sim["content"] = d["content"]
        if isinstance(d.get("title"), str) and d["title"].strip():
            sim["title"] = d["title"].strip()
        sim["godTouched"] = True   # 作者审阅/删改 = 上帝介入
        sim["updatedAt"] = int(time.time() * 1000)
        if not save_sim(bd, sim):
            self._send_json(500, {"error": "save_failed"})
            return
        self._send_json(200, {"ok": True, "sim": sim})

    # ---- 剧情模拟：删除 ----
    def _api_simulation_delete(self):
        d = self._read_json()
        bd = book_dir(d.get("book") or "")
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        if not delete_sim(bd, d.get("id") or ""):
            self._send_json(404, {"error": "sim_not_found"})
            return
        self._send_json(200, {"ok": True})

    # ---- 剧情模拟：采用并创作（SSE：--context-file 强约束注入正文生成）----
    def _api_simulation_adopt(self):
        d = self._read_json()
        bd = book_dir(d.get("book") or "")
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        sim = load_sim(bd, d.get("id") or "")
        if not sim:
            self._send_json(404, {"error": "sim_not_found"})
            return
        if sim.get("status") == "used":
            self._send_json(400, {"error": "sim_locked", "msg": "该模拟稿已被采用过"})
            return
        bid = os.path.basename(bd)
        # 采用前校验章节号仍是"下一章"（避免过期稿错位写章）
        chs = read_chapters(bd, with_content=False)
        expect = (int(chs[-1].get("number") or len(chs)) + 1) if chs else 1
        if int(sim.get("chapter") or 0) != expect:
            self._send_json(409, {
                "error": "chapter_mismatch",
                "msg": "模拟稿针对第%s章，但当前应写第%d章。请重新生成模拟。" % (sim.get("chapter"), expect),
            })
            return
        ctx_file = os.path.join(sims_dir(bd), "adopt_%s.md" % sim["id"])
        try:
            with open(ctx_file, "w", encoding="utf-8") as f:
                f.write(
                    "【本章剧情已由作者审定，必须严格按以下模拟稿执行，"
                    "不得偏离主线事件、人物动态与章末悬念】\n\n" + (sim.get("content") or "")
                )
        except Exception as e:
            self._send_json(500, {"error": "ctx_write_failed", "detail": str(e)})
            return
        r = begin_task("adopt", bid, "创作第%s章" % sim["chapter"])
        if r is not True:
            self._send_json(409, {
                "error": "budget" if r == "budget" else "busy",
                "task": task_snapshot(),
                "msg": ("余额不足 ¥0.5，无法发起创作。请在「用量花费」页重置计数（账户充值需到 DeepSeek 平台）。"
                        if r == "budget" else "已有生成任务在进行中，请等它完成"),
            })
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        try:
            emit({"stage": "start", "book": bid, "chapter": sim["chapter"]})
            rc, out = run_inkos(["write", "next", bid, "--context-file", ctx_file],
                                lambda line: emit({"line": line}))
        finally:
            end_task()
        if rc == 0:
            # 创作完成复核：章节数应 +1，避免 inkos 返回 0 但正文并未落盘，
            # 导致模拟稿被误标「已采用」、章节却缺失的脏状态。
            before = expect - 1  # 采用前应有的章节数
            after = len(read_chapters(bd, with_content=False))
            if after >= before + 1:
                sim["status"] = "used"
                sim["usedAt"] = int(time.time() * 1000)
                sim["godTouched"] = True   # 采用即上帝介入，决定此未来成为正史
                sim["decidedBy"] = "author"
                save_sim(bd, sim)
                emit({"stage": "verified", "chapter": sim["chapter"]})
            else:
                emit({"stage": "error",
                      "msg": "创作返回成功但章节未落盘（期望第%d章，实际仅%d章），请检查引擎日志后重试。已保留模拟稿。" % (expect, after)})
                rc = 1
        try:
            os.remove(ctx_file)
        except Exception:
            pass
        emit({"stage": "done", "returncode": rc, "book": bid, "chapter": sim["chapter"]})

    # ---- 自动推演：开关与状态 ----
    def _api_auto_sim(self):
        if self.command == "POST":
            d = self._read_json()
            want = bool(d.get("enabled"))
            with AUTO_SIM_LOCK:
                AUTO_SIM_STATE["enabled"] = want
            self._send_json(200, _api_auto_sim_state())
        else:
            self._send_json(200, _api_auto_sim_state())

    # ---- 生成（SSE 流式）----
    def _api_generate(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        bid = os.path.basename(bd)
        mode = d.get("mode", "next")
        target = d.get("target")
        chapter = d.get("chapter")
        if mode == "auto":
            args = ["auto", bid, str(target or (d.get("targetChapters") or 3))]
        elif mode == "next":
            args = ["write", "next", bid]
        elif mode == "rewrite":
            args = ["write", "rewrite", bid, str(chapter)]
        else:
            self._send_json(400, {"error": "unknown_mode"})
            return
        r = begin_task("generate", bid, "生成（%s）" % mode)
        if r is not True:
            self._send_json(409, {
                "error": "budget" if r == "budget" else "busy",
                "task": task_snapshot(),
                "msg": ("余额不足 ¥0.5，无法发起生成。请在「用量花费」页重置计数（账户充值需到 DeepSeek 平台）。"
                        if r == "budget" else "已有生成任务在进行中，请等它完成"),
            })
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        try:
            emit({"stage": "start", "mode": mode, "book": bid, "args": args})
            rc, out = run_inkos(args, lambda line: emit({"line": line}))
        finally:
            end_task()
        emit({"stage": "done", "returncode": rc, "book": bid})

    # ---- 导出（SSE 流式）----
    def _api_export(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        bid = os.path.basename(bd)
        title = book_title(bd)
        fmt = d.get("format", "md")
        if not isinstance(fmt, str) or fmt.lower() not in ("txt", "md", "epub"):
            self._send_json(400, {"error": "unsupported_export_format", "allowed": ["txt", "md", "epub"]})
            return
        fmt = fmt.lower()
        rel = "export/%s.%s" % (safe_file_stem(title), fmt)
        out_path = safe_rel(bd, rel)
        if not out_path:
            self._send_json(400, {"error": "invalid_export_path"})
            return
        try:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
        except Exception as e:
            self._send_json(500, {"error": "export_directory_failed", "detail": str(e)})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        emit({"stage": "start", "format": fmt, "book": bid})
        rc, out = run_inkos(["export", bid, "--format", fmt, "--output", out_path],
                            lambda line: emit({"line": line}))
        emit({"stage": "done", "returncode": rc, "path": out_path, "rel": rel, "book": bid})

    # ---- 回收站：清单 ----
    def _api_trash(self):
        self._send_json(200, {"items": load_trash()})

    # ---- 回收站：软删除章节 ----
    def _api_chapter_delete(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        try:
            num = int(d.get("number"))
        except Exception:
            self._send_json(400, {"error": "bad_num"})
            return
        item, err = _trash_chapter(bd, num)
        if err:
            self._send_json(404 if err == "not_found" else 400, {"error": err})
            return
        items = load_trash()
        items.append(item)
        save_trash(items)
        self._send_json(200, {"ok": True, "item": item})

    # ---- 回收站：软删除书本 ----
    def _api_book_delete(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found", "book": book})
            return
        item, err = _trash_book(bd)
        if err:
            self._send_json(400, {"error": err})
            return
        items = load_trash()
        items.append(item)
        save_trash(items)
        self._send_json(200, {"ok": True, "item": item})

    # ---- 回收站：恢复（回滚） ----
    def _api_trash_restore(self):
        d = self._read_json()
        ok, err = _restore_trash(d.get("id") or "")
        if not ok:
            code = 404 if err == "not_found" else 400
            msg = {
                "book_exists": "该书已存在（可能已重新创建），无法恢复",
                "chapter_exists": "该章号已存在（可能已重新生成），请先处理冲突再恢复",
                "book_missing": "原书目录已不可见，无法恢复该章节",
            }.get(err, err)
            self._send_json(code, {"error": err, "msg": msg})
            return
        self._send_json(200, {"ok": True})

    # ---- 回收站：永久删除 ----
    def _api_trash_purge(self):
        d = self._read_json()
        ok, err = _purge_trash(d.get("id") or "")
        if not ok:
            self._send_json(404 if err == "not_found" else 400, {"error": err})
            return
        self._send_json(200, {"ok": True})

    # ---- 回收站：清空 ----
    def _api_trash_empty(self):
        for it in load_trash():
            trash_full = os.path.join(BOOK_ROOT, it["trashPath"])
            try:
                if it["kind"] == "book":
                    if os.path.isdir(trash_full):
                        shutil.rmtree(trash_full)
                    elif os.path.exists(trash_full):
                        os.remove(trash_full)
                else:
                    if os.path.exists(trash_full):
                        os.remove(trash_full)
            except Exception:
                pass
        save_trash([])
        self._send_json(200, {"ok": True})

    # ---- SOP 作战室：规则资产 ----
    def _api_sop_rules(self):
        self._send_json(200, SOP_RULES)

    # ---- SOP 作战室：变现里程碑 + 日更节奏 ----
    def _api_sop_milestones(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        chs = read_chapters(bd, with_content=False)
        total_words = sum((c.get("wordCount") or 0) for c in chs)
        ch_count = len(chs)
        # 读取 book.json 补充字段
        bj = {}
        try:
            bj = json.load(open(os.path.join(bd, "book.json"), "r", encoding="utf-8"))
        except Exception:
            pass
        has_cover = bool(bj.get("cover"))
        track = bj.get("track", "")
        benchmark = bj.get("benchmark", "")
        target_words = bj.get("targetWordCount", 0)
        # 日更节奏：从章节 createdAt 计算
        days = {}
        for c in chs:
            ts = c.get("createdAt", "")
            if ts and len(ts) >= 10:
                d = ts[:10]  # YYYY-MM-DD
                days[d] = days.get(d, 0) + (c.get("wordCount") or 0)
        sorted_days = sorted(days.items(), reverse=True)
        # 连续更新天数
        streak = 0
        from datetime import date, timedelta
        today = date.today()
        for i in range(30):
            d = (today - timedelta(days=i)).isoformat()
            if d in days:
                streak += 1
            elif i > 2:  # 最近3天哪天没更就断
                break
        # 近7日均值
        last7_total = sum(days.get((today - timedelta(days=i)).isoformat(), 0) for i in range(7))
        avg_daily = round(last7_total / 7) if last7_total else 0
        # 里程碑计算
        stages = []
        rules = SOP_RULES.get("milestones", [])
        for m in rules:
            th = m.get("thresholdWords", 0)
            pct = min(100, round(total_words / th * 100)) if th else 0
            stage = {
                "id": m["id"],
                "label": m["label"],
                "emoji": m.get("emoji", ""),
                "threshold": th,
                "current": total_words,
                "percent": pct,
                "met": total_words >= th,
                "details": m.get("details", ""),
            }
            if m["id"] == "recommend":
                req = m.get("requirements", {})
                stage["requirements"] = {
                    "minWords": total_words >= req.get("minWords", 80000),
                    "hasCover": has_cover,
                    "dailyUpdate": avg_daily >= req.get("dailyUpdate", 4000),
                    "consecutive": streak >= req.get("consecutiveDays", 3),
                }
                stage["met"] = (total_words >= req.get("minWords", 80000)
                               and has_cover
                               and avg_daily >= req.get("dailyUpdate", 4000)
                               and streak >= req.get("consecutiveDays", 3))
            elif m["id"] == "debut":
                stage["requirements"] = {"chapter2_50pct": "manual check",
                                         "readRate100k_20pct": "manual check"}
            elif m["id"] == "full-attendance":
                req = m.get("requirements", {})
                stage["requirements"] = {
                    "dailyMinWords": avg_daily >= req.get("dailyMinWords", 4000),
                    "noMissDays_streak": streak >= req.get("noMissDays", 30),
                }
            stages.append(stage)
        self._send_json(200, {
            "book": book_title(bd),
            "totalWords": total_words,
            "chapterCount": ch_count,
            "stages": stages,
            "cadence": {
                "streak": streak,
                "avgDailyWords": avg_daily,
                "last7Total": last7_total,
            },
            "track": track,
            "benchmark": benchmark,
            "targetWordCount": target_words,
            "hasCover": has_cover,
        })

    # ---- SOP 作战室：红线扫描 ----
    def _api_sop_redline(self):
        bd = book_dir(self._book_param())
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        chs = read_chapters(bd, with_content=False)
        rules = SOP_RULES.get("redlines", {})
        ai_pitfalls = SOP_RULES.get("aiPitfalls", {})
        # 收集所有需要扫描的关键词
        keyword_map = {}  # type -> keyword -> severity_label
        for rid, r in rules.items():
            for kw in r.get("keywords", []):
                keyword_map.setdefault(kw.lower(), {"type": rid, "label": r.get("label", rid),
                                                     "severity": r.get("severity", "warning")})
        chapter_results = []
        total_critical, total_warning = 0, 0
        for c in chs:
            content = ""
            if c.get("file"):
                try:
                    content = open(os.path.join(bd, "chapters", c["file"]), "r",
                                   encoding="utf-8").read()
                except Exception:
                    content = ""
            hits = []
            body_lower = content.lower()
            scanned = set()
            for kw, info in sorted(keyword_map.items()):
                if kw in scanned:
                    continue
                scanned.add(kw)
                count = body_lower.count(kw)
                if count > 0:
                    hits.append({
                        "type": info["type"],
                        "label": info["label"],
                        "severity": info["severity"],
                        "keyword": kw,
                        "count": count,
                    })
                    if info["severity"] == "critical":
                        total_critical += count
                    else:
                        total_warning += count
            # 检测重复句子（注水 / 逻辑崩坏启发式）
            if content:
                sentences = [s.strip() for s in re.split(r'[。！？\n]', content) if len(s.strip()) > 10]
                from collections import Counter
                sent_counts = Counter(sentences)
                repeat_hits = [(s, cnt) for s, cnt in sent_counts.most_common(3) if cnt >= 3]
                for s, cnt in repeat_hits:
                    hits.append({
                        "type": "repetition",
                        "label": ai_pitfalls.get("repetition", {}).get("label", "重复注水"),
                        "severity": ai_pitfalls.get("repetition", {}).get("severity", "warning"),
                        "keyword": s[:40],
                        "count": cnt,
                    })
                    total_warning += cnt
            chapter_results.append({
                "number": c["number"],
                "title": c.get("title", ""),
                "wordCount": c.get("wordCount", 0),
                "hits": hits,
            })
        self._send_json(200, {
            "chapters": chapter_results,
            "summary": {"criticalHits": total_critical, "warningHits": total_warning},
            "redlines": {rid: {"label": r.get("label", rid), "severity": r.get("severity", "warning"),
                               "description": r.get("description", "")}
                         for rid, r in rules.items()},
            "aiPitfalls": {pid: {"label": p.get("label", pid), "severity": p.get("severity", "warning"),
                                 "description": p.get("description", "")}
                           for pid, p in ai_pitfalls.items()},
        })

    # ---- 书本赛道设置 ----
    def _api_book_track(self):
        d = self._read_json()
        book = d.get("book") or self._book_param()
        bd = book_dir(book)
        if not bd:
            self._send_json(400, {"error": "book_not_found"})
            return
        try:
            bj = json.load(open(os.path.join(bd, "book.json"), "r", encoding="utf-8"))
        except Exception:
            bj = {}
        for key in ("track", "benchmark", "targetWordCount", "genre", "platform", "cover"):
            if key in d:
                bj[key] = d[key]
        with open(os.path.join(bd, "book.json"), "w", encoding="utf-8") as f:
            json.dump(bj, f, ensure_ascii=False, indent=2)
        self._send_json(200, {"ok": True})

    # ---- API Key 设置 / 清除（工作台内直接配置，DPAPI 加密落盘 + 热更新内存） ----
    def _api_key(self):
        global API_KEY, KEY_STATUS
        d = self._read_json()
        action = d.get("action") or "set"
        if action == "clear":
            try:
                if os.path.exists(KEY_PATH):
                    os.remove(KEY_PATH)
            except Exception:
                pass
            API_KEY = None
            KEY_STATUS = "missing"
            broadcast()
            self._send_json(200, {"ok": True, "key_status": KEY_STATUS})
            return
        key = (d.get("key") or "").strip()
        if not key:
            self._send_json(400, {"error": "key_required", "msg": "请输入 API Key"})
            return
        try:
            from crypto_dpapi import encrypt_bytes
            blob = base64.b64encode(encrypt_bytes(key.encode("utf-8")))
            with open(KEY_PATH, "wb") as f:
                f.write(blob)
            API_KEY = key
            KEY_STATUS = "ok"
        except Exception as e:
            self._send_json(500, {"error": "encrypt_failed", "detail": "%s: %s" % (type(e).__name__, e)})
            return
        broadcast()
        self._send_json(200, {"ok": True, "key_status": "ok"})

    # ---- 代理转发 ----
    def _forward(self, method, body):
        path = urllib.parse.urlsplit(self.path).path
        if method != "POST" or path not in UPSTREAM_ROUTES["POST"]:
            return self._forward_unreserved(method, body)
        if KEY_STATUS != "ok" or not API_KEY:
            return self._forward_unreserved(method, body)
        try:
            req_json = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "invalid_chat_request"})
            return
        if not isinstance(req_json, dict):
            self._send_json(400, {"error": "invalid_chat_request"})
            return
        model = req_json.get("model", "deepseek-v4-flash")
        if not isinstance(model, str) or not model:
            self._send_json(400, {"error": "invalid_model"})
            return
        limits = []
        changed = False
        for key in ("max_tokens", "max_completion_tokens"):
            if key in req_json:
                value = req_json[key]
                if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                    self._send_json(400, {"error": "invalid_max_tokens", "max": MAX_OUTPUT_TOKENS})
                    return
                if value > MAX_OUTPUT_TOKENS:
                    req_json[key] = MAX_OUTPUT_TOKENS
                    changed = True
                limits.append(req_json[key])
        if not limits:
            req_json["max_tokens"] = 16000
            limits.append(16000)
            changed = True
        if changed:
            body = json.dumps(req_json, ensure_ascii=False).encode("utf-8")
        max_tokens = max(limits)
        reservation = reserve_request_budget(model, len(body or b"{}"), max_tokens)
        if reservation is None:
            self._send_json(409, {"error": "budget", "msg": "可用余额不足以预留本次请求费用上限"})
            return
        try:
            return self._forward_unreserved(method, body)
        finally:
            release_request_budget(reservation)

    def _forward_unreserved(self, method, body):
        global API_KEY
        fwd_path = urllib.parse.urlsplit(self.path).path
        sys.stderr.write("[monitor] FWD %s %s\n" % (method, fwd_path))
        sys.stderr.flush()
        if fwd_path not in UPSTREAM_ROUTES.get(method, set()):
            self._send_json(404, {"error": "upstream_route_not_allowed"})
            return
        try:
            target = _upstream_url(fwd_path)
        except ValueError:
            self._send_json(500, {"error": "invalid_upstream_config"})
            return
        if KEY_STATUS != "ok" or not API_KEY:
            self._send_json(503, {"error": "api_key_unavailable", "detail": KEY_STATUS})
            return

        # 解析请求体，便于为流式补全 usage
        req_json = None
        if body:
            try:
                req_json = json.loads(body.decode("utf-8"))
            except Exception:
                req_json = None

        is_chat = "/chat/completions" in fwd_path
        is_stream = False
        if isinstance(req_json, dict):
            is_stream = bool(req_json.get("stream"))
            so = req_json.get("stream_options")
            if not isinstance(so, dict):
                so = {}
            if is_chat and is_stream and not so.get("include_usage"):
                so["include_usage"] = True
                req_json["stream_options"] = so
                body = json.dumps(req_json).encode("utf-8")

        # 转发头（剔除逐跳头与上游会重写的鉴权头）
        # 关键：不能把客户端的 Accept-Encoding（gzip/br...）透传给上游。上游会据此
        # 返回压缩字节，而本代理的 SSE 转发不带 Content-Encoding 响应头，客户端
        # （inkos 的 fetch）会把压缩流当 UTF-8 文本解析，表现为乱码/解析失败。
        headers = {}
        for k in self.headers.keys():
            lk = k.lower()
            if lk in ("host", "content-length", "connection", "transfer-encoding",
                      "authorization", "accept-encoding"):
                continue
            headers[k] = self.headers[k]
        headers["Accept-Encoding"] = "identity"
        # 始终用内存中的真实 Key 覆盖
        headers["Authorization"] = "Bearer " + API_KEY

        try:
            req = urllib.request.Request(target, data=body if method == "POST" else None, method=method, headers=headers)
        except Exception as e:
            self._send_json(400, {"error": "bad_request", "detail": str(e)})
            return

        try:
            resp = UPSTREAM_OPENER.open(req, timeout=300)
        except urllib.error.HTTPError as e:
            err_body = e.read()
            self._send_bytes(e.code, err_body, e.headers.get("Content-Type", "application/json"))
            return
        except Exception as e:
            self._send_json(502, {"error": "upstream_unreachable", "detail": str(e)})
            return

        ct = resp.headers.get("Content-Type", "")
        if "text/event-stream" in ct:
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                model = req_json.get("model", "unknown") if isinstance(req_json, dict) else "unknown"
                # resp.read(n) 由 http.client 去除 chunked framing 后返回 SSE 字节。
                buf = b""
                captured = False
                client_connected = True
                while True:
                    chunk = resp.read(4096)
                    if not chunk:
                        break
                    if client_connected:
                        try:
                            self.wfile.write(chunk)
                            self.wfile.flush()
                        except Exception:
                            # 客户端断开后仍读完上游，以尽量捕获最终 usage 帧。
                            client_connected = False
                    if not captured:
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            s = line.decode("utf-8", "replace").rstrip("\r")
                            if s.startswith("data:"):
                                payload = s[5:].strip()
                                if payload and payload != "[DONE]":
                                    try:
                                        d = json.loads(payload)
                                        u = extract_usage(d)
                                        if u:
                                            record_usage(d.get("model", model), *u)
                                            captured = True
                                    except Exception:
                                        pass
            finally:
                resp.close()
            return
        try:
            data = resp.read()
        finally:
            resp.close()
        try:
            d = json.loads(data.decode("utf-8"))
            u = extract_usage(d)
            if u:
                model = d.get("model", req_json.get("model", "unknown") if isinstance(req_json, dict) else "unknown")
                record_usage(model, *u)
        except Exception:
            pass
        self._send_bytes(resp.status, data, ct or "application/json")


# ----------------------------- 主入口 -----------------------------
def main():
    load_config()
    validate_config()
    load_usage()
    load_key()
    port = configured_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    # 先成功绑定端口，再启动守护线程，避免启动失败留下未收尾后台工作。
    threading.Thread(target=_auto_sim_loop, name="auto-sim", daemon=True).start()
    sys.stdout.write("[monitor] listening on http://127.0.0.1:%d  key=%s\n" % (port, KEY_STATUS))
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _terminate_active_processes()
        server.server_close()


if __name__ == "__main__":
    main()
