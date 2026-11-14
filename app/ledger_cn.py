# -*- coding: utf-8 -*-
"""ledger_cn.py —— 数目账本地对账（创世自研版）。

借鉴 NEST-DRAMA 数目账思路：正文里说出口的数字从此是事实——"同一所指同一单位
数量不同 = 冲突"，除非角色是明着质疑/改口（由作者裁定豁免）。
但账本文件沿用创世已有的 story/particle_ledger.md（Markdown 表格），不引入新格式。

功能（全部本地、零 LLM 消耗）：
  parse_ledger(md_text)   -> rows[{noun, unit, qty, note}]  解析 md 表格
  num_facts(text)         -> facts[{noun, unit, qty, raw, sent}]  从正文抽"数字+单位+所指"
  conflicts(facts, rows)  -> [(新事实, 账上条目)]  同指同单位数量不同
  注：数字支持阿拉伯数字与中文数字（万/千/百/十）；所指取数字前后最近名词短语。
"""
from __future__ import annotations

import re

_CN_DIG = {"零": 0, "〇": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4,
           "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
_CN_UNIT = {"十": 10, "百": 100, "千": 1000, "万": 10000, "亿": 100000000}

_NOUN_BOUND = re.compile(r"[，。；！？!?,:：\n\"“”『』「」]")
_STOP_POS = "的地得在了着与和或是但很更最都也已经我你他她它们你们这那之其"
# 名词前的副词性前导（数量语义中不计入所指）
_LEAD_ADV = ("共", "总", "约", "近", "余", "多", "整", "足", "只", "就", "才", "刚", "足足")
# 货币/通货词前缀：单字中文数字后须紧跟量词或这类词才算数目（杜绝"一共有/看了一眼"误抽）
_CURRENCY = ("金币", "银币", "铜钱", "铜板", "灵石", "元宝", "银子", "银票", "金票", "魔核币")
# 数字后置量词时，回看数字前最近的名词作为所指（"魔核一颗卖了…"→ 魔核）
_VERB_HEAD = ("卖", "拿", "给", "说", "走", "来", "去", "看", "是", "要", "有", "交", "扔",
              "抱", "带", "背", "提", "拎", "藏", "取", "装", "吞", "吃", "喝", "用", "使",
              "放", "摸", "抓", "捏", "指", "点", "答", "回", "望", "转", "收", "付", "递",
              "推", "拉", "砍", "杀", "打", "斗", "躲", "逃", "喊", "叫")


def cn2int(s):
    """中文数字转 int，失败返回 None（如 '五百二十' -> 520）。"""
    s = s.strip()
    if not s:
        return None
    if re.fullmatch(r"[0-9.]+", s):
        try:
            return int(float(s))
        except Exception:
            return None
    total, num, unit, section = 0, 0, 1, 0
    for ch in s:
        if ch in _CN_DIG:
            num = _CN_DIG[ch]
        elif ch in _CN_UNIT:
            unit = _CN_UNIT[ch]
            if unit >= 10000:
                total = (total + num) * unit
                section = 0
            else:
                section += num * unit if num else unit
            num = 0
        else:
            return None
    return total + section + num


def _unit_of(text, end):
    """数字后的单位 token（枚/颗/两/人/里…），无则空。"""
    m = re.match(r"(万两|万金|万枚|万颗|两|枚|颗|粒|个|只|头|匹|把|柄|件|套|副|斤|斗|石|"
                 r"贯|文|里|丈|尺|寸|年|月|日|天|夜|刻|时|次|回|遍|招|层|重|品|阶|星|道|座|"
                 r"间|门|块|滴|坛|壶|瓶|碗|车|人|名|圈|株|本|页)", text[end:])
    return m.group(1) if m else ""


def _iter_numbers(text):
    """产出 (start, end, value)。中文数字整段收集（'三百二十' -> 320）。
    单字中文数字（一/二/…）必须后跟量词或货币词才算数目，避免"一共有/看了一眼"误抽。"""
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isdigit():
            j = i
            while j < n and (text[j].isdigit() or text[j] == "."):
                j += 1
            try:
                v = int(float(text[i:j]))
            except Exception:
                v = None
            yield i, j, v
            i = j
            continue
        if ch in _CN_DIG or ch in _CN_UNIT:
            j = i
            while j < n and (text[j] in _CN_DIG or text[j] in _CN_UNIT):
                j += 1
            raw = text[i:j]
            single_cn = len(raw) == 1
            if single_cn:
                nxt = text[j:j + 2]
                if not (_unit_of(text, j) or any(nxt.startswith(c) for c in _CURRENCY)):
                    i = j
                    continue
            v = cn2int(raw)
            yield i, j, v
            i = j
            continue
        i += 1


def _lookahead_noun(text, end, max_len=8):
    """从 end 向后取名词短语（跳停用词/标点），去掉副词性前导。"""
    seg = re.split(_NOUN_BOUND, text[end:end + max_len + 2], maxsplit=1)[0]
    out = []
    for c in seg:
        if c in _STOP_POS or c in "，。；！？!?:：、\n":
            break
        out.append(c)
    noun = "".join(out)[:6]
    for adv in _LEAD_ADV:
        if noun.startswith(adv) and len(noun) > len(adv):
            noun = noun[len(adv):]
            break
    return noun


def _lookback_noun(text, start, max_len=8):
    """从 start 向前取最近名词短语（用于"魔核一颗"这类数字后置结构）。
    尾部剪掉"还剩/总共/需要"等数量性后补动词，保留真正所指（赤目狼魔核还剩两颗→赤目狼魔核）。"""
    seg = text[max(0, start - max_len - 2):start]
    seg = re.split(_NOUN_BOUND, seg, maxsplit=1)[-1]
    out = []
    for c in reversed(seg):
        if c in _STOP_POS or c in "，。；！？!?:：、\n":
            break
        out.append(c)
    noun = "".join(reversed(out))[:6]
    for tail in ("还剩", "剩下", "还有", "仍剩", "另有", "总共", "总计", "共有", "需要",
                 "还剩有", "仍", "另", "共", "需", "还", "欠", "借", "花去", "花了"):
        if noun.endswith(tail) and len(noun) > len(tail):
            noun = noun[: -len(tail)]
            break
    return noun


def num_facts(text):
    """从正文抽数目事实。返回 [{noun, unit, qty, raw, sent}]。"""
    facts = []
    for s, e, v in _iter_numbers(text):
        if v is None:
            continue
        unit = _unit_of(text, e)
        noun = _lookahead_noun(text, e + len(unit))
        if not noun or noun[0] in _VERB_HEAD:
            back = _lookback_noun(text, s)
            if back:
                noun = back
        if not noun and not unit:
            continue
        if len(noun) <= 1 and not unit:
            continue
        ls = text.rfind("\n", 0, s) + 1
        le = text.find("\n", s)
        if le < 0:
            le = len(text)
        sent = text[ls:le][:60]
        facts.append({"noun": noun, "unit": unit, "qty": v,
                      "raw": text[s:e], "sent": sent.strip()})
    return facts


def parse_ledger(md_text):
    """解析创世 particle_ledger.md 表格 → [{noun, unit, qty, note}]。
    条目（含括号备注如 金币（总））整体作 noun——比对时"金币"⊂"金币（总）"仍可命中，
    unit 留空表示不确定单位（此时冲突判定只看所指与数量）。"""
    rows = []
    for line in (md_text or "").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2 or not cells[0]:
            continue
        head = cells[0].replace("**", "")
        if "条目" in head and "期初" in "".join(cells):
            continue
        if set(head) <= {"-", " ", "|"}:
            continue
        nums = re.findall(r"\d+(?:\.\d+)?", "|".join(cells[1:4]))
        if not nums:
            continue
        # 优先取「期末」列（index 4）为已确立基准，无则回退「期初」
        qty = None
        if len(cells) >= 5:
            m5 = re.search(r"\d+(?:\.\d+)?", cells[4])
            if m5:
                qty = int(float(m5.group(0)))
        if qty is None:
            qty = int(float(nums[0]))
        noun = re.sub(r"^[-*]\s*", "", head).strip()
        if not noun:
            continue
        rows.append({"noun": noun, "unit": "", "qty": qty, "note": head})
    return rows


def ledger_table(md_text):
    """只读视图解析：把 particle_ledger.md 表格逐行结构化，保留每列**原值字符串**。

    与 parse_ledger 的分工：
      · parse_ledger —— 对账语义（期末优先强转 int，供冲突判定 / 注入提示）；
      · ledger_table —— 展示语义（忠实保留 ~420 / 未清点 / 3（随身）等歧义原串，
        不做数值强转，避免 UI 呈现误导），专供只读模块化展示端点。

    rows = [{name, cols:{begin,inc,spend,end,note}}]，自动跳过表头 / 分隔线 / 非表格行。
    （创世 UI 规范 N01：数据型只读信息必须结构化呈现，禁止把 md 原文整段直糊。）
    """
    rows = []
    for line in (md_text or "").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2 or not cells[0]:
            continue
        if re.fullmatch(r"[:\|\s-]+", "|".join(cells)):  # 分隔线行
            continue
        head = cells[0].replace("**", "").strip()
        if not head:
            continue
        if ("条目" in head) and ("期初" in "|".join(cells)):  # 表头行
            continue
        name = re.sub(r"^[-*]\s*", "", head).strip()
        if not name:
            continue

        def _col(i):
            return cells[i] if len(cells) > i else ""

        rows.append({
            "name": name,
            "cols": {"begin": _col(1), "inc": _col(2), "spend": _col(3),
                     "end": _col(4), "note": _col(5)},
        })
    return rows


def _same_ref(a_noun, b_noun):
    x, y = a_noun, b_noun
    return x == y or (len(x) >= 2 and x in y) or (len(y) >= 2 and y in x)


def conflicts(facts, rows):
    """新稿数目 vs 账本：同指同数量不同 → 冲突。返回 [(fact, row)]。
    账上单位留空即只按所指+数量比对（同一物品换数即嫌疑，交由作者裁定豁免）。"""
    out = []
    for f in facts:
        for r in rows:
            if r.get("unit") and f["unit"] and r["unit"] != f["unit"]:
                continue
            if _same_ref(f["noun"], r["noun"]) and f["qty"] != r["qty"]:
                out.append((f, r))
                break
    return out


def ledger_hint(rows, limit=12):
    """把账本概览编成注入提示（给推演系统与执法报告用）。"""
    if not rows:
        return ""
    lines = ["当前数目账（已确立的事实，同指换数会被对账拦截）："]
    for r in rows[:limit]:
        u = r.get("unit") or ""
        lines.append("· %s = %d%s" % (r["note"], r["qty"], u))
    return "\n".join(lines)


def _self_test():
    md = """| 条目 | 期初 | 增量 | 消耗 | 期末 | 备注 |
|------|------|------|------|------|------|
| 金币（总） | 120 | 0 | 0 | 120 | 上期结余 |
| 赤目狼魔核 | 0 | 1 | 0 | 1 | 一阶上段 |"""
    rows = parse_ledger(md)
    print("ledger rows:", rows)
    t = "萧炎数了数，一共有三百金币。魔核一颗卖了一百金币，赤目狼魔核还剩两颗。他看了一眼账本。"
    facts = num_facts(t)
    print("facts:")
    for f in facts:
        print("  %s %s=%d (raw=%s)" % (f["noun"], f["unit"], f["qty"], f["raw"]))
    cf = conflicts(facts, rows)
    print("conflicts:", len(cf))
    for f, r in cf:
        print("  %s=%d 账上 %s=%d" % (f["noun"], f["qty"], r["note"], r["qty"]))


if __name__ == "__main__":
    _self_test()
