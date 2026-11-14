# -*- coding: utf-8 -*-
"""audit_cn.py —— 反 AI 腔本地执法器（创世自研版）。

设计来源：借鉴 NEST-DRAMA dupian.py 的分层执法思路（机检先修、修不动才定点补丁、
密度归一判毙、词表带证据标注）。规则为本项目自研重写，不复制任何第三方代码。

执法档位：
  DEL  —— 直接删除命中词（删后句子语义不减，如"下意识地"）
  DELC —— 删除命中所在的小句（按钮式微反应整族拦截，不打地鼠）
  SUB  —— 确定性替换为更朴素的表达
  ARG  —— 需要人工/LLM 定点的病灶（机检绝不擅自代笔）

使用（全部本地、零 LLM 消耗）：
  scan(text)      -> hits[(name, tier, frag, sent)]  执法级命中清单
  repair(text)    -> (new_text, residue_hits, log)   机修：只做信息量不减的删改
  density_verdict(text) -> (kill, n, dens_per_k)     密度归一判毙（双门限）
  patch_prompt(residue) -> str                       把残留病灶编成定点补丁指令（只发命中句）
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------- 规则表
# 每条: (规则名, 正则, 档位, 替换, 证据来源)
# 证据: 指纹库(高频换皮重灾区) / 判例(用户裁定) / 语料统计
RULES = [
    # ── 一、旁白自报（写即破功：活人不知道自己"下意识"）────────────
    ("旁白自报·无意识", r"(不由自主地?|下意识地?|不自觉地?|无意识地?|鬼使神差地?|莫名地?|不知怎的|鬼使神差)", "DEL", None, "判例"),
    ("旁白自报·自察", r"(他|她|我)(才)?(意识到|发现自己正|察觉到)(?:自己)?(在)?", "ARG", None, "判例"),

    # ── 二、按钮式微反应族（整族拦截，不逐词打地鼠）──────────────
    ("按钮·顿口", r"(微微)?顿了顿|顿了一下|(略|稍)一停顿|停顿了一下", "DELC", None, "指纹库"),
    ("按钮·深呼吸", r"深(深地)?吸(了)?一口气|深呼吸了?一(下|口)?|吐出一口(浊)?气|长舒一口气", "DELC", None, "指纹库"),
    ("按钮·喉舌心跳", r"喉结[^，。；！？\n]{0,5}(滚动|滑动|上下|动了动)|(呼吸|气息)[^，。；！？\n]{0,3}(一滞|一窒|屏住|放轻|乱了)|心(跳|脏)[^，。；！？\n]{0,6}(漏了一拍|停了一拍|骤然加快|狂跳)", "DELC", None, "指纹库"),
    ("按钮·眸", r"垂眸|抬眸|敛眸|眸(光|色|底)?[^，。；！？\n]{0,3}(一沉|微暗|骤冷|闪了闪)|(低)?垂着眼帘", "DELC", None, "指纹库"),
    ("按钮·瞳孔", r"瞳孔[^，。；！？\n]{0,3}(一缩|骤缩|微缩|放大)|眼(中|底|神)[^，。；！？\n]{0,3}(闪过|掠过|浮现)(一)?(丝|抹|道)?", "DELC", None, "指纹库"),
    ("按钮·嘴角", r"嘴角[^，。；！？\n]{0,3}(勾起|扬起|抽动|一扯|微不可察)|抿了抿(唇|嘴)|(唇|嘴)角(微)?(勾|扬)", "DELC", None, "指纹库"),
    ("按钮·指节青筋", r"指节[^，。；！？\n]{0,3}泛白|手背青筋(暴起|直跳)?", "DELC", None, "指纹库"),
    ("按钮·脸色", r"(脸色|面色|神情)[^，。；！？\n]{0,3}(一沉|一凝|骤变|铁青|煞白)|脸(色|上)[^，。；！？\n]{0,4}闪过", "DELC", None, "指纹库"),

    # ── 三、身体语言转嫁（手替嘴演戏：AI 用小动作代替行动）────────
    ("转嫁·指尖摩挲", r"(指甲|指尖|拇指|指节|掌心)[^，。；！？\n]{0,8}(擦过|蹭了蹭|摩挲|摩擦|揉搓|划过|叩了叩|轻叩|敲了敲|捻了捻|收紧|蜷起)", "ARG", None, "判例"),
    ("转嫁·攥衣角", r"(攥|捏|揪|捋|抚)(着|了)?(衣角|袖口|领口|裤缝)|(衣角|袖口|领口)[^，。；！？\n]{0,6}(攥|捏|揪)", "ARG", None, "判例"),

    # ── 四、质感批发 / 账目思维（进屋就盘点，物品统一发工牌）──────
    ("质感·新旧并置", r"新旧并置|过于(整齐|干净|陈旧|清晰|新)|太(新|旧|稳|破|干净)了?|锈(色|迹)斑斑|簇新|锃亮", "ARG", None, "指纹库"),
    ("质感·斑驳剥落", r"斑驳|剥落[，,]\s*露出", "ARG", None, "指纹库"),

    # ── 五、句式模板 ──────────────────────────────
    ("模板·眼中闪过", r"眼(中|里|底)(闪过|掠过)(一)?(丝|抹|道)?(精芒|寒光|杀意|复杂|异样)", "ARG", None, "指纹库"),
    ("模板·空气凝固", r"空气[^，。；！？\n]{0,5}(凝固|安静|仿佛凝滞)|(整个)?(大厅|房间|场中)[^，。；！？\n]{0,5}(鸦雀无声|落针可闻)", "ARG", None, "指纹库"),
    ("模板·心绪", r"心中一(凛|紧|沉|颤|惊)|(一股|一阵)[^，。；！？\n]{0,5}涌上心头", "DELC", None, "指纹库"),
    ("模板·这一刻", r"这一刻[^，。；！？\n]{0,4}(他|她|我)(终于)?(明白|懂|知道|意识到)", "ARG", None, "指纹库"),
    ("模板·命运齿轮", r"命运的齿轮|命运的(安排|玩笑)|也许这就是(命运|天意)|(仿佛|像是)命运[^。！？\n]{0,8}", "DELC", None, "指纹库"),
    ("模板·无人知晓", r"没有人(知道|注意到|察觉)|(仿佛|似乎)没有人(看见|发现)", "ARG", None, "指纹库"),
    ("模板·不是A是B", r"[^，。；！？\n]{1,6}(从来|并|可|但)?不是[^，。；！？\n]{1,10}[，,](而)?是[^。；！？\n]{1,10}", "ARG", None, "指纹库"),
    ("量词·一丝一抹", r"(一丝|一抹|一缕|些许|几分)(?=[^，。；！？\n]{0,3}(疲惫|不安|寒意|凉意|暖意|笑意|嘲讽|复杂|异样|慌|怒|喜|光))", "DEL", None, "指纹库"),
    ("旁白·声音里带着", r"(声音|眼(中|里|底)|语气|脸上)(里)?(带|透|藏)着", "ARG", None, "指纹库"),

    # ── 六、结构层 ──────────────────────────────
    ("结构·预告计数", r"(有|是)?[一二三四五六七八九十两](件事|个原因|点理由|种可能|条线索|个问题)", "ARG", None, "结构指纹"),
    ("结构·冒号标签", r"(结论|问题|答案|关键|真相|代价)[:：]", "ARG", None, "结构指纹"),
    ("结构·排比短句", r"([^，。；！？\n]{1,6}[。！])\s*([^，。；！？\n]{1,6}[。！])\s*([^，。；！？\n]{1,6}[。！])", "ARG", None, "结构指纹"),
]

# 档位常量
DEL = "DEL"; DELC = "DELC"; SUB = "SUB"; ARG = "ARG"

_COMPILED = [(n, re.compile(p), t, r, e) for (n, p, t, r, e) in RULES]
_SENT_SPLIT = re.compile(r"(?<=[。！？!?])|\n+")
_CLAUSE_SPLIT = re.compile(r"[，。；！？!?,;]")
# 帝王式"他/她/它/我/你/我们" + "地" 的断肢虚词（机修收尾用）
_VOID_SUFFIX = re.compile(r"([，。；！？\n】])\s*[地的得]\s*(?=[^，。；！？\n])")


def _clean(t):
    return re.sub(r"[ \t]+", " ", t).strip()


def scan(text, quota_check=True):
    """执法级命中清单。返回 [(规则名, 档位, 命中片段, 所在句)]。"""
    if not text:
        return []
    hits = []
    for name, pat, tier, _repl, _ev in _COMPILED:
        for m in pat.finditer(text):
            frag = m.group(0).strip()
            if len(frag) < 1:
                continue
            s = m.start()
            line_start = text.rfind("\n", 0, s) + 1
            line_end = text.find("\n", s)
            if line_end < 0:
                line_end = len(text)
            sent = _clean(text[line_start:line_end][:60])
            hits.append((name, tier, frag[:40], sent))
    return hits


def _clause_of(text, s, e):
    """命中片段所在小句的起止（按中文标点切）。返回 (cs, ce)。"""
    cs = s
    while cs > 0 and text[cs - 1] not in "，。；！？\n":
        cs -= 1
    ce = e
    while ce < len(text) and text[ce] not in "，。；！？\n":
        ce += 1
    return cs, ce


def repair(text):
    """本地确定性修复：只删"删后信息量不减"的词与按钮小句，不擅自代笔。
    返回 (修后文本, 需人/LLM 议的残留命中, 修复日志列表)。"""
    if not text:
        return text, [], []
    log = []
    # 1) DEL / SUB 确定性处理（DEL 无替换值则直接删除该词）
    for name, pat, tier, repl, _ev in _COMPILED:
        if tier in (DEL, SUB):
            text = pat.sub(repl if repl is not None else "", text)
    # 2) DELC：先在固定文本上收集命中小句 span（升序），邻接/重叠合并后
    #    从右往左一次性删除，避免边删边 finditer 的 span 错位与标点粘连
    text1 = text
    spans = []
    for name, pat, tier, _repl, _ev in _COMPILED:
        if tier == DELC:
            for m in pat.finditer(text1):
                cs, ce = _clause_of(text1, m.start(), m.end())
                spans.append((cs, ce, name))
    if spans:
        spans.sort(key=lambda x: (x[0], x[1]))
        merged = [list(spans[0])]
        for cs, ce, name in spans[1:]:
            if cs <= merged[-1][1]:
                if ce > merged[-1][1]:
                    merged[-1][1] = ce
            else:
                merged.append([cs, ce, name])
        for cs, ce, name in reversed(merged):
            piece = _clean(text1[cs:ce])
            text = text[:cs] + text[ce:]
            log.append("DELC %s：「%s」" % (name, piece[:30]))
    # 3) 粘连标点清理 + 断肢虚词收尾
    text = re.sub(r"[，。；！？]{2,}", lambda m: "。" if "。" in m.group(0) or "！" in m.group(0) else "，", text)
    text = _VOID_SUFFIX.sub(r"\1", text)
    text = re.sub(r"^\s*[，。、]+", "", text)
    text = re.sub(r"[，。、]\s*$", "", text)
    # 4) 收尾：扫出仍需议的病灶（ARG 级，交 LLM 定点或作者）
    residue = [h for h in scan(text) if h[1] in (ARG,)]
    return _clean(text), residue, log


def density_verdict(text, kill_abs=10, kill_min=5, kill_per_k=4.0):
    """整稿是否"机器手感"到该重推。返回 (kill, 执法级命中数, 每千字密度)。

    双门限按篇幅归一：命中 ≥ kill_abs 直接毙；或命中 ≥ kill_min 且密度 ≥ kill_per_k/千字。
    （旧式绝对计数会在 300 字短回合误杀、3000 字长稿漏杀。）"""
    hits = [h for h in scan(text) if h[1] != "WATCH"]
    n = len(hits)
    dens = n * 1000.0 / max(len(text or ""), 1)
    kill = n >= kill_abs or (n >= kill_min and dens >= kill_per_k)
    return kill, n, round(dens, 1)


def patch_prompt(residue, diags=None):
    """把残留病灶编成定点补丁指令（只发命中句，不发全文——省 token 关键）。"""
    lines = []
    for name, tier, frag, sent in residue[:8]:
        lines.append("· [%s]「%s」 ← 出自：%s" % (name, frag, sent))
    if diags:
        for d in diags[:3]:
            lines.append("· [统计层] " + d)
    return "\n".join(lines)


PATCH_SYS = (
    "你是精修校对。下面给出几处被机检判定为 AI 腔的句子。逐句改写：**信息量一字不减**"
    "（谁做了什么、说了什么、想什么全部保留），只换表达。可删的直接删（删后句子仍成立的修饰一律删）。"
    "不要重写整段、不新增情节、不加金句。若某处是该角色声纹卡注明的**既定签名动作**"
    "（每人至多一个，如某人紧张时摆弄扳指），那是人物特征不是 AI 腔，原样放回。\n"
    "输出严格 JSON：{\"fixes\":[{\"old\":\"原句逐字照抄\",\"new\":\"改后句\"}]}，改不动的原样放回 new。只输出 JSON。"
)


def _self_test():
    t = "萧炎下意识地握紧了拳头，他深吸一口气，瞳孔骤缩。嘴角勾起一抹弧度，眼中闪过一丝精芒。命运的齿轮开始转动。"
    hits = scan(t)
    print("scan hits:", len(hits))
    for h in hits:
        print(" ", h[0], h[1], h[2])
    nt, residue, log = repair(t)
    print("repair ->", nt)
    print("residue:", len(residue), "log:", len(log))
    kill, n, d = density_verdict(nt)
    print("verdict kill=%s n=%d dens=%s" % (kill, n, d))


if __name__ == "__main__":
    _self_test()
