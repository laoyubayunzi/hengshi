"""parsers.py - 从 hengshi 的命令行输出里解析结构化数据。

单独成模块是为了可测试：解析逻辑一旦出错，报告里就是错数字，
而这类错误不会让程序崩，只会让结论悄悄变味。
每个函数都是纯函数：字符串进，字典/列表出，没有副作用。
"""
import re

FLOAT = r"-?\d+\.\d+"


def parse_verify(out: str) -> str:
    """返回 'OK' / 'FAIL'。"""
    return "OK" if ("OK" in out and "FAIL" not in out) else "FAIL"


def parse_ttest(out: str):
    """解析 ttest 输出。

    每个变体跑三次各打一行 `run N : t = ...`，最后一行是 `median t = ...`。
    返回 (median_t_table, median_t_ct, effect_tt, effect_ct)。
    """
    med = [float(x) for x in re.findall(r"median t =\s*(" + FLOAT + r")", out)]
    eff = [float(x) for x in re.findall(r"差=([+-]\d+\.\d+)%", out)]
    t_tt = abs(med[0]) if len(med) > 0 else None
    t_ct = abs(med[1]) if len(med) > 1 else None
    e_tt = abs(eff[2]) if len(eff) > 2 else None
    e_ct = abs(eff[5]) if len(eff) > 5 else None
    return t_tt, t_ct, e_tt, e_ct


def parse_libs(out: str):
    """解析 `LIB <name> t=<x> effect=<y>` 行。"""
    libs = []
    for line in out.splitlines():
        m = re.match(r"LIB\s+(\S+)\s+t=([\d.]+)\s+min=([\d.]+)\s+max=([\d.]+)\s+"
                     r"effect=([\d.]+)\s+verdict=(LEAK|clean)(\s+UNSTABLE)?", line)
        if m:
            libs.append({"name": m.group(1), "t": float(m.group(2)),
                         "min_t": float(m.group(3)), "max_t": float(m.group(4)),
                         "effect_pct": float(m.group(5)),
                         "verdict": m.group(6),
                         "unstable": bool(m.group(7))})
            continue
        # 兼容旧格式
        m = re.match(r"LIB\s+(\S+)\s+t=([\d.]+)\s+effect=([\d.]+)", line)
        if m:
            t = float(m.group(2))
            libs.append({"name": m.group(1), "t": t, "effect_pct": float(m.group(3)),
                         "verdict": "LEAK" if t > 4.5 else "clean"})
    return libs


def parse_compare(out: str):
    """解析 `t=.. 效应量=..` 两行，返回 (ttable, small)。"""
    hits = re.findall(r"t=\s*(" + FLOAT + r")\s+效应量=([+-]\d+\.\d+)%", out)
    tt = {"t": abs(float(hits[0][0])), "effect_pct": abs(float(hits[0][1]))} if len(hits) > 0 else None
    sm = {"t": abs(float(hits[1][0])), "effect_pct": abs(float(hits[1][1]))} if len(hits) > 1 else None
    return tt, sm


def parse_sweep(out: str):
    """解析假阳性评估的表格行。"""
    variants = []
    for line in out.splitlines():
        m = re.match(r"(.+?)\s+(\d+)/(\d+)\s+([\d.]+)\s+([\d.]+)\s+"
                     r"(OK|MISCLASSIFIED|NOT-DETECTED\(blind\))\s*$", line)
        if m:
            tag = m.group(6)
            variants.append({"name": m.group(1).strip(), "over": int(m.group(2)), "reps": int(m.group(3)),
                             "max_t": float(m.group(4)), "median_t": float(m.group(5)),
                             "verdict": tag,
                             "correct": tag == "OK",
                             "blind": tag.startswith("NOT-DETECTED")})
    return variants


def parse_sweep_summary(out: str):
    """解析灵敏度和假阳性两行。"""
    d = {}
    m = re.search(r"灵敏度（[^）]*）: ([\d.]+)%", out)
    if m:
        d["sensitivity_pct"] = float(m.group(1))
    m = re.search(r"假阳性（[^）]*）: ([\d.]+)%", out)
    if m:
        d["false_positive_pct"] = float(m.group(1))
    return d


def parse_converge(out: str):
    """解析 `n  |t|tt  |t|ct` 三列表格。"""
    conv = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s*$", line)
        if m:
            conv.append({"n": int(m.group(1)), "t_ttable": float(m.group(2)), "t_ct": float(m.group(3))})
    return conv


def parse_attack(out: str):
    """解析密钥恢复输出。"""
    d = {}
    m = re.search(r"真实 rk\[0\.\.3\] : ([0-9a-f ]+)", out)
    if m:
        d["true_round_keys"] = m.group(1).split()
    m = re.search(r"恢复 rk\[0\.\.3\] : ([0-9a-f ]+)", out)
    if m:
        d["recovered_round_keys"] = m.group(1).split()
    m = re.search(r"反推主密钥 : ([0-9a-f]+)", out)
    if m:
        d["recovered_master_key"] = m.group(1)
    m = re.search(r"真实主密钥 : ([0-9a-f]+)", out)
    if m:
        d["true_master_key"] = m.group(1)
    if "recovered_master_key" in d and "true_master_key" in d:
        d["master_key_match"] = d["recovered_master_key"] == d["true_master_key"]
    return d


def parse_real_recovery(out: str):
    """解析真实库部分恢复输出。"""
    m = re.search(r"结果：(\d+)/(\d+) 个字节判定成功", out)
    pairs = re.findall(r"\s+b(\d)\s+0x([0-9a-f])\s+最高组=0x([0-9a-f])\s+\((\d+)/", out)
    return {
        "matched": int(m.group(1)) if m else None,
        "total": int(m.group(2)) if m else None,
        "per_byte": [{"byte": int(b), "true_hi": t, "best_hi": g, "score": int(sc)}
                     for b, t, g, sc in pairs],
    }


def parse_bench(out: str):
    """解析与 dudect 方法的同机对照表。"""
    rows = []
    for line in out.splitlines():
        m = re.match(r"(\S.*?)\s{2,}([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(一致|不一致)\s+(LEAK|clean)\s*$", line)
        if m:
            rows.append({"name": m.group(1).strip(), "t_ours": float(m.group(2)),
                         "t_dudect": float(m.group(3)), "ms": float(m.group(4)),
                         "agree": m.group(5) == "一致", "verdict": m.group(6)})
    return rows
