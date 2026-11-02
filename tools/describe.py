"""describe.py - 把结构化结果渲染成统一措辞的唯一出口。

为什么要这个模块：README、report.md、findings.md 之前各自拼字符串，
结果出现"16 bit 固定结论" vs "3–4/4" vs "未实施密钥恢复" 三种互相矛盾的写法。
现在三份文档都只调用这里的函数，措辞与数字只有一个来源。
"""


def _runs(rec):
    """取三次重复的 matched 列表，过滤 None。"""
    runs = (rec or {}).get("runs") or []
    return [r for r in runs if r is not None]


def recovery_level(rec):
    """部分恢复的等级：'完整' 不会出现在这里（完整恢复只在自研布局）。

    返回 'partial'（有字节恢复成功）/ 'none'（一个都没成功）/ 'unknown'（没数据）
    """
    runs = _runs(rec)
    if not runs:
        return "unknown"
    return "partial" if max(runs) > 0 else "none"


def recovery_runs_text(rec):
    """三次重复的实际分布，例如 '4/4、4/4、3/4'。"""
    runs = _runs(rec)
    total = (rec or {}).get("total") or 4
    if not runs:
        return "无数据"
    return "、".join(f"{r}/{total}" for r in runs)


def recovery_sentence(rec, lib_name="GmSSL"):
    """完整的一句话，供正文使用。"""
    lvl = recovery_level(rec)
    if lvl == "unknown":
        return f"{lib_name}：无部分恢复数据"
    if lvl == "none":
        return (f"{lib_name} 上该方法未收敛（三次重复 {recovery_runs_text(rec)}），"
                f"如实记为未验证")
    best = max(_runs(rec))
    total = (rec or {}).get("total") or 4
    return (f"{lib_name} 可恢复 rk[0] 部分字节的高 4 bit"
            f"（三次重复 {recovery_runs_text(rec)}，稳定成功 {best}/{total} 个字节，"
            f"低 4 bit 在行粒度下不可辨识）")


def recovery_short(rec, lib_name="GmSSL"):
    """短句，供表格或摘要使用。"""
    lvl = recovery_level(rec)
    if lvl == "partial":
        return f"{lib_name} 部分恢复（{recovery_runs_text(rec)} 字节的高 4 bit）"
    if lvl == "none":
        return f"{lib_name} 未收敛（{recovery_runs_text(rec)}）"
    return f"{lib_name} 无数据"


def cost_sentence(cost):
    """修复代价的一句话。"""
    c = cost or {}
    if not c.get("ratio"):
        return "修复代价：无数据"
    return (f"常量时间化的性能代价为 **{c['ratio']:.2f}x**"
            f"（T-table {c['cycles_ttable']:.0f} 周期/次 → 常量时间 {c['cycles_ct']:.0f} 周期/次）")


def scope_sentence(rep):
    """证据范围的标准表述，三份文档共用。"""
    rr = rep.get("real_recovery") or {}
    g = rr.get("gmssl") or {}
    t = rr.get("tongsuo") or {}
    g_txt = recovery_short(g, "GmSSL")
    t_txt = recovery_short(t, "Tongsuo")
    return ("完整 128 bit 主密钥恢复仅在自研实现的行对齐布局上完成；"
            f"真实库为**部分**恢复——{g_txt}，{t_txt}。")
