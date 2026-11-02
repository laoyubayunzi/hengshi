"""check_docs.py - 公开文档的一致性扫描。

拦的不是代码 bug，而是"报告里出现自相矛盾或明显错误的表述"——
这类问题不会让程序崩，只会让评委怀疑哪份数据是真的。

跑法：python tools/check_docs.py            退出码 0 = 通过
"""
import glob
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (正则, 说明)
BANNED = [
    (r"None/\d+", "出现了 None/None 之类的缺失值渲染"),
    (r"\bNone\b(?=[^a-zA-Z]|$)", "文档里出现未替换的 None"),
    (r"未实施密钥恢复", "旧口径：声称未做密钥恢复"),
    (r"未对 GmSSL ?/ ?Tongsuo 实施", "旧口径：声称未对真实库实施"),
    (r"稳定 4/4", "旧口径：固定声称稳定 4/4"),
    (r"共 ?16 ?bit|（16 bit）|16 bit（4 字节", "硬编码 16 bit 结论（应为三次分布）"),
    (r"假阳性率 ?0\.0%|假阳性率为 ?0", "旧口径：把'本轮未观察到'写成总体假阳性率"),
    (r"无第三方库", "旧口径：与内嵌第三方源码矛盾"),
]

TARGETS = [
    "README.md", "report.md", "findings.md", "RELEASE_NOTES.md",
    "技术说明.md", "演示脚本.md", "ENVIRONMENT.md", "THIRD_PARTY_NOTICES.md",
]


def main() -> int:
    problems = []
    checked = 0
    for name in TARGETS:
        p = os.path.join(ROOT, name)
        if not os.path.exists(p):
            continue
        checked += 1
        text = open(p, encoding="utf-8").read()
        lines = text.splitlines()
        for rx, why in BANNED:
            for i, line in enumerate(lines, 1):
                if re.search(rx, line):
                    problems.append(f"{name}:{i}  {why}\n      {line.strip()[:110]}")

    # 反模式：把"行对齐"当成修复建议（必须有否定词才算正确表述）
    for name in ("README.md", "report.md", "findings.md", "技术说明.md"):
        p = os.path.join(ROOT, name)
        if not os.path.exists(p):
            continue
        for i, line in enumerate(open(p, encoding="utf-8").read().splitlines(), 1):
            if "缓存行对齐" in line and "修复建议" in line:
                if not any(x in line for x in ("并不", "放大", "不应", "不是一条修复建议")):
                    problems.append(f"{name}:{i}  把放大效应写成了修复建议\n      {line.strip()[:110]}")

    # 一致性：只要文档里提到密钥恢复，就必须同时出现"分级/部分"的限定
    for name in ("README.md", "report.md", "findings.md"):
        p = os.path.join(ROOT, name)
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8").read()
        if "密钥恢复" in text and ("部分" not in text and "分级" not in text):
            problems.append(f"{name}  提到密钥恢复但没有任何'部分/分级'限定")

    # 数值一致性：文档里出现的 t 值必须能在 report.json 找到对应（±3%）
    import json
    rep_path = os.path.join(ROOT, "report.json")
    if os.path.exists(rep_path):
        rep = json.load(open(rep_path, encoding="utf-8"))
        known = set()
        def add(v):
            try:
                known.add(round(float(v), 1))
            except Exception:
                pass
        t = rep.get("ttest") or {}
        for k in ("t_ttable", "t_constant_time"):
            if t.get(k) is not None:
                add(t[k])
        for x in rep.get("libs") or []:
            add(x.get("t"))
        for k, v in (rep.get("compare_layouts") or {}).items():
            if v:
                add(v.get("t"))
        for c in rep.get("convergence") or []:
            add(c.get("t_ttable")); add(c.get("t_ct"))
        for v in (rep.get("false_positive") or {}).get("variants") or []:
            add(v.get("max_t")); add(v.get("median_t"))
        for r in rep.get("dudect_bench") or []:
            add(r.get("t_ours")); add(r.get("t_dudect"))
        if rep.get("convergence_growth"):
            known.add(round(float(rep["convergence_growth"]), 2))
        if rep.get("convergence_n_ratio"):
            known.add(round(float(rep["convergence_n_ratio"]) ** 0.5, 2))   # 理论 √n
        cost = rep.get("cost") or {}
        if cost.get("ratio"):
            known.add(round(float(cost["ratio"]), 2))

        for name in TARGETS:
            p2 = os.path.join(ROOT, name)
            if not os.path.exists(p2):
                continue
            for i, line in enumerate(open(p2, encoding="utf-8").read().splitlines(), 1):
                # 只查形如 t = 12.34 / |t| = 12.34 / 12.34 倍 的数字
                for m in re.finditer(r"(?:\|t\|\s*[=＝]\s*|t\s*[=＝]\s*|)\b(\d{1,3}\.\d)\s*(?:倍)?", line):
                    pass
                for m in re.finditer(r"(?:\|t\|\s*[=＝]\s*|\bt\s*[=＝]\s*)(\d{1,3}\.\d+)", line):
                    val = round(float(m.group(1)), 1)
                    if not any(abs(val - k) <= max(0.15, k * 0.03) for k in known):
                        problems.append(f"{name}:{i}  数值疑似过期：t={m.group(1)}\n      {line.strip()[:110]}")
                for m in re.finditer(r"(\d\.\d{2})\s*倍", line):
                    val = round(float(m.group(1)), 2)
                    if not any(abs(val - k) <= max(0.05, k * 0.02) for k in known):
                        problems.append(f"{name}:{i}  数值疑似过期：{m.group(1)} 倍\n      {line.strip()[:110]}")

    print(f"扫描 {checked} 份公开文档")
    if problems:
        print(f"\n[FAIL] {len(problems)} 处问题：")
        for x in problems:
            print(f"  - {x}")
        return 1
    print("[PASS] 文档口径一致，无过期表述")
    return 0


if __name__ == "__main__":
    sys.exit(main())
