#!/usr/bin/env python3
"""check_schema.py - CI 用：校验 report.json / findings.json 的结构与口径。

只检查"报告生成器是否按约定产出"，**不检查 t 值大小**——
侧信道测量在共享 runner 上不稳定，t 值不能作为 CI 门禁。
退出码 0 = 结构合规。
"""
import json, os, sys

import sys as _sys
# Windows 上 stdout 可能是 cp1252（GitHub Actions 的 runner 就是），中文会直接抛
# UnicodeEncodeError。统一强制 UTF-8，避免"脚本在 CI 上跑不起来"这类环境性失败。
try:
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

REQUIRED_REPORT = ["tool", "version", "sm4_vector", "ttest", "convergence",
                   "attack_aligned_32rounds", "false_positive", "provenance",
                   "real_recovery", "cost"]
REQUIRED_TTEST = ["t_ttable", "t_constant_time", "verdict_ttable", "verdict_constant_time"]
DETECTION = {"clean", "leak", "inconclusive"}
EXPLOIT = {"未验证", "部分信息恢复", "完整密钥恢复", "不适用"}

ARGV = sys.argv[1:]


def _arg(name, default):
    if name in ARGV:
        i = ARGV.index(name)
        if i + 1 < len(ARGV):
            return ARGV[i + 1]
    return default


problems = []


def need(obj, key, where):
    if key not in obj:
        problems.append(f"{where} 缺少字段 {key}")
        return None
    return obj[key]


def main() -> int:
    rp = _arg("--report", os.path.join(ROOT, "report.json"))
    fp = _arg("--findings", os.path.join(ROOT, "findings.json"))
    for p in (rp, fp):
        if not os.path.exists(p):
            problems.append(f"缺少文件 {os.path.basename(p)}（先跑 make_report.py / make_findings.py）")

    if problems:
        print("\n".join("[FAIL] " + x for x in problems))
        return 1

    rep = json.load(open(rp, encoding="utf-8"))
    for k in REQUIRED_REPORT:
        need(rep, k, "report.json")
    for k in REQUIRED_TTEST:
        need(rep.get("ttest", {}), k, "report.json.ttest")

    # 标准向量必须是 OK —— 这是唯一可以硬性门禁的数值
    if rep.get("sm4_vector") != "OK":
        problems.append(f"SM4 标准向量未通过：{rep.get('sm4_vector')}")

    # 溯源角色过滤：独立实现数只能统计 target，基准工具必须单列
    pv = rep.get("provenance") or {}
    roles = pv.get("roles") or {}
    tgts = roles.get("target") or []
    src = pv.get("sources") or []
    if not tgts:
        problems.append("provenance.roles.target 缺失（无法确认同源结论只统计被测实现）")
    if not roles.get("benchmark"):
        problems.append("provenance.roles.benchmark 缺失（dudect 应作为基准工具单列）")
    if tgts:
        hashes_target = {x["sha256"] for x in src if x.get("role", "target") == "target"}
        hashes_all = {x["sha256"] for x in src}
        if pv.get("distinct_implementations") != len(hashes_target):
            problems.append(f"distinct_implementations={pv.get('distinct_implementations')} "
                            f"与 target 去重数 {len(hashes_target)} 不一致")
        elif pv.get("distinct_implementations") == len(hashes_all) and len(hashes_all) != len(hashes_target):
            problems.append("独立实现数疑似把基准工具也算了进去（应只统计 target）")
        # 受影响资产不得包含基准工具
        fnd_tmp = None
        if os.path.exists(fp):
            fnd_tmp = json.load(open(fp, encoding="utf-8")).get("findings") or []
        for f in (fnd_tmp or []):
            if f.get("kind") == "observation" and "供应链" in f.get("title", ""):
                if "dudect" in (f.get("asset") or ""):
                    problems.append(f"{f.get('id')}: 供应链条目的受影响资产里出现 dudect（基准工具不应计入）")

    # 收敛表结构
    conv = rep.get("convergence") or []
    if len(conv) < 3:
        problems.append("convergence 至少需要 3 个样本量点")
    for c in conv:
        for k in ("n", "t_ttable", "t_ct"):
            if k not in c:
                problems.append(f"convergence 条目缺少 {k}")

    # 假阳性评估
    fpv = (rep.get("false_positive") or {}).get("variants") or []
    if len(fpv) < 5:
        problems.append("false_positive.variants 少于 5 个变体")
    for v in fpv:
        if "ground" not in v and not v.get("correct") in (True, False):
            problems.append("false_positive 条目缺少 correct 判定")

    # findings 两级字段
    fnd = json.load(open(fp, encoding="utf-8")).get("findings") or []
    if not fnd:
        problems.append("findings 为空")
    for f in fnd:
        fid = f.get("id", "?")
        d = f.get("detection")
        e = f.get("exploit")
        if d not in DETECTION:
            problems.append(f"{fid}: detection={d!r} 不在 {sorted(DETECTION)}")
        if e not in EXPLOIT:
            problems.append(f"{fid}: exploit={e!r} 不在 {sorted(EXPLOIT)}")
        if not f.get("kind"):
            problems.append(f"{fid}: 缺少 kind")
    # 至少要有一条完整密钥恢复的证据，否则说明实验跑残了
    if not any(f.get("exploit") == "完整密钥恢复" for f in fnd):
        problems.append("没有任何 exploit=完整密钥恢复 的发现（密钥恢复实验未完成？）")

    if problems:
        print("\n".join("[FAIL] " + x for x in problems))
        return 1
    print(f"[PASS] 结构校验通过：{len(fnd)} 条发现，{len(conv)} 个收敛点，{len(fpv)} 个对照变体")
    return 0


if __name__ == "__main__":
    sys.exit(main())
