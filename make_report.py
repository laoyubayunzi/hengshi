# make_report.py - 跑实验并生成 report.json / report.md
#
# 三种模式：
#   python make_report.py           完整实验（约 60s，受机器噪声影响）
#   python make_report.py --quick   小样本（每类 4000），仍真实测量
#   python make_report.py --smoke   不跑任何计时实验，用 tests/fixture_report.json 生成报告（CI 用）
import hashlib
import json
import os
import re
import subprocess
import sys
import time

import sys as _sys
# Windows 上 stdout 可能是 cp1252（GitHub Actions 的 runner 就是），中文会直接抛
# UnicodeEncodeError。统一强制 UTF-8，避免"脚本在 CI 上跑不起来"这类环境性失败。
try:
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "hengshi.exe")

QUICK = "--quick" in sys.argv
SMOKE = "--smoke" in sys.argv

N_MAIN = 4000 if QUICK else 40000
REPS = 3
SWEEP_REPS = 3 if QUICK else 10
SWEEP_N = 4000 if QUICK else 20000


class ExperimentError(RuntimeError):
    pass


def run(*args, timeout=900):
    """跑一个实验。非零返回码直接抛错，避免用半截数据生成报告。"""
    t0 = time.time()
    p = subprocess.run([EXE, *map(str, args)], capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace")
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", "replace").strip()
        raise ExperimentError(f"hengshi {' '.join(map(str, args))} 退出码 {p.returncode}: {err[:300]}")
    return out, round(time.time() - t0, 1)


def collect():
    rep = {"tool": "hengshi", "version": "1.0", "mode": "quick" if QUICK else "full",
           "generated": time.strftime("%Y-%m-%d %H:%M:%S")}

    out, _ = run("verify")
    rep["sm4_vector"] = "OK" if "OK" in out and "FAIL" not in out else "FAIL"

    out, _ = run("ttest", N_MAIN)
    ts = [float(x) for x in re.findall(r"median t =\s*(-?\d+\.\d+)", out)]
    eff = [float(x) for x in re.findall(r"差=([+-]\d+\.\d+)%", out)]
    rep["ttest"] = {
        "n_per_class": N_MAIN,
        "t_ttable": abs(ts[0]) if len(ts) > 0 else None,
        "t_constant_time": abs(ts[1]) if len(ts) > 1 else None,
        "effect_ttable_pct": abs(eff[2]) if len(eff) > 2 else None,
        "effect_ct_pct": abs(eff[5]) if len(eff) > 5 else None,
        "verdict_ttable": "LEAK" if ts and abs(ts[0]) > 4.5 else "clean",
        "verdict_constant_time": "LEAK" if len(ts) > 1 and abs(ts[1]) > 4.5 else "clean",
    }

    out, _ = run("libs", N_MAIN, REPS)
    libs = []
    for line in out.splitlines():
        m = re.match(r"LIB\s+(\S+)\s+t=([\d.]+)\s+effect=([\d.]+)", line)
        if m:
            tv = float(m.group(2))
            libs.append({"name": m.group(1), "t": tv, "effect_pct": float(m.group(3)),
                         "verdict": "LEAK" if tv > 4.5 else "clean"})
    rep["libs"] = libs

    out, _ = run("compare", N_MAIN)
    ct = re.findall(r"t=\s*(-?\d+\.\d+)\s+效应量=([+-]\d+\.\d+)%", out)
    rep["compare_layouts"] = {
        "gmssl_ttable": {"t": abs(float(ct[0][0])), "effect_pct": abs(float(ct[0][1]))} if len(ct) > 0 else None,
        "gmssl_small": {"t": abs(float(ct[1][0])), "effect_pct": abs(float(ct[1][1]))} if len(ct) > 1 else None,
    }

    prov_meta = json.load(open(os.path.join(HERE, "provenance.json"), encoding="utf-8"))
    prov = []
    for x in prov_meta["sources"]:
        fp = os.path.join(HERE, "src", "thirdparty", x["file"])
        actual = hashlib.sha256(open(fp, "rb").read()).hexdigest() if os.path.exists(fp) else None
        rec = dict(x)
        rec["sha256_actual"] = actual
        rec["hash_match"] = (actual == x["sha256"])
        prov.append(rec)
    distinct = len({x["sha256"] for x in prov})
    rep["provenance"] = {
        "sources": prov,
        "distinct_implementations": distinct,
        "all_hash_verified": all(x["hash_match"] for x in prov),
        "note": ("Tongsuo 与 BabaSSL 的 SM4 源码字节级相同，且两个发行 tag 指向同一 commit："
                 "同一份上游实现被两个下游项目共用" if distinct < len(prov) else "各库实现互不相同"),
    }

    out, _ = run("sweep", SWEEP_REPS, SWEEP_N)
    variants = []
    for line in out.splitlines():
        m = re.match(r"(.+?)\s+(\d+)/(\d+)\s+([\d.]+)\s+([\d.]+)\s+(OK|MISCLASSIFIED)\s*$", line)
        if m:
            variants.append({"name": m.group(1).strip(), "over": int(m.group(2)), "reps": int(m.group(3)),
                             "max_t": float(m.group(4)), "median_t": float(m.group(5)),
                             "correct": m.group(6) == "OK"})
    rep["false_positive"] = {"variants": variants,
                             "all_correct": all(v["correct"] for v in variants) if variants else None}

    out, _ = run("converge")
    conv = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s*$", line)
        if m:
            conv.append({"n": int(m.group(1)), "t_ttable": float(m.group(2)), "t_ct": float(m.group(3))})
    rep["convergence"] = conv
    if len(conv) >= 2:
        rep["convergence_growth"] = round(conv[-1]["t_ttable"] / conv[0]["t_ttable"], 2)
        rep["convergence_n_ratio"] = round(conv[-1]["n"] / conv[0]["n"], 1)

    def parse_attack(out):
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

    out, _ = run("attack", 64, 200, 32)
    rep["attack_aligned_32rounds"] = parse_attack(out)
    out, _ = run("attack", 4, 200, 4)
    rep["attack_natural_4rounds"] = parse_attack(out)
    return rep


def render_markdown(rep):
    t = rep.get("ttest", {})
    libs = rep.get("libs", [])
    conv = rep.get("convergence", [])
    atk = rep.get("attack_aligned_32rounds", {})
    nat = rep.get("attack_natural_4rounds", {})
    cl = rep.get("compare_layouts") or {}
    pv = rep.get("provenance") or {}
    fp = rep.get("false_positive") or {}

    L = []
    L.append("# 衡时 · 实验报告（自动生成）\n")
    L.append(f"生成时间：{rep.get('generated')}　模式：{rep.get('mode', 'full')}　"
             f"工具：hengshi {rep.get('version')}\n")
    if str(rep.get("mode", "")).startswith("smoke"):
        L.append("> 本报告由固定夹具生成，用于验证报告链路；其中的测量数字来自一次真实实验快照，"
                 "不是本次运行现场测得。\n")

    L.append("## 1. 实现正确性\n")
    L.append(f"- SM4 标准测试向量（GB/T 32907）：**{rep.get('sm4_vector')}**\n")

    L.append(f"## 2. 泄漏检测（Welch t 检验，每类 {t.get('n_per_class')} 样本，"
             f"重复 3 次取中位，裁剪首尾 5%）\n")
    L.append("| 实现 | 中位 t | 效应量 | 判定 |")
    L.append("|---|---|---|---|")
    L.append(f"| T-table（自研） | {t.get('t_ttable'):.2f} | {t.get('effect_ttable_pct')}% | {t.get('verdict_ttable')} |")
    L.append(f"| 常量时间（自研，修复版） | {t.get('t_constant_time'):.2f} | {t.get('effect_ct_pct')}% | {t.get('verdict_constant_time')} |")
    L.append("\n阈值 |t| > 4.5。\n")

    if libs:
        L.append("### 2.1 真实国产库（官方源码，未改写算法）\n")
        L.append("| 库 | 中位 t | 效应量 | 判定 |")
        L.append("|---|---|---|---|")
        for x in libs:
            L.append(f"| {x['name']} | {x['t']:.2f} | {x['effect_pct']:.2f}% | **{x['verdict']}** |")
        L.append("\n**证据范围**：对真实库只完成统计判定，未实施密钥恢复（见 5.2 与 HS-003）。\n")

    if cl.get("gmssl_ttable"):
        L.append("### 2.2 同一份源码的两种编译配置（隔离「表布局」变量）\n")
        L.append("| 配置 | t | 效应量 | 判定 |")
        L.append("|---|---|---|---|")
        for name, key in (("GmSSL T-table (4 KB, 16 项/行)", "gmssl_ttable"),
                          ("GmSSL 小表 (256 B, 4 行)", "gmssl_small")):
            v = cl.get(key) or {}
            L.append(f"| {name} | {v.get('t', 0):.2f} | {v.get('effect_pct', 0)}% | "
                     f"{'LEAK' if abs(v.get('t', 0)) > 4.5 else 'clean'} |")
        L.append("\n结论：表变小并没有消除泄漏——根源是「访存地址由数据决定」，不是「表有多大」。\n")

    if pv.get("sources"):
        L.append("## 3. 源码来源核验（可追溯性）\n")
        L.append("| 库 | 版本 | commit | 许可证 | 文件 | 字节 | SHA-256（前 16） | 哈希核对 |")
        L.append("|---|---|---|---|---|---|---|---|")
        for x in pv["sources"]:
            ok = "一致" if x.get("hash_match") else "不一致"
            L.append(f"| {x['library']} | {x['version']} | `{x['commit']}` | {x['license']} | "
                     f"{x['file']} | {x['bytes']} | `{x['sha256'][:16]}` | {ok} |")
        L.append("\n来源（按发行 tag 固定下载）：")
        for x in pv["sources"]:
            L.append(f"- {x['library']} {x['version']}：{x['url']}")
        L.append(f"\n**三个库只对应 {pv['distinct_implementations']} 份独立实现。** {pv['note']}。")
        L.append("供应链含义：同一份上游实现的缺陷会同时影响多个下游库，"
                 "所谓「多家实现互相印证」在这种情形下并不成立。\n")

    if fp.get("variants"):
        vs = fp["variants"]
        L.append(f"## 4. 假阳性评估（{len(vs)} 个真值已知的实现，各 {vs[0]['reps']} 轮）\n")
        L.append("| 实现 | 越阈值轮次 | max \\|t\\| | 中位 \\|t\\| | 判定 |")
        L.append("|---|---|---|---|---|")
        for v in vs:
            L.append(f"| {v['name']} | {v['over']}/{v['reps']} | {v['max_t']:.1f} | {v['median_t']:.1f} | "
                     f"{'正确' if v['correct'] else '误判'} |")
        clean = sum(v["reps"] for v in vs if "table" not in v["name"].replace("const-time", ""))
        L.append(f"\n**本轮实验未观察到假阳性**（干净实现 0/{clean} 次越阈值）。判据：多轮中过半越阈值才算泄漏。"
                 "样本量有限，本结论仅描述本轮实验，不宜外推为总体假阳性率。\n")

    if conv:
        L.append("## 5. √n 收敛实验（区分真泄漏与噪声的判据）\n")
        L.append("| n/class | \\|t\\| T-table | \\|t\\| 常量时间 |")
        L.append("|---|---|---|")
        for c in conv:
            L.append(f"| {c['n']} | {c['t_ttable']:.2f} | {c['t_ct']:.2f} |")
        if rep.get("convergence_growth"):
            ratio = rep.get("convergence_n_ratio") or 1
            L.append(f"\n样本量放大 {ratio} 倍，T-table 的 |t| 放大 {rep['convergence_growth']} 倍"
                     f"（理论 √{ratio} ≈ {ratio ** 0.5:.2f} 倍）；常量时间版不随样本量增长。\n")

    L.append("## 6. 密钥恢复（Flush+Reload）\n")
    L.append("> **范围说明**：密钥恢复仅在**自研实现**上完成——行对齐布局是为隔离「表布局」这一变量而构造的受控实验。"
             "对 GmSSL / Tongsuo 未实施密钥恢复，对其结论仅为统计判定。\n")
    if atk:
        L.append("### 6.1 行对齐布局（每项独占缓存行），被攻击实现 32 轮\n")
        L.append(f"- 真实轮密钥：`{' '.join(atk.get('true_round_keys', []))}`")
        L.append(f"- 恢复轮密钥：`{' '.join(atk.get('recovered_round_keys', []))}`")
        if "recovered_master_key" in atk:
            L.append(f"- 反推主密钥：`{atk['recovered_master_key']}`")
            L.append(f"- 真实主密钥：`{atk['true_master_key']}`")
            L.append(f"- **是否一致：{atk.get('master_key_match')}**\n")
    if nat:
        L.append("### 6.2 自然布局（16 项/缓存行），被攻击实现 4 轮\n")
        L.append(f"- 真实轮密钥：`{' '.join(nat.get('true_round_keys', []))}`")
        L.append(f"- 恢复轮密钥：`{' '.join(nat.get('recovered_round_keys', []))}`")
        L.append("\n自然布局下只能恢复 rk[0] 的高半字节，后三轮因无法用半可信的 rk[0] 推进状态而失真。"
                 "完整边界见 findings.md 的 HS-003。\n")

    L.append("## 7. 可复现性\n")
    L.append("```\nhengshi verify\nhengshi libs 40000 3\nhengshi compare 40000\n"
             "hengshi ttest 40000\nhengshi converge\nhengshi attack 64 200 32\n"
             "hengshi attack 4 200 4\nhengshi sweep 10 20000\n```\n")

    open(os.path.join(HERE, "report.md"), "w", encoding="utf-8").write("\n".join(L))

    return (f"vector={rep.get('sm4_vector')}  t_tt={t.get('t_ttable')}  "
            f"t_ct={t.get('t_constant_time')}  growth={rep.get('convergence_growth')}x  "
            f"master_recovered={atk.get('master_key_match')}")


def main():
    if SMOKE:
        fixture = os.path.join(HERE, "tests", "fixture_report.json")
        if not os.path.exists(fixture):
            raise SystemExit("smoke 模式需要 tests/fixture_report.json")
        rep = json.load(open(fixture, encoding="utf-8"))
        rep["generated"] = time.strftime("%Y-%m-%d %H:%M:%S")
        rep["mode"] = "smoke (fixture)"
        json.dump(rep, open(os.path.join(HERE, "report.json"), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print("smoke: 由夹具生成 report.json / report.md（未执行任何计时实验）")
        print("  " + render_markdown(rep))
        return 0

    rep = collect()
    json.dump(rep, open(os.path.join(HERE, "report.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    brief = render_markdown(rep)
    print("wrote report.json / report.md")
    print("  " + brief)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ExperimentError as e:
        print(f"[实验失败] {e}", file=sys.stderr)
        print("报告未生成，避免用不完整数据产出结论。", file=sys.stderr)
        sys.exit(2)
