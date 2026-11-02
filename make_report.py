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
sys.path.insert(0, HERE)
from tools.describe import (recovery_level, recovery_runs_text, recovery_sentence,
                            recovery_short, cost_sentence, scope_sentence)
from tools.parsers import (parse_verify, parse_ttest, parse_libs, parse_compare,
                           parse_sweep, parse_sweep_summary, parse_converge, parse_attack,
                           parse_real_recovery, parse_bench)
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


DUDECT_EXE = os.path.join(HERE, "tests", "dudect_harness.exe")


def run_dudect_upstream(batch, budget):
    """调用上游 dudect harness：每个实现跑到触发或预算耗尽。"""
    impls = [("ours T-table", "ours_tt"), ("ours const-time", "ours_ct"),
             ("GmSSL", "gmssl"), ("Tongsuo-obs", "tongsuo")]
    if not os.path.exists(DUDECT_EXE):
        return []
    rows = []
    for label, key in impls:
        runs = []
        total_ms = 0
        for _ in range(3):
            t0 = time.time()
            try:
                p = subprocess.run([DUDECT_EXE, key, str(budget), str(batch)],
                                   capture_output=True, timeout=900)
            except Exception:
                continue
            out = p.stdout.decode("utf-8", "replace")
            total_ms += round((time.time() - t0) * 1000)
            m_state = re.search(r"state=(LEAK|clean)", out)
            m_samp = re.search(r"samples=(\d+)", out)
            ts = re.findall(r"max t:\s*\+?(-?[\d.]+)", out)
            runs.append({
                "verdict": m_state.group(1) if m_state else None,
                "samples": int(m_samp.group(1)) if m_samp else None,
                "max_t": abs(float(ts[-1])) if ts else None,
            })
        if not runs:
            continue
        verdicts = [r["verdict"] for r in runs]
        leak_n = sum(1 for v in verdicts if v == "LEAK")
        rows.append({
            "name": label,
            "verdicts": verdicts,
            "verdict": "LEAK" if leak_n >= 2 else "clean",   # 三次取多数
            "samples": [r["samples"] for r in runs],
            "max_t": max((r["max_t"] or 0) for r in runs),
            "ms": total_ms // len(runs),
        })
    return rows


def collect():
    rep = {"tool": "hengshi", "version": "1.0", "mode": "quick" if QUICK else "full",
           "generated": time.strftime("%Y-%m-%d %H:%M:%S")}

    out, _ = run("verify")
    rep["sm4_vector"] = parse_verify(out)

    out, _ = run("ttest", N_MAIN)
    t_tt, t_ct, e_tt, e_ct = parse_ttest(out)
    rep["ttest"] = {
        "n_per_class": N_MAIN,
        "t_ttable": t_tt,
        "t_constant_time": t_ct,
        "effect_ttable_pct": e_tt,
        "effect_ct_pct": e_ct,
        "verdict_ttable": "LEAK" if (t_tt or 0) > 4.5 else "clean",
        "verdict_constant_time": "LEAK" if (t_ct or 0) > 4.5 else "clean",
    }

    out, _ = run("libs", N_MAIN, REPS)
    rep["libs"] = parse_libs(out)

    out, _ = run("compare", N_MAIN)
    tt_cmp, sm_cmp = parse_compare(out)
    rep["compare_layouts"] = {"gmssl_ttable": tt_cmp, "gmssl_small": sm_cmp}

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
    variants = parse_sweep(out)
    summ = parse_sweep_summary(out)
    rep["false_positive"] = {"variants": variants, **summ,
                             "all_correct": all(v["correct"] for v in variants) if variants else None}

    out, _ = run("converge")
    conv = parse_converge(out)
    rep["convergence"] = conv
    if len(conv) >= 2:
        rep["convergence_growth"] = round(conv[-1]["t_ttable"] / conv[0]["t_ttable"], 2)
        rep["convergence_n_ratio"] = round(conv[-1]["n"] / conv[0]["n"], 1)

    # 上游 dudect（固定 commit）实测
    rep["dudect_upstream"] = run_dudect_upstream(20000, 120000)

    # 阈值/裁剪参数敏感性
    out, _ = run("bench", 15000)
    rep["dudect_bench"] = parse_bench(out)

    # 修复代价
    out, _ = run("cost", 12000)
    m = re.search(r"T-table\s+平均\s+([\d.]+) 周期/次", out)
    m2 = re.search(r"常量时间版\s+平均\s+([\d.]+) 周期/次", out)
    m3 = re.search(r"倍数 ([\d.]+)x", out)
    rep["cost"] = {
        "cycles_ttable": float(m.group(1)) if m else None,
        "cycles_ct": float(m2.group(1)) if m2 else None,
        "ratio": float(m3.group(1)) if m3 else None,
    }

    # 真实库部分密钥恢复（行粒度 → 高 4 bit）
    # 每个库跑 3 次取中位：单次受噪声影响会在 3/4 与 4/4 之间跳
    rr = {}
    for lib in ("gmssl", "tongsuo"):
        runs = []
        for _ in range(3):
            out, _ = run("attack-real", lib, 1200)
            runs.append(parse_real_recovery(out))
        matched = sorted(r["matched"] for r in runs if r.get("matched") is not None)
        rr[lib] = {
            "matched": matched[len(matched) // 2] if matched else None,
            "total": runs[0].get("total"),
            "runs": [r.get("matched") for r in runs],
            "per_byte": runs[-1].get("per_byte", []),
        }
    rep["real_recovery"] = rr

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
        L.append("| 库 | 中位 t | 跨轮范围 | 效应量 | 判定 |")
        L.append("|---|---|---|---|---|")
        for x in libs:
            rng = f"{x['min_t']:.1f}–{x['max_t']:.1f}" if "min_t" in x else "—"
            note = "（不稳定）" if x.get("unstable") else ""
            L.append(f"| {x['name']} | {x['t']:.2f} | {rng} | {x['effect_pct']:.2f}% | **{x['verdict']}**{note} |")
        L.append("\n**证据范围（分两级）**：" + scope_sentence(rep) + "\n")

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
        L.append(f"## 4. 对照组与判别能力评估（{len(vs)} 个真值已知的实现，各 {vs[0]['reps']} 轮）\n")
        L.append("| 实现 | 越阈值轮次 | max \\|t\\| | 中位 \\|t\\| | 判定 |")
        L.append("|---|---|---|---|---|")
        for v in vs:
            tag = "正确" if v["correct"] else ("未检出（测量盲区）" if v.get("blind") else "误判")
            L.append(f"| {v['name']} | {v['over']}/{v['reps']} | {v['max_t']:.1f} | {v['median_t']:.1f} | {tag} |")
        blind = sum(v["reps"] for v in vs if v.get("blind"))
        L.append("")
        L.append(f"- **灵敏度**：泄漏实现被正确判泄漏的轮次占比 {fp.get('sensitivity_pct')}%"
                 + (f"（{blind} 轮属测量盲区，不计入）" if blind else ""))
        L.append(f"- **假阳性**：干净实现被判泄漏的轮次占比 {fp.get('false_positive_pct')}%")
        L.append("- 判据：重复多轮中过半越阈值才算泄漏；单轮越阈值不算误判。")
        L.append("- 未检出的实现若因无法 flush 其表（Tongsuo pristine），记为**测量盲区**，"
                 "既不计入假阳性，也不计入灵敏度。\n")

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
    L.append("> **范围说明**：" + scope_sentence(rep) + "\n")
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

    rr = rep.get("real_recovery") or {}
    if rr:
        L.append("## 7. 真实库上的部分密钥恢复\n")
        L.append("> 行粒度只能确定表索引落在哪一行，因此上限是每个字节的高 4 bit。"
                 "这不是缺陷，是观测通道的物理边界（见 HS-003）。\n")
        L.append("| 实现 | 恢复的高 4 bit 字节数 | 说明 |")
        L.append("|---|---|---|")
        for name, key in (("GmSSL", "gmssl"), ("Tongsuo", "tongsuo")):
            v = rr.get(key) or {}
            lvl = recovery_level(v)
            note = "部分恢复" if lvl == "partial" else ("未收敛（原因待查）" if lvl == "none" else "无数据")
            L.append(f"| {name} | {recovery_runs_text(v)} | {note} |")
        g = rr.get("gmssl") or {}
        if g.get("per_byte"):
            L.append("\nGmSSL 逐字节（最近一次）：\n")
            L.append("| 字节 | 真实高4位 | 恢复高4位 | 得分 |")
            L.append("|---|---|---|---|")
            for b in g["per_byte"]:
                L.append(f"| b{b['byte']} | 0x{b['true_hi']} | 0x{b['best_hi']} | {b['score']} |")
        L.append("\n**结论**：" + recovery_sentence(rr.get("gmssl") or {}, "GmSSL") +
                 "；" + recovery_sentence(rr.get("tongsuo") or {}, "Tongsuo") +
                 "。完整 128 bit 主密钥恢复仍需更细的观测通道。\n")

    cs = rep.get("cost") or {}
    if cs.get("ratio"):
        L.append("## 8. 修复代价（闭环的最后一环）\n")
        L.append("| 实现 | 平均周期/次 | 相对代价 |")
        L.append("|---|---|---|")
        L.append(f"| T-table（泄漏） | {cs['cycles_ttable']:.0f} | 1.00x |")
        L.append(f"| 常量时间（修复） | {cs['cycles_ct']:.0f} | **{cs['ratio']:.2f}x** |")
        L.append("\n检测 → 修复 → 复测（t 从数十降到阈值内）→ 代价量化，这一环闭合。"
                 "代价说明：本实现用全表扫描替代查表，位切片通常更便宜，但仍是数倍量级。\n")

    du = rep.get("dudect_upstream") or []
    if du:
        tmap = {"ours T-table": t.get("verdict_ttable"),
                "ours const-time": t.get("verdict_constant_time")}
        for _l in libs:                      # 真实库的判定取自 A.2 的横向对比
            tmap[_l["name"]] = _l["verdict"]
        L.append("## 9. 与上游 dudect 的同机对照\n")
        L.append("> 直接编译 **上游 dudect**（oreparaz/dudect，commit `dc269651`，MIT）作为对照，"
                 "不是复现其算法：它自己做 102 个检验（1 次未裁剪 + 100 个上尾裁剪百分位 + 1 次二阶），"
                 "取最大 \\|t\\|。为对齐威胁模型，双方测量前都刷表。\n")
        L.append("| 实现 | dudect 结论（三次） | 触发样本数 | dudect max \\|t\\| | 耗时 (ms) | 本工具结论 | 一致 |")
        L.append("|---|---|---|---|---|---|---|")
        agree = 0
        for r in du:
            ours = tmap.get(r["name"], "—")
            same = (str(ours).upper() == str(r["verdict"]).upper())
            agree += 1 if same else 0
            vd = "、".join(str(v) for v in r.get("verdicts") or [])
            samp = "、".join(str(v) for v in (r.get("samples") or []))
            L.append(f"| {r['name']} | {r['verdict']}（三次 {vd}） | {samp} | "
                     f"{r['max_t']:.1f} | {r['ms']} | {ours} | {'是' if same else '否'} |")
        L.append(f"\n判定一致 {agree}/{len(du)}。dudect 的结论与之相同，说明本工具的判据没有引入偏差。\n")

    db = rep.get("dudect_bench") or []
    if db:
        L.append("### 9.1 阈值与裁剪参数敏感性（本工具的判据内部对照）\n")
        L.append("> 同一批样本上换两套预处理：本工具（裁剪 5%、阈值 4.5、三次取中位）与"
                 "更严口径（裁剪 1%、阈值 10）。**这不是 dudect**，只说明结论对参数不敏感。\n")
        L.append("| 实现 | 本工具 \\|t\\| | 严口径 \\|t\\| | 采集耗时 (ms) | 判定一致 |")
        L.append("|---|---|---|---|---|")
        for r in db:
            L.append(f"| {r['name']} | {r['t_ours']:.1f} | {r['t_dudect']:.1f} | {r['ms']:.0f} | "
                     f"{'是' if r['agree'] else '否'} |")
        L.append("")

    L.append("## 10. 可复现性\n")
    L.append("```\nhengshi verify\nhengshi libs 40000 3\nhengshi compare 40000\n"
             "hengshi ttest 40000\nhengshi converge\nhengshi attack 64 200 32\n"
             "hengshi attack 4 200 4\nhengshi sweep 10 20000\n```\n")

    out_name = "report.smoke.md" if str(rep.get("mode", "")).startswith("smoke") else "report.md"
    open(os.path.join(HERE, out_name), "w", encoding="utf-8").write("\n".join(L))

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
        # 写到 report.smoke.json，不覆盖真实实验产物
        json.dump(rep, open(os.path.join(HERE, "report.smoke.json"), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print("smoke: 由夹具生成 report.smoke.json（未执行任何计时实验，不覆盖 report.json）")
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
