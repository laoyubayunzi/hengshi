"""sync_docs.py - 用 report.json 生成技术说明文档的「数据附录」。

为什么要有这个：技术说明里原先散落着一批手写数字（布局实验 t、收敛表、横向对比 t…），
每次重跑实验都过期，而且过期了没人发现。现在所有会变动的数字只出现在一个
自动生成的附录里，正文只引用附录编号，不再复制数字。
"""
import json
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.abspath(__file__))

BEGIN = "<!-- DATA-APPENDIX:BEGIN -->"
END = "<!-- DATA-APPENDIX:END -->"


def fmt(x, nd=2):
    return f"{x:.{nd}f}" if isinstance(x, (int, float)) else "—"


def build(rep):
    t = rep.get("ttest") or {}
    libs = rep.get("libs") or []
    cl = rep.get("compare_layouts") or {}
    conv = rep.get("convergence") or []
    fp = rep.get("false_positive") or {}
    rr = rep.get("real_recovery") or {}
    cost = rep.get("cost") or {}
    atk = rep.get("attack_aligned_32rounds") or {}

    L = ["## 附录 A　数据快照（由 report.json 自动生成，请勿手改）", "",
         f"生成时间：{rep.get('generated')}　模式：{rep.get('mode')}", ""]

    L += ["### A.1 自研两种实现", "",
          "| 实现 | 中位 \\|t\\| | 效应量 | 判定 |", "|---|---|---|---|",
          f"| T-table | {fmt(t.get('t_ttable'))} | {fmt(t.get('effect_ttable_pct'))}% | {t.get('verdict_ttable')} |",
          f"| 常量时间 | {fmt(t.get('t_constant_time'))} | {fmt(t.get('effect_ct_pct'))}% | {t.get('verdict_constant_time')} |",
          ""]

    L += ["### A.2 横向对比（含同源码两种构建）", "",
          "| 口径 | 中位 \\|t\\| | 效应量 | 判定 |", "|---|---|---|---|"]
    for x in libs:
        L.append(f"| {x['name']} | {fmt(x['t'])} | {fmt(x['effect_pct'])}% | {x['verdict']} |")
    L.append("")

    if cl.get("gmssl_ttable"):
        a, b = cl["gmssl_ttable"], cl.get("gmssl_small") or {}
        L += ["### A.3 同一份源码的两种表布局", "",
              "| 配置 | 中位 \\|t\\| | 效应量 |", "|---|---|---|",
              f"| GmSSL T-table（4 KB，16 项/行） | {fmt(a['t'])} | {fmt(a['effect_pct'])}% |",
              f"| GmSSL 小表（256 B） | {fmt(b.get('t'))} | {fmt(b.get('effect_pct'))}% |", ""]

    if conv:
        L += ["### A.4 √n 收敛", "", "| n/class | \\|t\\| T-table | \\|t\\| 常量时间 |", "|---|---|---|"]
        for c in conv:
            L.append(f"| {c['n']} | {fmt(c['t_ttable'])} | {fmt(c['t_ct'])} |")
        if rep.get("convergence_growth"):
            L.append("")
            L.append(f"样本量放大 {rep.get('convergence_n_ratio')} 倍，"
                     f"T-table 的 |t| 放大 {rep.get('convergence_growth')} 倍"
                     f"（理论 √{rep.get('convergence_n_ratio')} ≈ "
                     f"{(rep.get('convergence_n_ratio') or 1) ** 0.5:.2f} 倍）。")
        L.append("")

    vs = fp.get("variants") or []
    if vs:
        L += ["### A.5 对照组与判别能力", "",
              "| 实现 | 越阈值轮次 | max \\|t\\| | 判定 |", "|---|---|---|---|"]
        for v in vs:
            tag = "正确" if v.get("correct") else ("未检出（测量盲区）" if v.get("blind") else "误判")
            L.append(f"| {v['name']} | {v['over']}/{v['reps']} | {fmt(v['max_t'], 1)} | {tag} |")
        L += ["",
              f"- 灵敏度：{fp.get('sensitivity_pct')}%",
              f"- 假阳性：{fp.get('false_positive_pct')}%", ""]

    if rr:
        g, ts = rr.get("gmssl") or {}, rr.get("tongsuo") or {}

        def runs(r):
            return "、".join(str(x) for x in (r.get("runs") or [])) or "—"
        L += ["### A.6 真实库部分恢复（行粒度 → 高 4 bit）", "",
              "| 实现 | 三次重复 | 说明 |", "|---|---|---|",
              f"| GmSSL | {runs(g)} | 每字节只能确定高 4 bit |",
              f"| Tongsuo | {runs(ts)} | 该方法未收敛 |", ""]

    if atk:
        L += ["### A.7 自研行对齐布局的完整恢复", "",
              f"- 真实轮密钥：`{' '.join(atk.get('true_round_keys', []))}`",
              f"- 恢复轮密钥：`{' '.join(atk.get('recovered_round_keys', []))}`",
              f"- 主密钥一致：**{atk.get('master_key_match')}**", ""]

    du = rep.get("dudect_upstream") or []
    if du:
        L += ["### A.9 与上游 dudect 的同机对照", "",
              "> 直接编译上游 dudect（oreparaz/dudect，commit dc269651，MIT）作为基准，",
              "> 统计全部由它自己完成（102 个检验：1 次未裁剪 + 100 个上尾裁剪百分位 + 1 次二阶），",
              "> 每次跑三遍取多数。", "",
              "| 实现 | dudect 结论（三次） | 触发样本 | dudect max \\|t\\| | 耗时 (ms) |",
              "|---|---|---|---|---|"]
        for r in du:
            vd = "、".join(str(v) for v in r.get("verdicts") or [])
            samp = "、".join(str(v) for v in (r.get("samples") or []))
            L.append(f"| {r['name']} | {r.get('verdict')}（{vd}） | {samp} | "
                     f"{(r.get('max_t') or 0):.1f} | {r.get('ms')} |")
        L += [""]

    db = rep.get("dudect_bench") or []
    if db:
        L += ["### A.10 阈值与裁剪参数敏感性（不是 dudect）", "",
              "| 实现 | 本工具 \\|t\\| | 严口径 \\|t\\| | 判定一致 |",
              "|---|---|---|---|"]
        for r in db:
            L.append(f"| {r['name']} | {r['t_ours']:.1f} | {r['t_dudect']:.1f} | "
                     f"{'是' if r['agree'] else '否'} |")
        L += ["", "> 同一批样本换两套预处理：本工具（裁剪 5%、阈值 4.5）与更严口径（裁剪 1%、阈值 10）。",
              "> 只说明结论对参数不敏感，**与 dudect 无关**。", ""]

    if cost.get("ratio"):
        L += ["### A.8 修复代价", "",
              "| 实现 | 周期/次 | 相对代价 |", "|---|---|---|",
              f"| T-table | {cost['cycles_ttable']:.0f} | 1.00x |",
              f"| 常量时间 | {cost['cycles_ct']:.0f} | {cost['ratio']:.2f}x |", ""]

    L.append("> 本附录由 `sync_docs.py` 从 `report.json` 生成；重跑实验后重新生成即可，正文不需要改动。")
    return "\n".join(L)


def main() -> int:
    rep = json.load(open(os.path.join(ROOT, "report.json"), encoding="utf-8"))
    block = f"{BEGIN}\n{build(rep)}\n{END}"
    touched = []
    for name in ("技术说明.md", "plan.md"):
        p = os.path.join(ROOT, name)
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8").read()
        if BEGIN in text and END in text:
            head = text.split(BEGIN)[0]
            tail = text.split(END, 1)[1]
            text = head + block + tail
        elif name == "技术说明.md":
            text = text.rstrip() + "\n\n" + block + "\n"
        else:
            continue
        open(p, "w", encoding="utf-8").write(text)
        touched.append(name)
    print("已更新数据附录：" + ", ".join(touched))
    return 0


if __name__ == "__main__":
    sys.exit(main())
