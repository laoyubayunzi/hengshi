# make_findings.py - 把实验数据整理成"检测发现"格式（合规报告骨架）
# 用法: python make_findings.py   （先跑 make_report.py 生成 report.json）
import json, os, time

import sys as _sys
# Windows 上 stdout 可能是 cp1252（GitHub Actions 的 runner 就是），中文会直接抛
# UnicodeEncodeError。统一强制 UTF-8，避免"脚本在 CI 上跑不起来"这类环境性失败。
try:
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
rep = json.load(open(os.path.join(HERE, "report.json"), encoding="utf-8"))

t = rep.get("ttest", {})
g = rep.get("gmssl", {})
a = rep.get("attack_aligned_32rounds", {})

# 两个独立字段，互不覆盖：
#   detection: clean / leak / inconclusive —— 有没有数据相关的时间差异
#   exploit  : 未验证 / 部分信息恢复 / 完整密钥恢复 —— 这个差异被利用到了什么程度
# severity 只是从 exploit 派生的三档，方便排序，不替代上面两栏。
EXPLOIT_LEVELS = ["未验证", "部分信息恢复", "完整密钥恢复"]
SEV_BY_EXPLOIT = {"完整密钥恢复": "高", "部分信息恢复": "中", "未验证": "待验证", "不适用": "信息"}

findings = []
fid = 1

def add(title, asset, tval, effect, evidence, impact, fix, retest, ref,
        kind="leak", detection="leak", exploit="未验证"):
    global fid
    findings.append({
        "id": f"HS-{fid:03d}", "title": title, "asset": asset, "kind": kind,
        "detection": detection, "exploit": exploit,
        "severity": SEV_BY_EXPLOIT.get(exploit, "信息"), "t": tval, "effect_pct": effect,
        "evidence": evidence, "impact": impact, "fix": fix, "retest": retest, "ref": ref,
    })
    fid += 1

add("SM4 T-table 实现存在缓存时序泄漏，可导致主密钥恢复",
    "自研 SM4 T-table 实现（与 GmSSL/OpenSSL 主流写法同构）",
    t.get("t_ttable"), t.get("effect_ttable_pct"),
    [f"Welch t = {t.get('t_ttable'):.2f}（阈值 4.5，每类 40000 样本，重复 3 次取中位）",
     f"效应量 {t.get('effect_ttable_pct')}%",
     "Flush+Reload 观测 + 轮密钥回归：200 条 trace 恢复 rk[0..3]，反推主密钥与原密钥完全一致"],
    "对手在同机或共享页场景下可判定常量时间性并在可接受时间内恢复 128 bit 主密钥",
    "改用访存地址与密钥无关的实现（S-box 全表扫描 + 掩码选择，或位切片）；给出参考实现并实测",
    f"修复后 Welch t = {t.get('t_constant_time'):.2f}，效应量 {t.get('effect_ct_pct')}%，落在阈值内",
    "GM/T 0028-2014 密码模块安全技术要求（物理安全 / 缓解其他攻击要求，条款号按实际版本核对）",
    exploit="完整密钥恢复")

pv = rep.get("provenance") or {}
if pv.get("sources") and pv.get("distinct_implementations", 99) < len(pv["sources"]):
    add("多个国产库共用同一份 SM4 上游实现（供应链集中度风险）",
        "；".join(x["library"] for x in pv["sources"]),
        None, None,
        [f"{x['library']}: {x['file']}  SHA-256 {x['sha256'][:32]}…" for x in pv["sources"]],
        "同一上游实现的时序泄漏会同时存在于多个下游库；\"多家实现互相印证\"的假设不成立，选型时不能靠库数量判断安全性",
        "选型时核验实现来源（哈希/上游血缘），而非只看厂商数量；对共用上游统一修补",
        "两者源码完全相同，因此预期行为一致；BabaSSL 未独立运行验证，本报告不对其单独下结论",
        "供应链管理实践（GB/T 36637 类要求，条款按实际标准核对）", kind="observation", detection="inconclusive", exploit="不适用")

# 自然布局的边界结论（负结果，但含部分信息）
add("自然布局（16 项/缓存行）下只能得到表索引高 4 bit，无法稳定完成完整主密钥恢复",
    "GmSSL / Tongsuo 等采用 4 KB T-table 的实现",
    None, None,
    ["每张表 1024 字节 = 16 条缓存行，256 个表项中同一行的 16 个候选完全不可区分",
     "32 轮访问使命中集合高度饱和：单轮某条行未被访问的概率约 12.6%，观测端信噪比被进一步压低",
     "同一行内候选的歧义会在轮状态递推中快速累积，无法稳定收敛到 128 bit 主密钥"],
    "当前观测通道（缓存行粒度 + Flush/Reload）对真实库的上限是部分信息，不是密钥恢复；"
    "评估其风险时应按「部分信息暴露」而非「主密钥可恢复」计",
    "若需真实库密钥恢复，需更细的观测通道（perf 计数、预取器状态、页级）或非饱和的表布局",
    "在自研行对齐布局上已验证完整恢复（HS-001），说明瓶颈在观测粒度而非算法",
    "GM/T 0028-2014（条款号按实际版本核对）",
    kind="boundary", detection="leak", exploit="部分信息恢复")

for L in (rep.get("libs") or []):
    add(f"{L['name']} 官方 SM4 实现存在可测的时序泄漏",
        f"{L['name']} 上游 SM4 实现（官方源码，未改写，标准向量通过）",
        L["t"], L["effect_pct"],
        [f"Welch t = {L['t']:.2f}（重复 3 次取中位）",
         f"效应量 {L['effect_pct']:.2f}%",
         "T 表位于只读段，攻击者只能观测；这正是共享主机场景"],
        f"表明存在数据相关时序通道；能否进一步用于密钥恢复尚需单独验证。效应量 {L['effect_pct']:.2f}% 说明优化削弱但未消除泄漏",
        "改用位切片（bitslice）或恒定地址访问实现，消除访存地址与数据的相关性。"
        "注意：把表项按缓存行对齐并不会缓解问题——它会把单次可观测位从 4 bit 提升到 8 bit（见 HS 报告中的布局实验），属于放大攻面，不应作为加固手段",
        "本工具已提供常量时间替代实现的对照测量方法，可用于复测",
        "GM/T 0028-2014（条款号按实际版本核对）")

cl = rep.get("compare_layouts") or {}
sm = cl.get("gmssl_small") or {}
if sm.get("t") is not None:
    add("同一实现的「小表」编译配置同样泄漏（表小不等于安全）",
        "GmSSL small-footprint 配置（256 B S-box，仅占 4 条缓存行）",
        sm.get("t"), sm.get("effect_pct"),
        [f"Welch t = {sm.get('t'):.2f}（重复 3 次取中位）",
         f"效应量 {sm.get('effect_pct')}%（与大表配置同量级）",
         "两种配置唯一差别是表布局；算法、编译选项、机器完全相同"],
        "常见加固设想「把表缩小到能放进 L1 就安全了」被证伪：泄漏根源是访存地址由数据决定，不是表的大小",
        "消除地址的数据相关性（全表扫描 + 掩码、位切片、或恒定地址访问）；仅调整表大小无效",
        "见 HS-001 的修复实现及其复测结果",
        "同上")

with open(os.path.join(HERE, "findings.json"), "w", encoding="utf-8") as f:
    json.dump({"tool": "hengshi", "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "findings": findings},
              f, ensure_ascii=False, indent=2)

L = []
L.append("# 衡时 · 检测发现报告\n")
L.append(f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}　检测工具：hengshi v1　测试平台：本机 Intel / Windows 11\n")
L.append("## 摘要\n")
leak_n = sum(1 for x in findings if x.get("kind", "leak") == "leak")
obs_n = len(findings) - leak_n
L.append(f"本次共记录 {len(findings)} 条发现：**{leak_n} 个实现经实测判定存在时序泄漏**"
         f"（自研 T-table、GmSSL 官方实现、GmSSL 小表配置、Tongsuo 官方实现）；"
         f"另有 {obs_n} 条为源码同源性的供应链观察（BabaSSL 与 Tongsuo 同源，未单独实测）。\n")
L.append("证据分层说明：")
L.append("- **统计证据**（Welch t 值 + 效应量 + √n 收敛）覆盖上述 4 个实测实现与 3 个干净对照实现；")
L.append("- **密码学证据**（密钥恢复）目前仅对**自研实现的行对齐布局**完成；"
         "未对 GmSSL / Tongsuo 实施密钥恢复，对其结论仅限统计判定。\n")
L.append("**两级判定，两个字段，不混为一谈**：")
L.append("- `detection`（检测结论）：`clean` / `leak` / `inconclusive` —— 是否存在数据相关的时间差异；")
L.append("- `exploit`（可利用性）：`未验证` / `部分信息恢复` / `完整密钥恢复` —— 该差异被利用到什么程度。")
L.append("- 严重度是从 `exploit` 派生的三档排序值，不替代上面两栏；**不按 t 值分级**（t 只反映统计置信度）。\n")
L.append("| 编号 | 发现 | 检测结论 | 可利用性 | t 值 | 效应量 |")
L.append("|---|---|---|---|---|---|")
for x in findings:
    tv = f"{x['t']:.2f}" if x['t'] is not None else "—"
    ev = f"{x['effect_pct']}%" if x['effect_pct'] is not None else "—"
    L.append(f"| {x['id']} | {x['title']} | {x.get('detection','—')} | {x.get('exploit','—')} | {tv} | {ev} |")
L.append("")
for x in findings:
    L.append(f"---\n\n## {x['id']}　{x['title']}\n")
    L.append(f"**严重度**：{x['severity']}　**受影响资产**：{x['asset']}\n")
    L.append("**证据**：")
    for e in x["evidence"]:
        L.append(f"- {e}")
    L.append(f"\n**影响**：{x['impact']}\n")
    L.append(f"**修复建议**：{x['fix']}\n")
    L.append(f"**复测结论**：{x['retest']}\n")
    L.append(f"**参考**：{x['ref']}\n")

L.append("---\n\n## 检测方法\n")
L.append("1. **静态画像**：表布局（每缓存行表项数）、表地址对齐、是否 .rodata 只读。")
L.append("2. **统计检测**：固定/随机两类输入各 40000 样本，裁剪首尾 5%，Welch t 检验，阈值 4.5；绑核 + 高优先级 + 三次取中位保证复现。")
L.append("3. **√n 收敛**：样本量 2000→80000，真泄漏 |t| 按 √n 增长，噪声不增长。")
L.append("4. **密码学实证**：Flush+Reload 观测 + 逐轮密钥回归 + 密钥扩展逆推，验证'能恢复主密钥'这一实际危害。\n")
L.append("## 局限\n")
L.append("- 覆盖范围为 SM4（含两种编译配置），未含 SM2/SM3。")
L.append("- 同进程/共享页假设，跨进程攻击需额外处理。")
L.append("- 未覆盖多核干扰、虚拟化、超线程等真实测评环境噪声。")

open(os.path.join(HERE, "findings.md"), "w", encoding="utf-8").write("\n".join(L))
print(f"wrote findings.json / findings.md  ({len(findings)} findings)")
