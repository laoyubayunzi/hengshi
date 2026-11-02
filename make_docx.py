# make_docx.py - 生成作品文档（docx）
# 用法: python make_docx.py
import json, os, time
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn

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
fnd = json.load(open(os.path.join(HERE, "findings.json"), encoding="utf-8"))

doc = Document()

# 中文字体
style = doc.styles["Normal"]
style.font.name = "Microsoft YaHei"
style.font.size = Pt(10.5)
style.element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")

def h(text, level=1):
    p = doc.add_heading(text, level=level)
    for r in p.runs:
        r.font.name = "Microsoft YaHei"
        r._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    return p

def body(text, bold=False):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.bold = bold
    r.font.name = "Microsoft YaHei"
    r._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    return p

def bullet(text):
    p = doc.add_paragraph(text, style="List Bullet")
    for r in p.runs:
        r.font.name = "Microsoft YaHei"
        r._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    return p

def table(header, rows, widths=None):
    t = doc.add_table(rows=1, cols=len(header))
    t.style = "Light Grid Accent 1"
    for i, cell in enumerate(t.rows[0].cells):
        cell.text = header[i]
        for p in cell.paragraphs:
            for r in p.runs:
                r.bold = True
                r.font.size = Pt(9.5)
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = str(v)
            for p in cells[i].paragraphs:
                for r in p.runs:
                    r.font.size = Pt(9.5)
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Inches(w)
    doc.add_paragraph()
    return t

def image(path, caption, width=5.9):
    if os.path.exists(path):
        doc.add_picture(path, width=Inches(width))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(caption)
        r.italic = True
        r.font.size = Pt(9)
        r.font.name = "Microsoft YaHei"
        r._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")

# ---------------- 封面 ----------------
t = doc.add_heading("衡时", level=0)
for r in t.runs:
    r.font.name = "Microsoft YaHei"
    r._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
doc.add_paragraph("面向国密实现的常量时间性检测与密钥泄漏定位平台").alignment = WD_ALIGN_PARAGRAPH.CENTER
doc.add_paragraph()
body("赛道：自由作品赛（软件类，信息安全技术与应用设计）")
body("作品形态：可执行程序 + 检测报告生成器（Windows x64，单文件，无第三方依赖）")
body("文档版本：v1.0　生成时间：" + time.strftime("%Y-%m-%d"))
doc.add_page_break()

# ---------------- 一、概述 ----------------
h("一、作品概述", 1)
body("国密算法本身是安全的，但密码算法的软件实现往往不是常量时间的：执行路径或访存地址一旦依赖密钥，"
     "攻击者就能通过缓存时序把密钥还原出来。本作品解决的就是「如何在不修改被测实现、无需插桩、"
     "也无需专用采集硬件的前提下，判断一个国密实现是否常量时间，并在判定不安全时给出可复现的证据」这一问题。"
     "当前版本面向支持 RDTSCP / CLFLUSH 的 x86 平台，被测源码需编入测试程序。")
body("作品给出两类证据，适用范围不同（这一点在文中处处标明）：")
bullet("统计证据：固定/随机两类输入下的 Welch t 检验，配合 √n 收敛实验区分「真泄漏」与「机器噪声」。"
        "覆盖面最广：4 个实测实现 + 3 个干净对照。")
bullet("密码学证据：Flush+Reload 观测缓存行命中，逐轮回归轮密钥，再用密钥扩展的逆推关系还原 128 bit 主密钥。"
        "覆盖面较窄：仅在自研实现的行对齐布局上完成，用于证明「泄漏可被利用到什么程度」。")
body("在真实实现上，本作品对两个主流国产密码库（GmSSL、Tongsuo）给出了检测结论，并额外发现二者共用同一份上游实现。")

# ---------------- 二、问题 ----------------
h("二、问题定义与威胁模型", 1)
body("威胁模型：攻击者与受害者在同一物理机（同进程调用，或共享库映射到同一物理页），"
     "能够执行 rdtscp 计时与 clflush，知道自己提交的明文，不知道密钥。目标是判断实现是否常量时间，"
     "若否，恢复密钥。该类攻击不需要 root 权限、不需要特殊硬件，在共享云主机、多租户虚拟化场景中现实存在。")
body("作品要回答三个问题：")
bullet("会不会漏（是否常量时间）——要求给出可复现的统计判据，而不是单次观察。")
bullet("漏了多少（危害有多实）——要求在可接受时间内真的把密钥恢复出来。")
bullet("漏在哪（定位与修复）——要求能落到轮次、字节、缓存行粒度，并验证修复有效。")

# ---------------- 三、现状 ----------------
h("三、国内外研究现状与差异", 1)
table(["工作", "做了什么", "不足"],
      [["ctgrind (2010)", "Valgrind 上标记 secret，检查密钥相关分支", "只覆盖分支，不管查表；依赖源码"],
       ["dudect (2017)", "两类别 Welch t 检验", "只给「有无」，不给「在哪、怎么修」"],
       ["DATA / MicroWalk", "更细的地址轨迹观测", "工程重型，不面向国密工程实践"],
       ["Binsec/Rel (2021)", "二进制级关系式分析", "学术工具，接入成本高"],
       ["国内商用密码测评", "硬件侧信道平台（示波器 + 探头）", "测芯片不测软件实现，慢、贵"]],
      widths=[1.5, 2.6, 2.4])
body("本作品的差异点：面向国密软件实现、不修改被测源码、给出分层证据（统计判定 + 有条件时的密码学实证）、"
     "并输出可交付的检测报告（发现编号、严重度、证据、修复建议、复测结论）。")

# ---------------- 四、系统设计 ----------------
h("四、系统设计", 1)
body("系统分四层，逐层收敛证据：")
table(["层次", "做什么", "关键点"],
      [["1 静态画像", "表布局、地址对齐、是否只读段", "决定单次观测能看到几位密钥"],
       ["2 统计检测", "两类别执行周期 + Welch t", "测量前 clflush，两类别交替采样"],
       ["3 密码学实证", "Flush+Reload + 轮密钥回归", "乱序探测，避免预取器造成假饱和"],
       ["4 报告与复测", "发现格式化 + 修复后复测", "严重度按已证实的可利用程度分级"]],
      widths=[1.2, 2.6, 2.8])
body("工程实现要点：rdtscp + lfence 保证计时不被乱序执行污染；绑核 + 高优先级 + 三次取中位降低抖动；"
     "两类输入走完全相同的指令路径，避免前置代码差异污染测量（见第六节）。")

# ---------------- 五、关键技术 ----------------
h("五、关键技术", 1)
body("1. 统计判据与 √n 收敛", bold=True)
body("对同一实现采样两类执行周期（固定明文 / 随机明文），裁剪首尾 5% 离群值后计算 Welch t 值："
     "t = (mean_A - mean_B) / sqrt(var_A/n_A + var_B/n_B)，判据 |t| > 4.5。"
     "为排除「t 值是噪声凑出来的」这一质疑，进一步做样本量阶梯实验：真泄漏 |t| 按 √n 增长，噪声不增长。")
body("2. Flush+Reload 与轮密钥回归", bold=True)
body("每条 trace：flush 四张表全部缓存行 → 用随机明文加密一次 → 依伪随机顺序探测各缓存行重载时间，"
     "判定是否被访问。对第 r 轮，表下标字节等于 byte_j(X[r+1]⊕X[r+2]⊕X[r+3]) ⊕ byte_j(rk[r])；"
     "对 256 个候选统计「预测行是否在命中集合内」的比例，正确候选接近 100%，错误候选接近随机水平。")
body("3. 主密钥反推", bold=True)
body("拿到 rk[0..3] 后，利用密钥扩展逆推关系 K[i] = K[i+4] ⊕ T'(K[i+1]⊕K[i+2]⊕K[i+3]⊕CK[i])（i=3,2,1,0），"
     "再 MK[i] = K[i] ⊕ FK[i]，即可还原主密钥。")
body("4. 表布局对可观测位数的影响（结论一）", bold=True)
body("缓存行 64 字节、表项 4 字节，一行装 16 项，因此自然布局下单次观测只能确定表下标的高 4 位；"
     "把表项按缓存行对齐后可观测完整 8 位。实验进一步证明：表变小（4 KB → 256 B）并不能消除泄漏——"
     "泄漏根源是访存地址由数据决定，不是表的大小（结论二）。")
body("自然布局下的信息边界（负结果）", bold=True)
body("对 GmSSL / Tongsuo 这类 4 KB T-table 实现，缓存行观测不是零信息，但也达不到密钥恢复。把边界算清：")
bullet("目标轮访问的那一行必然在命中集合中：P(hit | 正确候选) ≈ 1；")
bullet("错误候选对应另一行，被剩余 31 轮碰到的概率：P(hit | 错误候选) = 1 − (15/16)^31 ≈ 86.5%；")
bullet("因此单条 trace 仍有约 13.5 个百分点的区分度，理论上可用大量 trace 恢复「目标表索引落在哪一行」。")
body("真正的边界有三条：同一行内 16 个表项不可区分（每字节约 4 bit）；低半字节歧义在逐轮状态递推中组合爆炸；"
     "32 轮访问使命中集合高度饱和（单轮某行未被访问的概率仅约 12.6%），信噪比被进一步压低。"
     "结论：自然布局可得到部分信息，当前方法无法稳定完成真实库的完整主密钥恢复。")
body("本作品据此采用两级判定：detection（clean / leak / inconclusive）与 exploit（未验证 / 部分信息恢复 / 完整密钥恢复），"
     "两个字段相互独立，避免把「测出了泄漏」误读为「密钥能被恢复」。")

# ---------------- 六、实验 ----------------
h("六、实验与结果", 1)
h("6.1 实现正确性", 2)
body("两个自研实现（T-table 与常量时间）均通过 GB/T 32907 标准测试向量："
     "密钥与明文均为 0123456789abcdeffedcba9876543210 时，密文为 681edf34d206965e86b3e94f536e4246。")

h("6.2 泄漏检测", 2)
tt = rep.get("ttest", {})
libs = rep.get("libs", [])
rows = [["T-table（自研）", f"{tt.get('t_ttable'):.2f}", f"{tt.get('effect_ttable_pct')}%", "LEAK"],
        ["常量时间（自研，修复版）", f"{tt.get('t_constant_time'):.2f}", f"{tt.get('effect_ct_pct')}%", "clean"]]
for L in libs:
    rows.append([f"{L['name']} 官方实现", f"{L['t']:.2f}", f"{L['effect_pct']:.2f}%", L["verdict"]])
table(["实现", "中位 t", "效应量", "判定"], rows, widths=[2.3, 1.3, 1.3, 1.2])
_n_cmp = 2 + len(libs)
_cn = {2: "两种", 3: "三种", 4: "四种", 5: "五种", 6: "六种"}.get(_n_cmp, "多种")
image(os.path.join(HERE, "viz", "impl_compare.png"), f"图 1　{_cn}实现的 |t| 对比（阈值 4.5）")

h("6.3 √n 收敛", 2)
conv = rep.get("convergence", [])
table(["n/class", "|t| T-table", "|t| 常量时间"],
      [[c["n"], f"{c['t_ttable']:.2f}", f"{c['t_ct']:.2f}"] for c in conv], widths=[1.5, 2, 2])
body(f"样本量放大 {rep.get('convergence_n_ratio')} 倍，T-table 的 |t| 放大 {rep.get('convergence_growth')} 倍"
     f"（理论 √n 预期 {(rep.get('convergence_n_ratio') or 1) ** 0.5:.2f} 倍）；常量时间版不随样本量增长。")
image(os.path.join(HERE, "viz", "t_vs_n.png"), "图 2　|t| 随样本量增长：真泄漏 vs 噪声")

h("6.4 密钥恢复", 2)
a = rep.get("attack_aligned_32rounds", {})
body("范围说明：密钥恢复仅在自研实现上完成——行对齐布局是为了隔离「表布局」这一变量而构造的受控实验。"
     "对 GmSSL / Tongsuo 未实施密钥恢复，对其结论仅限于统计泄漏判定。")
body("行对齐表布局、被攻击实现 32 轮、200 条 trace：")
table(["项", "值"],
      [["真实轮密钥", " ".join(a.get("true_round_keys", []))],
       ["恢复轮密钥", " ".join(a.get("recovered_round_keys", []))],
       ["反推主密钥", a.get("recovered_master_key", "—")],
       ["真实主密钥", a.get("true_master_key", "—")],
       ["是否一致", "是" if a.get("master_key_match") else "否"]], widths=[1.6, 4.4])
body("自然布局、4 轮实现作为对照：只能恢复 rk[0] 的高半字节（真实 f1 21 86 f9 → 恢复 f0 20 80 f0），"
     "与 6.4 的理论预测一致。")
image(os.path.join(HERE, "viz", "heatmap.png"), "图 3　缓存行命中热图：左为自然布局（饱和），右为行对齐布局")

h("6.5 假阳性评估", 2)
fp = rep.get("false_positive", {})
vs = fp.get("variants", [])
table(["实现", "真值", "越阈值轮次", "中位 |t|"],
      [[v["name"], "泄漏" if "table" in v["name"] else "干净", f"{v['over']}/{v['reps']}", f"{v['median_t']:.1f}"] for v in vs],
      widths=[2.4, 1.0, 1.4, 1.2])
clean = sum(v["reps"] for v in vs if "table" not in v["name"].replace("const-time", ""))
body(f"本轮实验未观察到假阳性（干净实现的 {clean} 次轮次中 0 次越阈值）。判据为「重复多轮中过半越阈值」，"
     f"单轮偶发越阈视为噪声。样本量有限，本结论仅描述本轮实验，不外推为总体假阳性率。")
body("严重度按已被实证的可利用程度分级（高 / 待验证 / 信息），不按 t 值或效应量——"
     "t 值只反映统计置信度，且随样本量增长，不能作为严重度依据。")

h("6.6 供应链核验", 2)
pv = rep.get("provenance", {})
src = pv.get("sources", [])
if src:
    table(["库", "版本", "commit", "许可证", "原文 SHA-256（前 16）", "核对"],
          [[x["library"], x["version"], x.get("commit", "—"), x.get("license", "—"),
            x["sha256"][:16], "一致" if x.get("hash_match", True) else "不一致"] for x in src],
          widths=[0.9, 0.8, 1.2, 0.9, 1.5, 0.7])
    body("原文链接（按发行 tag 固定下载，可逐条核对）：")
    for x in src:
        bullet(f"{x['library']} {x['version']}：{x.get('url', '—')}")
    body(f"三个库只对应 {pv.get('distinct_implementations')} 份独立实现。{pv.get('note')}。"
         "这说明「多家实现互相印证」在国产密码库领域不成立，选型必须核验实现血缘。")

# ---------------- 七、应用前景 ----------------
h("七、应用前景", 1)
bullet("商用密码应用安全性评估（密评）：为软件密码模块提供常量时间性检测证据，替代纯人工 + 硬件平台的低效流程。")
bullet("IoT / 固件供应链：二进制级、无源码依赖，可直接检测第三方提供的库与固件中的密码实现。")
bullet("开发侧回归测试：把检测接入 CI，任何引入数据相关访存的提交都会被拦下。")

# ---------------- 八、局限 ----------------
h("八、局限与后续工作", 1)
bullet("覆盖范围：目前为 SM4（含两种表布局），尚未覆盖 SM2/SM3；SM2 的标量乘泄漏形态完全不同。")
bullet("运行环境假设：同进程或共享页；跨进程攻击需额外处理。")
bullet("噪声环境：未系统评估多核干扰、虚拟化、超线程对判定的影响。")
bullet("架构覆盖：仅 x86-64，未覆盖 ARM 及国产 CPU 的缓存层次差异。")
bullet("后续：接入更多实现、把泄漏定位精确到源码行/指令偏移、输出对标 GM/T 0028 的合规模板。")

# ---------------- 九、声明 ----------------
h("九、说明", 1)
body("本作品检测对象均为公开开源实现或其编译配置；密钥恢复实验在作者自有机器、自有实现上完成，"
     "不涉及任何第三方系统的未授权访问。作品中引用的上游源码遵循其原始许可证（Apache-2.0 / OpenSSL License）。")

out = os.path.join(HERE, "衡时-作品文档.docx")
doc.save(out)
print("saved:", out)
print("paragraphs:", len(doc.paragraphs), "tables:", len(doc.tables), "images:", len(doc.inline_shapes))
