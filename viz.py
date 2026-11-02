# viz.py - 用 Pillow 画三张图（不依赖 matplotlib）
# 用法: python viz.py
import csv, json, os, math
from PIL import Image, ImageDraw, ImageFont

import sys as _sys
# Windows 上 stdout 可能是 cp1252（GitHub Actions 的 runner 就是），中文会直接抛
# UnicodeEncodeError。统一强制 UTF-8，避免"脚本在 CI 上跑不起来"这类环境性失败。
try:
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "viz")
os.makedirs(OUT, exist_ok=True)

def font(size):
    for p in (r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\simhei.ttf", r"C:\Windows\Fonts\arial.ttf"):
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    return ImageFont.load_default()

def axes(d, w, h, pad, title, xlabel, ylabel):
    f_title, f_lab = font(18), font(13)
    d.rectangle([pad, pad, w - pad, h - pad], outline=(60, 60, 60), width=1)
    d.text((pad, 8), title, fill=(20, 20, 20), font=f_title)
    d.text((w // 2 - 40, h - 22), xlabel, fill=(60, 60, 60), font=f_lab)
    d.text((6, h // 2), ylabel, fill=(60, 60, 60), font=f_lab)

# ---------- 图 1：|t| 随样本量增长 ----------
def chart_t_vs_n(conv, path):
    W, H, pad = 760, 420, 60
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    axes(d, W, H, pad, "|t| vs sample size  (real leak grows ~ sqrt(n), noise does not)",
         "samples per class (log scale)", "|t|")
    xs = [c["n"] for c in conv]
    xmin, xmax = math.log2(min(xs)), math.log2(max(xs))
    ymax = max(max(c["t_ttable"] for c in conv), 10) * 1.15
    def px(n):
        return pad + (math.log2(n) - xmin) / (xmax - xmin) * (W - 2 * pad)
    def py(v):
        return H - pad - (v / ymax) * (H - 2 * pad)
    # 阈值线
    d.line([pad, py(4.5), W - pad, py(4.5)], fill=(200, 120, 0), width=1)
    d.text((W - pad - 90, py(4.5) - 16), "threshold 4.5", fill=(200, 120, 0), font=font(12))
    for key, color, label in (("t_ttable", (200, 40, 40), "T-table (leaky)"),
                              ("t_ct", (30, 120, 200), "constant-time")):
        pts = [(px(c["n"]), py(c[key])) for c in conv]
        d.line(pts, fill=color, width=2)
        for (x, y) in pts:
            d.ellipse([x - 3, y - 3, x + 3, y + 3], fill=color)
        d.text((pts[-1][0] - 110, pts[-1][1] - 18), label, fill=color, font=font(12))
    for c in conv:
        d.text((px(c["n"]) - 14, H - pad + 4), str(c["n"]), fill=(80, 80, 80), font=font(11))
    img.save(path)

# ---------- 图 2：缓存行命中热图 ----------
def load_hits(path):
    rows = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.setdefault(int(r["table"]), {})[int(r["line"])] = int(r["hit"])
    return rows

def chart_heatmap(natural, aligned, path):
    cell = 6
    block_w = 4 * 16 * cell + 40          # 自然布局：4 表 × 16 行
    block_w2 = 4 * 256 * cell // 4 + 40   # 行对齐：每行 4 像素宽（1024 格放得下）
    W = block_w + block_w2 + 80
    H = 220
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    f = font(13)

    x = 20
    d.text((x, 8), "natural layout (16 items/line): all 64 lines hit -> saturated", fill=(20, 20, 20), font=f)
    for t in range(4):
        for l in range(16):
            hit = natural.get(t, {}).get(l, 0)
            xx = x + t * (16 * cell + 6) + l * cell
            d.rectangle([xx, 40, xx + cell - 1, 40 + 60], fill=(210, 40, 40) if hit else (235, 235, 235))
    x2 = x + block_w + 30
    d.text((x2, 8), "line-aligned (1 item/line): ~1/8 lines hit -> recoverable", fill=(20, 20, 20), font=f)
    for t in range(4):
        for l in range(256):
            hit = aligned.get(t, {}).get(l, 0)
            xx = x2 + t * (256 * 2 + 6) + l * 2
            d.rectangle([xx, 40, xx + 1, 40 + 120], fill=(40, 110, 200) if hit else (235, 235, 235))
    img.save(path)

# ---------- 图 3：三种实现对比 ----------
def chart_impl_compare(values, path):
    W, H, pad = 620, 360, 60
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    axes(d, W, H, pad, "|t| by implementation  (threshold 4.5)", "", "|t|")
    names = list(values.keys())
    vmax = max(max(values.values()), 10) * 1.15
    bw = (W - 2 * pad) / (len(names) * 1.6)
    for i, n in enumerate(names):
        v = values[n]
        x0 = pad + (i + 0.3) * (W - 2 * pad) / len(names)
        h = (v / vmax) * (H - 2 * pad)
        color = (200, 40, 40) if v > 4.5 else (40, 160, 90)
        d.rectangle([x0, H - pad - h, x0 + bw, H - pad], fill=color)
        d.text((x0, H - pad - h - 16), f"{v:.1f}", fill=(30, 30, 30), font=font(12))
        d.text((x0, H - pad + 4), n, fill=(60, 60, 60), font=font(11))
    d.line([pad, H - pad - (4.5 / vmax) * (H - 2 * pad), W - pad, H - pad - (4.5 / vmax) * (H - 2 * pad)],
           fill=(200, 120, 0), width=1)
    img.save(path)

def main():
    rep = json.load(open(os.path.join(HERE, "report.json"), encoding="utf-8"))
    conv = rep.get("convergence") or []
    if conv:
        chart_t_vs_n(conv, os.path.join(OUT, "t_vs_n.png"))
    nat = os.path.join(HERE, "heat_natural.csv")
    ali = os.path.join(HERE, "heat_aligned.csv")
    if os.path.exists(nat) and os.path.exists(ali):
        chart_heatmap(load_hits(nat), load_hits(ali), os.path.join(OUT, "heatmap.png"))
    vals = {}
    t = rep.get("ttest", {})
    if t.get("t_ttable") is not None:
        vals["our T-table"] = abs(t["t_ttable"])
    if t.get("t_constant_time") is not None:
        vals["our const-time"] = abs(t["t_constant_time"])
    # 统一数据源：柱状图与正文表格都取 report["libs"]，避免同一库出现两个数
    for L in rep.get("libs", []):
        vals[L["name"]] = abs(L["t"])
    if vals:
        chart_impl_compare(vals, os.path.join(OUT, "impl_compare.png"))
    print("wrote:", ", ".join(sorted(os.listdir(OUT))))

if __name__ == "__main__":
    main()
