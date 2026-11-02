"""check_deps.py - 依赖预检。缺什么、怎么装，一次说清。"""
import importlib
import sys

# Windows runner 的 stdout 可能是 cp1252
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

REQUIRED = [
    ("docx", "python-docx", "生成作品文档（.docx）", True),
    ("PIL", "Pillow", "生成图表（viz/*.png）", True),
]
OPTIONAL = [
    ("yaml", "PyYAML", "仅本地校验工作流 YAML 时需要", False),
]


def probe(mod):
    try:
        importlib.import_module(mod)
        return True
    except Exception:
        return False


def main():
    strict = "--strict" in sys.argv
    missing = []
    print("依赖预检：")
    for mod, pkg, why, need in REQUIRED:
        ok = probe(mod)
        print(f"  {'OK  ' if ok else 'MISS'} {pkg:14s} {why}")
        if not ok:
            missing.append(pkg)
    for mod, pkg, why, _ in OPTIONAL:
        ok = probe(mod)
        print(f"  {'OK  ' if ok else '--  '} {pkg:14s} {why}（可选）")

    if missing:
        print(f"\n缺少：{', '.join(missing)}")
        print("安装：python -m pip install -r requirements.txt")
        print("提示：只跑实验与 JSON/Markdown 报告不需要这些依赖；只有生成 docx 与图表才需要。")
        return 1 if strict else 0
    print("\n[PASS] 依赖齐全")
    return 0


if __name__ == "__main__":
    sys.exit(main())
