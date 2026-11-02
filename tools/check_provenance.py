#!/usr/bin/env python3
"""check_provenance.py - CI 用：校验第三方源码哈希与 provenance.json 记录一致。

不做时间测量，只看"我们测的到底是不是那几份代码"。
退出码 0 = 全部一致。
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main() -> int:
    prov_path = os.path.join(ROOT, "provenance.json")
    if not os.path.exists(prov_path):
        print("[FAIL] provenance.json 缺失")
        return 1

    prov = json.load(open(prov_path, encoding="utf-8"))
    failures = 0
    print(f"{'库':10s} {'版本':10s} {'记录哈希':18s} {'实际哈希':18s} 结果")
    for x in prov["sources"]:
        fp = os.path.join(ROOT, "src", "thirdparty", x["file"])
        if not os.path.exists(fp):
            print(f"{x['library']:10s} {x['version']:10s} {'':18s} {'文件缺失':18s} FAIL")
            failures += 1
            continue
        actual = hashlib.sha256(open(fp, "rb").read()).hexdigest()
        ok = actual == x["sha256"]
        print(f"{x['library']:10s} {x['version']:10s} {x['sha256'][:16]:18s} {actual[:16]:18s} {'OK' if ok else 'MISMATCH'}")
        if not ok:
            failures += 1

    # 同源检查（当前预期：三个库里只有两份独立实现）
    distinct = len({x["sha256"] for x in prov["sources"]})
    print(f"\n独立实现数：{distinct} / 源码份数：{len(prov['sources'])}")
    if distinct != prov.get("distinct_implementations", distinct):
        print("[FAIL] 独立实现数与 provenance.json 记录不一致")
        failures += 1

    if failures:
        print(f"\n[FAIL] {failures} 项校验失败")
        return 1
    print("\n[PASS] 溯源校验通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
