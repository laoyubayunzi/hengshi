#!/usr/bin/env python3
"""check_provenance.py - CI 用：校验第三方源码哈希与 provenance.json 记录一致。

不做时间测量，只看"我们测的到底是不是那几份代码"。
失败时会给出可操作的诊断（最常见的是 core.autocrlf 把行尾改了）。
退出码 0 = 全部一致。
"""
import hashlib
import json
import os
import sys

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


def eol_hint(path: str) -> str:
    """判断文件是否被改成了 CRLF，并给出对应提示。"""
    data = open(path, "rb").read()
    crlf = data.count(b"\r\n")
    lf = data.count(b"\n") - crlf
    if crlf and not lf:
        return (f"文件是纯 CRLF（{crlf} 处）——几乎可以确定是 core.autocrlf 造成的。"
                " 修复：确认 .gitattributes 含 `src/thirdparty/** -text`，然后 "
                "`git rm --cached -r src/thirdparty && git reset --hard`")
    if crlf and lf:
        return f"文件混有 CRLF（{crlf}）与 LF（{lf}），行尾被改动过"
    return ""


def main() -> int:
    prov_path = os.path.join(ROOT, "provenance.json")
    if not os.path.exists(prov_path):
        print("[FAIL] provenance.json 缺失")
        return 1

    prov = json.load(open(prov_path, encoding="utf-8"))
    failures = 0
    hints = []

    print(f"{'库':10s} {'版本':10s} {'记录哈希':18s} {'实际哈希':18s} {'字节':>7s} 结果")
    for x in prov["sources"]:
        fp = os.path.join(ROOT, "src", "thirdparty", x["file"])
        if not os.path.exists(fp):
            print(f"{x['library']:10s} {x['version']:10s} {'':18s} {'文件缺失':18s} {'':>7s} FAIL")
            failures += 1
            continue
        actual = hashlib.sha256(open(fp, "rb").read()).hexdigest()
        size = os.path.getsize(fp)
        ok = actual == x["sha256"]
        print(f"{x['library']:10s} {x['version']:10s} {x['sha256'][:16]:18s} {actual[:16]:18s} {size:7d} "
              f"{'OK' if ok else 'MISMATCH'}")
        if not ok:
            failures += 1
            expect = x.get("bytes")
            if expect and size != expect:
                hints.append(f"{x['library']}: 文件 {size} 字节，记录 {expect} 字节，差 {size - int(expect)}")
            h = eol_hint(fp)
            if h:
                hints.append(f"{x['library']}: {h}")

    targets = [x for x in prov["sources"] if x.get("role", "target") == "target"]
    benches = [x for x in prov["sources"] if x.get("role") == "benchmark"]
    distinct = len({x["sha256"] for x in targets})
    print(f"\n被测实现：{distinct} 份独立实现 / {len(targets)} 份源码"
          + (f"；另有 {len(benches)} 份对照基准工具（不计入同源结论）" if benches else ""))
    if distinct != prov.get("distinct_implementations", distinct):
        print("[FAIL] 独立实现数与 provenance.json 记录不一致")
        failures += 1

    if failures:
        print(f"\n[FAIL] {failures} 项校验失败")
        if hints:
            print("\n诊断：")
            for h in hints:
                print(f"  - {h}")
        return 1

    print("\n[PASS] 溯源校验通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
