"""test_parsers.py - 解析逻辑的单元测试（纯确定性，不依赖硬件）。

跑法：python tests/test_parsers.py      退出码 0 = 全过
这些测试的价值：解析器出错不会让程序崩，只会让报告里的数字悄悄变错，
所以必须用固定输入钉死。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.parsers import (parse_verify, parse_ttest, parse_libs, parse_compare,
                           parse_sweep, parse_converge, parse_attack, parse_real_recovery)

fails = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        fails.append(name)


# ---------------- verify
check("verify 正常", parse_verify("  ttable : abc OK\n  ct     : abc OK\n") == "OK")
check("verify 含 FAIL", parse_verify("  ttable : abc FAIL\n") == "FAIL")
check("verify 空输出", parse_verify("") == "FAIL")

# ---------------- ttest
ttest_out = """
=== T-table（真实世界主流写法）===
  run 1 : t =   -50.10   A(fixed) mean=  5609.68  B(random) mean=  5930.36  差=+5.72%
  run 2 : t =   -58.44   A(fixed) mean=  5610.31  B(random) mean=  5925.00  差=+5.61%
  run 3 : t =   -60.44   A(fixed) mean=  5630.17  B(random) mean=  5959.35  差=+5.85%
  median t =   -60.44   >>> LEAK DETECTED

=== 常量时间版 ===
  run 1 : t =     0.14   A(fixed) mean= 18516.35  B(random) mean= 18515.76  差=-0.00%
  run 2 : t =    -0.46   A(fixed) mean= 18545.45  B(random) mean= 18547.36  差=+0.01%
  run 3 : t =    -0.63   A(fixed) mean= 18492.44  B(random) mean= 18495.10  差=+0.01%
  median t =    -0.63   >>> no leak
"""
t_tt, t_ct, e_tt, e_ct = parse_ttest(ttest_out)
check("ttest 取中位且取绝对值", (t_tt, t_ct) == (60.44, 0.63), f"got {(t_tt, t_ct)}")
check("ttest 效应量取自第三个 run", (e_tt, e_ct) == (5.85, 0.01), f"got {(e_tt, e_ct)}")
check("ttest 空输出返回 None", parse_ttest("") == (None, None, None, None))

# ---------------- libs
libs_out = """# 横向对比：3 个口径
LIB GmSSL t=6.09 min=2.91 max=10.23 effect=0.738 verdict=LEAK
   GmSSL：存在时序泄漏
LIB Tongsuo t=44.86 effect=4.154
   Tongsuo：存在时序泄漏
"""
libs = parse_libs(libs_out)
check("libs 解析出两个库", len(libs) == 2)
check("libs 名字与数值", libs[0]["name"] == "GmSSL" and abs(libs[0]["t"] - 6.09) < 1e-9)
check("libs 判定", libs[0]["verdict"] == "LEAK")
check("libs 跨轮范围", libs[0]["min_t"] == 2.91 and libs[0]["max_t"] == 10.23)
check("libs 空输出", parse_libs("") == [])

# ---------------- compare
cmp_out = """=== 同一份 GmSSL 源码，两种表布局 ===
  T-table 路径 (4 KB, 16 项/行) : t=   48.35  效应量=-5.025%   LEAK
  小表路径    (256 B, 4 行)     : t=  -28.76  效应量=+3.333%   LEAK
"""
tt_cmp, sm_cmp = parse_compare(cmp_out)
check("compare 两行都取绝对值", abs(tt_cmp["t"] - 48.35) < 1e-9 and abs(sm_cmp["t"] - 28.76) < 1e-9)
check("compare 效应量取绝对值", abs(tt_cmp["effect_pct"] - 5.025) < 1e-9)

# ---------------- sweep
sweep_out = """实现                 过阈值轮数    max |t| 中位 |t| 结论
our T-table                10/10        41.2       39.1  OK
our const-time              0/10         1.8        0.9  OK
null baseline              10/10        20.0       15.0  MISCLASSIFIED
"""
vs = parse_sweep(sweep_out)
check("sweep 解析三行", len(vs) == 3)
check("sweep 过阈值计数", vs[0]["over"] == 10 and vs[1]["over"] == 0)
check("sweep 误判标记", vs[2]["correct"] is False)
check("sweep 表头不被当成数据", all(not v["name"].startswith("实现") for v in vs))

# ---------------- converge
conv_out = """   n/class     |t| ttable       |t| ct
      2000          14.76         0.85
      80000         89.23         0.34
"""
conv = parse_converge(conv_out)
check("converge 解析两行", len(conv) == 2)
check("converge 数值", conv[0]["n"] == 2000 and abs(conv[-1]["t_ttable"] - 89.23) < 1e-9)

# ---------------- attack
atk_out = """[attack] 真实 rk[0..3] : f12186f9 41662b61 5a6ab19a 7ba92077
[attack] 恢复 rk[0..3] : f12186f9 41662b61 5a6ab19a 7ba92077
[attack] 反推主密钥 : 0123456789abcdeffedcba9876543210
[attack] 真实主密钥 : 0123456789abcdeffedcba9876543210
"""
a = parse_attack(atk_out)
check("attack 轮密钥各 4 个", len(a["true_round_keys"]) == 4 and len(a["recovered_round_keys"]) == 4)
check("attack 主密钥一致判定", a["master_key_match"] is True)

atk_bad = atk_out.replace("0123456789abcdeffedcba9876543210\n", "ffffffffffffffffffffffffffffffff\n", 1)
check("attack 不一致能识别", parse_attack(atk_bad)["master_key_match"] is False)

# ---------------- real recovery
real_out = """  b0     0xf        最高组=0xf  (799/800)        799.0      731.8
  b1     0x2        最高组=0x2  (799/800)        799.0      733.9

  结果：4/4 个字节判定成功。
"""
r = parse_real_recovery(real_out)
check("real 计数", r["matched"] == 4 and r["total"] == 4)
check("real 逐字节两项", len(r["per_byte"]) == 2)
check("real 逐字节取值", r["per_byte"][0]["true_hi"] == "f" and r["per_byte"][1]["byte"] == 1)

# 带歧义的结果也要能解析
real_amb = """  b0     0xf        最高组=0xf  (1200/1200)       1200.0     1045.4

  结果：3/4 个字节判定成功，1 个歧义（边际不足 1%，不给出猜测）。
"""
r2 = parse_real_recovery(real_amb)
check("real 歧义结果的计数", r2["matched"] == 3 and r2["total"] == 4)

print()
if fails:
    print(f"[FAIL] {len(fails)} 项失败：{', '.join(fails)}")
    sys.exit(1)
print("[PASS] 解析器单元测试全部通过")
