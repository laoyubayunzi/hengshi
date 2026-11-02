# 衡时 · hengshi v1

**面向国密实现的常量时间性检测与密钥泄漏定位平台**

不修改被测源码、无需插桩、无需专用采集硬件；当前版本面向支持 RDTSCP / CLFLUSH 的 x86 平台。
两条证据链，适用范围不同：**统计判定**（t 值 + √n 收敛，覆盖全部实测实现）与 **密码学实证**（密钥恢复，仅在自研实现上完成）。

---

## 一键跑全套

```powershell
.\run_all.bat
```

约 60 秒：编译检查 → 全部实验 → 生成 report.md / findings.md / 三张图 → 打开目录。

## 许可证与第三方

- 本项目：**Apache License 2.0**（见 `LICENSE`）
- 内嵌的对照测试源码（GmSSL / Tongsuo / BabaSSL）版权归各自上游，声明见 `THIRD_PARTY_NOTICES.md`
- 上游源码未做任何算法修改，可逐字节回溯到记录的 commit

## CI 边界

GitHub 上的 `ci.yml` 只做四件事：**编译、SM4 标准向量、源码溯源哈希、报告结构校验**。
它**不跑任何计时实验**——共享 runner 的噪声会让 t 值失去意义。完整实验在 `experiment.yml`（self-hosted、手动触发）。

## 编译

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

依赖：MSVC（`cl`）。C11，**无外部运行时依赖**；`src/thirdparty/` 内嵌第三方源码，仅用于对照测试。

## 主要命令

```powershell
.\hengshi.exe verify                 # SM4 标准测试向量自检
.\hengshi.exe ttest 40000            # 两类别 Welch t 检验（自研实现）
.\hengshi.exe real 40000             # 实测 GmSSL 官方 SM4
.\hengshi.exe compare 40000          # 同源码两种表布局对比（表小≠安全）
.\hengshi.exe libs 40000 3            # 多库横向对比（GmSSL / Tongsuo）
.\hengshi.exe sweep 10 20000         # 假阳性评估（7 个真值已知的实现）
.\hengshi.exe converge               # √n 收敛实验
.\hengshi.exe attack 64 200 32       # Flush+Reload 密钥恢复（行对齐布局 / 32 轮实现）
.\hengshi.exe attack 4 200 4         # 同上，自然布局 / 4 轮实现（用来对比信息量）
.\hengshi.exe heat 64 heat.csv       # 导出单条 trace 的缓存行命中图
```

一次跑完全部并出报告与图：

```powershell
python make_report.py                # report.json + report.md
python make_findings.py              # findings.json + findings.md（检测发现格式）
python viz.py                        # viz/*.png（t-n 曲线、命中热图、实现对比）
```

<!-- DATA:BEGIN 以下内容由 sync_readme.py 从 report.json 生成，勿手改 -->

## 它证明了什么（数字由 report.json 自动同步）

**1. 实现是对的**（GB/T 32907 标准向量）

```
期望  681edf34d206965e86b3e94f536e4246   → T-table OK / 常量时间 OK
```

**2. 泄漏检测**（每类 40000 样本，重复 3 次取中位，阈值 |t| > 4.5）

| 实现 | 中位 t | 效应量 | 判定 | 严重度 |
|---|---|---|---|---|
| T-table（自研） | 76.30 | 6.95% | LEAK | 高（已实证密钥恢复） |
| 常量时间（自研，修复版） | 0.26 | 0.03% | clean | — |
| GmSSL 官方实现 | 92.94 | 7.25% | LEAK | 待验证（未做密钥恢复） |
| Tongsuo 官方实现 | 56.69 | 4.80% | LEAK | 待验证（未做密钥恢复） |
| GmSSL 小表配置 | 21.07 | 2.33% | LEAK | 待验证 |

严重度按**被证实的可利用程度**分级，不按 t 值——t 值只反映统计置信度，且随样本量增长。

**3. 真泄漏随样本量增长，噪声不增长**

| n/class | \|t\| T-table | \|t\| 常量时间 |
|---|---|---|
| 2000 | 11.42 | 1.11 |
| 80000 | 58.44 | 1.20 |

样本放大 40 倍，\|t\| 放大 5.12 倍（理论 √40 = 6.32）。

**4. 密钥真的能被恢复**（仅在自研实现的行对齐布局上完成）

```
真实轮密钥  f12186f9 41662b61 5a6ab19a 7ba92077
恢复轮密钥  f12186f9 41662b61 5a6ab19a 7ba92077
反推主密钥  0123456789abcdeffedcba9876543210
真实主密钥  0123456789abcdeffedcba9876543210    完全一致
```

对 GmSSL / Tongsuo **未实施密钥恢复**，其结论仅限统计判定。

**5. 不会乱报**

7 个真值已知的实现：泄漏实现 40/40 轮越阈值，干净实现 0/30 轮越阈值。**本轮实验未观察到假阳性**（样本量有限，不外推为总体假阳性率）。

**6. 三个库，两份代码**

| 库 | 版本 | commit | 许可证 | 文件 | 字节 | 行数 | SHA-256（前 16） |
|---|---|---|---|---|---|---|---|
| GmSSL | v3.2.0 | `7c9f02904ef3` | Apache-2.0 | gmssl_sm4.c | 29011 | 918 | `1d7374c8c8fc4ca9` |
| Tongsuo | 8.5.0 | `80cfbe3eb194` | Apache-2.0 | tongsuo_sm4.c | 19806 | 380 | `ada930751c8b9765` |
| BabaSSL | 8.5.0 | `80cfbe3eb194` | Apache-2.0 | babassl_sm4.c | 19806 | 380 | `ada930751c8b9765` |

**Tongsuo 与 BabaSSL 的 SM4 源码字节级相同，且两个发行 tag 指向同一 commit。** BabaSSL 未独立运行验证——源码相同，预期行为一致，但本报告不对其单独下结论。

<!-- DATA:END -->

## 文件

```
hengshi/
├─ hengshi.exe        编译产物
├─ build.ps1          编译脚本
├─ make_report.py     跑全部实验 → report.json / report.md
├─ report.md          最新实验报告
├─ 技术说明.md         威胁模型 / 方法 / 实验 / 局限（作品文档初稿）
├─ plan.md            26 周路线图
└─ src/
   ├─ timing.h        rdtscp / clflush / 栅栏
   ├─ sm4.h           SM4 接口
   ├─ sm4.c           真 SM4（S-box 取自 GmSSL）+ T-table + 常量时间实现 + 密钥扩展逆推
   └─ hengshi.c       统计检验 / 收敛实验 / Flush+Reload 攻击 / CLI
```

## 关键工程点

- **`clflush` 前置**：不把表踢出缓存，泄漏会被"表已经在缓存里"掩盖。
- **乱序探测**：顺序扫缓存行会被硬件预取器提前拉入，造成"全部命中"的假饱和。这是本项目实际踩到的坑，修好之前攻击完全失效。
- **首尾 5% 裁剪**：中断、调度、频率漂移造成的离群值。
- **两类别交替采样**：消除时间趋势，让 t 值可信。

## 局限

只覆盖 SM4 与两种布局；同进程/共享页假设；自然布局下只能统计判定而非单次恢复；未对抗多核噪声与虚拟化；未覆盖 ARM / 国产 CPU。详见 `技术说明.md` 第 8 节。
