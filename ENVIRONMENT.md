# 实验环境与复现清单

> 提交物里的所有数字都来自这一份环境。换机器跑会有差异，换架构跑结论可能不同。

## 测试平台

| 项 | 值 |
|---|---|
| CPU | Intel（x86-64，支持 RDTSCP / CLFLUSH / lfence） |
| 操作系统 | Windows 11（10.0.26200） |
| 编译器 | MSVC 19.44（Visual Studio 2022 Build Tools，x64） |
| 编译选项 | `/utf-8 /O2 /W3 /MT`（静态运行库，目标机无需 VC 运行时） |
| 绑核 | 启动时 `SetThreadAffinityMask` 绑 0 号核，进程 `HIGH_PRIORITY_CLASS` |
| 电源 | 全程接电源（电池模式下 CPU 降频会让 t 值漂移） |

## 软件依赖

| 用途 | 依赖 | 说明 |
|---|---|---|
| 编译 | MSVC（`cl`） | 无其他本地依赖 |
| 运行时 | 无 | 不链接第三方运行时库 |
| 报告生成 | Python 3（openpyxl 以外的标准库 + `python-docx`） | 仅生成文档时需要 |
| PDF 导出 | LibreOffice Kit | 可选，仅导出 PDF 时需要 |

## 第三方源码（对照测试用）

| 库 | 版本 | commit | 许可证 | 来源 |
|---|---|---|---|---|
| GmSSL | v3.2.0 | `7c9f02904ef3` | Apache-2.0 | https://github.com/guanzhi/GmSSL/blob/v3.2.0/src/sm4.c |
| Tongsuo | 8.5.0 | `80cfbe3eb194` | Apache-2.0 | https://github.com/Tongsuo-Project/Tongsuo/blob/8.5.0/crypto/sm4/sm4.c |
| BabaSSL | 8.5.0 | `80cfbe3eb194` | Apache-2.0 | https://github.com/BabaSSL/BabaSSL/blob/8.5.0/crypto/sm4/sm4.c |

三份源码按发行 tag 固定下载，文件哈希记录在 `provenance.json`，每次生成报告时现场复算比对；
`tools/check_provenance.py` 可在 CI 里独立校验。

## 运行模式（CI 与本地）

| 模式 | 命令 | 做什么 | 用在哪 |
|---|---|---|---|
| 完整 | `python make_report.py` | 全部计时实验（约 60s） | 本地 / 自托管机器 |
| 快速 | `python make_report.py --quick` | 小样本（每类 4000）真实测量 | 本地调试 |
| 夹具 | `python make_report.py --smoke` | **不跑任何计时实验**，由 `tests/fixture_report.json` 生成报告 | GitHub 共享 runner |

`--smoke` 存在的理由：共享 runner 的调度噪声会让 t 值不可信，把 t 值当 CI 门禁只能得到随机红的流水线。
CI 只校验「能编译 + 算法正确 + 源码可溯源 + 报告链路可用」，完整实验交给 `.github/workflows/experiment.yml`（self-hosted + 手动触发）。

## 复现步骤

```powershell
# 1. 全套实验 + 报告 + 图表 + 作品文档（约 90 秒）
.\run_all.bat

# 2. 或者分步
.\build.ps1
.\hengshi.exe verify
.\hengshi.exe libs 40000 3
.\hengshi.exe compare 40000
.\hengshi.exe ttest 40000
.\hengshi.exe converge
.\hengshi.exe attack 64 200 32
.\hengshi.exe attack 4 200 4
.\hengshi.exe sweep 10 20000
.\hengshi.exe heat 64 heat_aligned.csv
.\hengshi.exe heat 4 heat_natural.csv
python make_report.py
python sync_readme.py
python make_findings.py
python viz.py
python make_docx.py
```

## 已知的环境敏感项

| 现象 | 原因 | 处理 |
|---|---|---|
| 单次 t 值波动大 | CPU 调频、后台负载 | 每次实验重复 3 次取中位；绑核 + 高优先级 |
| 收敛曲线出现回落 | 高样本量端偶发被拖慢 | 每个 n 重复 3 次取中位（`CONV_REPS`） |
| 攻击失败、全命中 | 顺序探测被硬件预取器提前拉入 | 探测顺序随机化（`build_probe_order`） |
| 阈值判错 | 冷/热重载时间随频率变化 | 启动时现场标定（`calibrate_threshold`） |

## 不可用环境

- 不支持 RDTSCP / CLFLUSH 的平台（部分虚拟机、老 CPU）
- ARM / 国产 CPU：缓存层次不同，需重新标定阈值与探测顺序
- 电池供电的笔记本（频率策略不确定）
