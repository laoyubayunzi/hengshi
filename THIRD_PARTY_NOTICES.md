# 第三方声明（THIRD PARTY NOTICES）

本项目的 `src/thirdparty/` 目录内含三个上游项目的 SM4 实现源码，仅用于**对照测试**
（把真实库编进测试程序，测量它们的常量时间性）。这些文件不是本项目的原创代码，版权归各自上游所有。

本项目的 `LICENSE`（Apache License 2.0）适用于**本项目自身**的代码（`src/hengshi.c`、`src/sm4.c`、
`src/sm4.h`、`src/timing.h`、所有 `*.py`、`build.ps1`、`run_all.bat`、文档）。

---

## 1. GmSSL

| 项 | 内容 |
|---|---|
| 文件 | `src/thirdparty/gmssl_sm4.c` |
| 上游仓库 | https://github.com/guanzhi/GmSSL |
| 版本 / tag | `v3.2.0` |
| commit | `7c9f02904ef3` |
| 原始文件 | `src/sm4.c` |
| 文件 SHA-256 | `1d7374c8c8fc4ca9…`（完整值见 `provenance.json`） |
| 许可证 | Apache License 2.0 |
| 许可证原文 | https://github.com/guanzhi/GmSSL/blob/v3.2.0/LICENSE |
| 本项目的改动 | **未修改源码内容**。为使其能独立编译，另行提供了最小兼容头 `src/thirdparty/gmssl/sm4.h` 与 `src/thirdparty/gmssl/endian.h`（这两个头文件是本项目原创，非上游文件） |

## 2. Tongsuo

| 项 | 内容 |
|---|---|
| 文件 | `src/thirdparty/tongsuo_sm4.c` |
| 上游仓库 | https://github.com/Tongsuo-Project/Tongsuo |
| 版本 / tag | `8.5.0` |
| commit | `80cfbe3eb194` |
| 原始文件 | `crypto/sm4/sm4.c` |
| 文件 SHA-256 | `ada930751c8b9765…` |
| 许可证 | Apache License 2.0 |
| 许可证原文 | https://github.com/Tongsuo-Project/Tongsuo/blob/8.5.0/LICENSE.txt |
| 本项目的改动 | **未修改源码内容**。编译时以 `/Dstatic=` 把内部 `static` 表暴露为外部符号，以便缓存观测代码取到表地址；另提供最小兼容头 `src/thirdparty/tongsuo/openssl/e_os2.h` 与 `src/thirdparty/tongsuo/crypto/sm4.h`（本项目原创） |

> `/Dstatic=` 只影响 `static` 关键字的预处理展开，不改变任何算法逻辑、表内容或执行顺序。
> 这一点对测量结论至关重要，故在此显式声明。

## 3. BabaSSL

| 项 | 内容 |
|---|---|
| 文件 | `src/thirdparty/babassl_sm4.c` |
| 上游仓库 | https://github.com/BabaSSL/BabaSSL |
| 版本 / tag | `8.5.0` |
| commit | `80cfbe3eb194` |
| 原始文件 | `crypto/sm4/sm4.c` |
| 文件 SHA-256 | `ada930751c8b9765…` |
| 许可证 | Apache License 2.0 |
| 许可证原文 | https://github.com/BabaSSL/BabaSSL/blob/8.5.0/LICENSE |
| 本项目的改动 | 未编译、未修改。**仅作源码同源性比对**：其 SHA-256 与 Tongsuo 8.5.0 的 SM4 文件完全一致，两者 tag 指向同一 commit |

---

## 关于"三库两实现"

上述三个库中，Tongsuo 与 BabaSSL 的 SM4 源码字节级完全相同且指向同一 commit，
因此本项目实际只覆盖 **2 份独立实现**。这是本报告的一条供应链结论，不是遗漏。

## 引用与再分发

如果你把本项目的 `src/thirdparty/` 一并再分发，请同时保留：

1. 本文件（`THIRD_PARTY_NOTICES.md`）；
2. 上游各自的 LICENSE 文本（Apache-2.0 全文见根目录 `LICENSE`，其条款与上游一致）；
3. 各文件中的原始版权头（这些头未被删除或修改）。

Apache-2.0 第 4(b) 条要求对修改过的文件给出显著说明；本项目的做法是：**不改动上游源码**，
所有适配都放在本项目自有的头文件与编译参数里，因此上游文件可逐字节回溯到原 commit。

## 哈希校验

```powershell
python tools\check_provenance.py
```

该脚本会重新计算 `src/thirdparty/` 下三个文件的 SHA-256，与 `provenance.json` 记录比对，
并检查"独立实现数 = 2"这一结论是否仍然成立。
