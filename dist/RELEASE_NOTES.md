# 衡时 v1.0.0

面向 **SM4 软件实现** 的常量时间检测与泄漏验证原型。
不修改被测源码、无需插桩、无需专用采集硬件；面向支持 RDTSCP / CLFLUSH 的 x86 平台。

## 这个版本能做什么

| 能力 | 证据 |
|---|---|
| 常量时间性检测 | Welch t 检验 + √n 收敛判据（真泄漏 \|t\| ∝ √n，噪声不增长） |
| 可利用性分级 | detection（clean/leak/inconclusive）× exploit（未验证/部分/完整密钥恢复） |
| 完整密钥恢复 | 自研实现的行对齐布局：200 条 trace 恢复 128 bit 主密钥 |
| 真实库部分恢复 | GmSSL 4 KB T-table：恢复 rk[0] 各字节的高 4 bit，三次重复为 3–4/4（随噪声波动），即约 12–16 bit 部分信息 |
| 布局结论 | 表变小不消除泄漏；行对齐是放大而非缓解 |
| 供应链核验 | 三库两实现：Tongsuo 与 BabaSSL 的 SM4 源码字节级相同且同 commit |

## 明确的边界

- **完整密钥恢复只在自研、行对齐布局上完成**。真实库只做到**部分**信息恢复：GmSSL 三次重复为 3–4/4 个字节的高 4 bit（约 12–16 bit），低半字节在行粒度下不可辨识；Tongsuo 上该方法未收敛（多次重复 0–1/4），如实记为未验证。
- Tongsuo 的 T 表是 `static`，外部无法 flush。pristine 构建下 t≈1.6 属**测量盲区**，不代表安全。
- 统计检测与缓存观测使用不同构建（pristine / `-Dstatic=`），差异由反汇编核对：`ossl_sm4_encrypt` 830 条指令中 21 行调度不同。详见 `技术说明.md` 6.7。
- 仅覆盖 SM4 / Windows x86 / 同进程或共享页威胁模型。
- 假阳性结论表述为"本轮未观察到"，不外推为总体假阳性率。

## 资产

| 文件 | 说明 |
|---|---|
| `hengshi.exe` | 主程序（`/MT` 静态链接，仅依赖 KERNEL32.dll） |
| `hengshi-1.0.0-doc.pdf` | 作品文档（9 章、7 表、3 图） |
| `report.md` / `report.json` | 实验报告 |
| `findings.md` / `findings.json` | 检测发现报告（6 条） |
| `*.png` | 图表：\|t\| 随样本量、缓存行热图、实现对比 |
| `hengshi-1.0.0-src.zip` | 源码 |
| `SHA256SUMS.txt` | 全部资产的哈希 |

## 复现

```powershell
git clone https://github.com/laoyubayunzi/hengshi.git
cd hengshi
.\run_all.bat          # 约 90 秒，产出全部报告与图表
```

CI 只验证「编译 + 单元测试 + 标准向量 + 溯源 + 报告结构」，不跑计时实验（共享 runner 噪声不可控）。
完整实验见 `.github/workflows/experiment.yml`（self-hosted、手动触发）。

## 许可

Apache-2.0。内嵌的对照测试源码版权归 GmSSL / Tongsuo / BabaSSL 上游，详见 `THIRD_PARTY_NOTICES.md`。
