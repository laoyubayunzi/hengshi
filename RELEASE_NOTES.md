# 衡时 v1.0.2

面向 **SM4 软件实现** 的常量时间检测与泄漏验证原型。
不修改被测源码、无需插桩、无需专用采集硬件；面向支持 RDTSCP / CLFLUSH 的 x86 平台。

> **重要：v1.0.1 的测量数据已作废，请勿引用。**
> v1.0.2 修掉了 `flush_block` 的缓存行对齐缺陷（表首不按 64 字节对齐时会漏刷最后一条缓存行），
> 该缺陷影响 v1.0.1 中所有基于刷表的测量结果。两个版本的数值不可直接比较。

## 相对 v1.0.1 的变更

| 类别 | 变更 |
|---|---|
| 测量缺陷 | `flush_block` 改为起点向下对齐、终点向上对齐；补 `len == 0` 保护 |
| 对照基准 | 真正接入**上游 dudect**（commit `dc269651`，MIT，102 个检验），替换此前的简化对照 |
| 可复现性 | `build.ps1` 同时构建 `hengshi.exe` 与 `tests/dudect_harness.exe`；新 clone 一条命令即可跑完整报告 |
| 溯源口径 | provenance 增加 `role: target / benchmark`；供应链同源结论只统计被测实现（3 份源码 → 2 份独立实现），dudect 作为基准工具单列 |
| 稳定性 | `libs` 输出跨轮 min/max 与 `UNSTABLE` 标记（跨轮范围穿过阈值即标记） |
| 文档一致性 | 新增数值一致性扫描；技术说明的易变数字移入自动生成的数据附录 |

## 这个版本能做什么

| 能力 | 证据 |
|---|---|
| 常量时间性检测 | Welch t 检验 + √n 收敛判据（真泄漏 \|t\| ∝ √n，噪声不增长） |
| 可利用性分级 | detection（clean/leak/inconclusive）× exploit（未验证/部分/完整密钥恢复） |
| 完整密钥恢复 | 自研实现的行对齐布局：恢复 128 bit 主密钥 |
| 真实库部分恢复 | GmSSL 4 KB T-table：恢复 rk[0] 部分字节的高 4 bit（三次重复记录在报告） |
| 上游 dudect 对照 | 同一批实现上，dudect 与本工具判定一致 |
| 修复代价 | `hengshi cost`：常量时间化相对开销约 3–4 倍 |
| 供应链核验 | 3 份被测源码对应 2 份独立 SM4 实现（Tongsuo 与 BabaSSL 同源同 commit） |

## 明确的边界

- **完整 128 bit 密钥恢复只在自研、行对齐布局上完成**。真实库只做到部分恢复（高 4 bit 量级），
  Tongsuo 上该方法未收敛，如实记为未验证。
- Tongsuo 的 T 表是 `static`，外部无法 flush；pristine 构建下测不到，属**测量盲区**，不代表安全。
- 统计检测与缓存观测使用不同构建（pristine / `-Dstatic=`），差异已用反汇编核对。
- 仅覆盖 SM4 / Windows x86 / 同进程或共享页威胁模型。
- 假阳性与灵敏度分列报告，不外推为总体比例。

## 资产

| 文件 | 说明 |
|---|---|
| `hengshi.exe` | 主程序（`/MT` 静态链接，仅依赖 KERNEL32.dll） |
| `hengshi-1.0.2-doc.pdf` | 作品文档 |
| `report.md` / `report.json` | 实验报告 |
| `findings.md` / `findings.json` | 检测发现报告 |
| `*.png` | 图表 |
| `hengshi-1.0.2-src.zip` | 源码 |
| `SHA256SUMS.txt` | 全部资产的哈希 |

## 复现

```powershell
git clone https://github.com/laoyubayunzi/hengshi.git
cd hengshi
.\run_all.bat          # 构建 + 全套实验 + 报告 + 图表
```

## 许可

Apache-2.0。内嵌代码版权归 GmSSL / Tongsuo / BabaSSL / dudect 上游，详见 `THIRD_PARTY_NOTICES.md`。
