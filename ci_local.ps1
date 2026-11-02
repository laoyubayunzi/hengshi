# ci_local.ps1 - 在本机预演 GitHub Actions 的 smoke 链路
# 用法：powershell -ExecutionPolicy Bypass -File ci_local.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { $py = "C:\Users\Qwert\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe" }
else { $py = $py.Source }

function Step($n) { Write-Host "`n=== $n ===" -ForegroundColor Cyan }

Step "1/5 编译"
powershell -ExecutionPolicy Bypass -File .\build.ps1 | Out-Null
Write-Host "  编译完成" -ForegroundColor Green

Step "2/5 SM4 标准测试向量"
$out = & .\hengshi.exe verify
$out | Write-Output
$rc = $LASTEXITCODE
$text = ($out | Out-String)
$expected = '681edf34d206965e86b3e94f536e4246'
if ($rc -ne 0) { throw "verify 退出码 $rc" }
if ($text -notmatch $expected) { throw "未找到期望密文" }
if ($text -match 'FAIL') { throw "输出包含 FAIL" }
Write-Host "  通过" -ForegroundColor Green

# 关键：模拟 GitHub runner 的 cp1252 输出环境，否则本机（UTF-8 控制台）
# 测不出 UnicodeEncodeError 这类问题
$env:PYTHONIOENCODING = 'cp1252'

Step "3/5 第三方源码溯源校验"
& $py .\tools\check_provenance.py
if ($LASTEXITCODE -ne 0) { throw "溯源校验失败" }

Step "4/5 夹具生成报告"
& $py .\make_report.py --smoke
Copy-Item report.smoke.json report.json -Force
& $py .\make_findings.py
if ($LASTEXITCODE -ne 0) { throw "报告生成失败" }

Step "5/5 报告结构校验 + 文档口径扫描"
& $py .\tools\check_schema.py
& $py .\tools\check_docs.py
if ($LASTEXITCODE -ne 0) { throw "结构校验或文档扫描失败" }

Write-Host "`n[全部通过] 与 GitHub Actions 的 smoke 链路一致" -ForegroundColor Green

