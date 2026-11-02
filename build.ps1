# 衡时 编译脚本
# 三个编译单元：
#   1) 我们的实现      src\sm4.c
#   2) GmSSL 官方      src\thirdparty\gmssl_sm4.c                （T-table 路径）
#   3) 同源码小表配置  src\thirdparty\gmssl_sm4.c + ENABLE_SMALL_FOOTPRINT=1
#      —— 同一个库、两种配置，用来隔离"表布局"这一个变量
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) {
    $vcvars = Get-ChildItem 'C:\Program Files*\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat' |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $vcvars) { throw 'vcvars64.bat not found - need MSVC' }

$common = '/nologo /utf-8 /O2 /W3 /MT /I src\thirdparty'

# 小表配置：把对外符号全部改名，避免与 T-table 版本冲突
$ts_plain_renames = @(
    '/Dossl_sm4_encrypt=ts_plain_encrypt',
    '/Dossl_sm4_decrypt=ts_plain_decrypt',
    '/Dossl_sm4_set_key=ts_plain_set_key'
) -join ' '

$renames = @(
    '/DENABLE_SMALL_FOOTPRINT=1',
    '/DS=gmssl_small_S',
    '/Dsm4_set_encrypt_key=gmssl_small_set_encrypt_key',
    '/Dsm4_set_decrypt_key=gmssl_small_set_decrypt_key',
    '/Dsm4_encrypt=gmssl_small_encrypt',
    '/Dsm4_encrypt_blocks=gmssl_small_encrypt_blocks',
    '/Dsm4_cbc_encrypt_blocks=gmssl_small_cbc_encrypt_blocks',
    '/Dsm4_cbc_decrypt_blocks=gmssl_small_cbc_decrypt_blocks',
    '/Dsm4_ctr_encrypt_blocks=gmssl_small_ctr_encrypt_blocks',
    '/Dsm4_ctr32_encrypt_blocks=gmssl_small_ctr32_encrypt_blocks'
) -join ' '

$cmd = "call `"$vcvars`" >nul 2>&1 && cd /d `"$here`" && " +
       "cl $common /c src\hengshi.c /Fo:hengshi.obj && " +
       "cl $common /c src\sm4.c /Fo:sm4.obj && " +
       "cl $common /c src\thirdparty\gmssl_sm4.c /Fo:gmssl_tt.obj && " +
       "cl $common $renames /c src\thirdparty\gmssl_sm4.c /Fo:gmssl_small.obj && " +
       "cl $common /I src\thirdparty\tongsuo /Dstatic= /DSM4_S=TS_SM4_S /c src\thirdparty\tongsuo_sm4.c /Fo:tongsuo.obj && " +
       "cl $common /I src\thirdparty\tongsuo $ts_plain_renames /c src\thirdparty\tongsuo_sm4.c /Fo:tongsuo_plain.obj && " +
       "link /nologo hengshi.obj sm4.obj gmssl_tt.obj gmssl_small.obj tongsuo.obj tongsuo_plain.obj /OUT:hengshi.exe"

cmd /c $cmd
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }

Get-Item (Join-Path $here 'hengshi.exe') | Select-Object FullName, Length

# ---- dudect 对照 harness（tests\dudect_harness.exe）----
# 必须一起构建：make_report.py 会调用它做同机对照。
# 之前它只存在于本机工作目录（被 .gitignore 忽略），导致新 clone 无法跑完整报告。
$hcmd = "call `"$vcvars`" >nul 2>&1 && cd /d `"$here`" && " +
        "cl $common /I src\thirdparty\shim /c src\sm4.c /Fo:hs_sm4.obj && " +
        "cl $common /I src\thirdparty\shim /c src\thirdparty\gmssl_sm4.c /Fo:hs_gmssl.obj && " +
        "cl $common /I src\thirdparty\shim /I src\thirdparty\tongsuo /Dstatic= /DSM4_S=TS_SM4_S /c src\thirdparty\tongsuo_sm4.c /Fo:hs_tongsuo.obj && " +
        "cl $common /I src\thirdparty\shim /c tests\dudect_harness.c /Fo:hs_dudect.obj && " +
        "link /nologo hs_dudect.obj hs_sm4.obj hs_gmssl.obj hs_tongsuo.obj bcrypt.lib /OUT:tests\dudect_harness.exe"

cmd /c $hcmd
if ($LASTEXITCODE -ne 0) { throw "dudect harness build failed ($LASTEXITCODE)" }
Get-Item (Join-Path $here 'tests\dudect_harness.exe') | Select-Object FullName, Length
