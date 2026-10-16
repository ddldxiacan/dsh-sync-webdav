# dsh-sync -> GitHub 推送脚本
#
# 用法（在 PowerShell 里执行）：
#   cd "E:\Users\Administrator\Documents\deepseek-harness\commonl-workspace\dsh-sync-release"
#   powershell -ExecutionPolicy Bypass -File .\push-to-github.ps1
#
# 前置条件（只需一次）：
#   1. 已在 GitHub 网页上创建空仓库：https://github.com/new
#      仓库名 dsh-sync-release，选 Private，不要勾选 README/.gitignore/License（保持空仓库）
#   2. 首次推送会弹出凭据窗口；用户名填 ddldxiacan，密码填 Personal Access Token
#      （GitHub 已不支持账号密码。Token 生成：Settings -> Developer settings ->
#        Personal access tokens -> Tokens (classic) -> 勾选 repo 权限）

[CmdletBinding()]
param(
    [string]$RepoUrl   = 'https://github.com/ddldxiacan/dsh-sync-release.git',
    [string]$GitExe    = 'D:\Program Files\Git\cmd\git.exe',
    [string]$Branch    = 'main'
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

# --- 1. 定位 git ---
Write-Step '定位 git'
if (-not (Test-Path $GitExe)) {
    $candidates = @(
        'D:\Program Files\Git\cmd\git.exe',
        'D:\Program Files\Git\bin\git.exe',
        'C:\Program Files\Git\cmd\git.exe',
        'C:\Program Files (x86)\Git\cmd\git.exe',
        "$env:LOCALAPPDATA\grok\git\2.55.0.windows.5\cmd\git.exe"
    )
    $found = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $found) {
        throw "找不到 git.exe。请手动指定：.\push-to-github.ps1 -GitExe '你的\git.exe 完整路径'"
    }
    $GitExe = $found
}
$gitVersion = & $GitExe --version
Write-Ok "$gitVersion  ($GitExe)"

# --- 2. 校验工作目录 ---
Write-Step '校验仓库内容'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
Write-Ok "工作目录: $here"

foreach ($f in @('README.md', 'LICENSE', '.gitignore', 'package.json', 'index.js', 'client.js', 'cordis.patch.yml', 'tools-selftest.mjs')) {
    if (-not (Test-Path $f)) { throw "缺少必需文件: $f" }
}
Write-Ok '必需文件齐全'

# 敏感信息兜底检查（防手滑把凭据提交上去）
$leak = Get-ChildItem -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\\.git\\' } |
    Select-String -Pattern 'ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}' -List
if ($leak) {
    Write-Warn "检测到疑似 GitHub Token，已中止："
    $leak | ForEach-Object { Write-Warn "  $($_.Path):$($_.LineNumber)" }
    throw '请先移除凭据再推送'
}
Write-Ok '未检测到凭据泄露'

# --- 3. 初始化仓库 ---
Write-Step '初始化本地仓库'
if (-not (Test-Path '.git')) {
    & $GitExe init -b $Branch 2>$null
    if ($LASTEXITCODE -ne 0) { & $GitExe init; & $GitExe symbolic-ref HEAD "refs/heads/$Branch" }
    Write-Ok "已初始化，默认分支 $Branch"
} else {
    Write-Ok '已存在 .git，跳过初始化'
}

# --- 4. 暂存与提交 ---
Write-Step '暂存文件'
& $GitExe add -A
& $GitExe status --short

Write-Step '提交'
& $GitExe rev-parse --verify HEAD *> $null
$hasCommit = ($LASTEXITCODE -eq 0)
if ($hasCommit) {
    $pending = & $GitExe status --porcelain
    if ($pending) {
        & $GitExe commit -m 'Update dsh-sync plugin'
        Write-Ok '已提交增量改动'
    } else {
        Write-Ok '工作区干净，无需提交'
    }
} else {
    $initialMessage = @'
feat: dsh-sync WebDAV 配置同步插件

DSH 双半区插件，把 ~/.dsh 整体配置加密备份到 WebDAV，支持跨机器恢复。

Host 半区（index.js）
- 打包 ~/.dsh，排除 dsh-runtimes/node_modules/sessions/logs/npm-cache/tmp*/cache*/大于 10MB 的文件
- scrypt + AES-256-GCM 加密，含 SHA-256 内容校验与篡改检测
- 零依赖 WebDAV 客户端（PROPFIND/MKCOL/PUT/GET + Basic Auth）
- 恢复前自动本地快照，保留最近 5 份，支持回滚
- 路径穿越防护（拒绝绝对路径/盘符/UNC/ADS）
- 5 个 HTTP 端点，fail-soft，不阻塞宿主

Client 半区（client.js）
- 挂在设置页 settings.section 的「配置同步（WebDAV）」卡片
- 服务器配置与连通性测试、备份、选择性恢复、快照回滚
- 口令仅存内存，绝不持久化；主题令牌全部取自宿主真实表

安全设计：恢复与回滚都只覆盖、不删除，避免误删 dsh-runtimes 导致宿主无法启动。

安装：DSH 插件管理器中安装 github:ddldxiacan/dsh-sync-release，或 dsh plugin --profile desktop install github:ddldxiacan/dsh-sync-release

自测：node tools-selftest.mjs  ->  37 passed, 0 failed
'@
    & $GitExe commit -m $initialMessage
    Write-Ok '已创建首个提交'
}

# --- 5. 配置远端 ---
Write-Step '配置远端'
$remotes = & $GitExe remote
if ($remotes -contains 'origin') {
    $current = & $GitExe remote get-url origin
    if ($current -ne $RepoUrl) {
        & $GitExe remote set-url origin $RepoUrl
        Write-Ok "origin 已更新为 $RepoUrl"
    } else {
        Write-Ok "origin 已是 $RepoUrl"
    }
} else {
    & $GitExe remote add origin $RepoUrl
    Write-Ok "已添加 origin -> $RepoUrl"
}

# --- 6. 推送 ---
Write-Step '推送到 GitHub'
Write-Host '    首次推送会弹出凭据窗口：用户名 ddldxiacan，密码填 Personal Access Token' -ForegroundColor Yellow
& $GitExe push -u origin $Branch 2>&1 | ForEach-Object { Write-Host "    $_" }

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n完成！仓库地址：https://github.com/ddldxiacan/dsh-sync-release" -ForegroundColor Green
} else {
    Write-Host "`n推送失败。常见原因：" -ForegroundColor Red
    Write-Host '  1) GitHub 上还没有创建 dsh-sync-release 仓库 -> 去 https://github.com/new 创建（Private，留空）'
    Write-Host '  2) 凭据错误 -> 密码必须用 Personal Access Token，不是账号密码'
    Write-Host '  3) 网络问题 -> 需要代理时先配置：git config --global http.proxy http://127.0.0.1:端口'
    exit 1
}
