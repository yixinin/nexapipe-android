<#
.SYNOPSIS
    本地预检 release APK 的签名 secrets，避免把错误的值填进 GitHub Secrets。

.DESCRIPTION
    做三件事：
      1. 检查 *.jks.base64 文件本身是否适合填入 GitHub Secret（单行、无 BOM、无空白）；
      2. 在内存里解码，校验文件头是密钥库、算出 sha256；
      3. 调用 keytool 用密码/别名真正读一次，确认三个密码类 secret 是对的。

    输出的「sha256 / 字节数」可以直接和 CI 日志里 “签名库校验” 那一段比对：
    两边一致，就说明 GitHub Secret 里存的值与本地这把钥匙完全一致。

.PARAMETER Base64File
    base64 文件路径，默认 ~/.nexapipe-signing/nexapipe-release.jks.base64

.PARAMETER PasswordFile
    密码文件路径，默认 ~/.nexapipe-signing/keystore-password.txt

.PARAMETER Alias
    key 别名，默认 nexapipe

.PARAMETER ShowValue
    额外把 base64 内容原样打印出来（很长），仅在需要手工粘贴时使用。
#>
[CmdletBinding()]
param(
    [string]$Base64File = "$env:USERPROFILE\.nexapipe-signing\nexapipe-release.jks.base64",
    [string]$PasswordFile = "$env:USERPROFILE\.nexapipe-signing\keystore-password.txt",
    [string]$Alias = "nexapipe",
    [switch]$ShowValue
)

$ErrorActionPreference = "Stop"

function Write-Ok   { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Bad  { param($m) Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Write-Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Step { param($m) Write-Host "`n== $m" -ForegroundColor Cyan }

function Find-Keytool {
    $cmd = Get-Command keytool -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @("$(if ($env:JAVA_HOME) { "$env:JAVA_HOME\bin\keytool.exe" })",
                     "C:\Program Files\openjdk\bin\keytool.exe",
                     "C:\Program Files\Java\jdk*\bin\keytool.exe")) {
        if (-not $p) { continue }
        $hit = Get-Item $p -ErrorAction SilentlyContinue
        if ($hit) { return $hit.FullName }
    }
    return $null
}

Write-Host "nexapipe 签名 secrets 预检" -ForegroundColor White

# ---- 1. 输入文件 -------------------------------------------------------------
Write-Step "检查 base64 文件"
if (-not (Test-Path -LiteralPath $Base64File)) {
    Write-Bad "找不到 $Base64File"
    exit 1
}
$fi = Get-Item -LiteralPath $Base64File
Write-Ok ("文件: {0} ({1} 字节)" -f $fi.FullName, $fi.Length)

$raw = [IO.File]::ReadAllBytes($Base64File)
$problems = @()
if ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF) {
    $problems += "文件带 UTF-8 BOM，粘贴到 GitHub Secret 时可能被一起带进去"
}
$text = [Text.Encoding]::ASCII.GetString($raw)
$crlf = ($text -split "`n").Count - 1
if ($crlf -gt 3) {
    $problems += "内容被折成 $($crlf+1) 行，粘贴时容易被截断（CI 现在能容忍换行，但仍建议单行）"
}
$b64 = $text -replace '\s', ''
$b64 = $b64.Trim([char]0x22, [char]0x60, [char]0x27)
if ($b64 -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
    $problems += "含有非 base64 字符，粘贴时可能混进了别的内容"
}
# $b64 首字符合法性
if ($b64.Length -eq 0) { Write-Bad "文件为空"; exit 1 }

if ($problems.Count) {
    foreach ($p in $problems) { Write-Warn $p }
} else {
    Write-Ok "内容为干净的 base64 单行"
}
Write-Ok ("清理后长度 {0} 个字符，前 8 位 '{1}'" -f $b64.Length, $b64.Substring(0, [Math]::Min(8, $b64.Length)))
if ($b64 -notlike "MII*") {
    Write-Warn "标准 PKCS12 密钥库的 base64 通常以 'MII' 开头，这里不是，请确认没弄错文件"
}

# ---- 2. 解码 + 结构校验 -----------------------------------------------------
Write-Step "解码并校验密钥库结构"
try {
    $bytes = [Convert]::FromBase64String($b64)
} catch {
    Write-Bad "base64 解码失败: $($_.Exception.Message)"
    exit 1
}
$magic = ($bytes[0..3] | ForEach-Object { $_.ToString("x2") }) -join ''
$sha = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes))).Replace('-', '').ToLower()

Write-Ok ("解码后 {0} 字节，文件头 0x{1}" -f $bytes.Length, $magic)
Write-Ok ("sha256 {0}" -f $sha)

$magicOk = $magic.StartsWith("3082") -or $magic.StartsWith("30") -or $magic -eq "feedfeed"
if (-not $magicOk) {
    Write-Bad "文件头 0x$magic 不是密钥库（期望 0x3082… PKCS12 / 0x30… DER / 0xfeedfeed JKS）"
    Write-Host "       解码后开头是这样：" -ForegroundColor DarkGray
    $preview = [Text.Encoding]::ASCII.GetString($bytes[0..([Math]::Min(47, $bytes.Length - 1))])
    Write-Host ("       {0}" -f ($preview -replace '[^\x20-\x7e]', '.')) -ForegroundColor DarkGray
    exit 1
}
if ($bytes.Length -lt 1000) { Write-Bad "只有 $($bytes.Length) 字节，明显不完整"; exit 1 }

# ---- 3. keytool 实测密码/别名 ------------------------------------------------
Write-Step "用 keytool 验证密码与别名"
$keytool = Find-Keytool
if (-not $keytool) {
    Write-Warn "找不到 keytool，跳过该步（把 JDK 的 bin 加进 PATH 再跑一次）"
} else {
    $pw = $null
    if (Test-Path -LiteralPath $PasswordFile) {
        $pw = ([IO.File]::ReadAllText($PasswordFile)).Trim()
    }
    if (-not $pw) {
        Write-Warn "读不到密码文件 $PasswordFile，跳过（可用 -PasswordFile 指定）"
    } else {
        $tmp = Join-Path $env:TEMP ("nexapipe-preflight-{0}.jks" -f ([Guid]::NewGuid().ToString("N").Substring(0, 8)))
        [IO.File]::WriteAllBytes($tmp, $bytes)
        try {
            $out = & $keytool -list -keystore $tmp -storepass $pw -alias $Alias 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "keytool 读取成功，别名 $Alias 存在，密码正确"
                if ($out -match 'SHA256:\s*([0-9A-F:]+)') {
                    Write-Ok ("证书指纹 SHA256: {0}" -f $Matches[1])
                }
            } else {
                Write-Bad "keytool 失败（密码或别名不对）:"
                $out | ForEach-Object { Write-Host "       $_" -ForegroundColor DarkGray }
                exit 1
            }
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---- 4. 与 CI 比对 ----------------------------------------------------------
Write-Step "填写 GitHub Secret 并比对"
Write-Host @"
  1) 打开 https://github.com/yixinin/nexapipe-android/settings/secrets/actions
     编辑 RELEASE_KEYSTORE_BASE64，粘贴的内容必须与下面这条命令输出【逐字一致】。
     推荐用 notepad 打开后 Ctrl+A / Ctrl+C，避免终端折行或提示符混入：

         notepad "$($fi.FullName)"

  2) 另外三个 secret：
         RELEASE_KEYSTORE_PASSWORD = keystore-password.txt 的内容
         RELEASE_KEY_ALIAS         = $Alias
         RELEASE_KEY_PASSWORD      = keystore-password.txt 的内容

  3) 到 Actions 里 Run workflow，勾选 "signing_only"，约 1 分钟出结果。
     日志中「签名库校验」的 sha256 必须等于：

         $sha
"@ -ForegroundColor Gray

if ($ShowValue) {
    Write-Step "base64 原文"
    Write-Host $b64
}
