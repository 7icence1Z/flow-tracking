# FLOW 启动器
# 1) 后台拉起采集器（pythonw，无窗口）
# 2) 用 Edge 的应用窗口模式打开面板（独立 profile，不干扰日常浏览器）
# 用法： powershell -ExecutionPolicy Bypass -File .\start.ps1
#        powershell -ExecutionPolicy Bypass -File .\start.ps1 -Stop

param(
  [switch]$Stop,
  [int]$Port = 7717,
  [int]$Width = 800,
  [int]$Height = 630,
  [switch]$DefaultProfile
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$server = Join-Path $root 'server.py'

function Get-FlowProc {
  Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -match 'server\.py' -and $_.CommandLine -match [regex]::Escape($root) }
}

if ($Stop) {
  $p = Get-FlowProc
  if ($p) { $p | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }; "已停止采集器（$($p.ProcessId -join ', ')）" }
  else { "采集器没在运行" }
  return
}

# ── 找解释器：优先 pythonw（不带控制台窗口）
$py = $null
foreach ($n in 'pythonw.exe', 'python.exe') {
  $c = Get-Command $n -ErrorAction SilentlyContinue
  if ($c) { $py = $c.Source; break }
}
if (-not $py) { throw '找不到 python，请先安装并加入 PATH' }

# ── 已在运行就不重复启动
if (-not (Get-FlowProc)) {
  Start-Process -FilePath $py -ArgumentList "`"$server`"" -WorkingDirectory $root -WindowStyle Hidden
  Write-Host "采集器已启动：$py"
} else {
  Write-Host '采集器已在运行'
}

# ── 等端口起来
$ok = $false
for ($i = 0; $i -lt 60; $i++) {
  try {
    $c = [Net.Sockets.TcpClient]::new('127.0.0.1', $Port)
    $c.Close(); $ok = $true; break
  } catch { Start-Sleep -Milliseconds 150 }
}
if (-not $ok) { throw "端口 $Port 没起来，看看 server.py 是否报错" }

$url = "http://127.0.0.1:$Port/"

# ── 找 Edge / Chrome
$browser = $null
foreach ($p in @(
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
  )) { if (Test-Path $p) { $browser = $p; break } }

if ($browser) {
  $args = @(
    "--app=$url",
    "--window-size=$Width,$Height",
    '--window-position=140,90',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-features=msEdgeFirstRunExperience,msImplicitSignin',
    '--disable-background-mode'
  )
  if (-not $DefaultProfile) {
    $profile = Join-Path $root '.edge-profile'
    New-Item -ItemType Directory -Force -Path $profile | Out-Null
    $args += "--user-data-dir=$profile"
  }
  Start-Process -FilePath $browser -ArgumentList $args | Out-Null
  Write-Host "面板已打开：$url"
} else {
  Write-Host "没找到 Edge/Chrome，请手动打开：$url"
}
