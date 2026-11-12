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
  # 认「命令行里有 server.py」的 python 进程：绝对路径匹配，或者它就是当前端口的监听者
  # （从别的目录用相对路径 pythonw server.py 起的，也得能被 -Stop 认出来）
  $listen = @()
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $listen = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty OwningProcess)
  }
  Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
    Where-Object {
      $_.CommandLine -and $_.CommandLine -match 'server\.py' -and (
        $_.CommandLine -match [regex]::Escape($root) -or $listen -contains $_.ProcessId
      )
    }
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
  # 端口通过环境变量传给采集器，-Port 才真的生效
  $env:FLOW_PORT = "$Port"
  Start-Process -FilePath $py -ArgumentList "`"$server`"" -WorkingDirectory $root -WindowStyle Hidden
  Remove-Item Env:\FLOW_PORT -ErrorAction SilentlyContinue
  Write-Host "采集器已启动：$py（端口 $Port）"
} else {
  Write-Host '采集器已在运行'
}

# ── 权限提示：本机模式（没开 VPN 时）逐进程的 ↓↑ 速率要管理员权限（内核 eStats）
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
  Write-Host '提示：当前不是管理员 —— 本机模式只能数连接；想看每个进程的 ↓↑ 速率，请右键「以管理员身份运行」再开一次' -ForegroundColor DarkGray
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

# ── 已经有一扇面板窗口开着，就别再开第二扇
$win = Get-Process -Name msedge, chrome -ErrorAction SilentlyContinue |
  Where-Object { $_.MainWindowTitle -like 'FLOW*' }
if ($win) {
  Write-Host "面板窗口已经开着（pid $($win.Id -join ', ')）"
  return
}

# ── 找 Edge / Chrome（只用它们的应用窗口模式，绝不交给"默认浏览器"）
$browser = $null
foreach ($p in @(
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
  )) { if (Test-Path $p) { $browser = $p; break } }

if (-not $browser) { throw '没找到 Edge 或 Chrome，起不了独立窗口。装一个 Edge 再试。' }

$appArgs = @(
  "--app=$url",                      # 应用窗口：没有地址栏、没有标签页、没有书签栏
  "--window-size=$Width,$Height",
  '--window-position=140,90',
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-features=msEdgeFirstRunExperience,msImplicitSignin',
  '--disable-background-mode'
)
if (-not $DefaultProfile) {
  # 独立 profile：不碰你日常浏览器的历史、登录和扩展；关掉浏览器不会带走这扇窗
  $profile = Join-Path $root '.app-profile'
  New-Item -ItemType Directory -Force -Path $profile | Out-Null
  $appArgs += "--user-data-dir=$profile"
}
Start-Process -FilePath $browser -ArgumentList $appArgs | Out-Null
Write-Host "面板窗口已打开：$url（$(Split-Path -Leaf $browser) 应用窗口模式）"

