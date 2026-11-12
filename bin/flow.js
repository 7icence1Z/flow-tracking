#!/usr/bin/env node
'use strict';

// FLOW · 流量出口监看 —— npm 包装层
// 只做三件事：找到包内的 start.ps1，把参数翻译成它的开关，然后交给 PowerShell。
// 采集器、面板、判定逻辑全在包内的 Python 与 HTML 里，这里不做任何业务。

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const ROOT = path.resolve(__dirname, '..');
const PS1 = path.join(ROOT, 'start.ps1');

const USAGE = `FLOW · 流量出口监看
这一刻的流量走直连还是走 VPN、走的哪块网卡、从哪个 IP 出去。

用法：
  flow                    打开面板（后台起采集器 + 应用窗口）
  flow stop               停掉采集器
  flow admin              以管理员身份打开（本机模式才能看到每进程速率）
  flow --help             显示这段说明

选项：
  -p, --port <端口>       面板端口（默认 7717）
      --width <像素>      窗口宽（默认 800）
      --height <像素>     窗口高（默认 630）
      --default-profile   用你日常浏览器的 profile（默认用包内的独立 profile）

要求：Windows 10/11 + Python 3.10+。零依赖，不需要 pip 安装任何东西。
面板只监听 127.0.0.1，不写日志，不上传数据。
`;

function die(msg, code = 1) {
  console.error('flow: ' + msg);
  process.exit(code);
}

function take(argv, i, flag) {
  const v = argv[i];
  if (v === undefined) die(`${flag} 后面要跟一个整数`);
  if (!/^\d+$/.test(v)) die(`${flag} 需要整数，收到的是「${v}」`);
  return v;
}

function parse(argv) {
  const out = { ps: [], admin: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h' || a === 'help') out.help = true;
    else if (a === 'stop' || a === '--stop' || a === '-Stop') out.ps.push('-Stop');
    else if (a === 'admin' || a === '--admin' || a === '-Admin') out.admin = true;
    else if (a === '--default-profile' || a === '-DefaultProfile') out.ps.push('-DefaultProfile');
    else if (a === '-p' || a === '--port') out.ps.push('-Port', take(argv, ++i, a));
    else if (a === '--width') out.ps.push('-Width', take(argv, ++i, a));
    else if (a === '--height') out.ps.push('-Height', take(argv, ++i, a));
    else if (/^--(port|width|height)=/.test(a)) {
      const [k, v] = a.slice(2).split('=');
      if (!/^\d+$/.test(v)) die(`--${k} 需要整数，收到的是「${v}」`);
      out.ps.push({ port: '-Port', width: '-Width', height: '-Height' }[k], v);
    } else die(`看不懂的参数「${a}」（flow --help 看用法）`);
  }
  return out;
}

function psRun(extra) {
  const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS1, ...extra];
  const r = spawnSync('powershell.exe', args, { stdio: 'inherit' });
  if (r.error) die('启动 powershell.exe 失败：' + r.error.message);
  process.exit(r.status === null ? 1 : r.status);
}

function q(s) {
  return "'" + String(s).replace(/'/g, "''") + "'";
}

function psRunAdmin() {
  const list = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS1].map(q).join(',');
  const cmd = `$p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -PassThru -ArgumentList ${list}; ` +
              `if (-not $p) { exit 2 }; Start-Sleep -Milliseconds 300; exit 0`;
  const r = spawnSync('powershell.exe', ['-NoProfile', '-Command', cmd], { stdio: 'inherit' });
  if (r.error) die('拉起提权进程失败：' + r.error.message);
  if (r.status === 2) die('UAC 被取消了（管理员那条路需要你在弹窗里点「是」）');
  if (r.status !== 0) die('提权启动失败（退出码 ' + r.status + '）');
  process.exit(0);
}

const opt = parse(process.argv.slice(2));
if (opt.help) {
  process.stdout.write(USAGE);
  process.exit(0);
}
if (process.platform !== 'win32') {
  die('FLOW 只支持 Windows（判定依赖注册表、WMI、netsh、GetIfTable2）');
}
if (!fs.existsSync(PS1)) {
  die('安装看起来不完整，找不到 ' + PS1);
}
if (opt.admin) psRunAdmin();
psRun(opt.ps);
