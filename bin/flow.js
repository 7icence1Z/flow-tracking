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
  flow status             打印一次当前状态，不打开面板（别名：stat）
  flow stop               停掉采集器
  flow admin              以管理员身份打开（本机模式才能看到每进程速率）
  flow --help             显示这段说明（别名：-h、help）
  flow --version          打印版本（别名：-v、version；不需要采集器在跑）

选项：
  -p, --port <端口>       面板端口（默认 7717；status / stop 也认）
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

/* 版本与包名都从包里的 package.json 读，发新版只改一处 */
function pkg() {
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  } catch {
    return { name: 'flow-tracking', version: '0.0.0' };
  }
}

function take(argv, i, flag) {
  const v = argv[i];
  if (v === undefined) die(`${flag} 后面要跟一个整数`);
  if (!/^\d+$/.test(v)) die(`${flag} 需要整数，收到的是「${v}」`);
  return v;
}

function parse(argv) {
  const out = { ps: [], admin: false, help: false, version: false, status: false, port: 0 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h' || a === 'help') out.help = true;
    else if (a === '--version' || a === '-v' || a === 'version' || a === '-Version') out.version = true;
    else if (a === 'status' || a === 'stat' || a === '--status' || a === '-Status') out.status = true;
    else if (a === 'stop' || a === '--stop' || a === '-Stop') out.ps.push('-Stop');
    else if (a === 'admin' || a === '--admin' || a === '-Admin') out.admin = true;
    else if (a === '--default-profile' || a === '-DefaultProfile') out.ps.push('-DefaultProfile');
    else if (a === '-p' || a === '--port') {
      const v = take(argv, ++i, a);
      out.port = Number(v);
      out.ps.push('-Port', v);
    } else if (a === '--width') out.ps.push('-Width', take(argv, ++i, a));
    else if (a === '--height') out.ps.push('-Height', take(argv, ++i, a));
    else if (/^--(port|width|height)=/.test(a)) {
      const [k, v] = a.slice(2).split('=');
      if (!/^\d+$/.test(v)) die(`--${k} 需要整数，收到的是「${v}」`);
      if (k === 'port') out.port = Number(v);
      out.ps.push({ port: '-Port', width: '-Width', height: '-Height' }[k], v);
    } else die(`看不懂的参数「${a}」（flow --help 看用法）`);
  }
  return out;
}

/* ── flow status：读 /api/state 打印一屏，不打开面板 ── */

function fmtRate(bytes) {
  let b = Math.max(0, Number(bytes) || 0), i = 0;
  const u = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(b < 10 ? 1 : 0) : String(Math.round(b))) + ' ' + u[i];
}

function fmtBytes(bytes) {
  let b = Math.max(0, Number(bytes) || 0), i = 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(b < 10 ? 1 : 0) : String(Math.round(b))) + ' ' + u[i];
}

function hhmmss(ts) {
  const d = new Date((Number(ts) || 0) * 1000);
  const p = n => String(n).padStart(2, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

// 中文占两格：label 对齐用（不加颜色，输出干净，方便贴进 issue）
function cw(s) {
  return [...String(s)].reduce((n, ch) => n + (ch.codePointAt(0) > 0x2e80 ? 2 : 1), 0);
}
function pad(s, n) {
  return s + ' '.repeat(Math.max(1, n - cw(s)));
}

function probeText(p) {
  if (!p || typeof p.ok !== 'boolean') return '—';
  if (p.ok) return (p.ms ? p.ms + ' ms' : '通');
  const why = p.kind || '失败';
  return `不通（${why}${p.ms ? ' ' + p.ms + ' ms' : ''}）`;
}

function getState(port, cb) {
  const req = require('node:http').get(
    { host: '127.0.0.1', port, path: '/api/state', timeout: 3000 },
    res => {
      let d = '';
      res.setEncoding('utf8');
      res.on('data', c => { d += c; });
      res.on('end', () => {
        try { cb(null, JSON.parse(d)); } catch (e) { cb(e); }
      });
    });
  req.on('timeout', () => req.destroy(new Error('等 3 秒没响应')));
  req.on('error', cb);
}

function runStatus(port) {
  let ver = '';
  try { ver = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version || ''; } catch { /* 无版本也照跑 */ }
  getState(port, (err, s) => {
    const head = 'FLOW' + (ver ? ' v' + ver : '') + ' · 状态';
    if (err) {
      console.log(head);
      console.log(pad('采集器', 8) + `没在运行（127.0.0.1:${port}，${err.code || err.message}）`);
      console.log('        先 `flow` 起采集器，或用 -p 指定别的端口');
      process.exit(1);
    }
    const out = [head];
    const line = (label, text) => out.push(pad(label, 8) + text);
    const two = (label, first, more) => {
      line(label, first);
      for (const m of more) out.push(' '.repeat(8) + m);
    };
    const p = s.path || {}, dg = s.diag || {};
    const pr = s.probes || {}, iface = s.iface || {}, t = s.tunnel || {};
    const host = s.host || {}, sp = s.split || {};
    const cli = s.client || {}, node = s.node || {}, eg = s.egress || {};

    line('采集器', `在线 · 127.0.0.1:${port} · 快照 ${hhmmss(s.ts)}`);

    const mode = t.version
      ? `mihomo v${t.version} · ${t.mode || 'rule'} 模式${t.tun ? ' · TUN' : ''}`
      : (cli.name ? `${cli.name}${cli.kind ? '（' + cli.kind + '）' : ''}${t.tun ? ' · TUN' : ''}` : '没有代理客户端');
    line('模式', mode);

    line('判定', `${p.active || '?'} —— ${p.brief || p.reason || '—'}`);
    if (dg.label) {
      two('诊断', `[${dg.state || '?'}] ${dg.label}`, dg.why ? [dg.why] : []);
    }

    two('通道', `代理通道 ${probeText(pr.vpn)} · 直连目标 ${probeText(pr.direct)} · 直连对照 ${probeText(pr.control)}`, []);

    let nic = iface.name || '网卡';
    if (iface.kind === 'wlan' && iface.ssid) nic = `WLAN ${iface.ssid}`;
    const nicBits = [nic];
    if (iface.ip) nicBits.push(iface.ip);
    if (iface.gateway) nicBits.push('网关 ' + iface.gateway);
    if (iface.band) nicBits.push(`${iface.band}${iface.channel ? ' ch' + iface.channel : ''}`);
    if (iface.signal) nicBits.push(`信号 ${iface.signal}%`);
    line('网卡', nicBits.join(' · '));

    const total = s.total || {};
    line('大盘', `↓${fmtRate(total.down)} ↑${fmtRate(total.up)}`);

    const bits = [];
    if (sp.proxy && sp.direct) {
      bits.push(`经代理 ↓${fmtRate(sp.proxy.down)} ↑${fmtRate(sp.proxy.up)}`);
      bits.push(`不走代理 ↓${fmtRate(sp.direct.down)} ↑${fmtRate(sp.direct.up)}（估算 = 网卡 − 经代理）`);
    } else if (sp.client) {
      bits.push(`经客户端 ↓${fmtRate(sp.client.down)} ↑${fmtRate(sp.client.up)}（入口字节，隧道份额未知）`);
    } else if (pr.vpn && pr.vpn.ok === false && s.flow === 'host') {
      bits.push('经客户端 —（还没数到，或端口没对上）');
    } else {
      bits.push('分账 —（客户端没给统计口，数不到经代理/不走代理）');
    }
    two('分账', bits[0], bits.slice(1));

    const cum = host.cum || {};
    const conns = s.flow === 'host' ? host.conns : t.conns;
    line('累计', `本次 ↓${fmtBytes(cum.down)} ↑${fmtBytes(cum.up)}${conns != null ? ' · 连接 ' + conns : ''}`);

    const egBits = [];
    if (eg.direct_ip) egBits.push(`直连 ${eg.direct_ip}${eg.direct_geo ? '（' + eg.direct_geo + '）' : ''}`);
    if (eg.vpn_ip) egBits.push(`经代理 ${eg.vpn_ip}${eg.vpn_geo ? '（' + eg.vpn_geo + '）' : ''}`);
    if (eg.vpn_err && !eg.vpn_ip) egBits.push(`经代理 —（${eg.vpn_err}）`);
    if (egBits.length) line('出口', egBits.join(' · '));

    if (cli.name) {
      const cliBits = [cli.name];
      if (cli.local) cliBits.push('本地口 ' + cli.local);
      if (cli.pid) cliBits.push('pid ' + cli.pid);
      line('客户端', cliBits.join(' · '));
    }
    if (node.name && (node.ip || node.server)) {
      const nd = [node.name];
      if (node.ip) nd.push(node.ip);
      if (node.rtt) nd.push('RTT ' + node.rtt + ' ms');
      line('节点', nd.join(' · '));
    }

    out.push('');
    out.push('更细的字段：`flow` 打开面板，或看 tools/peek.py');
    console.log(out.join('\n'));
    process.exit(s.ok === false ? 1 : 0);
  });
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
if (opt.version) {
  // 纯本地读 package.json：不需要采集器在跑，也不进 Windows 检查
  const p = pkg();
  process.stdout.write(`${p.name} v${p.version}\n`);
  process.exit(0);
}
if (process.platform !== 'win32') {
  die('FLOW 只支持 Windows（判定依赖注册表、WMI、netsh、GetIfTable2）');
}
if (opt.status) {
  // 异步取一次状态就退出：不能落回下面的 psRun（否则 status 会把面板也拉起来）
  runStatus(opt.port || 7717);
  return;
}
if (!fs.existsSync(PS1)) {
  die('安装看起来不完整，找不到 ' + PS1);
}
if (opt.admin) psRunAdmin();
psRun(opt.ps);
