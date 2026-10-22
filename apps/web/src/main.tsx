import { createRoot } from 'react-dom/client';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { BLESSING, VERSION } from '@nyaarink/version';
import './style.css';
console.log(BLESSING);

type Session = { id: string; authorization: 'accepted' | 'enrolled' | 'revoked'; acceptedAt: string; revokedAt?: string; connectivity: string; frozen: boolean; helperName: string; purpose: string; account?: string; platform?: string; sCleanup: string; cCleanup: string };
type Preview = { helperName: string; purpose: string; expiresAt: string; state: 'issued' };
type Metrics = { sshBytesSToC: number; sshBytesCToS: number; sshConnectionsOpened: number; sshConnectionsActive?: number; onlineSeconds: number; apiOperations: number; rttMs?: number | null; sampledAt?: string };
class ApiError extends Error { constructor(readonly status: number) { super('请求未完成'); } }
const duration = (seconds: number) => { const n = Math.max(0, Math.floor(seconds)); return [Math.floor(n / 3600), Math.floor(n / 60) % 60, n % 60].map(n => String(n).padStart(2, '0')).join(':'); };
const bytes = (n: number) => n >= 1048576 ? (n / 1048576).toFixed(2) + ' MiB' : (n / 1024).toFixed(1) + ' KiB';
const clean = (state: string) => ({ confirmed: '已确认清理', failed: '清理失败，需处理', pending: '等待清理确认', not_needed: '无需清理' }[state] ?? '状态待核实');
function Icon({ name }: { name: 'link' | 'terminal' | 'spark' | 'return' | 'shield' | 'device' | 'server' | 'download' }) {
  const paths = { link: 'm9 15 6-6m-7 3-2 2a4 4 0 0 0 6 6l3-3m1-5 2-2a4 4 0 0 0-6-6L9 7', terminal: 'M3 4h18v16H3Zm4 5 3 3-3 3m6 0h4', spark: 'm12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5Z', return: 'M5 9a8 8 0 1 1-1 7M5 4v6h6', shield: 'm12 3 8 3v6c0 5-8 9-8 9S4 17 4 12V6Zm-4 9 3 3 5-6', device: 'M3 3h18v13H3Zm5 18h8m-4-5v5', server: 'M4 3h16v8H4Zm0 10h16v8H4ZM8 7h.01M8 17h.01m4-10h4m-4 10h4', download: 'M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5' };
  return <svg className="icon" viewBox="0 0 24 24" aria-hidden="true"><path d={paths[name]} /></svg>;
}
function App() {
  const [theme, setTheme] = useState(() => { try { const value = localStorage.getItem('nyaarink-theme'); return value === 'light' || value === 'dark' ? value : 'system'; } catch { return 'system'; } });
  const [preview, setPreview] = useState<Preview>(), [session, setSession] = useState<Session>(), [metrics, setMetrics] = useState<Metrics>();
  const [loading, setLoading] = useState(true), [invalid, setInvalid] = useState(false), [unknown, setUnknown] = useState(false);
  const [consent, setConsent] = useState(false), [busy, setBusy] = useState(false), [message, setMessage] = useState('');
  const [platform, setPlatform] = useState<'win32' | 'linux'>(() => /Windows/i.test(navigator.userAgent) ? 'win32' : 'linux');
  const [recovery, setRecovery] = useState<{ code: string; until: number }>(), [now, setNow] = useState(Date.now());
  const csrf = useRef(''), accepting = useRef(crypto.randomUUID()), downloading = useRef<string | undefined>(undefined), current = useRef(session);
  const dialog = useRef<HTMLDialogElement>(null); current.current = session;
  const code = location.pathname.slice(1), validCode = /^[A-Za-z0-9_-]{43}$/.test(code);
  useEffect(() => {
    const media = matchMedia('(prefers-color-scheme: dark)');
    const apply = () => { document.documentElement.dataset.theme = theme === 'system' ? media.matches ? 'dark' : 'light' : theme; };
    apply(); media.addEventListener('change', apply); try { localStorage.setItem('nyaarink-theme', theme); } catch { /* Storage optional. */ }
    return () => media.removeEventListener('change', apply);
  }, [theme]);
  async function api<T>(path: string, body?: unknown, requestId?: string): Promise<T> {
    const response = await fetch('/api/v1/' + path, { method: body === undefined ? 'GET' : 'POST', headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-NR-CSRF': csrf.current, 'Idempotency-Key': requestId ?? crypto.randomUUID() }, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw new ApiError(response.status);
    const data = await response.json(); if (data.csrf) csrf.current = data.csrf; return data as T;
  }
  async function load() {
    try {
      const result = await api<(Preview | Session) & { csrf: string }>(validCode ? 'browser/invitation?code=' + encodeURIComponent(code) : 'browser/session');
      if ('id' in result) setSession(result); else setPreview(result);
      setInvalid(false); setUnknown(false);
    } catch (error) { if (error instanceof ApiError && [400, 401, 404].includes(error.status)) setInvalid(true); else setUnknown(true); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(); const clock = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(clock); }, []);
  useEffect(() => {
    if (!session?.id) return;
    let stopped = false, socket: WebSocket | undefined, retry: ReturnType<typeof setTimeout>;
    const connect = () => {
      if (stopped || current.current?.authorization === 'revoked') return;
      const url = new URL('/api/v1/browser/events', location.href); url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      socket = new WebSocket(url);
      socket.onmessage = event => { try { const data = JSON.parse(event.data) as { session: Session; metrics: Metrics }; setSession(data.session); setMetrics(data.metrics); setUnknown(false); } catch { setUnknown(true); } };
      socket.onclose = () => {
        if (!stopped && current.current?.authorization !== 'revoked') { setUnknown(true); retry = setTimeout(connect, 3000); }
      };
      socket.onerror = () => setUnknown(true);
    }; connect();
    return () => { stopped = true; clearTimeout(retry); socket?.close(); };
  }, [session?.id]);
  useEffect(() => {
    if (!recovery) return;
    const timer = setInterval(() => {
      if (Date.now() > recovery.until) { clearInterval(timer); return; }
      void api<Session>('browser/session').then(result => { setSession(result); setInvalid(false); setRecovery(undefined); setUnknown(false); }).catch(() => {});
    }, 2500); return () => clearInterval(timer);
  }, [recovery]);
  async function accept() {
    setBusy(true); setMessage('');
    try { const result = await api<Session>('invitations/accept', { code, consent: true }, accepting.current); setSession(result); setUnknown(false); }
    catch { setMessage('接受结果尚未确认，请重试。重复点击不会重复授权。'); }
    finally { setBusy(false); }
  }
  async function download() {
    setBusy(true); setMessage(''); downloading.current ??= crypto.randomUUID();
    try {
      const response = await fetch('/api/v1/browser/connection-script', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-NR-CSRF': csrf.current, 'Idempotency-Key': downloading.current }, body: JSON.stringify({ platform }), credentials: 'same-origin', signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new ApiError(response.status);
      const url = URL.createObjectURL(await response.blob()), a = document.createElement('a'); a.href = url; a.download = `NyaaRink-${session!.id}.${platform === 'win32' ? 'bat' : 'sh'}`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); downloading.current = undefined;
      setMessage('已下载。请在本机运行，按提示确认账户与安装变更。脚本含本次凭据，请勿转发。');
    } catch { setMessage('下载未完成，请重试。如已在本机运行，请等待连接状态更新。'); }
    finally { setBusy(false); }
  }
  async function disconnect() {
    if (!session) return; setBusy(true); dialog.current?.close(); setMessage('');
    try {
      const result = await api<Pick<Session, 'authorization' | 'sCleanup' | 'cCleanup'>>('browser/disconnect', { sessionId: session.id });
      setSession({ ...session, ...result, connectivity: 'offline', revokedAt: new Date().toISOString() }); setUnknown(false);
    } catch { setUnknown(true); setMessage('断开结果尚未确认。请重试，或在本机连接程序主动断开。'); }
    finally { setBusy(false); }
  }
  async function recover() {
    setBusy(true); setMessage('');
    try { await api('browser/context'); const result = await api<{ code: string; expiresInSeconds: number }>('browser/recovery', {}); setRecovery({ code: result.code, until: Date.now() + result.expiresInSeconds * 1000 }); }
    catch { setMessage('无法创建恢复码，请稍后重试。'); } finally { setBusy(false); }
  }
  const info = session ?? preview, ended = session?.authorization === 'revoked', online = !unknown && !session?.frozen && session?.connectivity === 'online';
  const title = loading ? '正在核实邀请…' : ended ? '本次协助已结束。' : invalid ? '此链接没有有效邀请。' : session ? '你的电脑，由你决定连接。' : '为这台电脑，开启一次远程协助。';
  const permission = (icon: Parameters<typeof Icon>[0]['name'], title: string, text: string) => <div className="permission"><Icon name={icon} /><div><h3>{title}</h3><p>{text}</p></div></div>;
  const metric = (label: string, value: ReactNode) => <div className="metric"><small>{label}</small><strong>{value}</strong></div>;
  return <div className="wrap"><header><div className="brand"><span className="logo"><Icon name="link" /></span><div><div className="brand-name">NyaaRink.</div><small>远程 SSH 协助</small></div></div><div className="header-tools"><span className="quiet">你的设备，你来授权。</span><div className="theme-switch" role="group" aria-label="页面主题">{[['system', '跟随系统'], ['light', '浅色'], ['dark', '暗色']].map(([value, name]) => <button key={value} aria-pressed={theme === value} onClick={() => setTheme(value!)}>{name}</button>)}</div></div></header>
    <main><section className="intro"><div><div className="eyebrow">An invitation to connect</div><h1>{title}</h1><p>{session && !ended ? '网络中断不会结束授权。需要结束协助时，请主动断开连接。' : '先了解访问范围，再决定是否接受。你的确认是协助开始的第一步。'}</p></div>{session && <div className="session-ref">SESSION<br /><b>{session.id}</b></div>}{preview && !session && <div className="session-ref">邀请有效期至<br /><b>{new Date(preview.expiresAt).toLocaleString()}</b></div>}</section>
    {message && <p className="callout" role="status">{message}</p>}
    {unknown && !ended && <div className="callout warning" role="status">页面失联或服务暂不可用，当前状态待核实。此情况不会撤销已有授权。<button className="text-button" onClick={() => void load()}>重新核实</button></div>}
    {loading ? <p role="status">正在加载…</p> : ended ? <section className="card"><div className="empty"><div className="empty-icon"><Icon name="shield" /></div><h2>访问权限已撤销</h2><p>现有 SSH 访问已终止。需要继续协助时，请重新邀请。</p><ul className="checklist"><li><span>邀请机配置与活跃凭据</span><span>{clean(session.sCleanup)}</span></li><li><span>本机公钥与登录启动项</span><span>{clean(session.cCleanup)}</span></li></ul><div className="callout warning"><b>请删除下载的本次连接脚本。</b><br />旧脚本已失效，不能恢复本次访问。已完成的系统修改与 SSH 服务会保留。</div></div></section> : invalid ? <section className="card"><div className="empty"><Icon name="link" /><h2>邀请可能已使用、过期或结束。</h2><p>需要新的协助时，请联系邀请方。刷新或关闭页面不会撤销已有授权。</p><button className="text-button" disabled={busy} onClick={() => void recover()}>此前已授权？恢复页面访问</button>{recovery && <div className="callout"><p>在本机连接程序中确认此配对码：</p><p className="recovery-code">{recovery.code}</p><p>{now > recovery.until ? '配对码已过期，请重新生成。' : `剩余 ${Math.max(0, Math.ceil((recovery.until - now) / 1000))} 秒`}</p><p>在原连接程序目录运行：</p><pre>node client.cjs resume-browser {recovery.code} --session &lt;原会话 ID&gt;</pre><p>只有在本机确认后，才能恢复页面。请勿确认他人提供的配对码。</p></div>}</div></section> : info && <div className="layout"><div className="stack"><section className="card pad"><div className="section-head"><h2>这次协助</h2><span className="tag purple">SSH 命令行访问</span></div><div className="host"><div className="avatar">{info.helperName.slice(0, 1)}</div><div><div className="host-name">{info.helperName}</div><p>邀请机持有者 · 名称由对方填写，未经实名认证</p></div></div><div className="purpose"><small>对方希望协助你</small><p>{info.purpose}</p></div><div className="permissions">{permission('terminal', '允许在授权账户内操作', '通过 SSH 执行命令、交互操作和传输文件。默认使用普通账户，实际账户在本机确认。')}{permission('spark', '协助者可能使用 AI Agent', '对方可能由人工操作，也可能让 AI Agent 参与。本服务无法可靠区分每条操作的发起来源。')}{permission('return', '断网后可重连，登录后会恢复', '关闭页面、退出 SSH 或网络中断不会结束授权。连接程序在你登录后自动恢复，请主动断开连接结束协助。')}</div><p className="trust-note">只接受你信任的协助者。SSH 可访问该账户有权限的文件与程序；断开不能撤回已读取的数据或回滚已完成的修改。</p></section>
      {(!session || session.authorization === 'accepted') && <section className="card"><div className="steps"><div className={`step ${session ? '' : 'current'}`}><em>1</em>接受邀请</div><div className={`step ${session ? 'current' : ''}`}><em>2</em>本机运行</div><div className="step"><em>3</em>建立连接</div></div><div className="pad"><h2>在本机完成连接</h2><p className="setup-sub">脚本会检测 SSH 服务，经你确认后按需安装并启动，再配置本次连接。</p><div className="os-tabs" role="group" aria-label="连接脚本系统">{[['win32', 'Windows'], ['linux', 'Ubuntu / Debian']].map(([value, name]) => <button key={value} aria-pressed={platform === value} onClick={() => { setPlatform(value as typeof platform); downloading.current = undefined; }}>{name}</button>)}</div><div className="download-row"><div><strong>{platform === 'win32' ? 'Windows .bat' : 'Linux .sh'}</strong><p>{session ? '仅用于本次连接 · 下载后在本机运行' : '接受后可下载'}</p></div><button className="btn" disabled={!session || busy || unknown} onClick={() => void download()}><Icon name="download" />下载连接脚本</button></div><p className="setup-sub">安装可能需要管理员权限；SSH 默认使用普通账户。脚本含本次凭据，请勿转发。</p></div></section>}
      {session && <section className="card pad"><div className="section-head"><h2>连接概览</h2><span className="tag">{metrics?.sampledAt ? new Date(metrics.sampledAt).toLocaleTimeString() + ' 采样' : '等待采样'}</span></div><div className="device-detail"><div><small>本机确认账户</small><b>{session.account ?? '等待本机确认'}</b></div><div><small>设备连接</small><b>{session.platform === 'win32' ? 'Windows' : session.platform === 'linux' ? 'Linux' : '未登记'} · {online ? '能力已核验' : '等待核验'}</b></div></div><div className="metrics">{metric('授权时长（含离线）', duration((now - Date.parse(session.acceptedAt)) / 1000))}{metric('累计在线', metrics ? duration(metrics.onlineSeconds) : '—')}{metric('连接往返延迟', !unknown && (metrics?.rttMs !== null && metrics?.rttMs !== undefined) ? metrics.rttMs + ' ms' : '—')}{metric('受控 SSH · 当前 / 累计', metrics ? `${metrics.sshConnectionsActive ?? 0} / ${metrics.sshConnectionsOpened}` : '—')}{metric('S端 → 本机', metrics ? bytes(metrics.sshBytesSToC) : '—')}{metric('本机 → S端', metrics ? bytes(metrics.sshBytesCToS) : '—')}</div><p className="metrics-note">受控 API 操作 {metrics?.apiOperations ?? '—'} 次。SSH 连接数仅统计服务管理的认证连接；原生 SSH 代理计入流量，不计入此连接数。延迟为连接程序往返时间，操作数不是命令总数。</p></section>}
      <aside className="footnote"><Icon name="shield" /><p><b>你的密码留在本机。</b> 默认仅保存操作元数据、撤销记录和流量指标，不保存命令正文或输出；系统 SSH 和终端可能另有日志。</p></aside></div>
      <aside className="card status-card pad right"><div className="rail-head"><h2>连接控制</h2><span>{unknown ? '状态待核实' : online ? '正在协助' : session ? '等待连接' : '等待你确认'}</span></div><div className="connection" aria-hidden="true"><div className="node local"><Icon name="device" /></div><div className="wire"><span className="wire-label">{online ? '已连接' : '由你开启'}</span></div><div className="node"><Icon name="server" /></div></div><div className="state-line"><span>访问授权</span><b>{session ? '已授权' : '尚未授权'}</b></div><div className="state-line"><span>本机连接</span><b>{unknown ? '待核实' : session?.frozen ? '访问冻结' : online ? '在线' : session?.authorization === 'enrolled' ? '离线 · 可恢复' : '未建立'}</b></div><hr className="rail-rule" /><div className="callout">{!session ? '点击“接受访问”后，此邀请才会被使用。随后需在本机运行连接脚本。' : session.frozen ? '服务正在冻结访问。授权保留，需邀请方修复权威数据。' : online ? '邀请方现在可以在授权账户内执行命令和传输文件。' : '授权仍有效。请运行连接脚本；已安装时，登录后会恢复，也可在本机运行 resume。'}</div>{!session ? <><label className="consent"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} /><span>我已了解访问范围、AI 参与可能性，以及主动断开前授权持续保留。</span></label><button className="btn primary wide" disabled={!consent || busy || unknown} onClick={() => void accept()}>接受访问</button><p className="micro">接受即使用此邀请，仅绑定当前浏览器</p></> : <><button className="btn danger-btn wide ended-actions" disabled={busy} onClick={() => dialog.current?.showModal()}>断开连接</button><p className="micro">终止访问并撤销权限，重连需重新邀请</p><details><summary>页面连不上，如何结束授权？</summary><p>在本机连接程序目录运行以下命令，并确认主动断开：</p><pre>node client.cjs disconnect --session {session.id}</pre><p>本地撤销不需要邀请机在线。连接程序保留清理与补交状态，恢复网络后需重新运行以补交。</p></details></>}</aside></div>}
    </main><footer className="footer"><div>NyaaRink · {VERSION} · 便捷式远程 SSH 控制协助服务。</div><div className="footer-links"><a href="https://github.com/NyaaCaster/NyaaRink" target="_blank" rel="noreferrer">源代码 / AGPL-3.0</a><span>{BLESSING}</span></div></footer>
    <dialog ref={dialog} aria-labelledby="disconnect-title"><h2 id="disconnect-title">结束本次远程协助？</h2><p>这会撤销本次授权，终止 SSH 访问，并清理本次凭据与登录启动项。正在执行的操作可能被中断，已完成的修改不会回滚。</p><div className="callout warning">之后需要对方重新发送邀请。单纯关闭页面不会结束授权。</div><div className="dialog-actions"><button className="btn" onClick={() => dialog.current?.close()}>继续协助</button><button className="btn danger-btn" onClick={() => void disconnect()}>确认断开连接</button></div></dialog>
  </div>;
}
createRoot(document.getElementById('root')!).render(<App />);
