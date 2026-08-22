--d48d6527c950c518d810efd427e833ca86bf6e2fc9b1cee277ab22bdbbcc
Content-Disposition: form-data; name="worker.js"

// WorkerDesk v3 - API中转站工单系统
// 角色: user=发单方(email+pass注册), worker=接单方(邮箱验证+认证码)
// Bindings: DB(D1), SESSIONS(KV), CODES(KV), WORKER_CODE(secret_text), SERVICE_NAME(optional plain_text)

const ORIGIN = 'https://kf.goutou.dpdns.org';
const SESSION_TTL = 60 * 60 * 24 * 30;
const CODE_TTL = 600; // 10 min verification code

const API_TYPES = [
  { id: 'chatgpt',  name: 'ChatGPT / OpenAI',  icon: '🟢' },
  { id: 'claude',   name: 'Claude / Anthropic', icon: '🟣' },
  { id: 'gemini',   name: 'Gemini / Google',    icon: '🔵' },
  { id: 'coding',   name: 'Cursor / Copilot',   icon: '💻' },
  { id: 'api4u',    name: '通用 API 接入',      icon: '🔌' },
  { id: 'billing',  name: '充值 / 账单',        icon: '💳' },
  { id: 'account',  name: '账号问题',           icon: '👤' },
  { id: 'other',    name: '其他',               icon: '❓' }
];

const TICKET_STATUS = {
  open:      { name: '待接单', color: '#22c55e', dot: '🟢' },
  claimed:   { name: '处理中', color: '#3b82f6', dot: '🔵' },
  completed: { name: '已完成', color: '#94a3b8', dot: '✅' },
  closed:    { name: '已关闭', color: '#6b7280', dot: '⚫' }
};

// =============== utils ===============
const json = (o, s=200, h={}) => new Response(JSON.stringify(o), { status:s, headers:{'Content-Type':'application/json; charset=utf-8', ...h} });
const esc  = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function sha256(s){ const b=await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join(''); }
function rndToken(n=24){ const a=new Uint8Array(n); crypto.getRandomValues(a); return [...a].map(x=>x.toString(16).padStart(2,'0')).join(''); }
function rndCode(){ return String(Math.floor(100000 + Math.random()*900000)); }
function getCookie(req, name){ const m=(req.headers.get('Cookie')||'').match(new RegExp('(?:^|;\\s*)'+name+'=([^;]+)')); return m?m[1]:null; }
async function session(req, env){
  const sid = getCookie(req, 'wd_sid');
  if (!sid) return null;
  return env.SESSIONS.get('sess:'+sid, { type:'json' });
}
const setCookie = t => `wd_sid=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL}`;
const clrCookie = ()=> 'wd_sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';

function fmtRel(s){
  if (!s) return '';
  const d = new Date(s.replace(' ','T')+'Z').getTime();
  const diff = (Date.now()-d)/1000;
  if (diff<60) return '刚刚';
  if (diff<3600) return Math.floor(diff/60)+'分钟前';
  if (diff<86400) return Math.floor(diff/3600)+'小时前';
  if (diff<604800) return Math.floor(diff/86400)+'天前';
  return s.substring(5,16);
}

function validEmail(e){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }

// =============== email (Resend) ===============
async function sendCode(to, code, env){
  if (!env.RESEND_API_KEY) return { ok: false, error: 'RESEND_API_KEY not configured' };
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'API中转站 <noreply@goutou.dpdns.org>',
      to: [to],
      subject: '【API中转站】您的邮箱验证码',
      text: `您的邮箱验证码是：${code}\n\n该验证码 10 分钟内有效，请勿告知他人。\n如非本人操作，请忽略此邮件。`
    })
  });
  if (!r.ok) {
    const t = await r.text().catch(()=> '');
    return { ok: false, error: '邮件发送失败: '+r.status+' '+t };
  }
  return { ok: true };
}

// =============== auth ===============
async function handleSendCode(req, env){
  const b = await req.json().catch(()=>({}));
  const email = (b.email||'').trim().toLowerCase();
  if (!validEmail(email)) return json({ error:'邮箱格式错误' }, 400);
  const code = rndCode();
  await env.CODES.put('code:'+email, code, { expirationTtl: CODE_TTL });
  const res = await sendCode(email, code, env);
  if (!res.ok) {
    // In case MailChannels isn't working yet, return code in dev mode is unsafe.
    // Return error; admin can check logs. Also log to console.
    console.log('MAIL_FAIL', email, code, res.error);
    return json({ error:'验证码邮件发送失败，请稍后重试或联系管理员。' }, 502);
  }
  return json({ ok:true });
}

async function handleRegister(req, env, role){
  const b = await req.json().catch(()=>({}));
  const email = (b.email||'').trim().toLowerCase();
  const pass = b.pass || '';
  const code = (b.code||'').trim();
  if (!validEmail(email)) return json({error:'邮箱格式错误'},400);
  if (pass.length < 6) return json({error:'口令至少 6 位'},400);

  // user role: no email verification required; just email + pass
  // worker role: email verification code required + worker auth code
  if (role === 'worker') {
    if (!/^\d{6}$/.test(code)) return json({error:'请输入 6 位邮箱验证码'},400);
    const saved = await env.CODES.get('code:'+email);
    if (!saved || saved !== code) return json({error:'验证码错误或已过期'},400);
    const wc = b.workerCode || '';
    if (!wc || wc !== env.WORKER_CODE) return json({error:'接单员认证码错误'},403);
  }

  const exists = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
  if (exists) return json({error:'该邮箱已注册'},409);

  const ph = await sha256(pass);
  const r = await env.DB.prepare('INSERT INTO users (email, pass_hash, role, verified) VALUES (?,?,?,?)')
    .bind(email, ph, role, role === 'worker' ? 1 : 0).run();
  const uid = r.meta.last_row_id;
  if (role === 'worker') await env.CODES.delete('code:'+email);

  const token = rndToken();
  const sess = { id: uid, email, role };
  await env.SESSIONS.put('sess:'+token, JSON.stringify(sess), { expirationTtl: SESSION_TTL });
  return json({ user: sess }, 200, { 'Set-Cookie': setCookie(token) });
}

async function handleLogin(req, env){
  const b = await req.json().catch(()=>({}));
  const email = (b.email||'').trim().toLowerCase();
  if (!validEmail(email)) return json({error:'请输入有效邮箱'},400);
  let u = await env.DB.prepare('SELECT id, email, role FROM users WHERE email=?').bind(email).first();
  if (!u) {
    const r = await env.DB.prepare('INSERT INTO users (email, pass_hash, role, verified) VALUES (?,?,?,?)')
      .bind(email, '', 'user', 0).run();
    u = { id: r.meta.last_row_id, email, role: 'user' };
  }
  const token = rndToken();
  const sess = { id:u.id, email:u.email, role:u.role };
  await env.SESSIONS.put('sess:'+token, JSON.stringify(sess), { expirationTtl: SESSION_TTL });
  return json({ user: sess }, 200, { 'Set-Cookie': setCookie(token) });
}

async function handleLogout(req, env){
  const sid = getCookie(req, 'wd_sid');
  if (sid) await env.SESSIONS.delete('sess:'+sid);
  return json({ok:true}, 200, { 'Set-Cookie': clrCookie() });
}

// =============== tickets ===============
async function handleCreateTicket(req, env){
  const u = await session(req, env);
  if (!u || u.role !== 'user') return json({error:'请以发单方身份登录'},401);
  const b = await req.json().catch(()=>({}));
  const api_type = b.api_type;
  const title = (b.title||'').trim();
  const description = (b.description||'').trim();
  const error_msg = (b.error_msg||'').trim();
  const todesk = (b.todesk_code||'').trim();
  if (!API_TYPES.find(x=>x.id===api_type)) return json({error:'请选择问题类型'},400);
  if (!title || title.length>80) return json({error:'标题 1-80 字'},400);
  if (!description || description.length>2000) return json({error:'问题描述 1-2000 字'},400);
  if (!todesk || todesk.length>50) return json({error:'请填写 ToDesk 远控码'},400);

  const r = await env.DB.prepare(
    `INSERT INTO tickets (user_id, api_type, title, description, error_msg, todesk_code)
     VALUES (?,?,?,?,?,?)`
  ).bind(u.id, api_type, title, description, error_msg || null, todesk).run();
  const ticketId = r.meta.last_row_id;
  return json({ id: ticketId });
}

async function handleListMyTickets(req, env){
  const u = await session(req, env);
  if (!u) return json({error:'未登录'},401);
  const { results } = await env.DB.prepare(
    `SELECT t.*, w.email AS worker_email
     FROM tickets t LEFT JOIN users w ON w.id=t.worker_id
     WHERE t.user_id=? ORDER BY t.id DESC LIMIT 200`
  ).bind(u.id).all();
  return json({ tickets: results || [] });
}

async function handleListOpenTickets(req, env){
  const u = await session(req, env);
  if (!u || u.role !== 'worker') return json({error:'需接单员账号'},401);
  const { results } = await env.DB.prepare(
    `SELECT t.id, t.api_type, t.title, t.description, t.error_msg, t.status, t.created_at, t.claimed_at,
            u.email AS user_email, w.email AS worker_email
     FROM tickets t JOIN users u ON u.id=t.user_id LEFT JOIN users w ON w.id=t.worker_id
     WHERE t.status IN ('open','claimed') ORDER BY t.id DESC LIMIT 200`
  ).all();
  return json({ tickets: results || [] });
}

async function handleTicketAction(req, env, id, action){
  const u = await session(req, env);
  if (!u) return json({error:'未登录'},401);
  const t = await env.DB.prepare('SELECT * FROM tickets WHERE id=?').bind(id).first();
  if (!t) return json({error:'工单不存在'},404);

  if (action === 'claim') {
    if (u.role !== 'worker') return json({error:'仅接单员可抢单'},403);
    if (t.status !== 'open') return json({error:'该工单已被接走或关闭'},400);
    if (t.user_id === u.id) return json({error:'不能接自己的单'},400);
    await env.DB.prepare("UPDATE tickets SET status='claimed', worker_id=?, claimed_at=datetime('now') WHERE id=? AND status='open'")
      .bind(u.id, id).run();
  } else if (action === 'complete') {
    if (t.worker_id !== u.id) return json({error:'仅接单员可标记完成'},403);
    if (t.status !== 'claimed') return json({error:'当前状态不可完成'},400);
    await env.DB.prepare("UPDATE tickets SET status='completed', completed_at=datetime('now') WHERE id=?").bind(id).run();
  } else if (action === 'close') {
    if (t.user_id !== u.id) return json({error:'仅发单方可关闭'},403);
    if (t.status === 'closed') return json({error:'已关闭'},400);
    await env.DB.prepare("UPDATE tickets SET status='closed', closed_at=datetime('now') WHERE id=?").bind(id).run();
  } else if (action === 'release') {
    if (t.worker_id !== u.id) return json({error:'仅接单方可放弃'},403);
    if (t.status !== 'claimed') return json({error:'当前状态不可放弃'},400);
    await env.DB.prepare("UPDATE tickets SET status='open', worker_id=NULL, claimed_at=NULL WHERE id=?").bind(id).run();
  } else return json({error:'未知操作'},400);

  return json({ok:true});
}

async function handleTicketDetail(req, env, id){
  const u = await session(req, env);
  if (!u) return json({error:'未登录'},401);
  const t = await env.DB.prepare(
    `SELECT t.*, w.email AS worker_email FROM tickets t LEFT JOIN users w ON w.id=t.worker_id WHERE t.id=?`
  ).bind(id).first();
  if (!t) return json({error:'工单不存在'},404);
  if (t.user_id !== u.id && t.worker_id !== u.id) return json({error:'无权限'},403);
  return json({ ticket: t });
}

async function handleRateTicket(req, env, id){
  const u = await session(req, env);
  if (!u) return json({error:'未登录'},401);
  const t = await env.DB.prepare('SELECT * FROM tickets WHERE id=?').bind(id).first();
  if (!t) return json({error:'工单不存在'},404);
  if (t.user_id !== u.id) return json({error:'仅发单方可评分'},403);
  if (t.status !== 'completed') return json({error:'仅已完成工单可评分'},400);
  if (t.rating !== null) return json({error:'已评分'},400);
  const b = await req.json().catch(()=>({}));
  const rating = parseInt(b.rating);
  if (!rating || rating < 1 || rating > 5) return json({error:'评分 1-5'},400);
  await env.DB.prepare('UPDATE tickets SET rating=? WHERE id=?').bind(rating, id).run();
  return json({ok:true});
}

async function handleWorkerStats(req, env){
  const u = await session(req, env);
  if (!u || u.role !== 'worker') return json({error:'需接单员账号'},401);
  const { results } = await env.DB.prepare(
    `SELECT COUNT(*) as total, COUNT(CASE WHEN status='completed' THEN 1 END) as completed,
            COUNT(CASE WHEN rating IS NOT NULL THEN 1 END) as rated,
            COALESCE(AVG(CASE WHEN rating IS NOT NULL THEN rating END), 0) as avg_rating
     FROM tickets WHERE worker_id=?`
  ).bind(u.id).all();
  return json({ stats: results[0] || { total:0, completed:0, rated:0, avg_rating:0 } });
}

// =============== messages ===============
async function handleSendMsg(req, env, ticketId){
  const u = await session(req, env);
  if (!u) return json({error:'未登录'},401);
  const t = await env.DB.prepare('SELECT * FROM tickets WHERE id=?').bind(ticketId).first();
  if (!t) return json({error:'工单不存在'},404);
  if (t.user_id !== u.id && t.worker_id !== u.id) return json({error:'无权限'},403);
  if (t.status !== 'claimed' && t.status !== 'completed') return json({error:'工单未在进行中'},400);
  const b = await req.json().catch(()=>({}));
  const content = (b.content||'').trim();
  if (!content || content.length>1000) return json({error:'消息 1-1000 字'},400);
  const r = await env.DB.prepare('INSERT INTO messages (ticket_id, sender_id, content) VALUES (?,?,?)')
    .bind(ticketId, u.id, content).run();
  return json({ id: r.meta.last_row_id });
}

async function handleGetMsgs(req, env, ticketId, afterId){
  const u = await session(req, env);
  if (!u) return json({error:'未登录'},401);
  const t = await env.DB.prepare('SELECT * FROM tickets WHERE id=?').bind(ticketId).first();
  if (!t) return json({error:'工单不存在'},404);
  if (t.user_id !== u.id && t.worker_id !== u.id) return json({error:'无权限'},403);
  let sql = 'SELECT id, sender_id, content, created_at FROM messages WHERE ticket_id=?';
  const params = [ticketId];
  if (afterId) { sql += ' AND id>?'; params.push(afterId); }
  sql += ' ORDER BY id ASC LIMIT 200';
  const { results } = await env.DB.prepare(sql).bind(...params).all();
  return json({ messages: results || [], me: u.id });
}

// =============== HTML pages ===============
function baseCss(accent){
  return `
*,*::before,*::after{box-sizing:border-box}
:root{--bg:#0b0f1a;--bg2:#121829;--card:rgba(255,255,255,.04);--border:rgba(255,255,255,.08);--text:#e6eaf2;--muted:#94a3b8;--dim:#64748b;--accent:${accent};--accent-h:${accent}dd;--radius:14px;--radius-sm:10px}
html,body{margin:0;padding:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh}
body{background:radial-gradient(ellipse at top left,${accent}22,transparent 55%),radial-gradient(ellipse at bottom right,rgba(236,72,153,.08),transparent 55%),var(--bg);min-height:100vh}
a{color:var(--accent);text-decoration:none}
.wrap{max-width:900px;margin:0 auto;padding:0 16px 100px}
.nav{position:sticky;top:0;z-index:50;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);background:rgba(11,15,26,.78);border-bottom:1px solid var(--border);padding:12px 0}
.nav-in{max-width:900px;margin:0 auto;padding:0 16px;display:flex;align-items:center;gap:12px}
.brand{font-size:1.1rem;font-weight:700;background:linear-gradient(135deg,${accent},#ec4899);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.brand small{opacity:.6;font-weight:400;font-size:.78rem;margin-left:6px;-webkit-text-fill-color:var(--muted)}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:10px}
.chip{background:var(--card);border:1px solid var(--border);padding:6px 12px;border-radius:20px;font-size:.82rem;color:var(--muted)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:9px 16px;border-radius:var(--radius-sm);border:1px solid transparent;font-size:.9rem;font-weight:500;cursor:pointer;transition:all .15s;font-family:inherit;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent-h);transform:translateY(-1px)}
.btn-ghost{background:var(--card);color:var(--text);border-color:var(--border)}
.btn-ghost:hover{background:rgba(255,255,255,.08)}
.btn-danger{background:#ef4444;color:#fff}
.btn-block{width:100%;padding:12px;font-size:1rem}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none!important}
.btn-link{background:none;border:none;color:var(--accent);cursor:pointer;padding:0;font:inherit}
.hero{text-align:center;padding:32px 16px 20px}
.hero h1{font-size:clamp(1.6rem,5vw,2.2rem);margin:0 0 8px;font-weight:800;background:linear-gradient(135deg,#fff,#94a3b8);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-.5px}
.hero p{color:var(--muted);margin:0;font-size:.95rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:14px;backdrop-filter:blur(8px)}
.card h3{margin:0 0 12px;font-size:1.05rem}
.form-row{margin-bottom:14px}
.form-row label{display:block;font-size:.85rem;color:var(--muted);margin-bottom:6px;font-weight:500}
.form-row input,.form-row textarea,.form-row select{width:100%;padding:11px 14px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:.95rem;font-family:inherit;transition:border .15s}
.form-row input:focus,.form-row textarea:focus,.form-row select:focus{outline:none;border-color:var(--accent);background:rgba(255,255,255,.06)}
.form-row textarea{min-height:100px;resize:vertical}
.form-row .hint{font-size:.78rem;color:var(--dim);margin-top:4px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:560px){.form-grid{grid-template-columns:1fr}}
.code-row{display:flex;gap:8px}
.code-row input{flex:1}
.code-row button{white-space:nowrap}
.ticket{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:12px;position:relative;overflow:hidden;transition:all .2s}
.ticket:hover{border-color:${accent}44}
.ticket::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:linear-gradient(180deg,var(--accent),transparent);opacity:.7}
.t-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}
.type-badge{padding:4px 10px;border-radius:6px;font-size:.78rem;font-weight:600;background:${accent}22;color:${accent};border:1px solid ${accent}44}
.t-status{font-size:.82rem;font-weight:500;margin-left:auto}
.t-title{margin:0 0 6px;font-size:1.05rem;font-weight:600}
.t-desc{margin:0 0 10px;color:var(--muted);font-size:.9rem;white-space:pre-wrap;word-break:break-word}
.t-meta{display:flex;gap:12px;flex-wrap:wrap;color:var(--dim);font-size:.8rem;margin-bottom:10px}
.t-actions{display:flex;gap:8px;flex-wrap:wrap}
.t-actions .btn{padding:7px 12px;font-size:.85rem}
.empty{text-align:center;padding:50px 20px;color:var(--dim)}
.empty .ic{font-size:2.8rem;opacity:.5;margin-bottom:10px}
.auth-box{max-width:420px;margin:40px auto}
.tabs{display:flex;gap:4px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px;margin-bottom:20px}
.tab{flex:1;padding:9px;text-align:center;border:none;background:transparent;color:var(--muted);border-radius:6px;cursor:pointer;font-size:.9rem;font-weight:500;font-family:inherit}
.tab.active{background:var(--accent);color:#fff}
.fab{position:fixed;right:20px;bottom:24px;width:56px;height:56px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#ec4899);color:#fff;border:none;font-size:1.6rem;cursor:pointer;box-shadow:0 8px 24px ${accent}66;z-index:30;transition:transform .2s;display:flex;align-items:center;justify-content:center}
.fab:hover{transform:scale(1.08) rotate(90deg)}
@media(min-width:860px){.fab{display:none}}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(8px);z-index:100;display:none;align-items:flex-end;justify-content:center}
.modal-bg.show{display:flex}
@media(min-width:640px){.modal-bg{align-items:center}}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:18px 18px 0 0;width:100%;max-width:560px;max-height:90vh;overflow-y:auto;padding:20px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
@media(min-width:640px){.modal{border-radius:18px}}
.modal h2{margin:0 0 4px;font-size:1.2rem}
.modal .sub{color:var(--muted);margin:0 0 18px;font-size:.9rem}
.modal-x{position:absolute;right:12px;top:12px;background:var(--card);border:1px solid var(--border);color:var(--muted);width:32px;height:32px;border-radius:50%;cursor:pointer}
.chat-box{position:fixed;inset:0;z-index:200;background:var(--bg);display:none;flex-direction:column}
.chat-box.show{display:flex}
.chat-head{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;background:var(--bg2)}
.chat-back{background:none;border:none;color:var(--text);font-size:1.2rem;cursor:pointer;padding:4px 8px}
.chat-title{flex:1;font-weight:600;font-size:1rem}
.chat-msgs{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:10px}
.msg{max-width:75%;padding:10px 14px;border-radius:14px;font-size:.92rem;word-break:break-word;white-space:pre-wrap}
.msg.me{align-self:flex-end;background:var(--accent);color:#fff;border-bottom-right-radius:4px}
.msg.them{align-self:flex-start;background:rgba(255,255,255,.06);border:1px solid var(--border);border-bottom-left-radius:4px}
.msg .time{display:block;font-size:.7rem;opacity:.65;margin-top:3px}
.chat-input{padding:10px 12px;border-top:1px solid var(--border);display:flex;gap:8px;background:var(--bg2)}
.chat-input input{flex:1;padding:11px 14px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:22px;color:var(--text);font-size:.95rem;font-family:inherit}
.chat-input input:focus{outline:none;border-color:var(--accent)}
.chat-input button{width:44px;height:44px;border-radius:50%;border:none;background:var(--accent);color:#fff;font-size:1.1rem;cursor:center;display:flex;align-items:center;justify-content:center}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(100px);background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:12px 20px;border-radius:var(--radius-sm);z-index:300;transition:transform .3s;box-shadow:0 10px 30px rgba(0,0,0,.4);max-width:90vw;font-size:.9rem}
.toast.show{transform:translateX(-50%) translateY(0)}
.toast.ok{border-color:#22c55e}
.toast.err{border-color:#ef4444}
.spin{display:inline-block;width:15px;height:15px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:sp .7s linear}
@keyframes sp{to{transform:rotate(360deg)}}
.pill{display:inline-block;padding:3px 9px;border-radius:11px;background:rgba(255,255,255,.06);color:var(--muted);font-size:.75rem;margin-left:6px}
.rating-box{display:flex;align-items:center;gap:4px;margin:8px 0}
.star-btn{background:none;border:none;font-size:1.2rem;cursor:pointer;padding:2px;color:var(--muted);transition:color .15s}
.star-btn:hover,.star-btn.active{color:#fbbf24}
.rating-hint{font-size:.75rem;color:var(--dim);margin-left:6px}
.rating-display{font-size:.9rem;color:#fbbf24;margin:6px 0}
.worker-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px;text-align:center}
.stat-value{font-size:1.5rem;font-weight:700;color:var(--accent)}
.stat-label{font-size:.78rem;color:var(--muted);margin-top:4px}
`;
}

function commonJs(){
  return `
const $=(s,r=document)=>r.querySelector(s);
const $$=(s,r=document)=>[...r.querySelectorAll(s)];
function toast(msg,type){const t=$('#toast');t.textContent=msg;t.className='toast show '+(type||'');clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove('show'),2500);}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmtRel(s){if(!s)return'';const d=new Date(s.replace(' ','T')+'Z').getTime();const diff=(Date.now()-d)/1000;if(diff<60)return'刚刚';if(diff<3600)return Math.floor(diff/60)+'分钟前';if(diff<86400)return Math.floor(diff/3600)+'小时前';if(diff<604800)return Math.floor(diff/86400)+'天前';return s.substring(5,16);}
async function api(m,p,b){const o={method:m,headers:{}};if(b){o.headers['Content-Type']='application/json';o.body=JSON.stringify(b);}const r=await fetch(p,o);let d;try{d=await r.json();}catch{d={};}if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d;}
function openModal(id){$('#'+id).classList.add('show');}
function closeModal(id){$('#'+id).classList.remove('show');}
window.closeModal=closeModal;
function initNotify(){if('Notification' in window&&Notification.permission==='default')Notification.requestPermission();}
function notify(title,body){if('Notification' in window&&Notification.permission==='granted')new Notification(title,{body,icon:'/favicon.ico'});}
`;
}

// ---------- user page (/fd) ----------
function renderUserPage(user){
  const typeOpts = API_TYPES.map(t => `<option value="${t.id}">${t.icon} ${esc(t.name)}</option>`).join('');
  return `<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>API中转站 · 提交工单</title>
<style>${baseCss('#10b981')}</style>
</head><body>
<nav class="nav"><div class="nav-in">
  <div class="brand">🛟 API 中转站<small>技术支持</small></div>
  <div class="nav-right">
    ${user ? `<span class="chip">👤 ${esc(user.email)}</span><button class="btn btn-ghost" id="logoutBtn">退出</button>`
           : `<a class="btn btn-primary" href="/fd#login">登录</a>`}
  </div>
</div></nav>

<div class="wrap">
  <div class="hero">
    <h1>遇到 API 使用问题？</h1>
    <p>填写工单 + ToDesk 远控码，技术接单员会远程协助您排查</p>
  </div>

  ${!user ? `
  <div class="card auth-box" id="authCard">
    <h3 style="margin:0 0 12px">登录</h3>
    <p style="margin:0 0 14px;color:var(--muted);font-size:.9rem">仅需输入邮箱即可登录/注册</p>
    <form id="authForm">
      <div class="form-row"><label>邮箱</label><input type="email" name="email" required placeholder="you@example.com"/></div>
      <button type="submit" class="btn btn-primary btn-block" id="authSubmit">登录</button>
    </form>
  </div>` : `

  <div class="card">
    <h3>📝 提交新工单</h3>
    <form id="ticketForm">
      <div class="form-row">
        <label>问题类型 *</label>
        <select name="api_type" required>${typeOpts}</select>
      </div>
      <div class="form-row">
        <label>问题标题 *</label>
        <input name="title" required maxlength="80" placeholder="一句话说明，如：ChatGPT API 401 鉴权失败"/>
      </div>
      <div class="form-row">
        <label>详细描述 *</label>
        <textarea name="description" required maxlength="2000" placeholder="请描述：使用的 API、请求参数、报错信息、复现步骤等，越详细越快解决"></textarea>
      </div>
      <div class="form-row">
        <label>报错信息（可选）</label>
        <textarea name="error_msg" maxlength="1000" placeholder="粘贴完整的错误返回或控制台报错" style="min-height:70px"></textarea>
      </div>
      <div class="form-row">
        <label>ToDesk 远控码 *</label>
        <input name="todesk_code" required maxlength="50" placeholder="如 123 456 789（临时密码请写在描述里）"/>
        <div class="hint">接单员接单后才可见远控码；请确保 ToDesk 已开启</div>
      </div>
      <button type="submit" class="btn btn-primary btn-block">提交工单</button>
    </form>
  </div>

  <div style="display:flex;align-items:center;justify-content:space-between;margin:20px 0 10px">
    <h3 style="margin:0;font-size:1.05rem">📋 我的工单</h3>
    <button class="btn btn-ghost" id="refreshBtn">刷新</button>
  </div>
  <div id="ticketList"></div>`}
</div>

<button class="fab" id="fabTop" title="顶部">↑</button>

<!-- chat -->
<div class="chat-box" id="chatBox">
  <div class="chat-head">
    <button class="chat-back" id="chatBack">←</button>
    <div class="chat-title" id="chatTitle">对话</div>
  </div>
  <div class="chat-msgs" id="chatMsgs"></div>
  <div class="chat-input">
    <input id="chatInput" placeholder="输入消息..." maxlength="1000"/>
    <button id="chatSend">➤</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
${commonJs()}
const STATE = { user: ${user ? JSON.stringify({id:user.id,email:user.email,role:user.role}) : 'null'}, tickets: [], prevTickets: {}, chatId:null, lastMsgId:0, pollTimer:null };
initNotify();

$('#authForm')?.addEventListener('submit', async e=>{
  e.preventDefault();
  const body={email:e.target.email.value.trim()};
  const btn=$('#authSubmit');btn.disabled=true;btn.innerHTML='<span class="spin"></span>';
  try{
    await api('POST', '/api/auth/login', body);
    toast('登录成功','ok');
    setTimeout(()=>location.reload(),500);
  }catch(err){toast(err.message,'err');btn.disabled=false;btn.textContent='登录';}
});

$('#logoutBtn')?.addEventListener('click', async()=>{await api('POST','/api/auth/logout');location.reload();});

// ticket submit
$('#ticketForm')?.addEventListener('submit', async e=>{
  e.preventDefault();const f=e.target;
  const body={api_type:f.api_type.value,title:f.title.value.trim(),description:f.description.value.trim(),error_msg:f.error_msg.value.trim(),todesk_code:f.todesk_code.value.trim()};
  const btn=f.querySelector('button[type=submit]');btn.disabled=true;btn.innerHTML='<span class="spin"></span>';
  try{
    await api('POST','/api/tickets',body);
    toast('工单已提交','ok');f.reset();loadTickets();
  }catch(err){toast(err.message,'err');}finally{btn.disabled=false;btn.textContent='提交工单';}
});

$('#refreshBtn')?.addEventListener('click', loadTickets);

function typeBadge(id){const t=${JSON.stringify(API_TYPES)}.find(x=>x.id===id)||{icon:'❓',name:id};return '<span class="type-badge">'+t.icon+' '+esc(t.name)+'</span>';}
function statusPill(s){const m=${JSON.stringify(TICKET_STATUS)};const x=m[s]||m.open;return '<span class="t-status" style="color:'+x.color+'">'+x.dot+' '+x.name+'</span>';}

async function loadTickets(){
  try{
    const d=await api('GET','/api/tickets/mine');
    const newTickets=d.tickets||[];
    newTickets.forEach(t=>{
      const prev=STATE.prevTickets[t.id];
      if(prev&&prev.status==='open'&&t.status==='claimed'){
        notify('工单被接取','#'+t.id+' '+t.title+' 已被 '+t.worker_email+' 接取');
      }
    });
    STATE.prevTickets={};newTickets.forEach(t=>{STATE.prevTickets[t.id]=t;});
    STATE.tickets=newTickets;renderTickets();
  }catch(e){toast(e.message,'err');}
}
function renderTickets(){
  const box=$('#ticketList');if(!box)return;
  if(!STATE.tickets.length){box.innerHTML='<div class="empty"><div class="ic">📭</div><p>还没有工单</p></div>';return;}
  box.innerHTML=STATE.tickets.map(t=>{
    let actions='';
    if(t.status==='open'){
      actions='<button class="btn btn-ghost" data-act="close" data-id="'+t.id+'">关闭工单</button>';
    } else if(t.status==='claimed'||t.status==='completed'){
      actions='<button class="btn btn-primary" data-act="chat" data-id="'+t.id+'">💬 联系接单员</button>'
        + (t.status==='claimed'?'<button class="btn btn-ghost" data-act="close" data-id="'+t.id+'">关闭</button>':'');
    }
    const worker = t.worker_email ? '<span class="meta-item">🔧 '+esc(t.worker_email)+'</span>' : '';
    let ratingHtml='';
    if(t.status==='completed'){
      if(t.rating!==null){
        ratingHtml='<div class="rating-display">评分：'+[1,2,3,4,5].map(i=>i<=t.rating?'⭐':'☆').join('')+'</div>';
      } else {
        ratingHtml='<div class="rating-box" data-id="'+t.id+'">'+[1,2,3,4,5].map(i=>'<button class="star-btn" data-rating="'+i+'">☆</button>').join('')+'<span class="rating-hint">点击评分</span></div>';
        setTimeout(()=>{
          const box=document.querySelector('.rating-box[data-id="'+t.id+'"]');
          if(!box)return;
          const stars=box.querySelectorAll('.star-btn');
          box.addEventListener('mouseover',e=>{
            const s=e.target.closest('.star-btn');if(!s)return;
            const r=+s.dataset.rating;
            stars.forEach(st=>{st.textContent=+st.dataset.rating<=r?'⭐':'☆';});
          });
          box.addEventListener('mouseout',()=>{stars.forEach(st=>{st.textContent='☆';});});
        },0);
      }
    }
    return '<div class="ticket"><div class="t-head">'+typeBadge(t.api_type)+statusPill(t.status)+'</div>'
      +'<h3 class="t-title">'+esc(t.title)+'</h3>'
      +'<p class="t-desc">'+esc(t.description)+'</p>'
      +'<div class="t-meta"><span>🕒 '+fmtRel(t.created_at)+'</span>'+worker+'</div>'
      +ratingHtml
      +'<div class="t-actions">'+actions+'</div></div>';
  }).join('');
}

document.addEventListener('click', async e=>{
  const starBtn=e.target.closest('.star-btn');
  if(starBtn){
    const ratingBox=starBtn.closest('.rating-box');
    const ticketId=+ratingBox.dataset.id;
    const rating=+starBtn.dataset.rating;
    try{
      await api('POST','/api/tickets/'+ticketId+'/rating',{rating});
      toast('评分成功','ok');loadTickets();
    }catch(err){toast(err.message,'err');}
    return;
  }
  const b=e.target.closest('[data-act]');if(!b)return;
  const id=+b.dataset.id,act=b.dataset.act;
  if(act==='chat'){openChat(id);return;}
  if(act==='close'){
    if(!confirm('确定关闭这个工单？'))return;
    b.disabled=true;
    try{await api('POST','/api/tickets/'+id+'/close');toast('已关闭','ok');loadTickets();}
    catch(err){toast(err.message,'err');b.disabled=false;}
  }
});

// chat
function openChat(id){
  STATE.chatId=id;STATE.lastMsgId=0;
  const t=STATE.tickets.find(x=>x.id===id);
  $('#chatTitle').textContent=t?('#'+id+' · '+t.title):'对话';
  $('#chatBox').classList.add('show');
  $('#chatMsgs').innerHTML='';
  pollMsgs();
  STATE.pollTimer=setInterval(pollMsgs,2000);
}
function closeChat(){
  STATE.chatId=null;if(STATE.pollTimer){clearInterval(STATE.pollTimer);STATE.pollTimer=null;}
  $('#chatBox').classList.remove('show');
}
$('#chatBack').onclick=closeChat;
async function pollMsgs(){
  if(!STATE.chatId)return;
  try{
    const d=await api('GET','/api/tickets/'+STATE.chatId+'/messages?after='+STATE.lastMsgId);
    (d.messages||[]).forEach(m=>{
      if(m.id<=STATE.lastMsgId)return;STATE.lastMsgId=m.id;
      const me=m.sender_id===STATE.user.id;
      const div=document.createElement('div');div.className='msg '+(me?'me':'them');
      div.innerHTML=esc(m.content)+'<span class="time">'+fmtRel(m.created_at)+'</span>';
      $('#chatMsgs').appendChild(div);
      if(!me)notify('新消息','#'+STATE.chatId+': '+m.content.substring(0,50));
    });
    if(d.messages&&d.messages.length)$('#chatMsgs').scrollTop=$('#chatMsgs').scrollHeight;
  }catch(e){}
}
$('#chatSend').onclick=sendMsg;
$('#chatInput').addEventListener('keydown',e=>{if(e.key==='Enter')sendMsg();});
async function sendMsg(){
  const inp=$('#chatInput'),v=inp.value.trim();if(!v||!STATE.chatId)return;
  inp.value='';
  try{await api('POST','/api/tickets/'+STATE.chatId+'/messages',{content:v});pollMsgs();}
  catch(e){toast(e.message,'err');inp.value=v;}
}

$('#fabTop').onclick=()=>window.scrollTo({top:0,behavior:'smooth'});

if(STATE.user){ loadTickets(); setInterval(loadTickets, 5000); }
</script>
</body></html>`;
}

// ---------- worker page (/jd) ----------
function renderWorkerPage(user){
  return `<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>API中转站 · 接单后台</title>
<style>${baseCss('#6366f1')}</style>
</head><body>
<nav class="nav"><div class="nav-in">
  <div class="brand">🛠️ API 中转站<small>接单后台</small></div>
  <div class="nav-right">
    ${user ? `<span class="chip">🔧 ${esc(user.email)}</span><button class="btn btn-ghost" id="logoutBtn">退出</button>`
           : `<a class="btn btn-primary" href="/jd#login">登录</a>`}
  </div>
</div></nav>

<div class="wrap">
  ${!user ? `
  <div class="hero"><h1>接单员登录</h1><p>需邮箱验证 + 接单员认证码</p></div>
  <div class="card auth-box">
    <div class="tabs">
      <button class="tab active" data-mode="login">登录</button>
      <button class="tab" data-mode="register">注册接单员</button>
    </div>
    <form id="authForm">
      <div class="form-row"><label>邮箱</label><input type="email" name="email" required/></div>
      <div class="form-row"><label>口令</label><input type="password" name="pass" required minlength="6"/></div>
      <div class="form-row reg-only" style="display:none">
        <label>邮箱验证码</label>
        <div class="code-row"><input name="code" inputmode="numeric" maxlength="6"/><button type="button" class="btn btn-ghost" id="sendCodeBtn">获取验证码</button></div>
      </div>
      <div class="form-row reg-only" style="display:none">
        <label>接单员认证码</label><input name="workerCode" type="password" placeholder="向管理员索取"/>
      </div>
      <button type="submit" class="btn btn-primary btn-block" id="authSubmit">登录</button>
    </form>
  </div>` : `

  <div class="hero" style="padding:16px 16px 12px">
    <h1>工单大厅</h1>
    <p>实时刷新，待接单 / 进行中工单</p>
  </div>

  <div class="worker-stats" id="workerStats"></div>

  <div style="display:flex;align-items:center;gap:10px;margin:10px 0">
    <div class="tabs" style="margin:0;flex:1">
      <button class="tab active" data-view="open">待接单</button>
      <button class="tab" data-view="claimed">处理中</button>
      <button class="tab" data-view="mine">我接的</button>
    </div>
    <button class="btn btn-ghost" id="refreshBtn">↻ 刷新</button>
  </div>
  <div id="ticketList"></div>`}
</div>

<div class="chat-box" id="chatBox">
  <div class="chat-head"><button class="chat-back" id="chatBack">←</button><div class="chat-title" id="chatTitle">对话</div></div>
  <div class="chat-msgs" id="chatMsgs"></div>
  <div class="chat-input"><input id="chatInput" placeholder="输入消息..." maxlength="1000"/><button id="chatSend">➤</button></div>
</div>

<div class="toast" id="toast"></div>

<script>
${commonJs()}
const STATE={ user:${user?JSON.stringify({id:user.id,email:user.email,role:user.role}):'null'}, mode:'login', view:'open', tickets:[], prevTicketCount:0, chatId:null, lastMsgId:0, poll:null };
initNotify();

$$('.tab').forEach(t=>t.onclick=()=>{
  if(t.dataset.view!==undefined){ STATE.view=t.dataset.view; $$('.tab').forEach(x=>x.classList.toggle('active',x===t)); renderList(); return; }
  $$('.tab').forEach(x=>x.classList.remove('active'));t.classList.add('active');
  STATE.mode=t.dataset.mode;
  document.querySelectorAll('.reg-only').forEach(el=>el.style.display=STATE.mode==='register'?'':'none');
  $('#authSubmit').textContent=STATE.mode==='login'?'登录':'注册';
});

let cd=0;
$('#sendCodeBtn')?.addEventListener('click',async()=>{
  const email=document.querySelector('#authForm input[name=email]').value.trim();
  if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)){toast('请填邮箱','err');return;}
  if(cd>0)return;const b=$('#sendCodeBtn');b.disabled=true;
  try{await api('POST','/api/auth/send-code',{email});toast('已发送','ok');
    cd=60;const iv=setInterval(()=>{b.textContent=cd+'s';cd--;if(cd<0){clearInterval(iv);b.disabled=false;b.textContent='获取验证码';}},1000);
  }catch(e){toast(e.message,'err');b.disabled=false;}
});

$('#authForm')?.addEventListener('submit',async e=>{
  e.preventDefault();const f=e.target;
  const body={email:f.email.value.trim(),pass:f.pass.value};
  if(STATE.mode==='register'){body.code=f.code.value.trim();body.workerCode=f.workerCode.value;}
  const btn=$('#authSubmit');btn.disabled=true;btn.innerHTML='<span class="spin"></span>';
  try{
    await api('POST', STATE.mode==='login'?'/api/auth/login':'/api/auth/register?role=worker', body);
    toast('成功','ok');setTimeout(()=>location.reload(),500);
  }catch(err){toast(err.message,'err');btn.disabled=false;btn.textContent=STATE.mode==='login'?'登录':'注册';}
});

$('#logoutBtn')?.addEventListener('click',async()=>{await api('POST','/api/auth/logout');location.reload();});
$('#refreshBtn')?.addEventListener('click',loadAll);

function typeBadge(id){const t=${JSON.stringify(API_TYPES)}.find(x=>x.id===id)||{icon:'❓',name:id};return '<span class="type-badge">'+t.icon+' '+esc(t.name)+'</span>';}
function statusPill(s){const m=${JSON.stringify(TICKET_STATUS)};const x=m[s]||m.open;return '<span class="t-status" style="color:'+x.color+'">'+x.dot+' '+x.name+'</span>';}

async function loadAll(){
  try{
    const d=await api('GET','/api/tickets/open');
    const newTickets=d.tickets||[];
    const prevCount=STATE.prevTicketCount||0;
    if(prevCount>0&&newTickets.length>prevCount){
      const newCount=newTickets.length-prevCount;
      notify('新工单','有 '+newCount+' 个新工单待接取');
    }
    STATE.prevTicketCount=newTickets.length;
    STATE.tickets=newTickets;renderList();
    loadStats();
  }catch(e){toast(e.message,'err');}
}
async function loadStats(){
  try{
    const d=await api('GET','/api/worker/stats');
    const s=d.stats||{};
    const box=$('#workerStats');if(!box)return;
    box.innerHTML='<div class="stat-card"><div class="stat-value">'+(s.total||0)+'</div><div class="stat-label">总接单</div></div>'
      +'<div class="stat-card"><div class="stat-value">'+(s.completed||0)+'</div><div class="stat-label">已完成</div></div>'
      +'<div class="stat-card"><div class="stat-value">'+(s.rated||0)+'</div><div class="stat-label">已评分</div></div>'
      +'<div class="stat-card"><div class="stat-value">'+(s.avg_rating?Number(s.avg_rating).toFixed(1):'-')+'</div><div class="stat-label">平均分</div></div>';
  }catch(e){}
}
function renderList(){
  const box=$('#ticketList');if(!box)return;
  let ts=STATE.tickets;
  if(STATE.view==='open')ts=ts.filter(t=>t.status==='open');
  else if(STATE.view==='claimed')ts=ts.filter(t=>t.status==='claimed');
  else if(STATE.view==='mine')ts=ts.filter(t=>t.worker_email && t.worker_email===STATE.user.email);
  if(!ts.length){box.innerHTML='<div class="empty"><div class="ic">📭</div><p>暂无工单</p></div>';return;}
  box.innerHTML=ts.map(t=>{
    let act='';
    if(t.status==='open')act='<button class="btn btn-primary" data-act="claim" data-id="'+t.id+'">立即接单</button>';
    else if(t.status==='claimed'){
      const mine=t.worker_email===STATE.user.email;
      if(mine)act='<button class="btn btn-primary" data-act="chat" data-id="'+t.id+'">💬 联系发单方</button>'
        +'<button class="btn btn-ghost" data-act="release" data-id="'+t.id+'">放弃</button>'
        +'<button class="btn btn-ghost" data-act="complete" data-id="'+t.id+'">完成</button>';
      else act='<span class="pill">已被他人接走</span>';
    }
    const u=t.user_email?'<span>👤 '+esc(t.user_email)+'</span>':'';
    const todesk=(t.status==='claimed'&&t.worker_email===STATE.user.email)?'<div class="card" style="padding:10px 12px;margin:8px 0;background:rgba(16,185,129,.08);border-color:rgba(16,185,129,.3)"><b>🖥️ ToDesk:</b> '+esc(t.todesk_code||'(未提供)')+'</div>':'';
    const err=t.error_msg?'<div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:8px;padding:8px 12px;margin:8px 0;font-size:.85rem;color:#fca5a5;white-space:pre-wrap">'+esc(t.error_msg)+'</div>':'';
    return '<div class="ticket"><div class="t-head">'+typeBadge(t.api_type)+statusPill(t.status)+'</div>'
      +'<h3 class="t-title">'+esc(t.title)+'</h3>'
      +'<p class="t-desc">'+esc(t.description)+'</p>'
      +err+todesk
      +'<div class="t-meta"><span>🕒 '+fmtRel(t.created_at)+'</span>'+u+'</div>'
      +'<div class="t-actions">'+act+'</div></div>';
  }).join('');
}
document.addEventListener('click',async e=>{
  const b=e.target.closest('[data-act]');if(!b)return;
  const id=+b.dataset.id,act=b.dataset.act;
  if(act==='chat'){
    // need full ticket for title
    const t=STATE.tickets.find(x=>x.id===id)||{title:'#'+id};
    openChat(id,t.title);return;
  }
  b.disabled=true;
  try{
    if(act==='claim'){await api('POST','/api/tickets/'+id+'/claim');toast('接单成功','ok');}
    else if(act==='release'){if(!confirm('放弃此工单？')){b.disabled=false;return;}await api('POST','/api/tickets/'+id+'/release');toast('已放弃','ok');}
    else if(act==='complete'){if(!confirm('确认标记完成？')){b.disabled=false;return;}await api('POST','/api/tickets/'+id+'/complete');toast('已完成','ok');}
    loadAll();
  }catch(err){toast(err.message,'err');b.disabled=false;}
});

function openChat(id,title){
  STATE.chatId=id;STATE.lastMsgId=0;
  $('#chatTitle').textContent='# '+id+(title?' · '+title:'');
  $('#chatBox').classList.add('show');$('#chatMsgs').innerHTML='';
  pollMsgs();STATE.poll=setInterval(pollMsgs,2000);
}
function closeChat(){STATE.chatId=null;if(STATE.poll){clearInterval(STATE.poll);STATE.poll=null;}$('#chatBox').classList.remove('show');}
$('#chatBack').onclick=closeChat;
async function pollMsgs(){
  if(!STATE.chatId)return;
  try{
    const d=await api('GET','/api/tickets/'+STATE.chatId+'/messages?after='+STATE.lastMsgId);
    (d.messages||[]).forEach(m=>{
      if(m.id<=STATE.lastMsgId)return;STATE.lastMsgId=m.id;
      const me=m.sender_id===STATE.user.id;
      const div=document.createElement('div');div.className='msg '+(me?'me':'them');
      div.innerHTML=esc(m.content)+'<span class="time">'+fmtRel(m.created_at)+'</span>';
      $('#chatMsgs').appendChild(div);
      if(!me)notify('新消息','#'+STATE.chatId+': '+m.content.substring(0,50));
    });
    if(d.messages&&d.messages.length)$('#chatMsgs').scrollTop=$('#chatMsgs').scrollHeight;
  }catch(e){}
}
$('#chatSend').onclick=sendMsg;
$('#chatInput').addEventListener('keydown',e=>{if(e.key==='Enter')sendMsg();});
async function sendMsg(){
  const inp=$('#chatInput'),v=inp.value.trim();if(!v||!STATE.chatId)return;inp.value='';
  try{await api('POST','/api/tickets/'+STATE.chatId+'/messages',{content:v});pollMsgs();}
  catch(e){toast(e.message,'err');inp.value=v;}
}

if(STATE.user){ loadAll(); setInterval(loadAll, 5000); }
</script>
</body></html>`;
}

// =============== main ===============
export default {
  async fetch(req, env){
    const url = new URL(req.url);
    const p = url.pathname;

    // CORS (none needed, same-origin)

    // ---- API ----
    if (p === '/api/auth/send-code' && req.method==='POST') return handleSendCode(req, env);
    if (p === '/api/auth/register' && req.method==='POST') {
      const role = url.searchParams.get('role') === 'worker' ? 'worker' : 'user';
      return handleRegister(req, env, role);
    }
    if (p === '/api/auth/login' && req.method==='POST') return handleLogin(req, env);
    if (p === '/api/auth/logout' && req.method==='POST') return handleLogout(req, env);

    if (p === '/api/tickets' && req.method==='POST') return handleCreateTicket(req, env);
    if (p === '/api/tickets/mine' && req.method==='GET') return handleListMyTickets(req, env);
    if (p === '/api/tickets/open' && req.method==='GET') return handleListOpenTickets(req, env);

    let m;
    if (m = p.match(/^\/api\/tickets\/(\d+)$/)) {
      if (req.method==='GET') return handleTicketDetail(req, env, +m[1]);
    }
    if (m = p.match(/^\/api\/tickets\/(\d+)\/(claim|complete|close|release)$/)) {
      if (req.method==='POST') return handleTicketAction(req, env, +m[1], m[2]);
    }
    if (m = p.match(/^\/api\/tickets\/(\d+)\/messages$/)) {
      if (req.method==='GET') return handleGetMsgs(req, env, +m[1], url.searchParams.get('after'));
      if (req.method==='POST') return handleSendMsg(req, env, +m[1]);
    }
    if (m = p.match(/^\/api\/tickets\/(\d+)\/rating$/)) {
      if (req.method==='POST') return handleRateTicket(req, env, +m[1]);
    }
    if (p === '/api/worker/stats' && req.method==='GET') return handleWorkerStats(req, env);
    if (p === '/api/health') return json({ok:true, ts:Date.now()});
    if (p === '/api/test' || p === '/api/test/') {
      return json({
        name: 'test',
        ok: true,
        message: 'API test endpoint - 这是一个测试 API',
        method: req.method,
        path: p,
        timestamp: new Date().toISOString(),
        server: 'WorkerDesk/3.1',
        params: Object.fromEntries(url.searchParams.entries()),
        headers: {
          'user-agent': req.headers.get('user-agent'),
          'cf-ipcountry': req.headers.get('cf-ipcountry'),
          'cf-connecting-ip': req.headers.get('cf-connecting-ip')
        }
      });
    }
    if (p.startsWith('/api/')) return json({error:'not found'},404);

    // ---- Pages ----
    const u = await session(req, env);
    // Default → /fd
    if (p === '/' || p === '/fd') {
      // If a worker somehow hits /, send them to /jd
      if (u && u.role === 'worker') return Response.redirect(ORIGIN+'/jd', 302);
      return new Response(renderUserPage(u), { headers:{'Content-Type':'text/html; charset=utf-8'} });
    }
    if (p === '/jd') {
      if (u && u.role === 'user') return Response.redirect(ORIGIN+'/fd', 302);
      return new Response(renderWorkerPage(u), { headers:{'Content-Type':'text/html; charset=utf-8'} });
    }

    // SPA fallback → /fd
    return Response.redirect(ORIGIN+'/fd', 302);
  }
};

--d48d6527c950c518d810efd427e833ca86bf6e2fc9b1cee277ab22bdbbcc--
