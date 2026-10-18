/**
 * Jinletian 个人站 · 留言板后端（Val Town 版，单文件 val）
 * 用法：注册 val.town → New Val（起名如 jinletian-board）→ 全选粘贴本文件 → 保存即部署
 * 存储：Val Town SQLite（用户/会话/留言）+ Val Town Blob（图片，免费共 10MB）
 * 安全：PBKDF2-SHA256 10 万迭代密码哈希；opaque token 30 天可撤销；CORS 仅放行网站域名
 * 免费额度：10 万次运行/天 + SQLite/Blob 共 10MB（个人留言板绰绰有余）
 */
import { sqlite } from "https://esm.town/v/std/sqlite/main.ts";
import { blob } from "https://esm.town/v/std/blob/main.ts";

/* ================= 适配器（Val Town std → 统一接口） ================= */
const db = {
  exec: (sql) => sqlite.execute(sql),
  all: async (sql, args = []) => (await sqlite.execute({ sql, args })).rows,
  run: async (sql, args = []) => { await sqlite.execute({ sql, args }); }
};
const store = {
  async set(key, bytes) { await blob.set(key, bytes); },
  async get(key) {
    try {
      const r = await blob.get(key);
      return new Uint8Array(await r.arrayBuffer());
    } catch (e) { return null; }
  },
  async del(key) { try { await blob.delete(key); } catch (e) {} }
};

/* ================= 工具 ================= */
const TOKEN_TTL = 30 * 24 * 3600 * 1000;
const IMG_LIMIT = 80 * 1024;     // 留言图片 80KB（Val Town 免费存储共 10MB）
const AVATAR_LIMIT = 40 * 1024;  // 头像 40KB
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const enc = new TextEncoder();

function b64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function randomId() {
  return [...crypto.getRandomValues(new Uint8Array(16))]
    .map(x => x.toString(16).padStart(2, '0')).join('');
}
async function hashPassword(password, saltB64) {
  const salt = saltB64 ? b64ToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  let s1 = '', s2 = '';
  for (const b of salt) s1 += String.fromCharCode(b);
  for (const b of new Uint8Array(bits)) s2 += String.fromCharCode(b);
  return { salt: btoa(s1), hash: btoa(s2) };
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
const publicUser = u => ({ email: u.email, nickname: u.nickname, avatar: u.avatar || '', createdAt: u.created_at });
const publicMsg = m => ({ id: m.id, nickname: m.nickname, avatar: m.avatar || '',
  content: m.content, img: m.img || '', createdAt: m.created_at, own: !!m.own });

/* ================= 建表（首次请求自动执行） ================= */
let schemaReady = false;
async function ensureSchema() {
  if (schemaReady) return;
  await db.exec(`create table if not exists users(
    uid text primary key, email text unique not null, salt text not null, hash text not null,
    nickname text not null, avatar text default '', created_at integer not null)`);
  await db.exec(`create table if not exists tokens(
    token text primary key, uid text not null, email text not null, exp integer not null)`);
  await db.exec(`create table if not exists messages(
    id text primary key, uid text not null, nickname text not null, avatar text default '',
    content text default '', img text default '', created_at integer not null)`);
  await db.exec(`create index if not exists idx_msg_created on messages(created_at desc)`);
  schemaReady = true;
}
async function saveImage(dataB64) {
  const bytes = b64ToBytes(dataB64);
  const id = randomId();
  await store.set('img:' + id, bytes);
  return id;
}

/* ================= 路由 ================= */
const ALLOWED_ORIGINS = [
  'https://jinletian.github.io',
  'http://localhost:8787', 'http://127.0.0.1:8787',
  'http://localhost:3000', 'http://127.0.0.1:3000'
];

const routes = [];

routes.push({ m: 'GET', re: /^\/api\/health$/, fn: async (req, ctx) => ctx.json({ ok: true, ts: Date.now() }) });

routes.push({ m: 'POST', re: /^\/api\/register$/, fn: async (req, ctx) => {
  const body = await req.json().catch(() => null);
  const email = String(body?.email || '').trim().toLowerCase();
  const password = String(body?.password || '');
  const nickname = String(body?.nickname || '').trim().slice(0, 20);
  if (!emailRe.test(email)) return ctx.json({ error: '邮箱格式不正确' }, 400);
  if (password.length < 6) return ctx.json({ error: '密码至少 6 位' }, 400);
  if (!nickname) return ctx.json({ error: '请填写昵称' }, 400);
  const exist = await ctx.db.all('select uid from users where email = ?', [email]);
  if (exist.length) return ctx.json({ error: '该邮箱已注册，请直接登录' }, 409);
  let avatar = '';
  if (body?.avatarData) {
    if (b64ToBytes(String(body.avatarData)).length > AVATAR_LIMIT) {
      return ctx.json({ error: '头像过大（上限 40KB）' }, 400);
    }
    avatar = await saveImage(String(body.avatarData));
  }
  const { salt, hash } = await hashPassword(password);
  const uid = randomId();
  await ctx.db.run('insert into users(uid,email,salt,hash,nickname,avatar,created_at) values(?,?,?,?,?,?,?)',
    [uid, email, salt, hash, nickname, avatar, Date.now()]);
  const token = await ctx.issue({ uid, email });
  const user = { email, nickname, avatar, created_at: Date.now() };
  return ctx.json({ token, user });
}});

routes.push({ m: 'POST', re: /^\/api\/login$/, fn: async (req, ctx) => {
  const body = await req.json().catch(() => null);
  const email = String(body?.email || '').trim().toLowerCase();
  const password = String(body?.password || '');
  if (!email || !password) return ctx.json({ error: '请输入邮箱和密码' }, 400);
  const rows = await ctx.db.all('select * from users where email = ?', [email]);
  if (!rows.length) return ctx.json({ error: '邮箱或密码不正确' }, 401);
  const u = rows[0];
  const { hash } = await hashPassword(password, u.salt);
  if (!safeEqual(hash, u.hash)) return ctx.json({ error: '邮箱或密码不正确' }, 401);
  const token = await ctx.issue({ uid: u.uid, email: u.email });
  return ctx.json({ token, user: publicUser(u) });
}});

routes.push({ m: 'GET', re: /^\/api\/me$/, auth: true, fn: async (req, ctx) => {
  const rows = await ctx.db.all('select * from users where email = ?', [ctx.user.email]);
  if (!rows.length) return ctx.json({ error: '账号异常，请重新登录' }, 404);
  return ctx.json({ user: publicUser(rows[0]) });
}});

routes.push({ m: 'PATCH', re: /^\/api\/me$/, auth: true, fn: async (req, ctx) => {
  const rows = await ctx.db.all('select * from users where email = ?', [ctx.user.email]);
  if (!rows.length) return ctx.json({ error: '账号异常，请重新登录' }, 404);
  const u = rows[0];
  const body = await req.json().catch(() => null);
  const nick = String(body?.nickname || '').trim().slice(0, 20);
  if (nick) { u.nickname = nick; }
  if (body?.avatarData) {
    if (b64ToBytes(String(body.avatarData)).length > AVATAR_LIMIT) {
      return ctx.json({ error: '头像过大（上限 40KB）' }, 400);
    }
    u.avatar = await saveImage(String(body.avatarData));
  }
  await ctx.db.run('update users set nickname = ?, avatar = ? where uid = ?', [u.nickname, u.avatar, u.uid]);
  return ctx.json({ user: publicUser(u) });
}});

routes.push({ m: 'DELETE', re: /^\/api\/session$/, auth: true, fn: async (req, ctx) => {
  await ctx.db.run('delete from tokens where token = ?', [ctx.token]);
  return ctx.json({ ok: true });
}});

routes.push({ m: 'GET', re: /^\/api\/messages$/, optionalAuth: true, fn: async (req, ctx) => {
  const rows = await ctx.db.all(
    'select * from messages order by created_at desc limit 100', []);
  const messages = rows.map(m => publicMsg({ ...m, own: !!ctx.user && m.uid === ctx.user.uid }));
  return ctx.json({ messages, total: messages.length });
}});

routes.push({ m: 'POST', re: /^\/api\/messages$/, auth: true, fn: async (req, ctx) => {
  const body = await req.json().catch(() => null);
  const content = String(body?.content || '').trim().slice(0, 500);
  const imgData = body?.imgData ? String(body.imgData) : '';
  if (!content && !imgData) return ctx.json({ error: '内容不能为空' }, 400);
  const urows = await ctx.db.all('select * from users where email = ?', [ctx.user.email]);
  if (!urows.length) return ctx.json({ error: '账号异常，请重新登录' }, 404);
  const u = urows[0];
  let img = '';
  if (imgData) {
    if (b64ToBytes(imgData).length > IMG_LIMIT) return ctx.json({ error: '图片过大（上限 80KB）' }, 400);
    img = await saveImage(imgData);
  }
  const ts = Date.now();
  const id = randomId();
  await ctx.db.run('insert into messages(id,uid,nickname,avatar,content,img,created_at) values(?,?,?,?,?,?,?)',
    [id, u.uid, u.nickname, u.avatar || '', content, img, ts]);
  return ctx.json({ message: { id, nickname: u.nickname, avatar: u.avatar || '', content, img, createdAt: ts, own: true } });
}});

routes.push({ m: 'DELETE', re: /^\/api\/messages\/([0-9a-f]{32})$/, auth: true, fn: async (req, ctx) => {
  const id = ctx.params[0];
  const rows = await ctx.db.all('select * from messages where id = ?', [id]);
  if (!rows.length) return ctx.json({ error: '留言不存在或已删除' }, 404);
  if (rows[0].uid !== ctx.user.uid) return ctx.json({ error: '只能删除自己的留言' }, 403);
  await ctx.db.run('delete from messages where id = ?', [id]);
  return ctx.json({ ok: true });
}});

routes.push({ m: 'GET', re: /^\/api\/img\/([0-9a-f]{32})$/, fn: async (req, ctx) => {
  const bytes = await ctx.store.get('img:' + ctx.params[0]);
  if (!bytes) return new Response('Not Found', { status: 404, headers: ctx.cors });
  return new Response(bytes, { status: 200, headers: {
    'Content-Type': 'image/webp',
    'Cache-Control': 'public, max-age=31536000, immutable',
    ...ctx.cors
  } });
}});

/* ================= 入口 ================= */
async function issue(user) {
  const token = randomId() + randomId();
  await db.run('insert into tokens(token,uid,email,exp) values(?,?,?,?)',
    [token, user.uid, user.email, Date.now() + TOKEN_TTL]);
  return token;
}

export default async function handler(req) {
  const url = new URL(req.url);
  const origin = req.headers.get('Origin') || '';
  const cors = ALLOWED_ORIGINS.includes(origin)
    ? {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Vary': 'Origin'
      }
    : {};
  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
  });
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  try {
    await ensureSchema();
    const route = routes.find(r => r.m === req.method && r.re.test(url.pathname));
    if (!route) return json({ error: 'Not Found' }, 404);

    const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
    let user = null;
    if (token) {
      const rows = await db.all('select * from tokens where token = ?', [token]);
      if (rows.length && rows[0].exp > Date.now()) user = { uid: rows[0].uid, email: rows[0].email };
      else if (rows.length) await db.run('delete from tokens where token = ?', [token]);
    }
    if (route.auth && !user) return json({ error: '未登录或登录已过期' }, 401);

    const ctx = {
      db, store, json, cors, token, user,
      params: (url.pathname.match(route.re) || []).slice(1),
      issue
    };
    return await route.fn(req, ctx);
  } catch (e) {
    console.error('API error:', e);
    const msg = String(e && e.message || e);
    if (/storage|quota|exceed/i.test(msg)) {
      return json({ error: '存储空间已满（免费额度 10MB），请联系站长清理' }, 507);
    }
    return json({ error: '服务器内部错误' }, 500);
  }
}
