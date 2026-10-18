/**
 * Jinletian 个人站 · 留言板后端（零依赖，原生 fetch handler）
 * 生产：Deno Deploy（Deno KV 全局数据库）  测试：Node 原生 http 转接 + 内存 KV
 *  - 密码 PBKDF2-SHA256 10 万迭代（Web Crypto）
 *  - 会话 opaque token（64 hex）存 KV，30 天，可服务端撤销
 *  - KV key：user:<email> / tok:<token> / msg:<倒序时间>:<id> / img:<id>
 *  - 图片 base64 内联上传（留言 ≤100KB、头像 ≤60KB），/api/img/<id> 公开输出
 *  - CORS 仅放行 https://jinletian.github.io（+ 本地测试源）
 *  - 人人可见：GET /api/messages 公开；仅作者可删自己的留言
 */

/* ---------------- KV 抽象 ---------------- */
let kvInstance = null;

function createMemoryKV() {
  const m = new Map();
  return {
    async get(key) {
      return m.has(key) ? { key, value: m.get(key), versionstamp: 'mem' }
                        : { key, value: null, versionstamp: null };
    },
    async set(key, value) { m.set(key, value); },
    async delete(key) { m.delete(key); },
    list(prefix) {
      const out = [];
      for (const [k, v] of m) if (k.startsWith(prefix)) out.push({ key: k, value: v });
      out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
      return out;
    }
  };
}

export async function getKV() {
  if (kvInstance) return kvInstance;
  // @ts-ignore Deno 全局（仅 Deno Deploy 存在）
  if (typeof Deno !== 'undefined' && Deno.openKv) kvInstance = await Deno.openKv();
  else kvInstance = createMemoryKV();
  return kvInstance;
}

/* ---------------- 工具 ---------------- */
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const TOKEN_TTL = 30 * 24 * 3600 * 1000;
const IMG_LIMIT = 100 * 1024;
const AVATAR_LIMIT = 60 * 1024;
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const enc = new TextEncoder();

function b64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
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
  return { salt: bytesToB64(salt), hash: bytesToB64(new Uint8Array(bits)) };
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function issueToken(kv, user) {
  const token = randomId() + randomId();
  await kv.set('tok:' + token, { uid: user.uid, email: user.email, exp: Date.now() + TOKEN_TTL });
  return token;
}
function publicUser(u) {
  return { email: u.email, nickname: u.nickname, avatar: u.avatar || '', createdAt: u.createdAt };
}
function publicMsg(m, own) {
  return { id: m.id, nickname: m.nickname, avatar: m.avatar || '', content: m.content,
           img: m.img || '', createdAt: m.createdAt, own: !!own };
}
const msgKey = (ts, id) => 'msg:' + String(MAX_SAFE - ts).padStart(16, '0') + ':' + id;

async function saveImage(kv, data, type) {
  const id = randomId();
  await kv.set('img:' + id, { data, type: type || 'image/webp', createdAt: Date.now() });
  return id;
}

/* ---------------- 路由处理 ---------------- */
const api = {};

api.health = async (req, ctx) => ctx.json({ ok: true, ts: Date.now() });

api.register = async (req, ctx) => {
  const body = await req.json().catch(() => null);
  const email = String(body?.email || '').trim().toLowerCase();
  const password = String(body?.password || '');
  const nickname = String(body?.nickname || '').trim().slice(0, 20);
  if (!emailRe.test(email)) return ctx.json({ error: '邮箱格式不正确' }, 400);
  if (password.length < 6) return ctx.json({ error: '密码至少 6 位' }, 400);
  if (!nickname) return ctx.json({ error: '请填写昵称' }, 400);
  const kv = ctx.kv;
  if ((await kv.get('user:' + email)).value) return ctx.json({ error: '该邮箱已注册，请直接登录' }, 409);
  let avatar = '';
  if (body?.avatarData) {
    if (b64ToBytes(String(body.avatarData)).length > AVATAR_LIMIT) {
      return ctx.json({ error: '头像过大（上限 60KB）' }, 400);
    }
    avatar = await saveImage(kv, String(body.avatarData), String(body.avatarType || 'image/webp'));
  }
  const { salt, hash } = await hashPassword(password);
  const user = { uid: randomId(), email, salt, hash, nickname, avatar, createdAt: Date.now() };
  await kv.set('user:' + email, user);
  const token = await issueToken(kv, user);
  return ctx.json({ token, user: publicUser(user) });
};

api.login = async (req, ctx) => {
  const body = await req.json().catch(() => null);
  const email = String(body?.email || '').trim().toLowerCase();
  const password = String(body?.password || '');
  if (!email || !password) return ctx.json({ error: '请输入邮箱和密码' }, 400);
  const kv = ctx.kv;
  const user = (await kv.get('user:' + email)).value;
  if (!user) return ctx.json({ error: '邮箱或密码不正确' }, 401);
  const { hash } = await hashPassword(password, user.salt);
  if (!safeEqual(hash, user.hash)) return ctx.json({ error: '邮箱或密码不正确' }, 401);
  const token = await issueToken(kv, user);
  return ctx.json({ token, user: publicUser(user) });
};

api.me = async (req, ctx) => {
  const kv = ctx.kv;
  const user = (await kv.get('user:' + ctx.user.email)).value;
  if (!user) return ctx.json({ error: '账号异常，请重新登录' }, 404);
  return ctx.json({ user: publicUser(user) });
};

api.patchMe = async (req, ctx) => {
  const kv = ctx.kv;
  const user = (await kv.get('user:' + ctx.user.email)).value;
  if (!user) return ctx.json({ error: '账号异常，请重新登录' }, 404);
  const body = await req.json().catch(() => null);
  const nick = String(body?.nickname || '').trim().slice(0, 20);
  if (nick) user.nickname = nick;
  if (body?.avatarData) {
    if (b64ToBytes(String(body.avatarData)).length > AVATAR_LIMIT) {
      return ctx.json({ error: '头像过大（上限 60KB）' }, 400);
    }
    user.avatar = await saveImage(kv, String(body.avatarData), String(body.avatarType || 'image/webp'));
  }
  await kv.set('user:' + user.email, user);
  return ctx.json({ user: publicUser(user) });
};

api.logout = async (req, ctx) => {
  await ctx.kv.delete('tok:' + ctx.token);
  return ctx.json({ ok: true });
};

api.messages = async (req, ctx) => {
  const arr = [];
  for await (const e of ctx.kv.list('msg:')) {
    arr.push(publicMsg(e.value, ctx.user && e.value.uid === ctx.user.uid));
    if (arr.length >= 100) break;
  }
  return ctx.json({ messages: arr, total: arr.length });
};

api.postMessage = async (req, ctx) => {
  const body = await req.json().catch(() => null);
  const content = String(body?.content || '').trim().slice(0, 500);
  const imgData = body?.imgData ? String(body.imgData) : '';
  if (!content && !imgData) return ctx.json({ error: '内容不能为空' }, 400);
  if (imgData && imgData.length > IMG_LIMIT * 1.4) return ctx.json({ error: '图片过大（上限 100KB）' }, 400);
  const kv = ctx.kv;
  const user = (await kv.get('user:' + ctx.user.email)).value;
  if (!user) return ctx.json({ error: '账号异常，请重新登录' }, 404);
  let img = '';
  if (imgData) img = await saveImage(kv, imgData, String(body?.imgType || 'image/webp'));
  const ts = Date.now();
  const msg = { id: randomId(), uid: user.uid, nickname: user.nickname,
                avatar: user.avatar || '', content, img, createdAt: ts };
  await kv.set(msgKey(ts, msg.id), msg);
  return ctx.json({ message: publicMsg(msg, true) });
};

api.deleteMessage = async (req, ctx) => {
  const id = ctx.params[0];
  let target = null;
  for await (const e of ctx.kv.list('msg:')) {
    if (e.value.id === id) { target = e; break; }
  }
  if (!target) return ctx.json({ error: '留言不存在或已删除' }, 404);
  if (target.value.uid !== ctx.user.uid) return ctx.json({ error: '只能删除自己的留言' }, 403);
  await ctx.kv.delete(target.key);
  return ctx.json({ ok: true });
};

api.img = async (req, ctx) => {
  const img = (await ctx.kv.get('img:' + ctx.params[0])).value;
  if (!img) return new Response('Not Found', { status: 404, headers: ctx.cors });
  return new Response(b64ToBytes(img.data), {
    status: 200,
    headers: {
      'Content-Type': img.type || 'image/webp',
      'Cache-Control': 'public, max-age=31536000, immutable',
      ...ctx.cors
    }
  });
};

/* ---------------- 路由表 ---------------- */
const ROUTES = [
  { m: 'GET',    re: /^\/api\/health$/,                   fn: api.health },
  { m: 'POST',   re: /^\/api\/register$/,                 fn: api.register },
  { m: 'POST',   re: /^\/api\/login$/,                    fn: api.login },
  { m: 'GET',    re: /^\/api\/me$/,                       fn: api.me,        auth: true },
  { m: 'PATCH',  re: /^\/api\/me$/,                       fn: api.patchMe,   auth: true },
  { m: 'DELETE', re: /^\/api\/session$/,                  fn: api.logout,    auth: true },
  { m: 'GET',    re: /^\/api\/messages$/,                 fn: api.messages,  optionalAuth: true },
  { m: 'POST',   re: /^\/api\/messages$/,                 fn: api.postMessage, auth: true },
  { m: 'DELETE', re: /^\/api\/messages\/([0-9a-f]{32})$/, fn: api.deleteMessage, auth: true },
  { m: 'GET',    re: /^\/api\/img\/([0-9a-f]{32})$/,      fn: api.img }
];

const ALLOWED_ORIGINS = [
  'https://jinletian.github.io',
  'http://localhost:8787', 'http://127.0.0.1:8787',
  'http://localhost:3000', 'http://127.0.0.1:3000'
];

/* ---------------- 入口 ---------------- */
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

  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
  });

  const route = ROUTES.find(r => r.m === req.method && r.re.test(url.pathname));
  if (!route) return json({ error: 'Not Found' }, 404);

  const kv = await getKV();
  const ctx = { kv, json, cors, params: (url.pathname.match(route.re) || []).slice(1), user: null, token: '' };

  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (route.auth || route.optionalAuth) {
    if (token) {
      const t = (await kv.get('tok:' + token)).value;
      if (t && t.exp > Date.now()) ctx.user = { uid: t.uid, email: t.email };
    }
    if (route.auth && !ctx.user) return json({ error: '未登录或登录已过期' }, 401);
    ctx.token = token;
  }

  try {
    return await route.fn(req, ctx);
  } catch (e) {
    console.error('API error:', e);
    return json({ error: '服务器内部错误' }, 500);
  }
}
