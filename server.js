const express = require('express');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

// Key 藏在环境变量里，前端看不到
const SUPABASE_URL = (process.env.SUPABASE_URL || '').trim();
const SUPABASE_KEY = (process.env.SUPABASE_KEY || '').trim();
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ══════════════════════════════════════════════════════════
// ══ 登录 & 权限系统 ══
// 三个角色：boss(老板，全权) / sales(业务员，只管贷款+收购车辆业务，
// 不碰财务) / finance(财务，能看全部数据，只能新增收支登记，不能改/删
// 任何东西，也不能碰贷款合同)。
// 账号现在存在数据库里（car_users），老板可以在"账号管理"页面自己增删改，
// 不用再改代码重新部署。下面这个 USERS_RAW 只是"初始种子账号"——
// 第一次启动、数据库里还没有 car_users 这个key时，会用它来建立最初的
// 三个账号；之后账号管理全部走数据库，改这个数组不会再生效。
// ══════════════════════════════════════════════════════════
const USERS_RAW = [
  { usernames: ['gui', 'boss'], password: 'gui',    role: 'boss',    displayName: '老板' },
  { usernames: ['caiwu'],       password: 'gui888', role: 'finance', displayName: '财务' },
  { usernames: ['yewu'],        password: 'yewu888', role: 'sales',   displayName: '业务员' },
];
const VALID_ROLES = ['boss', 'finance', 'sales'];

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  const parts = String(stored || '').split(':');
  if (parts.length !== 2) return false;
  const [salt, hash] = parts;
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(check, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
function genUserId() {
  return 'u' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

// USER_RECORDS：数据库里 car_users 这一整个数组的内存副本（含密码哈希，
// 从不下发给前端）。USERS：username -> record 的查找表，每次 USER_RECORDS
// 变化后调用 rebuildUserIndex() 重建。
let USER_RECORDS = [];
let USERS = new Map();
function rebuildUserIndex() {
  USERS = new Map();
  USER_RECORDS.forEach(rec => { (rec.usernames || []).forEach(name => USERS.set(name, rec)); });
}
async function persistUsers() {
  const { error } = await supabase.from('pawndata').upsert([{ key: 'car_users', value: USER_RECORDS }], { onConflict: 'key' });
  if (error) throw new Error('DB_WRITE_ERROR: ' + error.message);
}
async function initUsers() {
  try {
    const { data, error } = await supabase.from('pawndata').select('value').eq('key', 'car_users').maybeSingle();
    if (!error && data && Array.isArray(data.value) && data.value.length > 0) {
      USER_RECORDS = data.value;
      console.log(`  账号：已从数据库加载 ${USER_RECORDS.length} 个账号`);
    } else {
      USER_RECORDS = USERS_RAW.map(u => ({
        id: genUserId(), usernames: u.usernames.slice(), displayName: u.displayName,
        role: u.role, status: 'active', passwordHash: hashPassword(u.password), createdAt: new Date().toISOString()
      }));
      await persistUsers();
      console.log('  账号：数据库中未找到账号数据，已写入初始种子账号（gui/boss, caiwu, yewu）');
    }
  } catch (e) {
    console.error('  账号：初始化失败，使用内存种子账号兜底：', e.message);
    USER_RECORDS = USERS_RAW.map(u => ({
      id: genUserId(), usernames: u.usernames.slice(), displayName: u.displayName,
      role: u.role, status: 'active', passwordHash: hashPassword(u.password), createdAt: new Date().toISOString()
    }));
  }
  rebuildUserIndex();
}
function sanitizeUser(rec) {
  return { id: rec.id, username: rec.usernames[0], usernames: rec.usernames, displayName: rec.displayName, role: rec.role, status: rec.status, createdAt: rec.createdAt };
}
function activeBossCount() {
  return USER_RECORDS.filter(r => r.role === 'boss' && r.status === 'active').length;
}
function invalidateSessionsFor(usernames) {
  sessions.forEach((sess, token) => { if (usernames.indexOf(sess.username) !== -1) sessions.delete(token); });
}

const sessions = new Map(); // token -> {username, role, displayName, ts}
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12小时不操作就要求重新登录

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const sess = sessions.get(token);
  if (!sess || (Date.now() - sess.ts) > SESSION_TTL_MS) {
    sessions.delete(token);
    return res.status(401).json({ error: 'UNAUTHORIZED', message: '请重新登录' });
  }
  sess.ts = Date.now(); // 续期
  req.user = sess;
  next();
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const rec = USERS.get(String(username || '').trim());
  if (!rec || !verifyPassword(String(password || ''), rec.passwordHash)) {
    return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: '用户名或密码错误' });
  }
  if (rec.status !== 'active') {
    return res.status(401).json({ error: 'ACCOUNT_DISABLED', message: '此账号已被禁用，请联系管理员' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { username: String(username).trim(), role: rec.role, displayName: rec.displayName, ts: Date.now() });
  res.json({ ok: true, token, role: rec.role, displayName: rec.displayName, username: String(username).trim() });
});

app.post('/api/logout', auth, (req, res) => {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ ok: true, username: req.user.username, role: req.user.role, displayName: req.user.displayName });
});

// ══ 账号管理（老板专属：自己新增/改角色/重置密码/启用禁用/删除员工账号）══
function requireBoss(req, res) {
  if (req.user.role !== 'boss') { res.status(403).json({ error: 'PERMISSION_DENIED', message: '只有老板能管理账号' }); return false; }
  return true;
}
app.get('/api/users', auth, (req, res) => {
  if (!requireBoss(req, res)) return;
  res.json({ ok: true, users: USER_RECORDS.map(sanitizeUser) });
});
app.post('/api/users', auth, async (req, res) => {
  if (!requireBoss(req, res)) return;
  try {
    const username = String((req.body || {}).username || '').trim();
    const displayName = String((req.body || {}).displayName || '').trim() || username;
    const role = String((req.body || {}).role || '').trim();
    const password = String((req.body || {}).password || '');
    if (!username) return res.status(400).json({ error: 'BAD_INPUT', message: '请输入用户名' });
    if (VALID_ROLES.indexOf(role) === -1) return res.status(400).json({ error: 'BAD_INPUT', message: '角色不合法' });
    if (password.length < 4) return res.status(400).json({ error: 'BAD_INPUT', message: '密码至少需要4位' });
    const lower = username.toLowerCase();
    const dup = USER_RECORDS.some(r => (r.usernames || []).some(n => n.toLowerCase() === lower));
    if (dup) return res.status(400).json({ error: 'DUP_USERNAME', message: '这个用户名已经被使用了' });
    const rec = { id: genUserId(), usernames: [username], displayName, role, status: 'active', passwordHash: hashPassword(password), createdAt: new Date().toISOString() };
    USER_RECORDS.push(rec);
    await persistUsers();
    rebuildUserIndex();
    res.json({ ok: true, user: sanitizeUser(rec) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/users/:id/reset-password', auth, async (req, res) => {
  if (!requireBoss(req, res)) return;
  try {
    const rec = USER_RECORDS.find(r => r.id === req.params.id);
    if (!rec) return res.status(404).json({ error: 'NOT_FOUND', message: '账号不存在' });
    const password = String((req.body || {}).password || '');
    if (password.length < 4) return res.status(400).json({ error: 'BAD_INPUT', message: '密码至少需要4位' });
    rec.passwordHash = hashPassword(password);
    await persistUsers();
    rebuildUserIndex();
    invalidateSessionsFor(rec.usernames);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/users/:id/update', auth, async (req, res) => {
  if (!requireBoss(req, res)) return;
  try {
    const rec = USER_RECORDS.find(r => r.id === req.params.id);
    if (!rec) return res.status(404).json({ error: 'NOT_FOUND', message: '账号不存在' });
    const body = req.body || {};
    const isSelf = (rec.usernames || []).indexOf(req.user.username) !== -1;
    if (body.role !== undefined) {
      const role = String(body.role).trim();
      if (VALID_ROLES.indexOf(role) === -1) return res.status(400).json({ error: 'BAD_INPUT', message: '角色不合法' });
      if (isSelf && role !== 'boss') return res.status(400).json({ error: 'SELF_LOCK', message: '不能把自己正在登录的老板账号改成别的角色，请用另一个老板账号操作' });
      if (rec.role === 'boss' && role !== 'boss' && rec.status === 'active' && activeBossCount() <= 1) {
        return res.status(400).json({ error: 'LAST_BOSS', message: '系统至少要保留一个启用中的老板账号' });
      }
      rec.role = role;
    }
    if (body.status !== undefined) {
      const status = String(body.status).trim();
      if (['active', 'disabled'].indexOf(status) === -1) return res.status(400).json({ error: 'BAD_INPUT', message: '状态不合法' });
      if (isSelf && status === 'disabled') return res.status(400).json({ error: 'SELF_LOCK', message: '不能禁用自己正在登录的账号' });
      if (rec.role === 'boss' && status === 'disabled' && activeBossCount() <= 1) {
        return res.status(400).json({ error: 'LAST_BOSS', message: '系统至少要保留一个启用中的老板账号' });
      }
      rec.status = status;
    }
    if (body.displayName !== undefined) {
      const dn = String(body.displayName).trim();
      if (dn) rec.displayName = dn;
    }
    await persistUsers();
    rebuildUserIndex();
    if (body.role !== undefined || body.status !== undefined) invalidateSessionsFor(rec.usernames);
    res.json({ ok: true, user: sanitizeUser(rec) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/users/:id', auth, async (req, res) => {
  if (!requireBoss(req, res)) return;
  try {
    const rec = USER_RECORDS.find(r => r.id === req.params.id);
    if (!rec) return res.status(404).json({ error: 'NOT_FOUND', message: '账号不存在' });
    const isSelf = (rec.usernames || []).indexOf(req.user.username) !== -1;
    if (isSelf) return res.status(400).json({ error: 'SELF_LOCK', message: '不能删除自己正在登录的账号' });
    if (rec.role === 'boss' && rec.status === 'active' && activeBossCount() <= 1) {
      return res.status(400).json({ error: 'LAST_BOSS', message: '系统至少要保留一个启用中的老板账号' });
    }
    USER_RECORDS = USER_RECORDS.filter(r => r.id !== rec.id);
    await persistUsers();
    rebuildUserIndex();
    invalidateSessionsFor(rec.usernames);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══ 每个角色对 car_loans / car_finance 两个数组的权限 ══
// add: 能不能新增记录；edit: 能不能改已有记录；del: 能不能删除已有记录
// sales 的 car_finance.add 是特例：只允许新增"收购车辆销售利润"这一类记录
// （卖收购车自动生成的那笔流水），因为这属于业务员的收购车辆业务本身，
// 不算"碰财务"；其他财务记录一律不能碰。
const ROLE_PERMS = {
  boss:    { car_loans: { add: true,  edit: true,  del: true  }, car_finance: { add: true,               edit: true,  del: true  } },
  sales:   { car_loans: { add: true,  edit: true,  del: false }, car_finance: { add: 'acquired_sale_only', edit: false, del: false } },
  finance: { car_loans: { add: false, edit: false, del: false }, car_finance: { add: 'no_settlement',    edit: false, del: false } },
};

function diffById(oldArr, newArr) {
  oldArr = Array.isArray(oldArr) ? oldArr : [];
  newArr = Array.isArray(newArr) ? newArr : [];
  const oldMap = new Map(oldArr.map(x => [x.id, x]));
  const newMap = new Map(newArr.map(x => [x.id, x]));
  const added = [], edited = [], removed = [];
  newMap.forEach((item, id) => {
    if (!oldMap.has(id)) added.push(item);
    else if (JSON.stringify(oldMap.get(id)) !== JSON.stringify(item)) edited.push(item);
  });
  oldMap.forEach((item, id) => { if (!newMap.has(id)) removed.push(item); });
  return { added, edited, removed };
}

function checkKeyPermission(role, key, newValue, currentData) {
  const perm = (ROLE_PERMS[role] || {})[key];
  if (!perm) return { ok: false, reason: `角色无权修改 ${key}` };
  if (perm.add === true && perm.edit === true && perm.del === true) return { ok: true }; // 老板全权，跳过diff，省点计算
  const oldArr = currentData[key] || [];
  const { added, edited, removed } = diffById(oldArr, newValue);
  if (removed.length > 0 && !perm.del) return { ok: false, reason: '无权删除记录' };
  if (edited.length > 0 && !perm.edit) return { ok: false, reason: '无权修改已有记录' };
  if (added.length > 0) {
    if (perm.add === true) { /* 允许 */ }
    else if (perm.add === 'acquired_sale_only') {
      const bad = added.find(r => r.category !== '收购车辆销售利润');
      if (bad) return { ok: false, reason: '业务员只能新增"收购车辆销售利润"这一类财务记录' };
    } else if (perm.add === 'no_settlement') {
      const bad = added.find(r => r.type === 'settlement');
      if (bad) return { ok: false, reason: '只有老板能确认提取历史利润' };
    } else {
      return { ok: false, reason: '无权新增记录' };
    }
  }
  return { ok: true };
}

function getInitData() {
  return {
    car_loans: [],
    car_finance: [],
    car_nextId: 1
  };
}

async function loadData() {
  const { data, error } = await supabase.from('pawndata').select('key, value')
    .in('key', ['car_loans', 'car_finance', 'car_nextId']);
  if (error) throw new Error('DB_READ_ERROR: ' + error.message);
  const result = {};
  if (data) data.forEach(row => { result[row.key] = row.value; });
  const init = getInitData();
  Object.keys(init).forEach(k => { if (result[k] === undefined) result[k] = init[k]; });
  return result;
}

// 读取所有数据（业务员看不到财务记录）
app.get('/api/data', auth, async (req, res) => {
  try {
    const data = await loadData();
    if (!Array.isArray(data.car_loans)) data.car_loans = [];
    if (!Array.isArray(data.car_finance)) data.car_finance = [];
    if (!data.car_nextId) data.car_nextId = 1;
    if (req.user.role === 'sales') {
      data.car_finance = []; // 业务员只管业务，财务数据服务器直接不下发
    }
    res.json(data);
  } catch(e) {
    res.status(500).json({ error: 'DB_ERROR', message: e.message });
  }
});

// 保存数据（按角色核对每个字段的增/改/删权限）
app.post('/api/data', auth, async (req, res) => {
  try {
    const body = req.body;
    const allowed = ['car_loans', 'car_finance', 'car_nextId'];
    const keys = Object.keys(body).filter(k => allowed.includes(k));
    if (keys.length === 0) return res.json({ ok: true });

    let current = null;
    if (keys.includes('car_loans') || keys.includes('car_finance')) {
      current = await loadData();
    }
    for (const key of keys) {
      if (key === 'car_nextId') {
        if (req.user.role === 'finance') return res.status(403).json({ error: 'PERMISSION_DENIED', message: '财务无权修改此数据' });
        continue;
      }
      const check = checkKeyPermission(req.user.role, key, body[key], current);
      if (!check.ok) return res.status(403).json({ error: 'PERMISSION_DENIED', message: check.reason });
    }

    const rows = keys.map(key => ({ key, value: body[key] }));
    const { error } = await supabase.from('pawndata').upsert(rows, { onConflict: 'key' });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// 测试连接
app.get('/api/test', async (req, res) => {
  try {
    const { data, error } = await supabase.from('pawndata').select('key').limit(1);
    if (error) return res.json({ ok: false, message: error.message });
    res.json({ ok: true, message: '数据库连接正常' });
  } catch(e) {
    res.json({ ok: false, message: e.message });
  }
});

// 备份数据（只有老板能导出全量原始数据）
app.get('/api/backup', auth, async (req, res) => {
  try {
    if (req.user.role !== 'boss') return res.status(403).json({ error: 'PERMISSION_DENIED', message: '只有老板能导出全量备份' });
    const data = await loadData();
    res.setHeader('Content-Disposition', `attachment; filename="car_backup_${new Date().toISOString().slice(0,10)}.json"`);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(data, null, 2));
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

initUsers().finally(() => {
  app.listen(PORT, () => {
    console.log(`\n${'═'.repeat(50)}`);
    console.log(`  🚗 MORODOK 汽车抵押贷款管理系统`);
    console.log(`${'═'.repeat(50)}`);
    console.log(`  访问地址: http://localhost:${PORT}`);
    console.log(`${'═'.repeat(50)}\n`);
  });
});
