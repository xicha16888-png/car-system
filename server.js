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
    await logAccountChange(req.user, 'add', displayName + '（' + username + '）', '新增账号，角色：' + role);
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
    await logAccountChange(req.user, 'edit', rec.displayName + '（' + rec.usernames[0] + '）', '重置了密码');
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
    const changeNotes = [];
    if (body.role !== undefined) {
      const role = String(body.role).trim();
      if (VALID_ROLES.indexOf(role) === -1) return res.status(400).json({ error: 'BAD_INPUT', message: '角色不合法' });
      if (isSelf && role !== 'boss') return res.status(400).json({ error: 'SELF_LOCK', message: '不能把自己正在登录的老板账号改成别的角色，请用另一个老板账号操作' });
      if (rec.role === 'boss' && role !== 'boss' && rec.status === 'active' && activeBossCount() <= 1) {
        return res.status(400).json({ error: 'LAST_BOSS', message: '系统至少要保留一个启用中的老板账号' });
      }
      if (role !== rec.role) changeNotes.push('角色改为' + role);
      rec.role = role;
    }
    if (body.status !== undefined) {
      const status = String(body.status).trim();
      if (['active', 'disabled'].indexOf(status) === -1) return res.status(400).json({ error: 'BAD_INPUT', message: '状态不合法' });
      if (isSelf && status === 'disabled') return res.status(400).json({ error: 'SELF_LOCK', message: '不能禁用自己正在登录的账号' });
      if (rec.role === 'boss' && status === 'disabled' && activeBossCount() <= 1) {
        return res.status(400).json({ error: 'LAST_BOSS', message: '系统至少要保留一个启用中的老板账号' });
      }
      if (status !== rec.status) changeNotes.push(status === 'disabled' ? '禁用了账号' : '启用了账号');
      rec.status = status;
    }
    if (body.displayName !== undefined) {
      const dn = String(body.displayName).trim();
      if (dn && dn !== rec.displayName) { changeNotes.push('姓名改为' + dn); rec.displayName = dn; }
    }
    await persistUsers();
    rebuildUserIndex();
    if (body.role !== undefined || body.status !== undefined) invalidateSessionsFor(rec.usernames);
    if (changeNotes.length > 0) await logAccountChange(req.user, 'edit', rec.displayName + '（' + rec.usernames[0] + '）', changeNotes.join('，'));
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
    await logAccountChange(req.user, 'delete', rec.displayName + '（' + rec.usernames[0] + '）', '删除了账号');
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══ 每个角色对 car_loans / car_finance 两个数组的权限 ══
// add: 能不能新增记录；edit: 能不能改已有记录；del: 能不能删除已有记录
// sales 的 car_finance.add 是特例（'business_repay'）：只允许新增两类财务记录——
//   1) "收购车辆销售利润"：卖收购车自动生成的那笔流水，属于业务员的收购车辆业务本身；
//   2) "利息收入"/"本金回收"/"滞纳金" 且必须带 loanId（关联到一个真实存在的合同）：
//      这是"回款登记"页面用的，业务员登记客户还款，本质也是自己贷款业务的一部分，
//      不算"碰财务"——但必须挂在具体合同上，不能凭空新增一笔不知道属于哪个客户的收入。
// 其他财务记录（老板的"其他收入/支出登记"那些手动杂项记录）业务员一律不能碰。
// finance 现在是完全只读：能看利润表/现金流/历史结算/收支记录，但新增/编辑/
// 删除财务记录、贷款合同全都不行——记账只能老板（或业务员上面那两类特例）来做，
// 财务只负责查看/核对，不经手数据本身。
const ROLE_PERMS = {
  boss:    { car_loans: { add: true,  edit: true,  del: true  }, car_finance: { add: true,             edit: true,  del: true  } },
  sales:   { car_loans: { add: true,  edit: true,  del: false }, car_finance: { add: 'business_repay', edit: false, del: false } },
  finance: { car_loans: { add: false, edit: false, del: false }, car_finance: { add: false,            edit: false, del: false } },
};
// sales 通过 'business_repay' 能新增的财务记录分类白名单；除"收购车辆销售利润"外，
// 其余几类都必须带 loanId（见 checkKeyPermission）。
const SALES_ALLOWED_FINANCE_CATEGORIES = ['收购车辆销售利润', '利息收入', '本金回收', '滞纳金'];

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

// 2026-09：不再直接把客户端提交的"完整数组"当成权威真相存进库里（老板除外）。
// 起因：业务员/财务这类角色本来在读的时候就看不到完整数据（比如业务员 GET
// 的时候 car_finance 永远是空的，见下面 /api/data GET），如果保存的时候直接
// 存"客户端提交的这份数组"，等于拿一份"这个角色本来就看不全"的快照去覆盖
// 数据库里真实的完整数据——哪怕权限检查（下面的 removed/edited 判断）拦住了
// "明显越权"的情况，只要客户端这份数据是过时的（比如两个人前后保存），一样
// 会把别人这期间新增的记录冲掉。
// 修复：除老板外，一律拿数据库里真实的当前数据 + 这次校验通过的增/改/删，
// 重新拼出真正要存的值，而不是直接相信客户端提交的完整数组本身。
function mergeArrayUpdate(oldArr, added, edited, removed, allowDel) {
  oldArr = Array.isArray(oldArr) ? oldArr : [];
  const removedIds = new Set(allowDel ? removed.map(x => x.id) : []);
  const editedMap = new Map(edited.map(x => [x.id, x]));
  const kept = oldArr.filter(x => !removedIds.has(x.id)).map(x => editedMap.has(x.id) ? editedMap.get(x.id) : x);
  return added.concat(kept); // 新增的放最前面，跟客户端 unshift() 的习惯保持一致
}

function checkKeyPermission(role, key, newValue, currentData) {
  const perm = (ROLE_PERMS[role] || {})[key];
  if (!perm) return { ok: false, reason: `角色无权修改 ${key}` };
  const oldArr = (currentData && currentData[key]) || [];
  // 2026-09：不管老板还是别的角色，diff都要算出来——除了给非老板角色做权限校验，
  // 现在还要拿它给"操作日志"记一笔"谁新增/改了/删了哪条记录"，所以老板这条快速
  // 通道也不再跳过这一步了。
  const { added, edited, removed } = diffById(oldArr, newValue);
  if (perm.add === true && perm.edit === true && perm.del === true) {
    return { ok: true, mergedValue: newValue, added, edited, removed }; // 老板全权，信任客户端提交的完整数组
  }
  if (removed.length > 0 && !perm.del) return { ok: false, reason: '无权删除记录' };
  if (edited.length > 0 && !perm.edit) return { ok: false, reason: '无权修改已有记录' };
  if (added.length > 0) {
    if (perm.add === true) { /* 允许 */ }
    else if (perm.add === 'business_repay') {
      const loanIds = new Set((currentData.car_loans || []).map(l => l.id));
      const bad = added.find(r => {
        if (!SALES_ALLOWED_FINANCE_CATEGORIES.includes(r.category)) return true;
        if (r.category === '收购车辆销售利润') return false; // 卖收购车那一笔，走原逻辑
        return !r.loanId || !loanIds.has(r.loanId); // 回款记录必须关联一个真实存在的合同
      });
      if (bad) return { ok: false, reason: '业务员只能新增"收购车辆销售利润"或关联真实合同的回款记录（利息收入/本金回收/滞纳金）' };
    } else {
      return { ok: false, reason: '无权新增记录' };
    }
  }
  return { ok: true, mergedValue: mergeArrayUpdate(oldArr, added, edited, removed, !!perm.del), added, edited, removed };
}

// ══════════════════════════════════════════════════════════
// ══ 操作日志（工作日志）══ 2026-09 新增：老板要能看到"谁动了系统"——
// 每次贷款/收购车辆/财务记录的新增、编辑、删除，都自动记一笔：谁（账号+角色）、
// 什么时间、动了哪张表的哪条记录、大致是什么内容。只读、追加写入，业务员/财务
// 自己看不到（只有老板能看，跟账号管理一样），避免争议时说不清楚。
// ══════════════════════════════════════════════════════════
const OPLOG_MAX = 3000; // 只保留最近这么多条，避免无限增长
let OPLOG = [];
function genOpId() { return 'OP' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
async function initOplog() {
  try {
    const { data, error } = await supabase.from('pawndata').select('value').eq('key', 'car_oplog').maybeSingle();
    if (!error && data && Array.isArray(data.value)) OPLOG = data.value;
    else OPLOG = [];
  } catch (e) {
    console.error('  操作日志：初始化失败，先用空日志兜底：', e.message);
    OPLOG = [];
  }
}
async function persistOplog() {
  const { error } = await supabase.from('pawndata').upsert([{ key: 'car_oplog', value: OPLOG }], { onConflict: 'key' });
  if (error) throw new Error('DB_WRITE_ERROR: ' + error.message);
}
// 贷款/收购车辆记录 -> 一句话摘要，方便日志里一眼看懂动的是谁
function summarizeLoanRecord(r) {
  if (!r) return '';
  if (r.assetType === 'acquired') return '收购车辆 ' + (r.plate || '') + (r.brand ? ' ' + r.brand : '');
  return (r.name || '') + ' · ' + (r.plate || '') + ' · ' + (r.amount != null ? '$' + r.amount : '');
}
function summarizeFinanceRecord(r) {
  if (!r) return '';
  return (r.category || '') + ' $' + (r.amount != null ? r.amount : 0) + (r.loanId ? '（关联' + r.loanId + '）' : '');
}
// 账号管理动作（新增/改角色改状态/重置密码/删除账号）单独记一笔日志——这些操作全都
// 只有老板能做，但老板账号可能不止一个，日志能看出"是哪个老板账号做的"
async function logAccountChange(user, action, targetDisplay, summary) {
  try {
    OPLOG = [{ id: genOpId(), time: new Date().toISOString(), username: user.username, displayName: user.displayName, role: user.role, dataKey: 'car_users', action, targetId: targetDisplay, summary }].concat(OPLOG);
    if (OPLOG.length > OPLOG_MAX) OPLOG = OPLOG.slice(0, OPLOG_MAX);
    await persistOplog();
  } catch (e) {
    console.error('操作日志写入失败（不影响本次账号操作）：', e.message);
  }
}

// 把 checkKeyPermission 算出来的 added/edited/removed 转成一条条日志，追加进 OPLOG
function logDataChanges(user, key, added, edited, removed) {
  const summarize = key === 'car_loans' ? summarizeLoanRecord : summarizeFinanceRecord;
  const now = new Date().toISOString();
  const entries = [];
  (added || []).forEach(r => entries.push({ id: genOpId(), time: now, username: user.username, displayName: user.displayName, role: user.role, dataKey: key, action: 'add', targetId: r.id, summary: summarize(r) }));
  (edited || []).forEach(r => entries.push({ id: genOpId(), time: now, username: user.username, displayName: user.displayName, role: user.role, dataKey: key, action: 'edit', targetId: r.id, summary: summarize(r) }));
  (removed || []).forEach(r => entries.push({ id: genOpId(), time: now, username: user.username, displayName: user.displayName, role: user.role, dataKey: key, action: 'delete', targetId: r.id, summary: summarize(r) }));
  if (entries.length === 0) return entries;
  OPLOG = entries.concat(OPLOG); // 最新的放最前面
  if (OPLOG.length > OPLOG_MAX) OPLOG = OPLOG.slice(0, OPLOG_MAX);
  return entries;
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
    const finalValues = {};
    const logBatches = []; // 攒够这次请求里所有key的日志，写完数据后一次性落库，避免半途报错留一半日志
    for (const key of keys) {
      if (key === 'car_nextId') {
        if (req.user.role === 'finance') return res.status(403).json({ error: 'PERMISSION_DENIED', message: '财务无权修改此数据' });
        finalValues[key] = body[key];
        continue;
      }
      const check = checkKeyPermission(req.user.role, key, body[key], current);
      if (!check.ok) return res.status(403).json({ error: 'PERMISSION_DENIED', message: check.reason });
      finalValues[key] = check.mergedValue;
      logBatches.push({ key, added: check.added, edited: check.edited, removed: check.removed });
    }

    const rows = keys.map(key => ({ key, value: finalValues[key] }));
    const { error } = await supabase.from('pawndata').upsert(rows, { onConflict: 'key' });
    if (error) return res.status(500).json({ error: error.message });

    // 数据写库成功之后再记操作日志（日志写失败也不影响这次保存本身，只打日志到控制台）
    try {
      let hasEntries = false;
      logBatches.forEach(b => { if (logDataChanges(req.user, b.key, b.added, b.edited, b.removed).length > 0) hasEntries = true; });
      if (hasEntries) await persistOplog();
    } catch (logErr) {
      console.error('操作日志写入失败（不影响本次数据保存）：', logErr.message);
    }

    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// 操作日志（只有老板能看，追踪谁新增/编辑/删除了哪条贷款或财务记录）
app.get('/api/oplog', auth, async (req, res) => {
  if (req.user.role !== 'boss') return res.status(403).json({ error: 'PERMISSION_DENIED', message: '只有老板能查看操作日志' });
  res.json({ ok: true, log: OPLOG });
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

Promise.all([initUsers(), initOplog()]).finally(() => {
  app.listen(PORT, () => {
    console.log(`\n${'═'.repeat(50)}`);
    console.log(`  🚗 MORODOK 汽车抵押贷款管理系统`);
    console.log(`${'═'.repeat(50)}`);
    console.log(`  访问地址: http://localhost:${PORT}`);
    console.log(`${'═'.repeat(50)}\n`);
  });
});
