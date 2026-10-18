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
// 2026-09：index.html绝对不能被浏览器缓存住——不然老板贴完新代码、Render部署好了
// 之后，业务员那边只要浏览器（或者手机）缓存了旧的index.html，哪怕手动刷新也可能
// 还是拿到本地缓存的老版本，出现"业务员看到的和老板看到的不一样"（比如业务员那边
// 还在用没修复"回款登记"bug之前的老代码）。加上这几个响应头之后，每次请求
// index.html浏览器都必须去服务器重新要一份最新的，不会用本地缓存顶替。
app.use(express.static(__dirname, {
  setHeaders: function(res, filePath) {
    if (filePath.endsWith('index.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

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
// 2026-10：'gui'/'boss' 原来是同一个账号的两个登录别名，导致操作日志分不清
// 是谁操作的——拆成两个独立账号：'boss' 是老板本人（超级管理员，系统设置全看），
// 'gui' 是贵（普通老板权限，但看不了系统设置）。见下面 splitMultiAliasAccounts()，
// 已有数据库数据的话由那边做一次性拆分迁移，这里只影响全新部署。
const USERS_RAW = [
  { usernames: ['boss'], password: 'gui',    role: 'boss',    displayName: '老板', isSuperAdmin: true },
  { usernames: ['gui'],  password: 'gui',    role: 'boss',    displayName: '贵',   isSuperAdmin: false },
  { usernames: ['caiwu'],       password: 'gui888', role: 'finance', displayName: '财务' },
  { usernames: ['yewu'],        password: 'yewu888', role: 'sales',   displayName: '业务员' },
];
// 迁移专用：账号被拆分后，新账号默认显示姓名 = 用户名，这里给几个已知的用户名
// 起更好认的姓名；没命中的就用用户名本身兜底，老板之后可以在账号管理里自己改名。
const ALIAS_DISPLAY_NAME_HINTS = { gui: '贵' };
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
// 拆分时，如果这几个用户名里有一个是"boss"，那个才是真正的超级管理员身份，
// 必须留在原账号上（不能简单掐数组第一个——种子数据里 usernames 是
// ['gui','boss']，'gui' 排第一但不该是留下来的那个）
const PREFERRED_PRIMARY_USERNAME = 'boss';
// 一次性迁移：①某个账号如果挂了不止一个登录用户名（历史遗留，比如'gui'和'boss'
// 曾经是同一个账号的两个别名），拆成各自独立的账号，不然操作日志永远分不清谁是谁；
// 拆出来的新账号默认 isSuperAdmin:false（不给系统设置权限，按需要老板自己加回去）。
// ②老账号如果压根没有 isSuperAdmin 这个字段（这个权限是后来才加的），老板角色
// 默认当成 true，不改变这些账号现有的使用习惯。返回是否有改动，有改动调用方要存库。
function splitMultiAliasAccounts() {
  var changed = false;
  var newRecords = [];
  USER_RECORDS.forEach(function(rec) {
    if (rec.role === 'boss' && rec.isSuperAdmin === undefined) {
      rec.isSuperAdmin = true;
      changed = true;
    }
    if (Array.isArray(rec.usernames) && rec.usernames.length > 1) {
      var keep = rec.usernames.indexOf(PREFERRED_PRIMARY_USERNAME) !== -1 ? PREFERRED_PRIMARY_USERNAME : rec.usernames[0];
      var extras = rec.usernames.filter(function(u){ return u !== keep; });
      rec.usernames = [keep];
      extras.forEach(function(alias) {
        newRecords.push({
          id: genUserId(), usernames: [alias], displayName: ALIAS_DISPLAY_NAME_HINTS[alias] || alias,
          role: rec.role, status: rec.status, passwordHash: rec.passwordHash,
          isSuperAdmin: false, createdAt: new Date().toISOString()
        });
      });
      console.log('  账号：「' + rec.displayName + '」账号原本有多个登录别名（' + [keep].concat(extras).join('/') + '），已拆分成独立账号');
      changed = true;
    }
  });
  if (newRecords.length > 0) USER_RECORDS = USER_RECORDS.concat(newRecords);
  return changed;
}
async function initUsers() {
  try {
    const { data, error } = await supabase.from('pawndata').select('value').eq('key', 'car_users').maybeSingle();
    if (!error && data && Array.isArray(data.value) && data.value.length > 0) {
      USER_RECORDS = data.value;
      console.log(`  账号：已从数据库加载 ${USER_RECORDS.length} 个账号`);
      if (splitMultiAliasAccounts()) { await persistUsers(); console.log('  账号：账号拆分迁移已保存'); }
    } else {
      USER_RECORDS = USERS_RAW.map(u => ({
        id: genUserId(), usernames: u.usernames.slice(), displayName: u.displayName,
        role: u.role, status: 'active', passwordHash: hashPassword(u.password), isSuperAdmin: !!u.isSuperAdmin, createdAt: new Date().toISOString()
      }));
      await persistUsers();
      console.log('  账号：数据库中未找到账号数据，已写入初始种子账号（boss, gui, caiwu, yewu）');
    }
  } catch (e) {
    console.error('  账号：初始化失败，使用内存种子账号兜底：', e.message);
    USER_RECORDS = USERS_RAW.map(u => ({
      id: genUserId(), usernames: u.usernames.slice(), displayName: u.displayName,
      role: u.role, status: 'active', passwordHash: hashPassword(u.password), isSuperAdmin: !!u.isSuperAdmin, createdAt: new Date().toISOString()
    }));
  }
  rebuildUserIndex();
}
function sanitizeUser(rec) {
  return { id: rec.id, username: rec.usernames[0], usernames: rec.usernames, displayName: rec.displayName, role: rec.role, status: rec.status, isSuperAdmin: !!rec.isSuperAdmin, canManualFinance: !!rec.canManualFinance, createdAt: rec.createdAt };
}
function activeBossCount() {
  return USER_RECORDS.filter(r => r.role === 'boss' && r.status === 'active').length;
}
// 系统设置（账号管理/操作日志/备份/恢复/数据体检）比普通老板权限更高一层——
// 不是所有"老板"角色的账号都能看，只有 isSuperAdmin:true 的才行
function activeSuperAdminCount() {
  return USER_RECORDS.filter(r => r.role === 'boss' && r.status === 'active' && r.isSuperAdmin === true).length;
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
  sessions.set(token, { username: String(username).trim(), role: rec.role, displayName: rec.displayName, isSuperAdmin: !!rec.isSuperAdmin, canManualFinance: !!rec.canManualFinance, ts: Date.now() });
  res.json({ ok: true, token, role: rec.role, displayName: rec.displayName, username: String(username).trim(), isSuperAdmin: !!rec.isSuperAdmin, canManualFinance: !!rec.canManualFinance });
});

app.post('/api/logout', auth, (req, res) => {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ ok: true, username: req.user.username, role: req.user.role, displayName: req.user.displayName, isSuperAdmin: !!req.user.isSuperAdmin, canManualFinance: !!req.user.canManualFinance });
});

// ══ 账号管理（系统设置专属：只有 isSuperAdmin:true 的老板账号能自己新增/改角色/
// 重置密码/启用禁用/删除员工账号——普通老板角色账号看不到、也调不了这几个接口）══
function requireSuperAdmin(req, res) {
  if (req.user.role !== 'boss' || !req.user.isSuperAdmin) { res.status(403).json({ error: 'PERMISSION_DENIED', message: '只有系统管理员能管理账号' }); return false; }
  return true;
}
app.get('/api/users', auth, (req, res) => {
  if (!requireSuperAdmin(req, res)) return;
  res.json({ ok: true, users: USER_RECORDS.map(sanitizeUser) });
});
app.post('/api/users', auth, async (req, res) => {
  if (!requireSuperAdmin(req, res)) return;
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
    // 新建的老板角色账号默认不给系统设置权限（isSuperAdmin:false），要的话前端勾选
    const isSuperAdmin = role === 'boss' && !!(req.body || {}).isSuperAdmin;
    // 新建的业务员账号默认不给"其他收入登记/支出登记"权限（canManualFinance:false），
    // 只有个别需要的账号（比如 siyan）才在前端单独勾选给
    const canManualFinance = role === 'sales' && !!(req.body || {}).canManualFinance;
    const rec = { id: genUserId(), usernames: [username], displayName, role, status: 'active', passwordHash: hashPassword(password), isSuperAdmin: isSuperAdmin, canManualFinance: canManualFinance, createdAt: new Date().toISOString() };
    USER_RECORDS.push(rec);
    await persistUsers();
    rebuildUserIndex();
    await logAccountChange(req.user, 'add', displayName + '（' + username + '）', '新增账号，角色：' + role + (isSuperAdmin?'（系统管理员）':'') + (canManualFinance?'（可登记其他收支）':''));
    res.json({ ok: true, user: sanitizeUser(rec) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/users/:id/reset-password', auth, async (req, res) => {
  if (!requireSuperAdmin(req, res)) return;
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
  if (!requireSuperAdmin(req, res)) return;
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
      if (role !== 'boss' && rec.isSuperAdmin) rec.isSuperAdmin = false; // 不是老板角色了，系统管理员权限没意义，一起清掉
      if (role !== 'sales' && rec.canManualFinance) rec.canManualFinance = false; // 不是业务员角色了，其他收支登记权限没意义，一起清掉
    }
    if (body.isSuperAdmin !== undefined) {
      const wantSuperAdmin = !!body.isSuperAdmin;
      // rec.role 这时候已经是上面 role 分支处理完之后的最新值了（如果这次请求也带了
      // role 字段的话），所以这里直接判断 rec.role 就够，不用再单独理会 body.role
      if (wantSuperAdmin && rec.role !== 'boss') {
        return res.status(400).json({ error: 'BAD_INPUT', message: '只有老板角色的账号能设为系统管理员' });
      }
      if (!wantSuperAdmin && rec.isSuperAdmin && rec.status === 'active' && activeSuperAdminCount() <= 1) {
        return res.status(400).json({ error: 'LAST_SUPER_ADMIN', message: '系统至少要保留一个系统管理员账号，否则没人能再管理账号/看操作日志' });
      }
      if (wantSuperAdmin !== rec.isSuperAdmin) changeNotes.push(wantSuperAdmin ? '设为系统管理员' : '取消系统管理员');
      rec.isSuperAdmin = wantSuperAdmin;
    }
    if (body.canManualFinance !== undefined) {
      const wantManualFinance = !!body.canManualFinance;
      // 同理，rec.role 这时候已经是上面 role 分支处理完之后的最新值了
      if (wantManualFinance && rec.role !== 'sales') {
        return res.status(400).json({ error: 'BAD_INPUT', message: '只有业务员角色的账号能单独授权"其他收入登记/支出登记"' });
      }
      if (wantManualFinance !== rec.canManualFinance) changeNotes.push(wantManualFinance ? '授权其他收支登记' : '取消其他收支登记授权');
      rec.canManualFinance = wantManualFinance;
    }
    if (body.status !== undefined) {
      const status = String(body.status).trim();
      if (['active', 'disabled'].indexOf(status) === -1) return res.status(400).json({ error: 'BAD_INPUT', message: '状态不合法' });
      if (isSelf && status === 'disabled') return res.status(400).json({ error: 'SELF_LOCK', message: '不能禁用自己正在登录的账号' });
      if (rec.role === 'boss' && status === 'disabled' && activeBossCount() <= 1) {
        return res.status(400).json({ error: 'LAST_BOSS', message: '系统至少要保留一个启用中的老板账号' });
      }
      if (rec.isSuperAdmin && status === 'disabled' && activeSuperAdminCount() <= 1) {
        return res.status(400).json({ error: 'LAST_SUPER_ADMIN', message: '系统至少要保留一个启用中的系统管理员账号' });
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
  if (!requireSuperAdmin(req, res)) return;
  try {
    const rec = USER_RECORDS.find(r => r.id === req.params.id);
    if (!rec) return res.status(404).json({ error: 'NOT_FOUND', message: '账号不存在' });
    const isSelf = (rec.usernames || []).indexOf(req.user.username) !== -1;
    if (isSelf) return res.status(400).json({ error: 'SELF_LOCK', message: '不能删除自己正在登录的账号' });
    if (rec.role === 'boss' && rec.status === 'active' && activeBossCount() <= 1) {
      return res.status(400).json({ error: 'LAST_BOSS', message: '系统至少要保留一个启用中的老板账号' });
    }
    if (rec.isSuperAdmin && rec.status === 'active' && activeSuperAdminCount() <= 1) {
      return res.status(400).json({ error: 'LAST_SUPER_ADMIN', message: '系统至少要保留一个启用中的系统管理员账号' });
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
// 2026-10-18 新增"员工工资"：员工档案(car_staff)和月度工资表(car_payroll)。只有老板角色能增删改；
// 财务能看（GET 下发）但不能改；业务员既看不到也改不了（见 GET /api/data 和这里没有 sales/finance 条目）。
ROLE_PERMS.boss.car_staff   = { add: true, edit: true, del: true };
ROLE_PERMS.boss.car_payroll = { add: true, edit: true, del: true };
// sales 通过 'business_repay' 能新增的财务记录分类白名单；除"收购车辆销售利润"外，
// 其余几类都必须带 loanId（见 checkKeyPermission）。
const SALES_ALLOWED_FINANCE_CATEGORIES = ['收购车辆销售利润', '利息收入', '本金回收', '滞纳金'];
// 2026-10：个别业务员账号（比如 siyan）可以被单独授权"其他收入登记/支出登记"
// 这两个页面——跟上面"回款登记"那条路完全独立：不用关联合同，分类是这张表单
// 自己固定的那几种（跟老板用的是同一张表单、同一套分类）。只有 user 记录上
// canManualFinance:true 的 sales 账号才能用，其他业务员不受影响。
const MANUAL_FINANCE_INCOME_CATEGORIES = ['利息收入', '本金回收', '手续费', '滞纳金', '其他收入'];
const MANUAL_FINANCE_EXPENSE_CATEGORIES = ['办公费用', '工资支出', '推广费用', '车辆评估费', '其他支出'];

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

function checkKeyPermission(user, key, newValue, currentData) {
  const role = user.role;
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
  // 2026-09 修复：sales在car_finance上是"add-only且看不到真实旧数据"的角色——
  // GET /api/data 那边对sales角色本来就不下发car_finance（财务数据保密，见那边
  // 注释），所以业务员客户端手上的"旧数组"永远是空的，每次登记回款、把新记录
  // unshift上去再提交，提交的这份数组天然就不包含数据库里任何一条真实旧记录。
  // 拿它跟数据库真实全量car_finance做diff，必然会把所有业务员看不到的旧记录都
  // 判定成"removed"——这根本不是业务员想删除任何东西，只是它没法在"整份数组"
  // 这个模型里诚实表达"我只是想加"，导致业务员每次登记回款都会被误判成"想删除
  // 全部记录"而被服务器拒绝（报"无权删除记录"）。这类角色本来就没有del权限，
  // 下面mergeArrayUpdate也不会真的按这份"removed"去删任何东西，所以这里放行
  // 不会造成真正的越权删除，只是不再冤枉它。
  const isBlindAddOnly = perm.add === 'business_repay' && perm.edit === false && perm.del === false;
  if (removed.length > 0 && !perm.del && !isBlindAddOnly) return { ok: false, reason: '无权删除记录' };
  if (edited.length > 0 && !perm.edit) return { ok: false, reason: '无权修改已有记录' };
  if (added.length > 0) {
    if (perm.add === true) { /* 允许 */ }
    else if (perm.add === 'business_repay') {
      const loanIds = new Set((currentData.car_loans || []).map(l => l.id));
      const canManual = role === 'sales' && user.canManualFinance === true;
      const bad = added.find(r => {
        // 原有：回款登记相关——收购车辆销售利润，或者利息收入/本金回收/滞纳金但
        // 必须关联一个真实存在的合同
        const okRepay = SALES_ALLOWED_FINANCE_CATEGORIES.includes(r.category) &&
          (r.category === '收购车辆销售利润' || (!!r.loanId && loanIds.has(r.loanId)));
        if (okRepay) return false;
        // 额外：被单独授权"其他收入登记/支出登记"的账号，可以不关联合同、按这两个
        // 页面自己的固定分类手动登记（跟老板用的是同一张表单）
        if (canManual) {
          if (r.type === 'income' && MANUAL_FINANCE_INCOME_CATEGORIES.includes(r.category)) return false;
          if (r.type === 'expense' && MANUAL_FINANCE_EXPENSE_CATEGORIES.includes(r.category)) return false;
        }
        return true;
      });
      if (bad) return { ok: false, reason: canManual ? '这条记录的分类不在允许登记的范围内' : '业务员只能新增"收购车辆销售利润"或关联真实合同的回款记录（利息收入/本金回收/滞纳金）' };
    } else {
      return { ok: false, reason: '无权新增记录' };
    }
  }
  // 2026-10-05 修复操作日志"假删除"：业务员提交的财务数组天然看不到旧记录（见上面
  // isBlindAddOnly 的说明），diff 会把数据库里所有旧记录都算成 removed。但没有 del 权限
  // 的角色，mergeArrayUpdate 根本不会真的删任何东西——这里如果还把 removed 原样返回，
  // 操作日志就会给业务员记上一大堆"删除"，其实数据一条没动（小美登记一笔回款，日志里
  // 却出现她"删除"了二十几条财务记录）。没有 del 权限时，真实被删的永远是空。
  const actualRemoved = perm.del ? removed : [];
  const mergedValue = mergeArrayUpdate(oldArr, added, edited, removed, !!perm.del);
  // 双保险：没有 del 权限的角色（业务员/财务），保存后数据库里原有的每一条记录都必须还在。
  // 万一以后谁改坏了上面的合并逻辑，宁可拒绝这次保存，也不让业务员的操作带走任何一条旧记录。
  if (!perm.del) {
    const mergedIds = new Set(mergedValue.map(x => x.id));
    const lost = oldArr.find(x => !mergedIds.has(x.id));
    if (lost) return { ok: false, reason: '内部校验失败：这次保存会导致已有记录丢失，已拒绝（记录 ' + lost.id + '）' };
  }
  return { ok: true, mergedValue, added, edited, removed: actualRemoved };
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
// ══════════════════════════════════════════════════════════
// ══ 自动快照（数据安全网）══ 2026-10-05 新增：老板要求"数据非常重要，绝不能再出现
// 记录不见了、还找不回来"。每次保存之前，服务器自动把"保存前那一刻的完整数据"存一份
// 快照（单独存在数据库 car_autosnap 这一行，不影响业务数据）：
//   · 距离上一份快照超过 6 小时，就在下一次保存前存一份；
//   · 只要这次保存会真的删除记录、或者是"整体恢复覆盖"，不管间隔多久都先存一份。
// 只保留最近 10 份。只有系统管理员能在"自动快照"页面下载，下载下来的文件格式跟
// "备份数据"完全一样，可以直接用"恢复数据"导回去。
// ══════════════════════════════════════════════════════════
const AUTOSNAP_KEY = 'car_autosnap';
const AUTOSNAP_MAX = 10;
const AUTOSNAP_INTERVAL_MS = 6 * 60 * 60 * 1000;
let AUTOSNAPS = null; // 内存缓存：[{id, ts, time, by, reason, loanCount, financeCount, car_loans, car_finance}]，最新的在最前
async function loadAutosnaps() {
  if (AUTOSNAPS) return AUTOSNAPS;
  const { data, error } = await supabase.from('pawndata').select('value').eq('key', AUTOSNAP_KEY).maybeSingle();
  if (error) throw new Error('DB_READ_ERROR: ' + error.message);
  AUTOSNAPS = (data && Array.isArray(data.value)) ? data.value : [];
  return AUTOSNAPS;
}
// 失败只打日志，绝不影响这次保存本身
async function maybeAutoSnapshot(user, current, reason, force) {
  try {
    if (!current) return;
    const list = await loadAutosnaps();
    const last = list[0];
    if (!force && last && (Date.now() - last.ts) < AUTOSNAP_INTERVAL_MS) return;
    const loans = Array.isArray(current.car_loans) ? current.car_loans : [];
    const finance = Array.isArray(current.car_finance) ? current.car_finance : [];
    list.unshift({
      id: 'S' + Date.now().toString(36), ts: Date.now(), time: new Date().toISOString(),
      by: (user && (user.displayName || user.username)) || '', reason: reason,
      loanCount: loans.length, financeCount: finance.length, car_loans: loans, car_finance: finance,
      car_staff: Array.isArray(current.car_staff) ? current.car_staff : [], car_payroll: Array.isArray(current.car_payroll) ? current.car_payroll : []
    });
    if (list.length > AUTOSNAP_MAX) list.length = AUTOSNAP_MAX;
    const { error } = await supabase.from('pawndata').upsert([{ key: AUTOSNAP_KEY, value: list }], { onConflict: 'key' });
    if (error) console.error('自动快照写入失败（不影响本次保存）：', error.message);
  } catch (e) {
    console.error('自动快照失败（不影响本次保存）：', e.message);
  }
}

// 贷款/收购车辆记录 -> 一句话摘要，方便日志里一眼看懂动的是谁
function summarizeLoanRecord(r) {
  if (!r) return '';
  if (r.assetType === 'acquired') return '收购车辆 ' + (r.plate || '') + (r.brand ? ' ' + r.brand : '');
  return (r.name || '') + ' · ' + (r.plate || '') + ' · ' + (r.amount != null ? '$' + r.amount : '') + (r.agent ? '（经办：' + r.agent + '）' : '');
}
function summarizeFinanceRecord(r) {
  if (!r) return '';
  return (r.category || '') + ' $' + (r.amount != null ? r.amount : 0) + (r.loanId ? '（关联' + r.loanId + '）' : '');
}
function summarizeStaffRecord(r) {
  if (!r) return '';
  return '员工 ' + (r.name || '') + ' · ' + (r.dept || '') + ' · 底薪$' + (r.baseSalary != null ? r.baseSalary : 0) + ' · ' + (r.status || '');
}
function summarizePayrollRecord(r) {
  if (!r) return '';
  return (r.month || '') + ' 工资 ' + (r.name || '') + ' · 实发$' + (r.total != null ? r.total : 0) + ' · ' + (r.status === 'paid' ? '已发放' : '待发放');
}
const SUMMARIZERS = { car_loans: summarizeLoanRecord, car_finance: summarizeFinanceRecord, car_staff: summarizeStaffRecord, car_payroll: summarizePayrollRecord };
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
// 2026-10-14：贷款记录被"编辑"时，如果客户姓名/车牌变了（正常编辑几乎不会改这两个，一旦变了
// 基本就是被别的单子覆盖了），日志里除了新内容，还要把"修改前"的客户/车牌/金额一并写下来——
// 这样哪怕以后真被覆盖，从操作日志里也能看到原来那笔是谁、多少钱，能照着补回。
function loanIdentityChanged(oldRec, newRec) {
  return !!(oldRec && newRec && (oldRec.name !== newRec.name || oldRec.plate !== newRec.plate));
}
function logDataChanges(user, key, added, edited, removed, before) {
  const summarize = SUMMARIZERS[key] || summarizeFinanceRecord;
  const now = new Date().toISOString();
  const entries = [];
  (added || []).forEach(r => entries.push({ id: genOpId(), time: now, username: user.username, displayName: user.displayName, role: user.role, dataKey: key, action: 'add', targetId: r.id, summary: summarize(r) }));
  (edited || []).forEach(r => {
    let summary = summarize(r);
    const old = before && before.get ? before.get(r.id) : null;
    if (key === 'car_loans' && old) {
      const changed = loanIdentityChanged(old, r);
      if (changed || old.amount !== r.amount) summary = (changed ? '⚠️客户/车牌被改！' : '') + summary + ' ｜ 修改前：' + summarize(old) + (old.date ? '（放款日 ' + old.date + '）' : '');
    }
    entries.push({ id: genOpId(), time: now, username: user.username, displayName: user.displayName, role: user.role, dataKey: key, action: 'edit', targetId: r.id, summary });
  });
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
    car_nextId: 1,
    car_staff: [],
    car_payroll: []
  };
}

async function loadData() {
  const { data, error } = await supabase.from('pawndata').select('key, value')
    .in('key', ['car_loans', 'car_finance', 'car_nextId', 'car_staff', 'car_payroll']);
  if (error) throw new Error('DB_READ_ERROR: ' + error.message);
  const result = {};
  if (data) data.forEach(row => { result[row.key] = row.value; });
  const init = getInitData();
  Object.keys(init).forEach(k => { if (result[k] === undefined) result[k] = init[k]; });
  return result;
}

// 读取所有数据（业务员看不到财务记录的具体金额/分类）
app.get('/api/data', auth, async (req, res) => {
  try {
    const data = await loadData();
    if (!Array.isArray(data.car_loans)) data.car_loans = [];
    if (!Array.isArray(data.car_finance)) data.car_finance = [];
    if (!data.car_nextId) data.car_nextId = 1;
    // 2026-09修复："哪张合同、第几期已经登记过回款"这件事，不管老板还是业务员登录
    // 都必须一样——不然回款登记/逾期催收页判断"是不是逾期"用的数据两边不一致，
    // 业务员那边会把明明已经收过的老期数当成没收过、全部误判成逾期，跟老板端
    // 完全对不上（这个字段本身不含金额，只是"loanId+第几期"这个组合，不算财务
    // 保密的范围）。在下面按角色清空car_finance之前，先把这份"期数清单"提出来，
    // 不管什么角色都完整下发；period字段是空的老记录（早年批量导入没写period），
    // 跟前端recordPeriod()一样从备注"第N期"里兜底解析一次。
    const loanPeriods = data.car_finance
      .filter(r => r && r.loanId)
      .map(r => {
        let period = r.period;
        if (!period) {
          const m = /第(\d+)期/.exec(r.note || '');
          period = m ? parseInt(m[1], 10) : 0;
        }
        return { loanId: r.loanId, period };
      })
      .filter(x => x.period > 0);
    data.car_finance_periods = loanPeriods;
    if (!Array.isArray(data.car_staff)) data.car_staff = [];
    if (!Array.isArray(data.car_payroll)) data.car_payroll = [];
    if (req.user.role === 'sales') {
      data.car_finance = []; // 业务员看不到具体金额/分类这些财务明细，上面car_finance_periods已经单独发了
    }
    if (req.user.role !== 'boss' && req.user.role !== 'finance') {
      data.car_staff = []; data.car_payroll = []; // 员工档案/工资表：只有老板和财务（只读）能看，业务员一条都拿不到
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
    const allowed = ['car_loans', 'car_finance', 'car_nextId', 'car_staff', 'car_payroll'];
    const keys = Object.keys(body).filter(k => allowed.includes(k));
    if (keys.length === 0) return res.json({ ok: true });

    let current = null;
    if (keys.includes('car_loans') || keys.includes('car_finance') || keys.includes('car_staff') || keys.includes('car_payroll')) {
      current = await loadData();
    }
    // 2026-10-05 新增"删除必须明说"：客户端提交时要在 _intendedRemovals 里列出"这次我是
    // 有意要删掉的记录ID"，服务器发现数据库里有记录在这次提交里不见了、但又不在这份清单
    // 里，就认定是"过期的完整数组把别人新增的记录冲掉了"这类意外，直接拒绝保存，
    // 而不是照单全收。整体恢复备份（_bulkReplace）是例外，且只允许系统管理员。
    const intendedRemovals = (body && typeof body._intendedRemovals === 'object' && body._intendedRemovals) || {};
    const bulkReplace = !!(body && body._bulkReplace === true);
    if (bulkReplace && !(req.user.role === 'boss' && req.user.isSuperAdmin)) {
      return res.status(403).json({ error: 'PERMISSION_DENIED', message: '只有系统管理员能整体恢复数据' });
    }
    const finalValues = {};
    const logBatches = []; // 攒够这次请求里所有key的日志，写完数据后一次性落库，避免半途报错留一半日志
    for (const key of keys) {
      if (key === 'car_nextId') {
        if (req.user.role === 'finance') return res.status(403).json({ error: 'PERMISSION_DENIED', message: '财务无权修改此数据' });
        finalValues[key] = body[key];
        continue;
      }
      const check = checkKeyPermission(req.user, key, body[key], current);
      if (!check.ok) return res.status(403).json({ error: 'PERMISSION_DENIED', message: check.reason });
      // 2026-10-14 新增"撞号拒绝"：客户端声明"这次是新增的记录ID"，如果这些ID在数据库里已经存在，
      // 说明两个人几乎同时新增、拿到了同一个编号。以前服务器会把后到的那条当成"编辑"，直接覆盖先到的
      // 那条（订单凭空被盖掉）；现在直接拒绝，让客户端重新生成编号再提交。
      const declaredNew = (body && body._newIds && Array.isArray(body._newIds[key])) ? body._newIds[key] : [];
      if (declaredNew.length > 0 && current && Array.isArray(current[key])) {
        const existing = new Set(current[key].map(x => x.id));
        const clash = declaredNew.find(id => existing.has(id));
        if (clash) {
          console.error('拒绝撞号：用户 ' + req.user.username + ' 新增的 ' + key + ' 记录 ' + clash + ' 在库里已存在');
          return res.status(409).json({ error: 'ID_COLLISION', message: '编号 ' + clash + ' 刚被别人用掉了，请重试' });
        }
      }
      if (check.removed.length > 0 && !bulkReplace) {
        const okIds = new Set(Array.isArray(intendedRemovals[key]) ? intendedRemovals[key] : []);
        const unexpected = check.removed.filter(r => !okIds.has(r.id));
        if (unexpected.length > 0) {
          console.error('拒绝意外删除：用户 ' + req.user.username + ' 的这次保存会让 ' + key + ' 里 ' + unexpected.length + ' 条记录消失，例如 ' + unexpected[0].id);
          return res.status(409).json({ error: 'UNEXPECTED_REMOVAL', message: '检测到这次保存会让 ' + unexpected.length + ' 条记录意外消失（例如 ' + unexpected[0].id + '），为保护数据已拒绝。请刷新页面后重试；如果确实想删除，请用页面上的删除按钮。' });
        }
      }
      // 2026-10-14 编号不许重复：保存结果里如果出现"库里原本没有的重复编号"，直接拒绝。
      // （库里已经存在的历史重复编号先放行，让管理员能用"修复重复编号"工具修好；工具只会减少重复。）
      if (key === 'car_loans' || key === 'car_finance' || key === 'car_staff' || key === 'car_payroll') {
        const dupOf = arr => { const seen = new Set(), dup = new Set(); (Array.isArray(arr) ? arr : []).forEach(x => { if (x && x.id != null) { if (seen.has(x.id)) dup.add(x.id); else seen.add(x.id); } }); return dup; };
        const newDup = dupOf(check.mergedValue);
        if (newDup.size > 0) {
          const oldDup = dupOf(current && current[key]);
          const bad = [...newDup].find(id => !oldDup.has(id));
          if (bad !== undefined) {
            console.error('拒绝重复编号：用户 ' + req.user.username + ' 的这次保存会让 ' + key + ' 里出现重复编号 ' + bad);
            return res.status(409).json({ error: 'DUPLICATE_ID', message: '编号 ' + bad + ' 会和已有记录重复，为避免订单/回款串号已拒绝。请刷新页面后重试' });
          }
        }
      }
      finalValues[key] = check.mergedValue;
      const beforeMap = new Map(((current && Array.isArray(current[key])) ? current[key] : []).map(x => [x.id, x]));
      logBatches.push({ key, added: check.added, edited: check.edited, removed: check.removed, before: beforeMap });
    }

    // 2026-10-14 业务员不能手动乱改"已结清"状态（曾出现：业务员把 A 车误标成已结清，真正还清的 B 车反而没结清）：
    // ①业务员把合同改成已结清，必须是"本金已全部收回"；②已结清的合同业务员不能改回别的状态（只有老板能改）。
    if (req.user.role === 'sales' && current) {
      const finAll = Array.isArray(finalValues.car_finance) ? finalValues.car_finance : (Array.isArray(current.car_finance) ? current.car_finance : []);
      for (const b of logBatches) {
        if (b.key !== 'car_loans') continue;
        for (const r of b.edited) {
          const old = b.before.get(r.id);
          if (!old || old.status === r.status) continue;
          if (r.status === 'closed' && r.assetType !== 'acquired') {
            const got = finAll.filter(x => x.loanId === r.id && x.category === '本金回收').reduce((a, x) => a + (Number(x.amount) || 0), 0);
            if (got < (r.amount || 0) - 0.005) {
              return res.status(403).json({ error: 'PERMISSION_DENIED', message: '合同 ' + r.id + '（' + (r.name || '') + '）本金还没有全部收回，业务员不能标记已结清。请先登记完回款，系统会在本金收完时自动结清；如确有特殊情况请联系老板' });
            }
          }
          if (old.status === 'closed' && r.status !== 'closed') {
            return res.status(403).json({ error: 'PERMISSION_DENIED', message: '合同 ' + r.id + ' 已结清，业务员不能改回其他状态，请联系老板' });
          }
        }
      }
    }
    // 2026-10-14 本金收完自动结清：登记的回款让某张合同"累计本金回收 ≥ 贷款金额"时，服务器直接把它标成已结清。
    // （业务员的页面看不到财务金额，自己算不出"本金是否收完"，以前只能靠手动改状态，容易改错车。）
    const autoClosed = [];
    if (current && Array.isArray(finalValues.car_finance)) {
      const addedPrincipal = logBatches.filter(b => b.key === 'car_finance').flatMap(b => b.added).filter(r => r && r.category === '本金回收' && r.loanId);
      if (addedPrincipal.length > 0) {
        const loansArr = Array.isArray(finalValues.car_loans) ? finalValues.car_loans : (Array.isArray(current.car_loans) ? current.car_loans : []);
        const ids = [...new Set(addedPrincipal.map(r => r.loanId))];
        const newLoans = loansArr.map(l => Object.assign({}, l));
        ids.forEach(id => {
          const hits = newLoans.filter(l => l.id === id);
          if (hits.length !== 1) return; // 编号重复/找不到，不自动动
          const l = hits[0];
          if (l.assetType === 'acquired' || l.status === 'closed' || l.status === 'pending' || !(l.amount > 0)) return;
          const got = finalValues.car_finance.filter(x => x.loanId === id && x.category === '本金回收').reduce((a, x) => a + (Number(x.amount) || 0), 0);
          if (got >= l.amount - 0.005) { const oldSt = l.status; l.status = 'closed'; autoClosed.push({ rec: l, oldSt, got }); }
        });
        if (autoClosed.length > 0) finalValues.car_loans = newLoans;
      }
    }

    // 保存之前先存一份"保存前的完整数据"快照（有删除/整体覆盖时强制存，否则每6小时存一份）
    if (current) {
      const hasRemoval = logBatches.some(b => b.removed.length > 0);
      // 贷款的客户姓名/车牌被改成别人（疑似订单被覆盖），同样强制先留快照
      const identityChanged = logBatches.some(b => b.key === 'car_loans' && b.edited.some(r => loanIdentityChanged(b.before.get(r.id), r)));
      // 系统管理员做"批量整理"类操作（如修复重复编号）时，客户端带 _snapshotReason，强制先留一份快照
      const forcedReason = (req.user.role === 'boss' && req.user.isSuperAdmin && body && typeof body._snapshotReason === 'string') ? body._snapshotReason.slice(0, 40) : '';
      await maybeAutoSnapshot(req.user, current, forcedReason || (bulkReplace ? '整体恢复覆盖前' : (hasRemoval ? '删除记录前' : (identityChanged ? '合同客户/车牌被修改前' : '定时'))), !!forcedReason || bulkReplace || hasRemoval || identityChanged);
    }

    const rows = Object.keys(finalValues).map(key => ({ key, value: finalValues[key] })); // 含自动结清顺带改的 car_loans
    const { error } = await supabase.from('pawndata').upsert(rows, { onConflict: 'key' });
    if (error) return res.status(500).json({ error: error.message });

    // 数据写库成功之后再记操作日志（日志写失败也不影响这次保存本身，只打日志到控制台）
    try {
      let hasEntries = false;
      logBatches.forEach(b => { if (logDataChanges(req.user, b.key, b.added, b.edited, b.removed, b.before).length > 0) hasEntries = true; });
      autoClosed.forEach(a => {
        OPLOG = [{ id: genOpId(), time: new Date().toISOString(), username: 'system', displayName: '系统自动结清', role: 'boss', dataKey: 'car_loans', action: 'edit', targetId: a.rec.id, summary: '本金已全部收回($' + a.got + ')，自动标记已结清：' + summarizeLoanRecord(a.rec) }].concat(OPLOG);
        hasEntries = true;
      });
      if (OPLOG.length > OPLOG_MAX) OPLOG = OPLOG.slice(0, OPLOG_MAX);
      if (hasEntries) await persistOplog();
    } catch (logErr) {
      console.error('操作日志写入失败（不影响本次数据保存）：', logErr.message);
    }

    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// 自动快照（只有系统管理员能看/下载）
app.get('/api/autosnap', auth, async (req, res) => {
  if (req.user.role !== 'boss' || !req.user.isSuperAdmin) return res.status(403).json({ error: 'PERMISSION_DENIED', message: '只有系统管理员能查看自动快照' });
  try {
    const list = await loadAutosnaps();
    res.json({ ok: true, snapshots: list.map(x => ({ id: x.id, time: x.time, by: x.by, reason: x.reason, loanCount: x.loanCount, financeCount: x.financeCount })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/autosnap/:id', auth, async (req, res) => {
  if (req.user.role !== 'boss' || !req.user.isSuperAdmin) return res.status(403).json({ error: 'PERMISSION_DENIED', message: '只有系统管理员能下载自动快照' });
  try {
    const list = await loadAutosnaps();
    const snap = list.find(x => x.id === req.params.id);
    if (!snap) return res.status(404).json({ error: 'NOT_FOUND', message: '快照不存在' });
    res.json({ car_loans: snap.car_loans, car_finance: snap.car_finance, car_staff: snap.car_staff || [], car_payroll: snap.car_payroll || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 操作日志（只有系统管理员能看，追踪谁新增/编辑/删除了哪条贷款或财务记录）
app.get('/api/oplog', auth, async (req, res) => {
  if (req.user.role !== 'boss' || !req.user.isSuperAdmin) return res.status(403).json({ error: 'PERMISSION_DENIED', message: '只有系统管理员能查看操作日志' });
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


// ══════════════════════════════════════════════════════════
// ══ 一次性数据修正（启动时自动执行，每条只跑一次）══
// 2026-10-14：线上数据里有几处已经确认的错误（见每条 describe），老板不会也不需要自己去页面里改——
// 部署后服务器启动时自动修好。安全措施：①执行前先强制存一份完整快照（"自动快照"页可下载）；
// ②每一步都带"前置条件"校验（客户/车牌/编号/回款合计都对得上才动手，对不上就不改）；
// ③只改状态/编号，绝不删除任何合同或财务记录；④每次改动都写进操作日志；⑤出任何错都不影响系统启动，
// 下次启动会重试（成功后才会标记为已完成）。
// ══════════════════════════════════════════════════════════
const MIGRATIONS_KEY = 'car_migrations';
const normPlate = v => String(v || '').replace(/\s+/g, '').toUpperCase();
const principalOf = (fin, id) => fin.filter(r => r.loanId === id && r.category === '本金回收').reduce((a, r) => a + (Number(r.amount) || 0), 0);
const DATA_MIGRATIONS = [{
  id: '20261014-fix-status-2AW-2BX-and-dup-CL202606002',
  describe: '①编号 CL202606002 被两笔订单同时占用：2BX-1980(hour Sivmey)继续用，另一笔换新编号；②2BX-1980 本金已全部收回→改为已结清；③2AW-8077 本金没收完却被标成已结清→改回还款中',
  apply(loans, fin, notes) {
    let changed = false;
    // ① 重复编号
    const DUP = 'CL202606002';
    if (loans.filter(l => l.id === DUP).length > 1) {
      const keepIdx = loans.findIndex(l => l.id === DUP && normPlate(l.plate) === '2BX-1980');
      if (keepIdx >= 0) {
        loans.forEach((l, i) => {
          if (l.id !== DUP || i === keepIdx) return;
          const m = String(l.date || '').slice(0, 7).replace('-', '');
          const prefix = 'CL' + (m.length === 6 ? m : '202610');
          let n = 0;
          loans.forEach(x => { if (x.id && x.id.startsWith(prefix)) { const k = parseInt(x.id.slice(-3)) || 0; if (k > n) n = k; } });
          l.id = prefix + String(n + 1).padStart(3, '0');
          l.note = (l.note ? l.note + ' ' : '') + '[系统修正：原编号 ' + DUP + ' 与另一笔订单重复，已改为新编号]';
          notes.push({ id: l.id, summary: '重复编号修正：' + summarizeLoanRecord(l) + ' ｜ 原编号 ' + DUP + ' → 新编号 ' + l.id + '（与 2BX-1980 重复）' });
          changed = true;
        });
      }
    }
    // ② 2BX-1980：本金全部收回 → 已结清
    const bx = loans.filter(l => l.id === DUP && normPlate(l.plate) === '2BX-1980');
    if (bx.length === 1 && bx[0].status !== 'closed' && bx[0].assetType !== 'acquired') {
      const got = principalOf(fin, bx[0].id);
      if ((bx[0].amount || 0) > 0 && got >= bx[0].amount - 0.005) {
        const oldSt = bx[0].status; bx[0].status = 'closed'; changed = true;
        notes.push({ id: bx[0].id, summary: '状态修正：' + summarizeLoanRecord(bx[0]) + ' ｜ 本金已收回 $' + got + '，状态 ' + oldSt + ' → 已结清' });
      }
    }
    // ③ 2AW-8077：本金没收完却被标成已结清 → 还款中
    const aw = loans.filter(l => l.id === 'CL202607001' && normPlate(l.plate) === '2AW-8077');
    if (aw.length === 1 && aw[0].status === 'closed' && aw[0].assetType !== 'acquired') {
      const got = principalOf(fin, aw[0].id);
      if (got < (aw[0].amount || 0) - 0.005) {
        aw[0].status = 'active'; changed = true;
        notes.push({ id: aw[0].id, summary: '状态修正：' + summarizeLoanRecord(aw[0]) + ' ｜ 本金只收回 $' + got + '（贷款 $' + aw[0].amount + '），被误标已结清 → 改回还款中' });
      }
    }
    return changed;
  }
}, {
  // 2026-10-14：2BX-1980(hour Sivmey) 这笔合同在线上系统里消失了（贷款列表的"还款中"和"已结清"里都找不到），
  // 但它的回款记录还在。下面是它 9月26日备份里的原始完整记录（客户/电话/车牌/放款/还款计划都在）。
  // 只有"现在系统里确实没有这笔(按车牌 2BX-1980 和客户名 hour Sivmey 都找不到)"时才补回；
  // 如果它的编号 CL202606002 现在被别的订单占着，那笔订单自动换新编号，两笔都保留。
  id: '20261014-restore-2BX-1980-hour-Sivmey',
  describe: '补回丢失的合同 2BX-1980(hour Sivmey, CL202606002)，状态按回款判断',
  expectAdd: 1,
  apply(loans, fin, notes) {
    const REC = {"id": "CL202606002", "date": "2026-06-18", "name": "hour Sivmey", "note": "汽车抵押-正常贷款(导入自贵总6月表,序号53)。已收本金$3000/利息$330,未还本金$8000/利息$165。", "rate": 1.5, "term": 4, "agent": "LI", "brand": "Ford Ranger Raptor", "color": "", "model": "", "phone": "855-81454142", "plate": "2BX-1980", "repay": "先息后本", "amount": 11000, "idcard": "", "status": "active", "haircut": 10, "monthly": 165, "estimate": 0, "schedule": [{"total": 1665, "period": 1, "dueDate": "2026-07-18", "interest": 165, "principal": 1500}, {"total": 1665, "period": 2, "dueDate": "2026-08-18", "interest": 165, "principal": 1500}, {"total": 1665, "period": 3, "dueDate": "2026-09-18", "interest": 165, "principal": 1500}, {"total": 6500, "period": 4, "dueDate": "2026-10-18", "interest": 0, "principal": 6500}], "totalRepay": 11495, "actualAmount": 9900, "totalInterest": 495, "customSchedule": [{"dueDate": "2026-07-18", "interest": 165, "principal": 1500}, {"dueDate": "2026-08-18", "interest": 165, "principal": 1500}, {"dueDate": "2026-09-18", "interest": 165, "principal": 1500}, {"dueDate": "2026-10-18", "interest": 0, "principal": 6500}]};
    const exists = loans.some(l => normPlate(l.plate) === '2BX-1980' || String(l.name || '').trim().toLowerCase() === 'hour sivmey');
    if (exists) return false;
    // 编号被别的订单占着 → 占用者换新编号
    loans.forEach(l => {
      if (l.id !== REC.id) return;
      const m = String(l.date || '').slice(0, 7).replace('-', '');
      const prefix = 'CL' + (m.length === 6 ? m : '202610');
      let n = 0;
      loans.forEach(x => { if (x.id && x.id.startsWith(prefix)) { const k = parseInt(x.id.slice(-3)) || 0; if (k > n) n = k; } });
      const oldId = l.id;
      l.id = prefix + String(n + 1).padStart(3, '0');
      l.note = (l.note ? l.note + ' ' : '') + '[系统修正：原编号 ' + oldId + ' 要还给 2BX-1980(hour Sivmey)，已改为新编号]';
      notes.push({ id: l.id, summary: '重复编号修正：' + summarizeLoanRecord(l) + ' ｜ 原编号 ' + oldId + ' → 新编号 ' + l.id });
    });
    const rec = JSON.parse(JSON.stringify(REC));
    const got = principalOf(fin, rec.id);
    rec.status = (got >= rec.amount - 0.005) ? 'closed' : 'active';
    rec.note = (rec.note ? rec.note + ' ' : '') + '[系统找回：该合同在系统里丢失，已从9月26日备份恢复；本金已收回 $' + got + ']';
    loans.unshift(rec);
    notes.push({ id: rec.id, summary: '找回丢失的合同：' + summarizeLoanRecord(rec) + ' ｜ 状态：' + (rec.status === 'closed' ? '已结清（本金已全部收回）' : '还款中') });
    return true;
  }
}, {
  // 2026-10-18：导入老板给的《汽车2部 工资表 2026年9月》——8名员工，出勤 8.6666 天（9月下旬开始），
  // 已发放，计入 9月支出（日期 2026-09-30）。财务里记一笔"工资支出"= 8 人实发合计。
  // 幂等：只要系统里已经有 2026-09 的工资表就不会再导入。
  id: '20261018-import-payroll-2026-09',
  describe: '导入汽车2部 2026年9月工资表（8人），已发放，计入9月支出',
  applyAll(d, notes) {
    const MONTH = '2026-09', PAID = '2026-09-30';
    if (d.car_payroll.some(r => r.month === MONTH)) return [];
    const SRC = [{"seq": 1, "name": "HAI MENGSORNG", "nickname": "HAI MENGSORNG", "dept": "汽车2部", "status": "在职", "base": 650, "days": 8.6666, "leave": 0, "daily": 25, "attPay": 216.67, "meal": 0, "bonus": 0, "advance": 0, "deduction": 0, "net": 216.67, "commission": 0, "total": 216.67, "note": ""}, {"seq": 2, "name": "LIMENG", "nickname": "LIMENG", "dept": "汽车2部", "status": "在职", "base": 630, "days": 8.6666, "leave": 0, "daily": 24.23, "attPay": 210, "meal": 0, "bonus": 0, "advance": 0, "deduction": 0, "net": 210, "commission": 0, "total": 210, "note": ""}, {"seq": 3, "name": "RATANAK", "nickname": "RATANAK", "dept": "汽车2部", "status": "在职", "base": 350, "days": 8.6666, "leave": 0, "daily": 13.46, "attPay": 116.67, "meal": 0, "bonus": 0, "advance": 0, "deduction": 0, "net": 116.67, "commission": 0, "total": 116.67, "note": ""}, {"seq": 4, "name": "CAI XING", "nickname": "CAI XING", "dept": "汽车2部", "status": "在职", "base": 700, "days": 8.6666, "leave": 0, "daily": 26.92, "attPay": 233.33, "meal": 0, "bonus": 0, "advance": 0, "deduction": 0, "net": 233.33, "commission": 0, "total": 233.33, "note": ""}, {"seq": 5, "name": "宋喆", "nickname": "宋喆", "dept": "汽车2部", "status": "在职", "base": 1500, "days": 8.6666, "leave": 0, "daily": 57.69, "attPay": 500, "meal": 0, "bonus": 0, "advance": 0, "deduction": 0, "net": 500, "commission": 0, "total": 500, "note": ""}, {"seq": 6, "name": "公司保安", "nickname": "公司保安", "dept": "汽车2部", "status": "在职", "base": 250, "days": 8.6666, "leave": 0, "daily": 9.62, "attPay": 83.33, "meal": 0, "bonus": 0, "advance": 0, "deduction": 0, "net": 83.33, "commission": 0, "total": 83.33, "note": ""}, {"seq": 7, "name": "車庫保安", "nickname": "車庫保安", "dept": "汽车2部", "status": "在职", "base": 250, "days": 8.6666, "leave": 0, "daily": 9.62, "attPay": 83.33, "meal": 0, "bonus": 0, "advance": 0, "deduction": 0, "net": 83.33, "commission": 0, "total": 83.33, "note": ""}, {"seq": 8, "name": "清潔阿姨", "nickname": "清潔阿姨", "dept": "汽车2部", "status": "在职", "base": 270, "days": 8.6666, "leave": 0, "daily": 10.38, "attPay": 90, "meal": 0, "bonus": 0, "advance": 0, "deduction": 0, "net": 90, "commission": 0, "total": 90, "note": ""}];
    const r2 = x => Math.round((Number(x) + 1e-9) * 100) / 100;
    let maxNo = 0;
    d.car_staff.forEach(x => { const k = parseInt(String(x.id || '').replace(/\D/g, '')) || 0; if (k > maxNo) maxNo = k; });
    const staffByName = {};
    d.car_staff.forEach(x => { staffByName[x.name] = x; });
    const newPayroll = [];
    SRC.forEach(x => {
      let st = staffByName[x.name];
      if (!st) {
        maxNo++;
        st = { id: 'ST' + String(maxNo).padStart(3, '0'), name: x.name, nickname: x.nickname || '', dept: x.dept || '', status: x.status || '在职', baseSalary: x.base, joinDate: '', phone: '', note: '', createdAt: new Date().toISOString() };
        d.car_staff.push(st); staffByName[x.name] = st;
        notes.push({ key: 'car_staff', id: st.id, summary: '导入员工档案：' + summarizeStaffRecord(st) });
      }
      newPayroll.push({
        id: 'PR' + MONTH.replace('-', '') + '_' + st.id, month: MONTH, staffId: st.id, name: x.name, nickname: x.nickname || '', dept: x.dept || '',
        base: x.base, days: x.days, leave: x.leave || 0, daily: x.daily, attendancePay: x.attPay, meal: x.meal || 0, bonus: x.bonus || 0,
        advance: x.advance || 0, deduction: x.deduction || 0, net: x.net, commission: x.commission || 0, total: x.total, note: x.note || '',
        status: 'paid', paidDate: PAID, financeId: 'FPAY_' + MONTH, createdAt: new Date().toISOString()
      });
    });
    const sum = r2(newPayroll.reduce((a, x) => a + x.total, 0));
    d.car_payroll = newPayroll.concat(d.car_payroll);
    newPayroll.forEach(x => notes.push({ key: 'car_payroll', id: x.id, summary: '导入工资表：' + summarizePayrollRecord(x) }));
    const fid = 'FPAY_' + MONTH;
    if (!d.car_finance.some(r => r.id === fid)) {
      const fr = { id: fid, type: 'expense', category: '工资支出', amount: sum, date: PAID, loanId: '', payrollMonth: MONTH,
        note: '2026年9月 员工工资（' + newPayroll.length + '人）· 汽车2部 · 由工资表自动入账' };
      d.car_finance.unshift(fr);
      notes.push({ key: 'car_finance', id: fid, summary: '工资表入账：' + summarizeFinanceRecord(fr) + ' ｜ ' + fr.note });
    }
    return ['car_staff', 'car_payroll', 'car_finance'];
  }
}];
async function runDataMigrations() {
  try {
    const { data: mrow, error: merr } = await supabase.from('pawndata').select('value').eq('key', MIGRATIONS_KEY).maybeSingle();
    if (merr) throw new Error('DB_READ_ERROR: ' + merr.message);
    const done = (mrow && Array.isArray(mrow.value)) ? mrow.value.slice() : [];
    const pending = DATA_MIGRATIONS.filter(m => !done.includes(m.id));
    if (pending.length === 0) return;
    let current = await loadData();
    if (!Array.isArray(current.car_loans) || !Array.isArray(current.car_finance)) throw new Error('数据格式异常，跳过自动修正');
    ['car_staff', 'car_payroll'].forEach(k => { if (!Array.isArray(current[k])) current[k] = []; });
    const sysUser = { username: 'system', displayName: '系统数据修正', role: 'boss' };
    const KEYS = ['car_loans', 'car_finance', 'car_staff', 'car_payroll'];
    for (const m of pending) {
      const d = {};
      KEYS.forEach(k => { d[k] = JSON.parse(JSON.stringify(current[k])); });
      const notes = [];
      let changedKeys = [];
      if (m.applyAll) {
        changedKeys = m.applyAll(d, notes) || [];
        // 安全检查：自动修正只能"改/加"，不许让任何一条原有记录消失
        KEYS.forEach(k => {
          const ids = new Set(d[k].map(x => x.id));
          if (current[k].some(x => !ids.has(x.id))) throw new Error('修正会让 ' + k + ' 里的记录消失，已中止：' + m.id);
        });
      } else {
        const changed = m.apply(d.car_loans, d.car_finance, notes);
        if (changed) {
          if (d.car_loans.length - current.car_loans.length !== (m.expectAdd || 0) || d.car_finance.length !== current.car_finance.length) throw new Error('修正会改变记录条数，已中止：' + m.id);
          changedKeys = ['car_loans'];
        }
      }
      if (changedKeys.length > 0) {
        await maybeAutoSnapshot(sysUser, current, '自动数据修正前', true);
        const { error } = await supabase.from('pawndata').upsert(changedKeys.map(k => ({ key: k, value: d[k] })), { onConflict: 'key' });
        if (error) throw new Error('写入失败：' + error.message);
        const now = new Date().toISOString();
        OPLOG = notes.map(n => ({ id: genOpId(), time: now, username: sysUser.username, displayName: sysUser.displayName, role: 'boss', dataKey: n.key || 'car_loans', action: n.action || 'edit', targetId: n.id, summary: n.summary })).concat(OPLOG);
        if (OPLOG.length > OPLOG_MAX) OPLOG = OPLOG.slice(0, OPLOG_MAX);
        await persistOplog();
        changedKeys.forEach(k => { current[k] = d[k]; });
        console.log('  数据修正已执行：' + m.id + '（' + notes.length + ' 项）');
      } else {
        console.log('  数据修正无需执行（数据已是正确状态或条件不符）：' + m.id);
      }
      done.push(m.id);
      const { error: e2 } = await supabase.from('pawndata').upsert([{ key: MIGRATIONS_KEY, value: done }], { onConflict: 'key' });
      if (e2) throw new Error('迁移标记写入失败：' + e2.message);
    }
  } catch (e) {
    console.error('  自动数据修正失败（不影响系统启动，下次启动会重试）：', e.message);
  }
}

Promise.all([initUsers(), initOplog()]).then(() => runDataMigrations()).catch(e => console.error('启动初始化异常：', e && e.message)).finally(() => {
  app.listen(PORT, () => {
    console.log(`\n${'═'.repeat(50)}`);
    console.log(`  🚗 MORODOK 汽车抵押贷款管理系统`);
    console.log(`${'═'.repeat(50)}`);
    console.log(`  访问地址: http://localhost:${PORT}`);
    console.log(`${'═'.repeat(50)}\n`);
  });
});
