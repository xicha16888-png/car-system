const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

// Key 藏在环境变量里，前端看不到
const SUPABASE_URL = (process.env.SUPABASE_URL || '').trim();
const SUPABASE_KEY = (process.env.SUPABASE_KEY || '').trim();
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

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

// 读取所有数据
app.get('/api/data', async (req, res) => {
  try {
    const data = await loadData();
    if (!Array.isArray(data.car_loans)) data.car_loans = [];
    if (!Array.isArray(data.car_finance)) data.car_finance = [];
    if (!data.car_nextId) data.car_nextId = 1;
    res.json(data);
  } catch(e) {
    res.status(500).json({ error: 'DB_ERROR', message: e.message });
  }
});

// 保存数据
app.post('/api/data', async (req, res) => {
  try {
    const body = req.body;
    const allowed = ['car_loans', 'car_finance', 'car_nextId'];
    const rows = Object.entries(body)
      .filter(([k]) => allowed.includes(k))
      .map(([key, value]) => ({ key, value }));
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

// 备份数据
app.get('/api/backup', async (req, res) => {
  try {
    const data = await loadData();
    res.setHeader('Content-Disposition', `attachment; filename="car_backup_${new Date().toISOString().slice(0,10)}.json"`);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(data, null, 2));
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n${'═'.repeat(50)}`);
  console.log(`  🚗 MORODOK 汽车抵押贷款管理系统`);
  console.log(`${'═'.repeat(50)}`);
  console.log(`  访问地址: http://localhost:${PORT}`);
  console.log(`${'═'.repeat(50)}\n`);
});
