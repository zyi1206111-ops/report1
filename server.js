const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'mbti-admin-2024'; // 管理后台令牌，部署时修改

app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ============ 工具函数 ============

// 生成授权码（与原平台相同的32字符集，排除I/O/1/0）
const CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function generateCode(length = 8) {
  let code = '';
  const bytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    code += CHARSET[bytes[i] % CHARSET.length];
  }
  return code;
}

// 验证授权码格式
function validateCodeFormat(code) {
  if (!code || code.length !== 8) return false;
  const upper = code.toUpperCase();
  for (const c of upper) {
    if (!CHARSET.includes(c)) return false;
  }
  return true;
}

// 管理员验证中间件
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ success: false, message: '管理员验证失败' });
  }
  next();
}

// ============ 授权码相关API ============

// 验证授权码（返回状态，不激活）
app.post('/api/auth/verify', (req, res) => {
  const { code, device_fingerprint, questionnaire_key = 'mbti16stage' } = req.body;

  if (!validateCodeFormat(code)) {
    return res.json({ success: false, message: '授权码格式不正确' });
  }

  const authCode = db.prepare(
    'SELECT * FROM auth_codes WHERE code = ? AND questionnaire_key = ?'
  ).get(code.toUpperCase(), questionnaire_key);

  if (!authCode) {
    return res.json({ success: false, message: '授权码不存在' });
  }

  if (authCode.revoked) {
    return res.json({ success: false, message: '授权码已被撤销' });
  }

  // 状态判断
  if (authCode.status === 'can_activate') {
    // 未激活，可以激活
    return res.json({
      success: true,
      data: {
        status: 'can_activate',
        message: '授权码有效，可以激活'
      }
    });
  } else if (authCode.status === 'activated') {
    // 已激活，检查设备是否匹配
    if (authCode.device_fingerprint === device_fingerprint) {
      return res.json({
        success: true,
        data: {
          status: 'activated',
          message: '授权码已绑定本设备，可以继续使用',
          is_owner: true
        }
      });
    } else {
      return res.json({
        success: false,
        message: '该授权码已在其他设备使用',
        data: { status: 'device_mismatch' }
      });
    }
  }

  res.json({ success: false, message: '授权码状态异常' });
});

// 激活授权码（首次使用，绑定设备）
app.post('/api/auth/activate', (req, res) => {
  const { code, device_fingerprint, device_info = {}, questionnaire_key = 'mbti16stage' } = req.body;

  if (!validateCodeFormat(code)) {
    return res.json({ success: false, message: '授权码格式不正确' });
  }

  if (!device_fingerprint) {
    return res.json({ success: false, message: '设备指纹缺失' });
  }

  const authCode = db.prepare(
    'SELECT * FROM auth_codes WHERE code = ? AND questionnaire_key = ?'
  ).get(code.toUpperCase(), questionnaire_key);

  if (!authCode) {
    return res.json({ success: false, message: '授权码不存在' });
  }

  if (authCode.revoked) {
    return res.json({ success: false, message: '授权码已被撤销' });
  }

  // 如果已经激活且设备匹配，直接返回成功
  if (authCode.status === 'activated') {
    if (authCode.device_fingerprint === device_fingerprint) {
      // 更新最后使用时间
      db.prepare('UPDATE auth_codes SET last_used_at = CURRENT_TIMESTAMP, use_count = use_count + 1 WHERE id = ?')
        .run(authCode.id);
      return res.json({ success: true, message: '授权码已激活，设备匹配' });
    } else {
      return res.json({ success: false, message: '该授权码已在其他设备使用' });
    }
  }

  // 激活并绑定设备
  const now = new Date().toISOString();
  db.prepare(`
    UPDATE auth_codes
    SET status = 'activated',
        device_fingerprint = ?,
        device_info = ?,
        activated_at = ?,
        last_used_at = ?,
        use_count = 1
    WHERE id = ?
  `).run(device_fingerprint, JSON.stringify(device_info), now, now, authCode.id);

  // 记录设备
  db.prepare(`
    INSERT OR REPLACE INTO devices (fingerprint, user_agent, last_seen, test_count)
    VALUES (?, ?, CURRENT_TIMESTAMP, COALESCE((SELECT test_count FROM devices WHERE fingerprint = ?), 0) + 1)
  `).run(device_fingerprint, device_info.user_agent || '', device_fingerprint);

  res.json({ success: true, message: '授权码激活成功，已绑定当前设备' });
});

// 提交答案并保存报告
app.post('/api/test/submit', (req, res) => {
  const { code, device_fingerprint, mbti_type, answers, scores, total_score, stage, questionnaire_key = 'mbti16stage' } = req.body;

  if (!validateCodeFormat(code)) {
    return res.json({ success: false, message: '授权码格式不正确' });
  }

  const authCode = db.prepare('SELECT * FROM auth_codes WHERE code = ?').get(code.toUpperCase());
  if (!authCode) return res.json({ success: false, message: '授权码不存在' });
  if (authCode.status !== 'activated') return res.json({ success: false, message: '授权码未激活' });
  if (authCode.device_fingerprint !== device_fingerprint) {
    return res.json({ success: false, message: '设备不匹配' });
  }

  // 保存答题记录
  const stmt = db.prepare(`
    INSERT INTO test_records (auth_code, questionnaire_key, mbti_type, answers, scores, total_score, stage, device_fingerprint)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const result = stmt.run(
    code.toUpperCase(),
    questionnaire_key,
    mbti_type,
    JSON.stringify(answers),
    JSON.stringify(scores),
    total_score,
    stage,
    device_fingerprint
  );

  // 更新使用次数
  db.prepare('UPDATE auth_codes SET last_used_at = CURRENT_TIMESTAMP, use_count = use_count + 1 WHERE id = ?')
    .run(authCode.id);

  res.json({
    success: true,
    message: '答案提交成功',
    record_id: result.lastInsertRowid
  });
});

// 获取报告（同一设备可以重复查看）
app.post('/api/test/report', (req, res) => {
  const { code, device_fingerprint, questionnaire_key = 'mbti16stage' } = req.body;

  if (!validateCodeFormat(code)) {
    return res.json({ success: false, message: '授权码格式不正确' });
  }

  const authCode = db.prepare('SELECT * FROM auth_codes WHERE code = ?').get(code.toUpperCase());
  if (!authCode) return res.json({ success: false, message: '授权码不存在' });
  if (authCode.device_fingerprint !== device_fingerprint) {
    return res.json({ success: false, message: '设备不匹配，无法查看报告' });
  }

  // 获取最新的测试记录
  const record = db.prepare(`
    SELECT * FROM test_records
    WHERE auth_code = ? AND questionnaire_key = ?
    ORDER BY created_at DESC LIMIT 1
  `).get(code.toUpperCase(), questionnaire_key);

  if (!record) {
    return res.json({ success: false, message: '尚未找到测试记录', data: null });
  }

  res.json({
    success: true,
    data: {
      id: record.id,
      mbti_type: record.mbti_type,
      answers: JSON.parse(record.answers),
      scores: JSON.parse(record.scores),
      total_score: record.total_score,
      stage: record.stage,
      created_at: record.created_at
    }
  });
});

// ============ 管理员API ============

// 管理员登录
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  const admin = db.prepare('SELECT * FROM admins WHERE username = ? AND password = ?').get(username, hash);
  if (admin) {
    res.json({ success: true, token: ADMIN_TOKEN });
  } else {
    res.json({ success: false, message: '用户名或密码错误' });
  }
});

// 批量生成授权码
app.post('/api/admin/generate', requireAdmin, (req, res) => {
  const { count = 50, questionnaire_key = 'mbti16stage' } = req.body;
  const num = Math.min(parseInt(count) || 50, 5000);

  const codes = [];
  const insertStmt = db.prepare('INSERT OR IGNORE INTO auth_codes (code, questionnaire_key) VALUES (?, ?)');

  let generated = 0;
  let attempts = 0;
  while (generated < num && attempts < num * 5) {
    const code = generateCode(8);
    const result = insertStmt.run(code, questionnaire_key);
    if (result.changes > 0) {
      codes.push(code);
      generated++;
    }
    attempts++;
  }

  res.json({
    success: true,
    message: `成功生成 ${generated} 个授权码`,
    count: generated,
    codes: codes
  });
});

// 获取授权码列表
app.get('/api/admin/codes', requireAdmin, (req, res) => {
  const { status, page = 1, pageSize = 50, search = '' } = req.query;
  let where = 'WHERE 1=1';
  const params = [];

  if (status) {
    where += ' AND status = ?';
    params.push(status);
  }
  if (search) {
    where += ' AND code LIKE ?';
    params.push('%' + search.toUpperCase() + '%');
  }

  const offset = (parseInt(page) - 1) * parseInt(pageSize);
  const codes = db.prepare(`
    SELECT * FROM auth_codes ${where}
    ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(...params, parseInt(pageSize), offset);

  const total = db.prepare(`SELECT COUNT(*) as count FROM auth_codes ${where}`).get(...params).count;

  res.json({ success: true, data: codes, total, page: parseInt(page), pageSize: parseInt(pageSize) });
});

// 撤销授权码
app.put('/api/admin/codes/:id/revoke', requireAdmin, (req, res) => {
  const { id } = req.params;
  db.prepare('UPDATE auth_codes SET revoked = 1 WHERE id = ?').run(id);
  res.json({ success: true, message: '授权码已撤销' });
});

// 统计数据
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as count FROM auth_codes').get().count;
  const activated = db.prepare("SELECT COUNT(*) as count FROM auth_codes WHERE status = 'activated'").get().count;
  const canActivate = db.prepare("SELECT COUNT(*) as count FROM auth_codes WHERE status = 'can_activate'").get().count;
  const revoked = db.prepare('SELECT COUNT(*) as count FROM auth_codes WHERE revoked = 1').get().count;
  const testCount = db.prepare('SELECT COUNT(*) as count FROM test_records').get().count;
  const deviceCount = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;

  // 今日数据
  const today = new Date().toISOString().split('T')[0];
  const todayCodes = db.prepare("SELECT COUNT(*) as count FROM auth_codes WHERE DATE(created_at) = ?").get(today).count;
  const todayTests = db.prepare("SELECT COUNT(*) as count FROM test_records WHERE DATE(created_at) = ?").get(today).count;

  res.json({
    success: true,
    data: {
      total_codes: total,
      activated,
      can_activate: canActivate,
      revoked,
      total_tests: testCount,
      total_devices: deviceCount,
      today_codes: todayCodes,
      today_tests: todayTests
    }
  });
});

// 导出授权码（CSV）
app.get('/api/admin/export', requireAdmin, (req, res) => {
  const { status = '' } = req.query;
  let where = 'WHERE 1=1';
  const params = [];
  if (status) { where += ' AND status = ?'; params.push(status); }

  const codes = db.prepare(`SELECT code, status, device_fingerprint, created_at, activated_at, use_count FROM auth_codes ${where} ORDER BY created_at DESC`).all(...params);

  let csv = '授权码,状态,设备指纹,创建时间,激活时间,使用次数\n';
  codes.forEach(c => {
    csv += `${c.code},${c.status},${c.device_fingerprint || '未绑定'},${c.created_at},${c.activated_at || '未激活'},${c.use_count}\n`;
  });

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename=auth_codes.csv');
  res.send('\ufeff' + csv);
});

// ============ 页面路由 ============

// 测试页面
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 管理后台
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 启动服务
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║   MBTI心智阶位测评系统已启动                  ║
║                                              ║
║   测试页面: http://localhost:${PORT}           ║
║   管理后台: http://localhost:${PORT}/admin     ║
║                                              ║
║   管理员令牌: ${ADMIN_TOKEN}   ║
║   默认账号: admin / admin123                  ║
╚══════════════════════════════════════════════╝
  `);
});
