const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'data', 'test.db');
const db = new Database(dbPath);

// 初始化数据库表
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// 授权码表
db.exec(`
  CREATE TABLE IF NOT EXISTS auth_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    questionnaire_key TEXT DEFAULT 'mbti16stage',
    status TEXT DEFAULT 'can_activate',
    device_fingerprint TEXT,
    device_info TEXT,
    activated_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    use_count INTEGER DEFAULT 0,
    revoked INTEGER DEFAULT 0
  );
`);

// 答题记录表
db.exec(`
  CREATE TABLE IF NOT EXISTS test_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_code TEXT NOT NULL,
    questionnaire_key TEXT DEFAULT 'mbti16stage',
    mbti_type TEXT,
    answers TEXT,
    scores TEXT,
    total_score INTEGER,
    stage TEXT,
    device_fingerprint TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// 设备表（记录设备信息）
db.exec(`
  CREATE TABLE IF NOT EXISTS devices (
    fingerprint TEXT PRIMARY KEY,
    user_agent TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    test_count INTEGER DEFAULT 0
  );
`);

// 管理员表
db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// 创建默认管理员（用户名admin，密码admin123，首次登录后建议修改）
const adminExists = db.prepare('SELECT id FROM admins WHERE username = ?').get('admin');
if (!adminExists) {
  const crypto = require('crypto');
  const hash = crypto.createHash('sha256').update('admin123').digest('hex');
  db.prepare('INSERT INTO admins (username, password) VALUES (?, ?)').run('admin', hash);
  console.log('默认管理员已创建: admin / admin123');
}

// 创建索引
db.exec('CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON auth_codes(code);');
db.exec('CREATE INDEX IF NOT EXISTS idx_auth_codes_device ON auth_codes(device_fingerprint);');
db.exec('CREATE INDEX IF NOT EXISTS idx_test_records_code ON test_records(auth_code);');

module.exports = db;
