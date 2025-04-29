require('dotenv').config();
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const express = require('express');
const app = express();
app.use(cors({
  origin: ['https://your-frontend.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 } // 1시간
}));

// MySQL 연결 설정
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// 질문 리스트 API (페이지네이션)
app.get('/api/questions', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 7;
  const offset = (page - 1) * limit;

  db.query('SELECT COUNT(*) as total FROM questions', (err, countResult) => {
    if (err) return res.status(500).json({ error: 'DB 오류' });
    const total = countResult[0].total;
    db.query('SELECT id, text FROM questions ORDER BY id ASC LIMIT ? OFFSET ?', [limit, offset], (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB 오류' });
      res.json({
        questions: rows,
        total
      });
    });
  });
});

// 기존 결과 제출 API
app.post('/api/mbti/submit', (req, res) => {
  const answers = req.body.answers;
  const gender = req.body.gender;
  res.json({ mbtiType: 'ESFP-T' });
});

// 회원가입 API
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: '모든 항목을 입력하세요.' });
  }
  try {
    // 이메일 또는 username 중복 체크
    db.query('SELECT id FROM users WHERE email = ? OR username = ?', [email, username], async (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB 오류' });
      if (rows.length > 0) {
        return res.status(409).json({ error: '이미 존재하는 이메일 또는 닉네임입니다.' });
      }
      // 비밀번호 해시
      const hash = await bcrypt.hash(password, 10);
      db.query(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hash],
        (err, result) => {
          if (err) return res.status(500).json({ error: 'DB 오류' });
          res.json({ success: true });
        }
      );
    });
  } catch (e) {
    res.status(500).json({ error: '서버 오류' });
  }
});

// 로그인 API
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: '이메일과 비밀번호를 입력하세요.' });
  }
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류' });
    if (rows.length === 0) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다.' });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다.' });
    }
    // 로그인 성공: 세션 등록
    req.session.user = { id: user.id, username: user.username, email: user.email };
    res.json({ success: true, username: user.username, email: user.email });
  });
});

// 세션 정보 확인 API
app.get('/api/session', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// 로그아웃 API
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: '로그아웃 실패' });
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// 닉네임 중복확인 API
app.get('/api/check-username', (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: '닉네임을 입력하세요.' });
  db.query('SELECT id FROM users WHERE username = ?', [username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류' });
    if (rows.length > 0) {
      return res.json({ exists: true });
    } else {
      return res.json({ exists: false });
    }
  });
});

// MBTI 결과 조회 API
app.get('/api/results/:typeCode', (req, res) => {
  const { typeCode } = req.params;
  db.query('SELECT * FROM mbti_results WHERE type_code = ?', [typeCode], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류' });
    if (rows.length === 0) {
      return res.status(404).json({ error: '결과를 찾을 수 없습니다.' });
    }
    const result = rows[0];
    // keywords는 JSON 문자열이므로 파싱
    try {
      result.keywords = JSON.parse(result.keywords);
    } catch (e) {
      result.keywords = [];
    }
    res.json(result);
  });
});

app.listen(5001, () => {
  console.log('백엔드 서버가 5001번 포트에서 실행 중입니다.');
});