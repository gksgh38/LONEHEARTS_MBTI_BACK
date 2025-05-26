require('dotenv').config();
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const express = require('express');
const app = express();
app.set('trust proxy', 1);
app.use(cors({
  origin: [
    'https://lonehearts-mbti-front.vercel.app',
    'http://localhost:3000'
  ],
  credentials: true
}));
app.use(express.json());

const isProduction = process.env.NODE_ENV === 'production';

const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  // 기타 옵션 (optional)
});

app.use(session({
  key: 'connect.sid',
  secret: process.env.SESSION_SECRET,
  store: sessionStore, // 세션 저장소로 MySQL 사용
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60,
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax',
    secure: isProduction // 배포(https)에서는 true, 개발(http)에서는 false
  }
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
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    const total = countResult[0].total;
    db.query('SELECT id, text, is_reverse FROM questions ORDER BY id ASC LIMIT ? OFFSET ?', [limit, offset], (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
      res.json({
        questions: rows,
        total
      });
    });
  });
});

// answers: [{questionId: 1, value: 5}, ...] (총 60개, 1~60번)
async function getClosestKmbtiCode(answers, db) {
  // 0. 모든 문항의 is_reverse 정보 조회
  const [questionRows] = await db.promise().query('SELECT id, is_reverse FROM questions ORDER BY id ASC');
  const reverseMap = {};
  questionRows.forEach(q => { reverseMap[q.id] = !!q.is_reverse; });

  // 1. A~J 그룹별 평균 구하기 (역채점 적용)
  const groupKeys = ['A','B','C','D','E','F','G','H','I','J'];
  const groupAverages = {};
  for (let i = 0; i < 10; i++) {
    // 각 그룹별 6개 문항의 값 추출 (역채점 적용)
    const groupAnswers = answers
      .filter(a => a.questionId > i * 6 && a.questionId <= (i + 1) * 6)
      .map(a => reverseMap[a.questionId] ? (6 - a.value) : a.value);
    // 평균 계산
    groupAverages[groupKeys[i]] = groupAnswers.reduce((sum, v) => sum + v, 0) / groupAnswers.length;
  }

  // 2. DB에서 모든 kmbti_score_distribution 데이터 가져오기
  const [rows] = await db.promise().query('SELECT * FROM kmbti_score_distribution');

  // 3. 각 유형별로 min/max 기반 거리 계산
  let minDistance = Infinity;
  let bestKmbtiCode = null;
  for (const row of rows) {
    let distance = 0;
    for (const key of groupKeys) {
      const min = Number(row[`score_${key}_min`]);
      const max = Number(row[`score_${key}_max`]);
      const avg = groupAverages[key];
      if (avg < min) distance += (min - avg);
      else if (avg > max) distance += (avg - max);
      // 범위 내면 거리 0
    }
    if (distance < minDistance) {
      minDistance = distance;
      bestKmbtiCode = row.kmbti_code;
    }
  }
  return bestKmbtiCode;
}

// 결과 제출 API
app.post('/api/kmbti/submit', async (req, res) => {
  const answers = req.body.answers;
  const gender = req.body.gender;
  
  const typeCode = await getClosestKmbtiCode(answers, db);
  db.query('SELECT * FROM kmbti_results WHERE type_code = ?', [typeCode], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    if (rows.length === 0) {
      return res.status(404).json({ error: '결과를 찾을 수 없습니다.' });
    }
    res.json(rows[0]);
  });
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
      if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
      if (rows.length > 0) {
        return res.status(409).json({ error: '이미 존재하는 이메일 또는 닉네임입니다.' });
      }
      // 비밀번호 해시
      const hash = await bcrypt.hash(password, 10);
      db.query(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hash],
        (err, result) => {
          if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
          res.json({ success: true });
        }
      );
    });
  } catch (e) {
    res.status(500).json({ error: '서버 오류' });
  }
});

// 로그인 API
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: '이메일과 비밀번호를 입력하세요.' });
  }
  try {
    const [rows] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다.' });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다.' });
    }
    const isAdmin = user.email === process.env.ADMIN_EMAIL;    
    req.session.user = { id: user.id, username: user.username, email: user.email, isAdmin };
    req.session.save(err => {
      if (err) return res.status(500).json({ error: '세션 저장 오류' });
      return res.json({ success: true, username: user.username, email: user.email, isAdmin });
    });
  } catch (err) {
    return res.status(500).json({ error: 'DB 오류', detail: err.message });
  }
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
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    if (rows.length > 0) {
      return res.json({ exists: true });
    } else {
      return res.json({ exists: false });
    }
  });
});

// KMBTI 결과 조회 API
app.get('/api/kmbti-results/:typeCode', (req, res) => {
  const { typeCode } = req.params;
  db.query('SELECT * FROM kmbti_results WHERE type_code = ?', [typeCode], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
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

function adminOnly(req, res, next) {
  if (!req.session.user || !req.session.user.isAdmin || req.session.user.email !== process.env.ADMIN_EMAIL) {
    return res.status(403).json({ error: '관리자만 접근할 수 있습니다.' });
  }
  next();
}

// 문항 수정(관리자) API
app.post('/api/admin/update-questions', adminOnly, (req, res) => {
  const questions = req.body.questions; // [{id, text, is_reverse}, ...]
  if (!Array.isArray(questions)) {
    return res.status(400).json({ error: '잘못된 요청입니다.' });
  }
  // 여러 문항을 한 번에 업데이트
  const updates = questions.map(q =>
    new Promise((resolve, reject) => {
      db.query('UPDATE questions SET text = ?, is_reverse = ? WHERE id = ?', [q.text, !!q.is_reverse, q.id], (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    })
  );
  Promise.all(updates)
    .then(() => res.json({ success: true }))
    .catch(() => res.status(500).json({ error: 'DB 업데이트 오류', detail: err.message }));
});

// KMBTI 점수분포(CRUD) API
// 전체 조회
app.get('/api/admin/kmbti-score-distributions', adminOnly, (req, res) => {
  db.query('SELECT * FROM kmbti_score_distribution ORDER BY kmbti_type_name ASC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    res.json(rows);
  });
});
// 단일 조회
app.get('/api/admin/kmbti-score-distributions/:id', adminOnly, (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM kmbti_score_distribution WHERE kmbti_type_name = ?', [id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    if (rows.length === 0) return res.status(404).json({ error: '해당 유형 없음' });
    res.json(rows[0]);
  });
});
// 생성
app.post('/api/admin/kmbti-score-distributions', adminOnly, (req, res) => {
  const {
    kmbti_type_name, kmbti_code,
    score_A_min, score_A_max, score_B_min, score_B_max, score_C_min, score_C_max, score_D_min, score_D_max, score_E_min, score_E_max,
    score_F_min, score_F_max, score_G_min, score_G_max, score_H_min, score_H_max, score_I_min, score_I_max, score_J_min, score_J_max
  } = req.body;
  if (!kmbti_type_name || !kmbti_code) {
    return res.status(400).json({ error: '필수값 누락' });
  }
  db.query(
    "INSERT INTO kmbti_score_distribution (kmbti_type_name, kmbti_code, score_A_min, score_A_max, score_B_min, score_B_max, score_C_min, score_C_max, score_D_min, score_D_max, score_E_min, score_E_max, score_F_min, score_F_max, score_G_min, score_G_max, score_H_min, score_H_max, score_I_min, score_I_max, score_J_min, score_J_max) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      kmbti_type_name, kmbti_code,
      score_A_min, score_A_max, score_B_min, score_B_max, score_C_min, score_C_max, score_D_min, score_D_max, score_E_min, score_E_max,
      score_F_min, score_F_max, score_G_min, score_G_max, score_H_min, score_H_max, score_I_min, score_I_max, score_J_min, score_J_max
    ],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
      // kmbti_results에도 자동 추가
      const emptyResultJson = {
        summary: "",
        keywords: [],
        traits: [
          { name: "감정표현", type: "", percent: 0, desc: "" },
          { name: "목표추진성", type: "", percent: 0, desc: "" },
          { name: "사회적 에너지", type: "", percent: 0, desc: "" },
          { name: "자기인식력", type: "", percent: 0, desc: "" }
        ],
        strengths: [],
        watchouts: [],
        relation_advice: { summary: "", guides: [] },
        relation_style: { summary: "", styles: [] },
        activity: { summary: "", activities: [] }
      };
      db.query(
        'INSERT INTO kmbti_results (type_code, type_name, result_json) VALUES (?, ?, ?)',
        [kmbti_code, kmbti_type_name, JSON.stringify(emptyResultJson)],
        (err2) => {
          if (err2) return res.status(500).json({ error: 'DB 오류(결과 자동생성)', detail: err2.message });
          res.json({ success: true, id: kmbti_type_name });
        }
      );
    }
  );
});
// 수정
app.put('/api/admin/kmbti-score-distributions/:id', adminOnly, (req, res) => {
  const { id } = req.params;
  const {
    kmbti_code,
    score_A_min, score_A_max, score_B_min, score_B_max, score_C_min, score_C_max, score_D_min, score_D_max, score_E_min, score_E_max,
    score_F_min, score_F_max, score_G_min, score_G_max, score_H_min, score_H_max, score_I_min, score_I_max, score_J_min, score_J_max
  } = req.body;
  db.query(
    `UPDATE kmbti_score_distribution SET kmbti_code=?, score_A_min=?, score_A_max=?, score_B_min=?, score_B_max=?, score_C_min=?, score_C_max=?, score_D_min=?, score_D_max=?, score_E_min=?, score_E_max=?, score_F_min=?, score_F_max=?, score_G_min=?, score_G_max=?, score_H_min=?, score_H_max=?, score_I_min=?, score_I_max=?, score_J_min=?, score_J_max=? WHERE kmbti_type_name=?`,
    [
      kmbti_code,
      score_A_min, score_A_max, score_B_min, score_B_max, score_C_min, score_C_max, score_D_min, score_D_max, score_E_min, score_E_max,
      score_F_min, score_F_max, score_G_min, score_G_max, score_H_min, score_H_max, score_I_min, score_I_max, score_J_min, score_J_max,
      id
    ],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
      res.json({ success: true });
    }
  );
});
// 삭제
app.delete('/api/admin/kmbti-score-distributions/:id', adminOnly, (req, res) => {
  const { id } = req.params;
  // 먼저 kmbti_score_distribution에서 삭제
  db.query('DELETE FROM kmbti_score_distribution WHERE kmbti_type_name = ?', [id], (err, result) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    // kmbti_results에서도 type_name 또는 type_code로 삭제
    db.query('DELETE FROM kmbti_results WHERE type_name = ? OR type_code = (SELECT kmbti_code FROM kmbti_score_distribution WHERE kmbti_type_name = ?)', [id, id], (err2) => {
      if (err2) return res.status(500).json({ error: 'kmbti_results 삭제 오류', detail: err2.message });
      res.json({ success: true });
    });
  });
});

// 인증 확인 미들웨어
function authRequired(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }
  next();
}

// 커뮤니티 게시글 목록 조회 API (페이지네이션)
app.get('/api/community/posts', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 30;
  const offset = (page - 1) * limit;

  // 총 게시글 수 조회
  db.query('SELECT COUNT(*) as total FROM board_community', (err, countResult) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    const total = countResult[0].total;
    const totalPages = Math.ceil(total / limit);
    
    // 게시글 목록 조회 (작성자 정보 포함)
    const query = `
      SELECT b.id, b.title, b.content, b.created_at, b.updated_at, 
             b.author_id, u.username as author_name
      FROM board_community b
      JOIN users u ON b.author_id = u.id
      ORDER BY b.created_at DESC
      LIMIT ? OFFSET ?
    `;
    
    db.query(query, [limit, offset], (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
      
      res.json({
        posts: rows,
        total,
        totalPages,
        currentPage: page,
        hasMore: page < totalPages
      });
    });
  });
});

// 커뮤니티 게시글 등록 API
app.post('/api/community/posts', authRequired, (req, res) => {
  const { title, content } = req.body;
  const authorId = req.session.user.id;
  
  // 입력값 검증
  if (!title || !content) {
    return res.status(400).json({ error: '제목과 내용을 모두 입력해주세요.' });
  }
  
  if (title.length > 255) {
    return res.status(400).json({ error: '제목은 255자 이내로 작성해주세요.' });
  }
  
  // 게시글 저장
  const query = 'INSERT INTO board_community (author_id, title, content) VALUES (?, ?, ?)';
  db.query(query, [authorId, title, content], (err, result) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    // 생성된 게시글 ID와 함께 성공 응답
    res.status(201).json({ 
      success: true, 
      postId: result.insertId,
      message: '게시글이 등록되었습니다.'
    });
  });
});

// 게시물 수정 API
app.put('/api/community/posts/:id', authRequired, (req, res) => {
  const postId = parseInt(req.params.id);
  const { title, content } = req.body;
  const userId = req.session.user.id;
  const isAdmin = req.session.user.isAdmin;
  
  // 입력값 검증
  if (!title || !content) {
    return res.status(400).json({ error: '제목과 내용을 모두 입력해주세요.' });
  }
  
  if (title.length > 255) {
    return res.status(400).json({ error: '제목은 255자 이내로 작성해주세요.' });
  }
  
  // 게시물 존재 및 권한 확인
  db.query('SELECT author_id FROM board_community WHERE id = ?', [postId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    if (rows.length === 0) {
      return res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    }
    
    const authorId = rows[0].author_id;
    
    // 작성자 본인이거나 관리자만 수정 가능
    if (authorId !== userId && !isAdmin) {
      return res.status(403).json({ error: '이 게시물을 수정할 권한이 없습니다.' });
    }
    
    // 게시물 수정
    db.query(
      'UPDATE board_community SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [title, content, postId],
      (updateErr, result) => {
        if (updateErr) return res.status(500).json({ error: 'DB 오류', detail: updateErr.message });
        
        res.json({ 
          success: true, 
          message: '게시물이 수정되었습니다.'
        });
      }
    );
  });
});

// 커뮤니티 게시물 개수 조회 API
app.get('/api/community/posts/count', (req, res) => {
  db.query('SELECT COUNT(*) as total FROM board_community', (err, result) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    const total = result[0].total;
    res.json({ total });
  });
});

// 커뮤니티 게시물 상세 조회 API
app.get('/api/community/posts/:id', (req, res) => {
  const postId = parseInt(req.params.id);
  
  if (isNaN(postId)) {
    return res.status(400).json({ error: '유효하지 않은 게시물 ID입니다.' });
  }
  
  // 게시물 정보와 작성자 정보를 함께 조회
  const query = `
    SELECT b.id, b.title, b.content, b.created_at, b.updated_at, 
           b.author_id, u.username as author_name
    FROM board_community b
    JOIN users u ON b.author_id = u.id
    WHERE b.id = ?
  `;
  
  db.query(query, [postId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    if (rows.length === 0) {
      return res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    }
    
    res.json(rows[0]);
  });
});

// 게시물 삭제 API
app.delete('/api/community/posts/:id', authRequired, (req, res) => {
  const postId = parseInt(req.params.id);
  const userId = req.session.user.id;
  const isAdmin = req.session.user.isAdmin;
  
  // 게시물 존재 및 권한 확인
  db.query('SELECT author_id FROM board_community WHERE id = ?', [postId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    if (rows.length === 0) {
      return res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    }
    
    const authorId = rows[0].author_id;
    
    // 작성자 본인이거나 관리자만 삭제 가능
    if (authorId !== userId && !isAdmin) {
      return res.status(403).json({ error: '이 게시물을 삭제할 권한이 없습니다.' });
    }
    
    // 게시물 삭제
    db.query('DELETE FROM board_community WHERE id = ?', [postId], (deleteErr, result) => {
      if (deleteErr) return res.status(500).json({ error: 'DB 오류', detail: deleteErr.message });
      
      res.json({ 
        success: true, 
        message: '게시물이 삭제되었습니다.'
      });
    });
  });
});

// QnA 게시글 목록 조회 API (페이지네이션)
app.get('/api/qna/posts', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 30;
  const offset = (page - 1) * limit;

  // 총 게시글 수 조회
  db.query('SELECT COUNT(*) as total FROM board_qna', (err, countResult) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    const total = countResult[0].total;
    const totalPages = Math.ceil(total / limit);
    
    // 게시글 목록 조회 (작성자 정보 포함)
    const query = `
      SELECT b.id, b.title, b.content, b.created_at, b.updated_at, 
             b.author_id, u.username as author_name
      FROM board_qna b
      JOIN users u ON b.author_id = u.id
      ORDER BY b.created_at DESC
      LIMIT ? OFFSET ?
    `;
    
    db.query(query, [limit, offset], (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
      
      res.json({
        posts: rows,
        total,
        totalPages,
        currentPage: page,
        hasMore: page < totalPages
      });
    });
  });
});

// QnA 게시물 개수 조회 API
app.get('/api/qna/posts/count', (req, res) => {
  db.query('SELECT COUNT(*) as total FROM board_qna', (err, result) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    const total = result[0].total;
    res.json({ total });
  });
});

// QnA 게시물 상세 조회 API
app.get('/api/qna/posts/:id', (req, res) => {
  const postId = parseInt(req.params.id);
  
  if (isNaN(postId)) {
    return res.status(400).json({ error: '유효하지 않은 게시물 ID입니다.' });
  }
  
  // 게시물 정보와 작성자 정보를 함께 조회
  const query = `
    SELECT b.id, b.title, b.content, b.created_at, b.updated_at, 
           b.author_id, u.username as author_name
    FROM board_qna b
    JOIN users u ON b.author_id = u.id
    WHERE b.id = ?
  `;
  
  db.query(query, [postId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    if (rows.length === 0) {
      return res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    }
    
    res.json(rows[0]);
  });
});

// QnA 게시글 등록 API (관리자만 가능)
app.post('/api/qna/posts', adminOnly, (req, res) => {
  const { title, content } = req.body;
  const authorId = req.session.user.id;
  
  // 입력값 검증
  if (!title || !content) {
    return res.status(400).json({ error: '제목과 내용을 모두 입력해주세요.' });
  }
  
  if (title.length > 255) {
    return res.status(400).json({ error: '제목은 255자 이내로 작성해주세요.' });
  }
  
  // 게시글 저장
  const query = 'INSERT INTO board_qna (author_id, title, content) VALUES (?, ?, ?)';
  db.query(query, [authorId, title, content], (err, result) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    // 생성된 게시글 ID와 함께 성공 응답
    res.status(201).json({ 
      success: true, 
      postId: result.insertId,
      message: 'QnA 게시글이 등록되었습니다.'
    });
  });
});

// QnA 게시물 수정 API (관리자만 가능)
app.put('/api/qna/posts/:id', adminOnly, (req, res) => {
  const postId = parseInt(req.params.id);
  const { title, content } = req.body;
  
  // 입력값 검증
  if (!title || !content) {
    return res.status(400).json({ error: '제목과 내용을 모두 입력해주세요.' });
  }
  
  if (title.length > 255) {
    return res.status(400).json({ error: '제목은 255자 이내로 작성해주세요.' });
  }
  
  // 게시물 존재 확인
  db.query('SELECT id FROM board_qna WHERE id = ?', [postId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    if (rows.length === 0) {
      return res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    }
    
    // 게시물 수정
    db.query(
      'UPDATE board_qna SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [title, content, postId],
      (updateErr, result) => {
        if (updateErr) return res.status(500).json({ error: 'DB 오류', detail: updateErr.message });
        
        res.json({ 
          success: true, 
          message: 'QnA 게시물이 수정되었습니다.'
        });
      }
    );
  });
});

// QnA 게시물 삭제 API (관리자만 가능)
app.delete('/api/qna/posts/:id', adminOnly, (req, res) => {
  const postId = parseInt(req.params.id);
  
  // 게시물 존재 확인
  db.query('SELECT id FROM board_qna WHERE id = ?', [postId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    
    if (rows.length === 0) {
      return res.status(404).json({ error: '게시물을 찾을 수 없습니다.' });
    }
    
    // 게시물 삭제
    db.query('DELETE FROM board_qna WHERE id = ?', [postId], (deleteErr, result) => {
      if (deleteErr) return res.status(500).json({ error: 'DB 오류', detail: deleteErr.message });
      
      res.json({ 
        success: true, 
        message: 'QnA 게시물이 삭제되었습니다.'
      });
    });
  });
});

// KMBTI 결과 전체 목록 조회
app.get('/api/admin/kmbti-results', adminOnly, (req, res) => {
  db.query('SELECT * FROM kmbti_results ORDER BY id ASC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    res.json(rows);
  });
});

// KMBTI 결과 생성
app.post('/api/admin/kmbti-results', adminOnly, (req, res) => {
  const { type_code, type_name, result_json } = req.body;
  if (!type_code || !type_name || !result_json) {
    return res.status(400).json({ error: '필수값 누락' });
  }
  db.query(
    'INSERT INTO kmbti_results (type_code, type_name, result_json) VALUES (?, ?, ?)',
    [type_code, type_name, JSON.stringify(result_json)],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
      res.json({ success: true, id: result.insertId });
    }
  );
});

// KMBTI 결과 수정
app.put('/api/admin/kmbti-results/:typeCode', adminOnly, (req, res) => {
  const { typeCode } = req.params;
  const { type_name, result_json } = req.body;
  if (!type_name || !result_json) {
    return res.status(400).json({ error: '필수값 누락' });
  }
  db.query(
    'UPDATE kmbti_results SET type_name = ?, result_json = ? WHERE type_code = ?',
    [type_name, JSON.stringify(result_json), typeCode],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
      res.json({ success: true });
    }
  );
});

// KMBTI 결과 삭제
app.delete('/api/admin/kmbti-results/:typeCode', adminOnly, (req, res) => {
  const { typeCode } = req.params;
  db.query('DELETE FROM kmbti_results WHERE type_code = ?', [typeCode], (err, result) => {
    if (err) return res.status(500).json({ error: 'DB 오류', detail: err.message });
    res.json({ success: true });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`백엔드 서버가 ${PORT}번 포트에서 실행 중입니다.`);
  console.log('NODE_ENV:', process.env.NODE_ENV);
});