import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import argon2 from 'argon2';
import pg from 'pg';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT || 10000);
const isProd = process.env.NODE_ENV === 'production';

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 8000
    })
  : null;

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false
});

function jsonError(res, status, message) {
  return res.status(status).json({ error: message });
}

function newSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function setSessionCookie(res, id) {
  res.cookie('thiral_session', id, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000,
    path: '/'
  });
}

function clearSessionCookie(res) {
  res.clearCookie('thiral_session', {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/'
  });
}

async function currentUser(req) {
  if (!pool) return null;
  const sid = req.cookies?.thiral_session;
  if (!sid) return null;
  const { rows } = await pool.query(
    `SELECT u.id,u.student_id,u.name,u.email,u.phone,u.dob,u.gender,
            u.role,u.last_login_at,s.expires_at
       FROM sessions s
       JOIN users u ON u.id=s.user_id
      WHERE s.id=$1 AND s.expires_at>now() AND u.is_active=true
      LIMIT 1`,
    [sid]
  );
  return rows[0] || null;
}

async function requireAuth(req, res, next) {
  try {
    req.user = await currentUser(req);
    if (!req.user) return jsonError(res, 401, 'Authentication required.');
    next();
  } catch (e) {
    console.error('Auth error:', e);
    jsonError(res, 500, 'Authentication service error.');
  }
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, () => {
    if (req.user.role !== 'ADMIN') return jsonError(res, 403, 'Admin access required.');
    next();
  });
}

app.get('/health', async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false, service: 'Thiral V139', database: 'missing' });
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'Thiral V139', database: 'ok', time: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ ok: false, service: 'Thiral V139', database: 'error' });
  }
});

const api = express.Router();
api.use(apiLimiter);

api.get('/auth/me', async (req, res) => {
  try {
    res.json({ user: await currentUser(req) });
  } catch (e) {
    console.error(e);
    jsonError(res, 500, 'Authentication service error.');
  }
});

api.post('/auth/login', authLimiter, async (req, res) => {
  try {
    if (!pool) return jsonError(res, 503, 'Database is not configured.');
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) return jsonError(res, 400, 'ID/email and password are required.');

    const { rows } = await pool.query(
      `SELECT id,student_id,name,email,password_hash,phone,dob,gender,role,is_active,last_login_at
         FROM users WHERE lower(email)=lower($1) LIMIT 1`,
      [email]
    );
    const user = rows[0];
    if (!user || !user.is_active || !user.password_hash) return jsonError(res, 401, 'Invalid ID/email or password.');

    const valid = await argon2.verify(user.password_hash, password);
    if (!valid) return jsonError(res, 401, 'Invalid ID/email or password.');

    const sid = newSessionId();
    await pool.query(`DELETE FROM sessions WHERE expires_at<=now()`);
    await pool.query(
      `INSERT INTO sessions(id,user_id,expires_at) VALUES($1,$2,now()+interval '30 minutes')`,
      [sid, user.id]
    );
    await pool.query(`UPDATE users SET last_login_at=now() WHERE id=$1`, [user.id]);

    const safe = { ...user };
    delete safe.password_hash;
    setSessionCookie(res, sid);
    res.json({ user: safe });
  } catch (e) {
    console.error('Login error:', e);
    jsonError(res, 500, 'Login service error.');
  }
});

api.post('/auth/register', authLimiter, async (req, res) => {
  try {
    if (!pool) return jsonError(res, 503, 'Database is not configured.');
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const phone = String(req.body?.phone || '').trim() || null;
    const dob = String(req.body?.dob || '').trim() || null;
    const gender = String(req.body?.gender || '').trim() || null;

    if (!name || !email || password.length < 8) {
      return jsonError(res, 400, 'Name, email and password (minimum 8 characters) are required.');
    }

    const exists = await pool.query(`SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1`, [email]);
    if (exists.rowCount) return jsonError(res, 409, 'This email is already registered.');

    const hash = await argon2.hash(password, { type: argon2.argon2id });
    const seq = await pool.query(`SELECT next_student_number() AS n`);
    const studentId = `THR-${String(seq.rows[0].n).padStart(6, '0')}`;

    const inserted = await pool.query(
      `INSERT INTO users(student_id,name,email,password_hash,phone,dob,gender,role,is_active)
       VALUES($1,$2,$3,$4,$5,$6,$7,'STUDENT',true)
       RETURNING id,student_id,name,email,phone,dob,gender,role,is_active,created_at,last_login_at`,
      [studentId, name, email, hash, phone, dob, gender]
    );

    const user = inserted.rows[0];
    const sid = newSessionId();
    await pool.query(
      `INSERT INTO sessions(id,user_id,expires_at) VALUES($1,$2,now()+interval '30 minutes')`,
      [sid, user.id]
    );
    setSessionCookie(res, sid);
    res.json({ user });
  } catch (e) {
    console.error('Register error:', e);
    if (e.code === '23505') return jsonError(res, 409, 'Email or student ID already exists.');
    jsonError(res, 500, 'Registration service error.');
  }
});

api.post('/auth/logout', async (req, res) => {
  try {
    if (pool && req.cookies?.thiral_session) {
      await pool.query(`DELETE FROM sessions WHERE id=$1`, [req.cookies.thiral_session]);
    }
  } catch (e) {
    console.error('Logout error:', e);
  }
  clearSessionCookie(res);
  res.json({ ok: true });
});

api.get('/questions', requireAuth, async (req, res) => {
  try {
    const exam = String(req.query.exam || '').trim();
    const subject = String(req.query.subject || '').trim();
    const language = String(req.query.language || 'ta').trim();
    const limit = Math.min(Math.max(parseInt(req.query.limit || '20', 10) || 20, 1), 200);
    if (!exam || !subject || !['ta', 'en'].includes(language)) return jsonError(res, 400, 'Invalid question request.');

    const { rows } = await pool.query(
      `SELECT id,exam,subject,subtopic,language,question,options,explanation
         FROM questions
        WHERE exam=$1 AND subject=$2 AND language=$3 AND is_active=true
        ORDER BY random() LIMIT $4`,
      [exam, subject, language, limit]
    );
    res.json({ questions: rows });
  } catch (e) {
    console.error('Questions error:', e);
    jsonError(res, 500, 'Question service error.');
  }
});

api.post('/attempts', requireAuth, async (req, res) => {
  try {
    const { exam, subject, mode, language = 'ta', questionIds = [] } = req.body || {};
    if (!exam || !subject || !['practice', 'mock'].includes(mode) || !['ta', 'en'].includes(language) || !Array.isArray(questionIds) || !questionIds.length) {
      return jsonError(res, 400, 'Invalid attempt.');
    }
    const ids = [...new Set(questionIds.map(Number).filter(Number.isInteger))];
    if (ids.length > 200) return jsonError(res, 400, 'Too many questions.');
    const valid = await pool.query(
      `SELECT id FROM questions WHERE id=ANY($1::bigint[]) AND exam=$2 AND language=$3 AND is_active=true`,
      [ids, exam, language]
    );
    if (valid.rows.length !== ids.length) return jsonError(res, 400, 'Invalid question set.');

    const inserted = await pool.query(
      `INSERT INTO attempts(user_id,exam,subject,mode,language,question_ids,status,started_at)
       VALUES($1,$2,$3,$4,$5,$6,'IN_PROGRESS',now()) RETURNING id`,
      [req.user.id, exam, subject, mode, language, ids]
    );
    res.json({ id: inserted.rows[0].id });
  } catch (e) {
    console.error('Attempt error:', e);
    jsonError(res, 500, 'Attempt service error.');
  }
});

api.post('/attempts/:id/submit', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const a = await client.query(`SELECT * FROM attempts WHERE id=$1 AND user_id=$2 FOR UPDATE`, [req.params.id, req.user.id]);
    if (!a.rowCount) { await client.query('ROLLBACK'); return jsonError(res, 404, 'Attempt not found.'); }
    if (a.rows[0].status === 'SUBMITTED') { await client.query('ROLLBACK'); return jsonError(res, 409, 'Attempt already submitted.'); }

    const answers = req.body?.answers && typeof req.body.answers === 'object' ? req.body.answers : {};
    const q = await client.query(`SELECT id,correct_option FROM questions WHERE id=ANY($1::bigint[])`, [a.rows[0].question_ids]);
    let correct = 0;
    for (const row of q.rows) if (Number(answers[String(row.id)]) === Number(row.correct_option)) correct++;
    const total = q.rows.length;
    const score = total ? Math.round((correct * 10000) / total) / 100 : 0;

    await client.query(
      `UPDATE attempts SET status='SUBMITTED',submitted_at=now(),score=$1,correct_count=$2,total_count=$3 WHERE id=$4`,
      [score, correct, total, req.params.id]
    );
    await client.query('COMMIT');
    res.json({ score, correct, total });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('Submit error:', e);
    jsonError(res, 500, 'Grading service error.');
  } finally {
    client.release();
  }
});

api.get('/results', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id,exam,subject,mode,language,score,correct_count,total_count,started_at,submitted_at
         FROM attempts WHERE user_id=$1 AND status='SUBMITTED' ORDER BY submitted_at DESC LIMIT 100`,
      [req.user.id]
    );
    res.json({ results: rows });
  } catch (e) {
    console.error('Results error:', e);
    jsonError(res, 500, 'Results service error.');
  }
});

api.get('/admin/summary', requireAdmin, async (req, res) => {
  try {
    const q = await pool.query(
      `SELECT count(*) FILTER(WHERE role='STUDENT' AND is_active=true)::int AS total,
              count(*) FILTER(WHERE role='STUDENT' AND is_active=true AND created_at::date=current_date)::int AS today,
              count(*) FILTER(WHERE role='STUDENT' AND is_active=true AND date_trunc('month',created_at)=date_trunc('month',now()))::int AS month,
              count(*) FILTER(WHERE role='STUDENT' AND gender='ஆண்')::int AS male,
              count(*) FILTER(WHERE role='STUDENT' AND gender='பெண்')::int AS female,
              count(*) FILTER(WHERE role='STUDENT' AND gender='மூன்றாம் பாலினம்')::int AS third,
              max(last_login_at) AS last_login
         FROM users`
    );
    res.json({ students: q.rows[0] });
  } catch (e) {
    console.error('Admin summary error:', e);
    jsonError(res, 500, 'Admin summary error.');
  }
});

api.get('/admin/students', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT student_id,name,email,phone,dob,gender,created_at,last_login_at
         FROM users WHERE role='STUDENT' AND is_active=true ORDER BY created_at DESC LIMIT 5000`
    );
    res.json({ students: rows });
  } catch (e) {
    console.error('Admin students error:', e);
    jsonError(res, 500, 'Admin students error.');
  }
});


// ===== Important News: minimal addition =====
async function ensureImportantNewsTable() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS important_news (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','published')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      published_at TIMESTAMPTZ
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS important_news_status_idx
    ON important_news(status, created_at DESC)
  `);
}

api.post('/admin/important-news', requireAdmin, async (req, res) => {
  try {
    if (!pool) return jsonError(res, 503, 'Database is not configured.');

    const title = String(req.body?.title || '').trim();
    const content = String(req.body?.content || '').trim();
    const status = String(req.body?.status || 'draft').trim().toLowerCase();

    if (!title || !content) {
      return jsonError(res, 400, 'Title and content are required.');
    }
    if (!['draft', 'published'].includes(status)) {
      return jsonError(res, 400, 'Invalid news status.');
    }

    const { rows } = await pool.query(
      `INSERT INTO important_news(title,content,status,published_at)
       VALUES($1,$2,$3,CASE WHEN $3='published' THEN now() ELSE NULL END)
       RETURNING id,title,content,status,created_at,updated_at,published_at`,
      [title, content, status]
    );

    res.status(201).json({ news: rows[0] });
  } catch (e) {
    console.error('Admin important news save error:', e);
    jsonError(res, 500, 'Important News save error.');
  }
});

api.get('/admin/important-news', requireAdmin, async (req, res) => {
  try {
    if (!pool) return jsonError(res, 503, 'Database is not configured.');

    const { rows } = await pool.query(
      `SELECT id,title,content,status,created_at,updated_at,published_at
         FROM important_news
        ORDER BY created_at DESC
        LIMIT 100`
    );

    res.json({ news: rows });
  } catch (e) {
    console.error('Admin important news list error:', e);
    jsonError(res, 500, 'Important News list error.');
  }
});

api.get('/important-news', requireAuth, async (req, res) => {
  try {
    if (!pool) return jsonError(res, 503, 'Database is not configured.');

    const { rows } = await pool.query(
      `SELECT id,title,content,published_at
         FROM important_news
        WHERE status='published'
        ORDER BY published_at DESC NULLS LAST, created_at DESC
        LIMIT 20`
    );

    res.json({ news: rows });
  } catch (e) {
    console.error('Important news public list error:', e);
    jsonError(res, 500, 'Important News service error.');
  }
});

app.use('/api', api);

const frontendDir = path.join(__dirname, 'frontend');
app.use(express.static(frontendDir, { index: false }));

// Express 5 compatible SPA fallback. This replaces app.get('*', ...).
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api') && req.path !== '/health') {
    return res.sendFile(path.join(frontendDir, 'Thiral_V139_Secure.html'));
  }
  next();
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Server error.' });
});

// IMPORTANT: listen immediately so Render receives the port even if Supabase is slow.
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Thiral V139 listening on port ${PORT}`);
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is missing. API/database features will not work.');
  } else {
    pool.query('SELECT 1')
      .then(async () => {
        console.log('Supabase database connection OK');
        try {
          await ensureImportantNewsTable();
          console.log('Important News table ready');
        } catch (err) {
          console.error('Important News table initialization failed:', err.message);
        }
      })
      .catch(err => console.error('Supabase database connection failed:', err.message));
  }
});
