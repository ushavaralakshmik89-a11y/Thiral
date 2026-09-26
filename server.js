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
app.set('trust proxy', 1);

// CORS for the separate Render Static Site (student website).
// Credentials are required because student login uses an httpOnly session cookie.
const allowedOrigins = new Set([
  'https://thiral.onrender.com',
  'https://thiral-v138-backend.onrender.com'
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const PORT = process.env.PORT || 10000;
const THIRAL_SECURITY_VERSION = 'V171';
const isProd = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is missing. Set it in Render Environment Variables.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 180, standardHeaders: true, legacyHeaders: false });

function sendError(res, status, error) {
  return res.status(status).json({ error });
}


/* Group 4 canonical subject/subtopic aliases. The database may contain either
   the Tamil UI key or its English label for bilingual rows. Never delete or
   rewrite existing question data: requests simply match both known labels. */
const SUBJECT_ALIASES = {
  'தமிழ்':'tamil','Tamil':'tamil',
  'பொது அறிவு':'gs','General Knowledge':'gs','general knowledge':'gs',
  'பொது அறிவு / General Studies':'gs','General Studies':'gs','general studies':'gs',
  'திறனறிவு / Aptitude':'apt','Aptitude':'apt','aptitude':'apt'
};
const GROUP4_SUBTOPIC_ALIASES = {
  'பண்டைய இந்தியா':'Ancient India','Ancient India':'பண்டைய இந்தியா',
  'இடைக்கால இந்தியா':'Medieval India','Medieval India':'இடைக்கால இந்தியா',
  'நவீன இந்தியா':'Modern India','Modern India':'நவீன இந்தியா',
  'சுதந்திரப் போராட்டம்':'Indian Freedom Movement','Indian Freedom Movement':'சுதந்திரப் போராட்டம்',
  'சங்க காலம்':'Sangam Age','Sangam Age':'சங்க காலம்',
  'சோழர்':'Cholas','Cholas':'சோழர்','பாண்டியர்':'Pandyas','Pandyas':'பாண்டியர்',
  'பல்லவர்':'Pallavas','Pallavas':'பல்லவர்','நாயக்கர்':'Nayaks','Nayaks':'நாயக்கர்',
  'அரசியலமைப்பு':'Constitution','Constitution':'அரசியலமைப்பு',
  'அடிப்படை உரிமைகள்':'Fundamental Rights','Fundamental Rights':'அடிப்படை உரிமைகள்',
  'பாராளுமன்றம்':'Parliament','Parliament':'பாராளுமன்றம்',
  'மாநில அரசு':'State Government','State Government':'மாநில அரசு',
  'உள்ளாட்சி':'Local Government','Local Government':'உள்ளாட்சி',
  'இந்தியா':'India','India':'இந்தியா','தமிழ்நாடு':'Tamil Nadu','Tamil Nadu':'தமிழ்நாடு',
  'ஆறுகள்':'Rivers','Rivers':'ஆறுகள்','மலைகள்':'Mountains','Mountains':'மலைகள்','வளங்கள்':'Resources','Resources':'வளங்கள்',
  'இயற்பியல்':'Physics','Physics':'இயற்பியல்','வேதியியல்':'Chemistry','Chemistry':'வேதியியல்',
  'உயிரியல்':'Biology','Biology':'உயிரியல்','சுற்றுச்சூழல்':'Environment','Environment':'சுற்றுச்சூழல்',
  'அடிப்படை பொருளாதாரம்':'Basic Economics','Basic Economics':'அடிப்படை பொருளாதாரம்',
  'இந்திய பொருளாதாரம்':'Indian Economy','Indian Economy':'இந்திய பொருளாதாரம்',
  'தமிழ்நாடு பொருளாதாரம்':'Tamil Nadu Economy','Tamil Nadu Economy':'தமிழ்நாடு பொருளாதாரம்',
  'எண்கள்':'Numbers','Numbers':'எண்கள்','பின்னங்கள்':'Fractions','Fractions':'பின்னங்கள்',
  'சதவீதம்':'Percentage','Percentage':'சதவீதம்','விகிதம்':'Ratio','Ratio':'விகிதம்','சராசரி':'Average','Average':'சராசரி',
  'பரப்பளவு':'Area','Area':'பரப்பளவு','சுற்றளவு':'Perimeter','Perimeter':'சுற்றளவு',
  'கனஅளவு':'Volume','Volume':'கனஅளவு','அலகுகள்':'Units','Units':'அலகுகள்',
  'இலாபம் மற்றும் நட்டம்':'Profit and Loss','Profit and Loss':'இலாபம் மற்றும் நட்டம்',
  'வட்டி':'Interest','Interest':'வட்டி','காலம் மற்றும் வேலை':'Time and Work','Time and Work':'காலம் மற்றும் வேலை',
  'வேகம் மற்றும் தூரம்':'Speed and Distance','Speed and Distance':'வேகம் மற்றும் தூரம்',
  'எண் தொடர்':'Number Series','Number Series':'எண் தொடர்','எழுத்துத் தொடர்':'Alphabet Series','Alphabet Series':'எழுத்துத் தொடர்',
  'ஒப்புமை':'Analogy','Analogy':'ஒப்புமை','வகைப்படுத்தல்':'Classification','Classification':'வகைப்படுத்தல்',
  'குறியீடு':'Coding','Coding':'குறியீடு',
  'எழுத்து வகைகள்':'Letter Types','Letter Types':'எழுத்து வகைகள்','சொல் வகைகள்':'Word Types','Word Types':'சொல் வகைகள்',
  'வேற்றுமை':'Cases','Cases':'வேற்றுமை','வினைச்சொல்':'Verb','Verb':'வினைச்சொல்','புணர்ச்சி':'Sandhi','Sandhi':'புணர்ச்சி',
  'ஒருபொருட்பன்மொழி':'Synonyms','Synonyms':'ஒருபொருட்பன்மொழி','எதிர்ச்சொல்':'Antonyms','Antonyms':'எதிர்ச்சொல்',
  'இணைச்சொல்':'Related Words','Related Words':'இணைச்சொல்','மரபுத்தொடர்':'Idioms','Idioms':'மரபுத்தொடர்','கலைச்சொல்':'Technical Terms','Technical Terms':'கலைச்சொல்',
  'சங்க இலக்கியம்':'Sangam Literature','Sangam Literature':'சங்க இலக்கியம்','பதினெண்கீழ்க்கணக்கு':'Pathinenkilkanakku','Pathinenkilkanakku':'பதினெண்கீழ்க்கணக்கு',
  'காப்பியங்கள்':'Epics','Epics':'காப்பியங்கள்','பக்தி இலக்கியம்':'Bhakti Literature','Bhakti Literature':'பக்தி இலக்கியம்',
  'நவீன இலக்கியம்':'Modern Literature','Modern Literature':'நவீன இலக்கியம்','அறத்துப்பால்':'Aram','Aram':'அறத்துப்பால்',
  'பொருட்பால்':'Porul','Porul':'பொருட்பால்','இன்பத்துப்பால்':'Inbam','Inbam':'இன்பத்துப்பால்',
  'குறள் பொருள்':'Kural Meaning','Kural Meaning':'குறள் பொருள்','குறள் சார்ந்த கருத்துகள்':'Kural Concepts','Kural Concepts':'குறள் சார்ந்த கருத்துகள்'
};
function canonicalSubject(raw){ return SUBJECT_ALIASES[String(raw||'').trim()] || String(raw||'').trim(); }
function subjectCandidates(raw){
  const s=String(raw||'').trim();
  if(!s) return [];
  const canonical=canonicalSubject(s);
  const aliases=Object.entries(SUBJECT_ALIASES)
    .filter(([label,key]) => key===canonical)
    .map(([label])=>label);
  return [...new Set([canonical,s,...aliases].filter(Boolean))];
}
function subtopicCandidates(raw){
  const s=String(raw||'').trim();
  if(!s) return [];
  const a=[s, GROUP4_SUBTOPIC_ALIASES[s] || ''];
  return [...new Set(a.filter(Boolean))];
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
  res.clearCookie('thiral_session', { httpOnly: true, secure: isProd, sameSite: 'lax', path: '/' });
}

async function getUserFromSession(req) {
  const sid = req.cookies?.thiral_session;
  if (!sid) return null;
  const q = await pool.query(
    `SELECT u.id,u.student_id,u.name,u.email,u.phone,u.dob,u.gender,u.role,u.is_active,u.must_change_password,s.expires_at
     FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.id=$1 AND s.expires_at > now() AND u.is_active=true`, [sid]
  );
  return q.rows[0] || null;
}

async function requireAuth(req, res, next) {
  try {
    const user = await getUserFromSession(req);
    if (!user) return sendError(res, 401, 'ACCESS DENIED: Login required.');
    req.user = user;
    next();
  } catch (e) {
    console.error(e);
    return sendError(res, 500, 'Authentication service error.');
  }
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, () => {
    if (req.user.role !== 'ADMIN') return sendError(res, 403, 'ACCESS DENIED: Admin authorization required.');
    next();
  });
}

async function requirePasswordReady(req, res, next) {
  await requireAuth(req, res, () => {
    if (req.user.role === 'STUDENT' && req.user.must_change_password === true) {
      return sendError(res, 403, 'PASSWORD_CHANGE_REQUIRED');
    }
    next();
  });
}

async function ensureAdmin() {
  const adminId = (process.env.ADMIN_ID || '').trim();
  const adminPassword = process.env.ADMIN_PASSWORD || '';
  if (!adminId || !adminPassword) {
    console.warn('ADMIN_ID / ADMIN_PASSWORD not set. Admin login cannot be seeded automatically.');
    return;
  }
  const hash = await argon2.hash(adminPassword);
  const existing = await pool.query('SELECT id FROM users WHERE email=$1 LIMIT 1', [adminId]);
  if (existing.rowCount) {
    await pool.query(
      `UPDATE users SET role='ADMIN', is_active=true, must_change_password=false, password_hash=$1, email=$2 WHERE id=$3`,
      [hash, adminId, existing.rows[0].id]
    );
    console.log(`Admin account ready: ${adminId}`);
  } else {
    let studentId = 'ADMIN-0001';

    const idCheck = await pool.query(
      'SELECT 1 FROM users WHERE student_id=$1 LIMIT 1',
      [studentId]
    );

    if (idCheck.rowCount) {
      const suffix = crypto.randomBytes(4).toString('hex').toUpperCase();
      studentId = `ADMIN-${suffix}`;
    }

    await pool.query(
      `INSERT INTO users(student_id,name,email,password_hash,role,is_active,must_change_password)
       VALUES($1,$2,$3,$4,'ADMIN',true,false)`,
      [studentId, 'Thiral Administrator', adminId, hash]
    );

    console.log(`Admin account created: ${adminId} (${studentId})`);
  }
}

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'Thiral V167 Secure Temporary Password', database: 'ok', time: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ ok: false, service: 'Thiral V167 Secure Temporary Password', database: 'error' });
  }
});

const api = express.Router();
api.use(apiLimiter);

api.get('/auth/me', async (req, res) => {
  try {
    const user = await getUserFromSession(req);
    res.json({ user: user || null });
  } catch (e) { sendError(res, 500, 'Authentication service error.'); }
});

api.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) return sendError(res, 400, 'ID/email and password are required.');
    const q = await pool.query(
      `SELECT id,student_id,name,email,password_hash,phone,dob,gender,role,is_active,must_change_password FROM users WHERE lower(email)=lower($1) LIMIT 1`, [email]
    );
    const u = q.rows[0];
    if (!u || !u.is_active) return sendError(res, 401, 'Invalid ID/email or password.');
    const ok = await argon2.verify(u.password_hash, password);
    if (!ok) return sendError(res, 401, 'Invalid ID/email or password.');
    const sid = newSessionId();
    await pool.query(`DELETE FROM sessions WHERE expires_at <= now()`);
    await pool.query(`INSERT INTO sessions(id,user_id,expires_at) VALUES($1,$2,now()+interval '30 minutes')`, [sid, u.id]);
    await pool.query(`UPDATE users SET last_login_at=now() WHERE id=$1`, [u.id]);
    await pool.query(`INSERT INTO activity_events(user_id,event_type,metadata) VALUES($1,'LOGIN',$2)`, [u.id, JSON.stringify({ role: u.role })]);
    setSessionCookie(res, sid);
    delete u.password_hash;
    res.json({ user: u });
  } catch (e) {
    console.error(e);
    sendError(res, 500, 'Login service error.');
  }
});


/*
 * Registration date normalization.
 * The frontend may send DOB as DD/MM/YYYY (for example 21/07/1991),
 * while PostgreSQL DATE expects ISO YYYY-MM-DD.
 * Existing database rows are not changed.
 */
function normalizeRegistrationDate(raw) {
  const value = String(raw || '').trim();
  if (!value) return null;

  // Already ISO: YYYY-MM-DD
  let m = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (m) {
    const y = Number(m[1]), mo = Number(m[2]), d = Number(m[3]);
    const dt = new Date(Date.UTC(y, mo - 1, d));
    if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) {
      throw new Error('Invalid date of birth.');
    }
    return value;
  }

  // Common Indian form: DD/MM/YYYY
  m = value.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!m) {
    // Also accept DD-MM-YYYY without changing the frontend.
    m = value.match(/^(\d{2})-(\d{2})-(\d{4})$/);
  }

  if (m) {
    const d = Number(m[1]), mo = Number(m[2]), y = Number(m[3]);
    const dt = new Date(Date.UTC(y, mo - 1, d));
    if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) {
      throw new Error('Invalid date of birth.');
    }
    return `${String(y).padStart(4, '0')}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
  }

  throw new Error('Invalid date of birth. Use DD/MM/YYYY.');
}

api.post('/auth/register', authLimiter, async (req, res) => {
  let client;
  try {
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const phone = String(req.body?.phone || '').trim();
    const dob = normalizeRegistrationDate(req.body?.dob);
    const gender = String(req.body?.gender || '').trim();

    if (!name || !email || password.length < 8) {
      return sendError(res, 400, 'Name, valid email and password (minimum 8 characters) are required.');
    }

    /*
       Registration-safe student number allocation.
       This version does NOT depend on a custom PostgreSQL function or sequence.
       It uses a transaction-scoped advisory lock so two simultaneous
       registrations cannot receive the same THR number.
       Existing rows are only read; nothing is deleted or rewritten.
    */
    client = await pool.connect();
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [741926]);

    const exists = await client.query(
      'SELECT 1 FROM users WHERE lower(email)=lower($1) LIMIT 1',
      [email]
    );
    if (exists.rowCount) {
      await client.query('ROLLBACK');
      return sendError(res, 409, 'This email is already registered.');
    }

    const numberQ = await client.query(`
      SELECT COALESCE(
        MAX((substring(student_id FROM '^THR-([0-9]+)$'))::BIGINT),
        0
      ) + 1 AS next_number
      FROM users
      WHERE student_id ~ '^THR-[0-9]+$'
    `);

    const nextNumber = Number(numberQ.rows[0]?.next_number || 1);
    if (!Number.isSafeInteger(nextNumber) || nextNumber < 1) {
      await client.query('ROLLBACK');
      return sendError(res, 500, 'Unable to allocate a new student ID safely.');
    }

    const studentId = `THR-${String(nextNumber).padStart(6, '0')}`;
    const hash = await argon2.hash(password);

    const ins = await client.query(
      `INSERT INTO users(student_id,name,email,password_hash,phone,dob,gender,role,is_active)
       VALUES($1,$2,$3,$4,$5,$6,$7,'STUDENT',true)
       RETURNING id,student_id,name,email,phone,dob,gender,role,is_active,created_at,last_login_at`,
      [studentId, name, email, hash, phone, dob, gender]
    );

    const u = ins.rows[0];
    const sid = newSessionId();
    await client.query(
      `INSERT INTO sessions(id,user_id,expires_at)
       VALUES($1,$2,now()+interval '30 minutes')`,
      [sid, u.id]
    );

    await client.query('COMMIT');
    setSessionCookie(res, sid);
    return res.json({ user: u });
  } catch (e) {
    if (client) {
      try { await client.query('ROLLBACK'); } catch (_) {}
    }

    console.error('Registration service error:', {
      code: e?.code || null,
      message: e?.message || String(e),
      detail: e?.detail || null,
      constraint: e?.constraint || null,
      table: e?.table || null,
      column: e?.column || null
    });

    if (e?.code === '23505') {
      return sendError(res, 409, 'Email or student ID already exists.');
    }
    return sendError(res, 500, 'Registration service error.');
  } finally {
    if (client) client.release();
  }
});


/* =========================================================
   THIRAL V162 SECURE OTP
   Password reset uses:
   Render -> HTTPS -> Google Apps Script -> Gmail
   No SMTP connection is required on Render.
   ========================================================= */

function otpConfigReady(){
  return Boolean(
    String(process.env.THIRAL_APPS_SCRIPT_URL || '').trim() &&
    String(process.env.THIRAL_API_KEY || '').trim()
  );
}

function hashOtp(value){
  const pepper = String(process.env.OTP_PEPPER || '').trim();
  return crypto
    .createHash('sha256')
    .update(pepper + ':' + String(value))
    .digest('hex');
}

function newOtp(){
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function newResetToken(){
  return crypto.randomBytes(32).toString('hex');
}

async function sendOtpThroughAppsScript(to, otp){
  const url = String(process.env.THIRAL_APPS_SCRIPT_URL || '').trim();
  const apiKey = String(process.env.THIRAL_API_KEY || '').trim();

  if(!url || !apiKey) throw new Error('OTP bridge configuration is missing.');

  const response = await fetch(url, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    redirect:'follow',
    body:JSON.stringify({
      api_key:apiKey,
      to:String(to || '').trim().toLowerCase(),
      otp:String(otp || '')
    })
  });

  const text = await response.text();
  let data = {};
  try { data = JSON.parse(text); } catch (_) {}

  if(!response.ok || data.ok !== true){
    const err = new Error('OTP email delivery failed.');
    err.status = response.status;
    err.bridgeMessage = String(data.message || '').slice(0,200);
    throw err;
  }
  return true;
}

function otpPublicMessage(){
  return 'If the registered email exists, an OTP has been sent.';
}

api.post('/auth/forgot-password/request', authLimiter, async (req,res)=>{
  try{
    const email = String(req.body?.email || '').trim().toLowerCase();

    if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
      return sendError(res,400,'Valid email is required.');
    }

    if(!otpConfigReady()){
      console.error('[OTP] Bridge configuration missing.');
      return sendError(res,503,'OTP service is not configured.');
    }

    const q = await pool.query(
      `SELECT id,email,is_active,role
       FROM users
       WHERE lower(email)=lower($1)
       LIMIT 1`,
      [email]
    );

    /*
      Do not reveal whether an email is registered.
      Only active STUDENT accounts can use student password reset.
    */
    const user = q.rows[0];
    if(!user || !user.is_active || user.role !== 'STUDENT'){
      return res.json({ok:true,message:otpPublicMessage()});
    }

    const recent = await pool.query(
      `SELECT id
       FROM password_reset_otps
       WHERE user_id=$1
         AND created_at > now() - interval '60 seconds'
       ORDER BY created_at DESC
       LIMIT 1`,
      [user.id]
    );

    if(recent.rowCount){
      return sendError(res,429,'Please wait before requesting another OTP.');
    }

    const otp = newOtp();
    const otpHash = hashOtp(otp);

    await pool.query(
      `UPDATE password_reset_otps
       SET used_at=now()
       WHERE user_id=$1 AND used_at IS NULL`,
      [user.id]
    );

    const ins = await pool.query(
      `INSERT INTO password_reset_otps
       (user_id,email,otp_hash,expires_at,attempts,used_at)
       VALUES($1,$2,$3,now()+interval '10 minutes',0,NULL)
       RETURNING id`,
      [user.id,user.email,otpHash]
    );

    try{
      await sendOtpThroughAppsScript(user.email,otp);
      console.log('[OTP] Apps Script mail sent successfully.');
    }catch(mailErr){
      await pool.query(
        `UPDATE password_reset_otps SET used_at=now() WHERE id=$1`,
        [ins.rows[0].id]
      );
      console.error('[OTP] Apps Script mail failed:', {
        status:mailErr?.status || null,
        message:mailErr?.message || String(mailErr),
        bridgeMessage:mailErr?.bridgeMessage || null
      });
      return sendError(res,502,'OTP email delivery failed.');
    }

    return res.json({ok:true,message:otpPublicMessage()});
  }catch(e){
    console.error('[OTP] Request error:',e);
    return sendError(res,500,'OTP service error.');
  }
});

api.post('/auth/forgot-password/verify', authLimiter, async (req,res)=>{
  try{
    const email = String(req.body?.email || '').trim().toLowerCase();
    const otp = String(req.body?.otp || '').trim();

    if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(otp)){
      return sendError(res,400,'Email and 6-digit OTP are required.');
    }

    const q = await pool.query(
      `SELECT o.id,o.user_id,o.otp_hash,o.expires_at,o.attempts,
              u.email,u.is_active,u.role
       FROM password_reset_otps o
       JOIN users u ON u.id=o.user_id
       WHERE lower(u.email)=lower($1)
         AND o.used_at IS NULL
       ORDER BY o.created_at DESC
       LIMIT 1`,
      [email]
    );

    if(!q.rowCount) return sendError(res,400,'Invalid or expired OTP.');

    const row = q.rows[0];

    if(!row.is_active || row.role !== 'STUDENT'){
      return sendError(res,400,'Invalid or expired OTP.');
    }

    if(new Date(row.expires_at).getTime() <= Date.now()){
      return sendError(res,400,'OTP has expired.');
    }

    if(Number(row.attempts) >= 5){
      return sendError(res,429,'Too many incorrect OTP attempts.');
    }

    const suppliedHash = hashOtp(otp);

    if(!crypto.timingSafeEqual(
      Buffer.from(suppliedHash,'utf8'),
      Buffer.from(String(row.otp_hash),'utf8')
    )){
      await pool.query(
        `UPDATE password_reset_otps
         SET attempts=attempts+1
         WHERE id=$1`,
        [row.id]
      );
      return sendError(res,400,'Invalid or expired OTP.');
    }

    const resetToken = newResetToken();
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    await pool.query(
      `UPDATE password_reset_otps
       SET verified_at=now(),reset_token_hash=$1
       WHERE id=$2`,
      [resetTokenHash,row.id]
    );

    return res.json({ok:true,reset_token:resetToken});
  }catch(e){
    console.error('[OTP] Verify error:',e);
    return sendError(res,500,'OTP verification service error.');
  }
});

api.post('/auth/forgot-password/reset', authLimiter, async (req,res)=>{
  try{
    const email = String(req.body?.email || '').trim().toLowerCase();
    const resetToken = String(req.body?.reset_token || '').trim();
    const newPassword = String(req.body?.password || '');

    if(!email || !resetToken || newPassword.length < 8){
      return sendError(res,400,'Email, reset token and password (minimum 8 characters) are required.');
    }

    const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    const q = await pool.query(
      `SELECT o.id,o.user_id,o.reset_token_hash,o.verified_at,
              u.email,u.is_active,u.role
       FROM password_reset_otps o
       JOIN users u ON u.id=o.user_id
       WHERE lower(u.email)=lower($1)
         AND o.reset_token_hash=$2
         AND o.used_at IS NULL
         AND o.verified_at IS NOT NULL
         AND o.expires_at > now()
       ORDER BY o.created_at DESC
       LIMIT 1`,
      [email,tokenHash]
    );

    if(!q.rowCount) return sendError(res,400,'Invalid or expired password reset token.');

    const row = q.rows[0];

    if(!row.is_active || row.role !== 'STUDENT'){
      return sendError(res,400,'Invalid password reset request.');
    }

    const passwordHash = await argon2.hash(newPassword);

    await pool.query('BEGIN');
    try{
      await pool.query(
        `UPDATE users SET password_hash=$1 WHERE id=$2`,
        [passwordHash,row.user_id]
      );

      await pool.query(
        `UPDATE password_reset_otps
         SET used_at=now(),reset_token_hash=NULL
         WHERE id=$1`,
        [row.id]
      );

      /* Password reset invalidates all existing sessions for this student. */
      await pool.query(
        `DELETE FROM sessions WHERE user_id=$1`,
        [row.user_id]
      );

      await pool.query(
        `INSERT INTO activity_events(user_id,event_type,metadata)
         VALUES($1,'PASSWORD_RESET',$2)`,
        [row.user_id,JSON.stringify({method:'OTP'})]
      );

      await pool.query('COMMIT');
    }catch(e){
      await pool.query('ROLLBACK');
      throw e;
    }

    return res.json({ok:true,message:'Password reset successfully.'});
  }catch(e){
    console.error('[OTP] Password reset error:',e);
    return sendError(res,500,'Password reset service error.');
  }
});



api.post('/auth/change-password', requireAuth, async (req,res)=>{
  const client = await pool.connect();
  try{
    if(req.user.role !== 'STUDENT'){
      return sendError(res,403,'Only student accounts can change this password.');
    }

    const currentPassword = String(req.body?.current_password || '');
    const newPassword = String(req.body?.new_password || '');
    const confirmPassword = String(req.body?.confirm_password || '');

    if(!currentPassword || !newPassword || !confirmPassword){
      return sendError(res,400,'Current password, new password and confirm password are required.');
    }
    if(newPassword.length < 8){
      return sendError(res,400,'New Password must be at least 8 characters.');
    }
    if(newPassword !== confirmPassword){
      return sendError(res,400,'New Password and Confirm Password must match.');
    }
    if(newPassword === currentPassword){
      return sendError(res,400,'New Password must be different from the temporary password.');
    }

    const q = await client.query(
      `SELECT id,password_hash,must_change_password,is_active,role
       FROM users WHERE id=$1 LIMIT 1 FOR UPDATE`,
      [req.user.id]
    );

    if(!q.rowCount || !q.rows[0].is_active || q.rows[0].role !== 'STUDENT'){
      return sendError(res,401,'Invalid password change request.');
    }

    const validCurrent = await argon2.verify(q.rows[0].password_hash,currentPassword);
    if(!validCurrent){
      return sendError(res,401,'Current password is incorrect.');
    }

    const passwordHash = await argon2.hash(newPassword);
    await client.query('BEGIN');
    await client.query(
      `UPDATE users
       SET password_hash=$1,must_change_password=false
       WHERE id=$2`,
      [passwordHash,req.user.id]
    );
    await client.query(
      `INSERT INTO activity_events(user_id,event_type,metadata)
       VALUES($1,'PASSWORD_CHANGED',$2)`,
      [req.user.id,JSON.stringify({method:q.rows[0].must_change_password ? 'FORCED_FIRST_LOGIN' : 'SELF_SERVICE'})]
    );
    await client.query('COMMIT');

    return res.json({ok:true,message:'Password changed successfully.'});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch(_){}
    console.error('[PASSWORD] Change error:',e);
    return sendError(res,500,'Password change service error.');
  }finally{
    client.release();
  }
});

api.patch('/admin/students/:studentId/password', requireAdmin, async (req,res)=>{
  const client = await pool.connect();
  try{
    const studentId = String(req.params.studentId || '').trim();
    const temporaryPassword = String(req.body?.temporary_password || '');

    if(!studentId || temporaryPassword.length < 8){
      return sendError(res,400,'Student ID and a temporary password of at least 8 characters are required.');
    }

    const q = await client.query(
      `SELECT id,student_id,role,is_active
       FROM users WHERE student_id=$1 LIMIT 1 FOR UPDATE`,
      [studentId]
    );

    if(!q.rowCount) return sendError(res,404,'Student not found.');

    const target = q.rows[0];
    if(target.role !== 'STUDENT') return sendError(res,400,'Only STUDENT accounts can be changed here.');
    if(!target.is_active) return sendError(res,400,'Student account is inactive. Reactivate it before setting a temporary password.');

    const passwordHash = await argon2.hash(temporaryPassword);

    await client.query('BEGIN');
    await client.query(
      `UPDATE users
       SET password_hash=$1,must_change_password=true
       WHERE id=$2`,
      [passwordHash,target.id]
    );
    await client.query(`DELETE FROM sessions WHERE user_id=$1`,[target.id]);
    await client.query(
      `INSERT INTO activity_events(user_id,event_type,metadata)
       VALUES($1,'TEMP_PASSWORD_SET',$2)`,
      [req.user.id,JSON.stringify({target_student_id:target.student_id})]
    );
    await client.query('COMMIT');

    return res.json({
      ok:true,
      student_id:target.student_id,
      must_change_password:true,
      message:'Temporary password set. Student must change it at next login.'
    });
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch(_){}
    console.error('[ADMIN] Temporary password error:',e);
    return sendError(res,500,'Temporary password service error.');
  }finally{
    client.release();
  }
});

api.post('/auth/heartbeat', requireAuth, async (req,res)=>{
  try{
    const sid = req.cookies?.thiral_session;
    if(!sid) return sendError(res,401,'Login required.');
    await pool.query(
      `UPDATE sessions SET expires_at=now()+interval '30 minutes' WHERE id=$1`,
      [sid]
    );
    res.json({ok:true,expires_at:new Date(Date.now()+30*60*1000).toISOString()});
  }catch(e){
    console.error('[HEARTBEAT] error:',e);
    sendError(res,500,'Session heartbeat service error.');
  }
});

api.post('/auth/logout', async (req, res) => {
  try {
    const sid = req.cookies?.thiral_session;
    if (sid) await pool.query('DELETE FROM sessions WHERE id=$1', [sid]);
  } catch (e) { console.error(e); }
  clearSessionCookie(res);
  res.json({ ok: true });
});

api.get('/questions', requirePasswordReady, async (req, res) => {
  try {
    const exam = String(req.query.exam || '').trim();
    const rawSubject = String(req.query.subject || '').trim();
    const subject = canonicalSubject(rawSubject);
    const subjectCandidatesList = subjectCandidates(rawSubject);
    const language = String(req.query.language || 'ta').trim();
    const subtopic = String(req.query.subtopic || '').trim();
    const historyMode = String(req.query.historyMode || '').trim();
    const limit = Math.min(Math.max(parseInt(req.query.limit || '20',10) || 20,1),200);
    const offset = Math.max(parseInt(req.query.offset || '0',10) || 0,0);
    if (!exam || !subject || !['ta','en'].includes(language)) return sendError(res,400,'Invalid question request.');

    const where = ['exam=$1','subject = ANY($2::text[])','language=$3','is_active=true'];
    const params = [exam, subjectCandidatesList, language];
    let n = 4;
    const subCandidates = subtopicCandidates(subtopic);
    if (subCandidates.length === 1) {
      where.push(`subtopic=$${n++}`); params.push(subCandidates[0]);
    } else if (subCandidates.length > 1) {
      where.push(`subtopic = ANY($${n}::text[])`); params.push(subCandidates); n++;
    }

    /* Question Bank continuation: exclude only questions already used
       in this user's Question Bank mode. Normal Practice/Mock are unchanged. */
    if (historyMode === 'bank') {
      where.push(`NOT EXISTS (
        SELECT 1 FROM question_history h
        WHERE h.user_id = ${n}
          AND h.question_id = questions.id
          AND h.mode = 'bank'
      )`);
      params.push(req.user.id);
      n++;
    }

    const countQ = await pool.query(`SELECT count(*)::int AS total FROM questions WHERE ${where.join(' AND ')}`, params);
    const total = Number(countQ.rows[0]?.total || 0);

    const dataParams = [...params, limit, offset];
    const q = await pool.query(
      `SELECT id,exam,subject,subtopic,language,question,options,explanation
       FROM questions
       WHERE ${where.join(' AND ')}
       ORDER BY id LIMIT $${n} OFFSET $${n+1}`, dataParams
    );

    const nextOffset = offset + q.rows.length;
    res.json({
      questions:q.rows,
      pagination:{limit,offset,returned:q.rows.length,total,hasMore:nextOffset<total,nextOffset}
    });
  } catch(e) { console.error(e); sendError(res,500,'Question service error.'); }
});

/* ===== FAST PRACTICE API =====
   Existing /questions API is intentionally left unchanged.
   Practice gets only the requested number of fresh questions.
*/
api.get('/practice/questions', requirePasswordReady, async (req, res) => {
  try {
    const exam = String(req.query.exam || '').trim();
    const rawSubject = String(req.query.subject || '').trim();
    const subject = canonicalSubject(rawSubject);
    const subjectCandidatesList = subjectCandidates(rawSubject);
    const language = String(req.query.language || 'ta').trim();
    const subtopic = String(req.query.subtopic || '').trim();
    const limit = Math.min(
      Math.max(parseInt(req.query.limit || '10', 10) || 10, 1),
      200
    );

    if (!exam || !subject || !['ta', 'en'].includes(language)) {
      return sendError(res, 400, 'Invalid question request.');
    }

    const params = [req.user.id, exam, subjectCandidatesList, language];
    let n = 5;

    let where = `
      q.exam = $2
      AND q.subject = ANY($3::text[])
      AND q.language = $4
      AND q.is_active = true
    `;

    const subCandidates = subtopicCandidates(subtopic);
    if (subCandidates.length === 1) {
      where += ` AND q.subtopic = $${n}`;
      params.push(subCandidates[0]);
      n++;
    } else if (subCandidates.length > 1) {
      where += ` AND q.subtopic = ANY($${n}::text[])`;
      params.push(subCandidates);
      n++;
    }

    params.push(limit);

    const sql = `
      SELECT
        q.id,
        q.exam,
        q.subject,
        q.subtopic,
        q.language,
        q.question,
        q.options,
        q.explanation
      FROM questions q
      WHERE ${where}
        AND NOT EXISTS (
          SELECT 1
          FROM question_history h
          WHERE h.user_id = $1
            AND h.question_id = q.id
            AND h.mode = 'practice'
        )
      ORDER BY random()
      LIMIT $${n}
    `;

    const result = await pool.query(sql, params);

    if (result.rows.length < limit) {
      return sendError(
        res,
        409,
        `???? ????????? ???????? ????? ????????? ${result.rows.length} ??????? ?????.`
      );
    }

    res.json({
      questions: result.rows,
      count: result.rows.length
    });
  } catch (e) {
    console.error('Practice question error:', e);
    sendError(res, 500, 'Practice question service error.');
  }
});

api.post('/attempts', requirePasswordReady, async (req,res)=>{
  try {
    const {exam,subject,mode,language,questionIds}=req.body||{};
    if(!exam || !subject || !['practice','mock','bank'].includes(mode) || !['ta','en','mixed'].includes(language) || !Array.isArray(questionIds) || !questionIds.length) return sendError(res,400,'Invalid attempt.');
    const ids=[...new Set(questionIds.map(Number).filter(Number.isInteger))];
    if(!ids.length || ids.length>5000) return sendError(res,400,'Invalid question list.');
    const q = language==='mixed'
      ? await pool.query(`SELECT id FROM questions WHERE id=ANY($1::bigint[]) AND exam=$2 AND is_active=true`,[ids,exam])
      : await pool.query(`SELECT id FROM questions WHERE id=ANY($1::bigint[]) AND exam=$2 AND language=$3 AND is_active=true`,[ids,exam,language]);
    const valid=new Set(q.rows.map(x=>String(x.id)));
    const clean=ids.filter(id=>valid.has(String(id)));
    if(clean.length!==ids.length) return sendError(res,400,'Some questions are not valid for this exam/language.');
    const ins=await pool.query(`INSERT INTO attempts(user_id,exam,subject,mode,language,question_ids) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,[req.user.id,exam,subject,mode,language,clean]);

    /* Normal Practice/Mock questions are reserved immediately.
       Question Bank is different: a question becomes 'used' only when
       the student actually finishes/logs out of that bank session. */
    if (mode !== 'bank') {
      await pool.query(
        `INSERT INTO question_history(user_id, question_id, mode)
         SELECT $1, x, $2
         FROM unnest($3::bigint[]) AS x
         ON CONFLICT (user_id, question_id, mode)
         DO NOTHING`,
        [req.user.id, mode, clean]
      );
    }

    res.json({id:ins.rows[0].id});
  }catch(e){console.error(e);sendError(res,500,'Attempt service error.');}
});

api.post('/attempts/:id/check-answer', requirePasswordReady, async (req,res)=>{
  try {
    const attemptId=Number(req.params.id);
    const questionId=Number(req.body?.questionId);
    const answer=Number(req.body?.answer);

    if(!Number.isInteger(attemptId) || !Number.isInteger(questionId) || !Number.isInteger(answer)) {
      return sendError(res,400,'Invalid answer data.');
    }

    const attemptResult=await pool.query(
      `SELECT id,status,question_ids
       FROM attempts
       WHERE id=$1 AND user_id=$2
       LIMIT 1`,
      [attemptId,req.user.id]
    );

    if(!attemptResult.rowCount) {
      return sendError(res,404,'Attempt not found.');
    }

    const attempt=attemptResult.rows[0];

    if(attempt.status==='SUBMITTED') {
      return sendError(res,409,'Attempt already submitted.');
    }

    const questionIds=Array.isArray(attempt.question_ids)
      ? attempt.question_ids.map(Number)
      : [];

    if(!questionIds.includes(questionId)) {
      return sendError(res,400,'Question does not belong to this attempt.');
    }

    const questionResult=await pool.query(
      `SELECT correct_option,explanation
       FROM questions
       WHERE id=$1 AND is_active=true
       LIMIT 1`,
      [questionId]
    );

    if(!questionResult.rowCount) {
      return sendError(res,404,'Question not found.');
    }

    const question=questionResult.rows[0];
    const isCorrect=Number(answer)===Number(question.correct_option);

    return res.json({
      correct:isCorrect,
      correct_option:Number(question.correct_option),
      explanation:question.explanation || ''
    });
  } catch(e) {
    console.error('Check answer error:',e);
    return sendError(res,500,'Answer checking service error.');
  }
});

api.post('/attempts/:id/submit', requirePasswordReady, async (req,res)=>{
  try {
    const id=Number(req.params.id);
    const a=await pool.query(`SELECT * FROM attempts WHERE id=$1 AND user_id=$2 LIMIT 1`,[id,req.user.id]);
    if(!a.rowCount) return sendError(res,404,'Attempt not found.');
    const attempt=a.rows[0];
    if(attempt.status==='SUBMITTED') return res.json({score:attempt.score,correct:attempt.correct_count,total:attempt.total_count});
    const answers=req.body?.answers && typeof req.body.answers==='object' ? req.body.answers : {};
    const allIds=Array.isArray(attempt.question_ids) ? attempt.question_ids.map(Number) : [];
    /* For Question Bank, only questions actually reached/answered in this
       session count toward the Review percentage and become permanently used.
       Unseen questions remain available next time. */
    const usedIds = attempt.mode === 'bank'
      ? allIds.filter(qid => Object.prototype.hasOwnProperty.call(answers,String(qid)) && Number.isInteger(Number(answers[String(qid)])))
      : allIds;

    const qs=usedIds.length
      ? await pool.query(`SELECT id,correct_option FROM questions WHERE id=ANY($1::bigint[])`,[usedIds])
      : {rows:[]};

    let correct=0;
    for(const q of qs.rows){
      const raw=answers[String(q.id)] ?? answers[q.id];
      const idx=Number(raw);
      if(Number.isInteger(idx) && idx>=0 && idx===Number(q.correct_option)) correct++;
    }

    const total=usedIds.length;
    const unanswered=usedIds.filter(qid => Number(answers[String(qid)])===-1).length;
    const score=total ? Number(((correct*100)/total).toFixed(2)) : 0;

    if (attempt.mode === 'bank' && usedIds.length) {
      await pool.query(
        `INSERT INTO question_history(user_id, question_id, mode)
         SELECT $1, x, 'bank'
         FROM unnest($2::bigint[]) AS x
         ON CONFLICT (user_id, question_id, mode) DO NOTHING`,
        [req.user.id, usedIds]
      );
    }

    await pool.query(`UPDATE attempts SET status='SUBMITTED',score=$1,correct_count=$2,total_count=$3,submitted_at=now() WHERE id=$4`,[score,correct,total,id]);
    await pool.query(`INSERT INTO activity_events(user_id,event_type,metadata) VALUES($1,'ATTEMPT_SUBMITTED',$2)`,[req.user.id,JSON.stringify({attempt_id:id,mode:attempt.mode,exam:attempt.exam,score,used_questions:total,unanswered})]);
    res.json({score,correct,total,unanswered,usedQuestionIds:usedIds});
  }catch(e){console.error(e);sendError(res,500,'Grading service error.');}
});

api.get('/results', requirePasswordReady, async (req,res)=>{
  try{
    const q=await pool.query(`SELECT id,exam,subject,mode,language,score,correct_count,total_count,started_at,submitted_at FROM attempts WHERE user_id=$1 AND status='SUBMITTED' ORDER BY started_at DESC LIMIT 100`,[req.user.id]);
    res.json({results:q.rows});
  }catch(e){console.error(e);sendError(res,500,'Results service error.');}
});

/* Group 4 UI topic map used only for Admin result filtering/export. Existing question rows keep their original subtopic values. */
const GROUP4_RESULT_TOPICS = {
  'தமிழ்': ['எழுத்து வகைகள்','சொல் வகைகள்','வேற்றுமை','வினைச்சொல்','புணர்ச்சி','ஒருபொருட்பன்மொழி','எதிர்ச்சொல்','இணைச்சொல்','மரபுத்தொடர்','கலைச்சொல்','சங்க இலக்கியம்','பதினெண்கீழ்க்கணக்கு','காப்பியங்கள்','பக்தி இலக்கியம்','நவீன இலக்கியம்','அறத்துப்பால்','பொருட்பால்','இன்பத்துப்பால்','குறள் பொருள்','குறள் சார்ந்த கருத்துகள்'],
  'இந்திய வரலாறு': ['பண்டைய இந்தியா','இடைக்கால இந்தியா','நவீன இந்தியா','சுதந்திரப் போராட்டம்'],
  'தமிழ்நாடு வரலாறு': ['சங்க காலம்','சோழர்','பாண்டியர்','பல்லவர்','நாயக்கர்'],
  'இந்திய அரசியல்': ['அரசியலமைப்பு','அடிப்படை உரிமைகள்','பாராளுமன்றம்','மாநில அரசு','உள்ளாட்சி'],
  'புவியியல்': ['இந்தியா','தமிழ்நாடு','ஆறுகள்','மலைகள்','வளங்கள்'],
  'அறிவியல்': ['இயற்பியல்','வேதியியல்','உயிரியல்','சுற்றுச்சூழல்'],
  'பொருளாதாரம்': ['அடிப்படை பொருளாதாரம்','இந்திய பொருளாதாரம்','தமிழ்நாடு பொருளாதாரம்'],
  'அடிப்படை கணிதம்': ['எண்கள்','பின்னங்கள்','சதவீதம்','விகிதம்','சராசரி'],
  'அளவியல்': ['பரப்பளவு','சுற்றளவு','கனஅளவு','அலகுகள்'],
  'வணிகக் கணிதம்': ['இலாபம் மற்றும் நட்டம்','வட்டி','காலம் மற்றும் வேலை','வேகம் மற்றும் தூரம்'],
  'தர்க்கத் திறன்': ['எண் தொடர்','எழுத்துத் தொடர்','ஒப்புமை','வகைப்படுத்தல்','குறியீடு']
};
function group4TopicForSubtopic(v){
  const s=String(v||'').trim();
  const tamil = GROUP4_SUBTOPIC_ALIASES[s] || s;
  for(const [topic,subs] of Object.entries(GROUP4_RESULT_TOPICS)){ if(subs.includes(s) || subs.includes(tamil)) return topic; }
  return '';
}

/* Admin: exam-wise overall results. Student identity is included for result reporting. */
api.get('/admin/exam-results', requireAdmin, async (req,res)=>{
  try{
    const exam = String(req.query.exam || '').trim();
    const type = String(req.query.type || '').trim().toLowerCase();
    const subjectFilter = String(req.query.subject || '').trim();
    const from = String(req.query.from || '').trim();
    const to = String(req.query.to || '').trim();
    const requestedSubtopic = String(req.query.subtopic || '').trim();
    const requestedSubtopics = String(req.query.subtopics || '').split('|').map(x=>x.trim()).filter(Boolean);
    const requestedSubtopicCandidates = [...new Set([...requestedSubtopics, ...requestedSubtopics.map(x=>GROUP4_SUBTOPIC_ALIASES[x]||'')].filter(Boolean))];
    const requestedSubtopicCandidatesSingle = requestedSubtopic ? [...new Set([requestedSubtopic, GROUP4_SUBTOPIC_ALIASES[requestedSubtopic]||''].filter(Boolean))] : [];
    const minPct = req.query.min_pct === undefined || req.query.min_pct === '' ? 0 : Number(req.query.min_pct);
    const maxPct = req.query.max_pct === undefined || req.query.max_pct === '' ? 100 : Number(req.query.max_pct);
    const page = Math.max(parseInt(req.query.page || '1',10) || 1,1);
    const limit = Math.min(Math.max(parseInt(req.query.limit || '100',10) || 100,1),200);
    if(!Number.isFinite(minPct) || !Number.isFinite(maxPct) || minPct<0 || maxPct>100 || minPct>maxPct){
      return sendError(res,400,'Invalid percentage range.');
    }

    const where=[`a.status='SUBMITTED'`];
    const params=[];
    const add=(sql,val)=>{params.push(val);where.push(sql.replace('?', '$'+params.length));};
    if(exam) add(`a.exam=?` ,exam);
    if(subjectFilter){
      const subjectList = subjectCandidates(subjectFilter);
      where.push(`a.subject = ANY($${params.length+1}::text[])`);
      params.push(subjectList);
    }
    if(from) add(`a.submitted_at::date >= ?::date`,from);
    if(to) add(`a.submitted_at::date <= ?::date`,to);
    if(requestedSubtopic){
      where.push(`EXISTS (SELECT 1 FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic = ANY($${params.length+1}::text[]))`);
      params.push(requestedSubtopicCandidatesSingle);
    } else if(requestedSubtopics.length){
      where.push(`EXISTS (SELECT 1 FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic = ANY($${params.length+1}::text[]))`);
      params.push(requestedSubtopicCandidates);
    }
    where.push(`COALESCE(a.score,0) >= $${params.length+1}`); params.push(minPct);
    where.push(`COALESCE(a.score,0) <= $${params.length+1}`); params.push(maxPct);

    const typeSql=`CASE
      WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam'
      WHEN a.mode='mock' THEN 'Mock Test'
      WHEN a.mode='bank' THEN 'Question Bank'
      WHEN a.total_count=10 THEN '10 Questions'
      WHEN a.total_count=20 THEN '20 Questions'
      WHEN a.total_count=50 THEN '50 Questions'
      ELSE 'Practice'
    END`;
    if(type && ['model','mock','practice','bank','10','20','50'].includes(type)){
      const typeExpr=type==='model' ? `lower(a.exam) LIKE '%model%'` : type==='mock' ? `a.mode='mock'` : type==='bank' ? `a.mode='bank'` : type==='10' ? `a.total_count=10` : type==='20' ? `a.total_count=20` : type==='50' ? `a.total_count=50` : `(a.mode='practice' AND lower(a.exam) NOT LIKE '%model%' AND a.total_count NOT IN (10,20,50))`;
      where.push(typeExpr);
    }

    const whereSql=where.join(' AND ');
    const base=`FROM attempts a WHERE ${whereSql}`;
    const countQ=await pool.query(`SELECT count(*)::int AS total, count(DISTINCT a.user_id)::int AS participants, COALESCE(sum(a.total_count),0)::bigint AS total_questions, COALESCE(avg(a.score),0)::numeric(10,2) AS average_pct, COALESCE(max(a.score),0)::numeric(10,2) AS highest_pct, COALESCE(min(a.score),0)::numeric(10,2) AS lowest_pct ${base}`,params);
    const offset=(page-1)*limit;
    const pageParams=params.slice();
    pageParams.push(limit,offset);
    const rowsQ=await pool.query(`SELECT a.id AS attempt_id,u.name,u.email,a.exam,${typeSql} AS exam_type,to_char(COALESCE(a.submitted_at,a.started_at),'DD-MM-YYYY HH24:MI') AS date,COALESCE(a.total_count,0)::int AS questions,COALESCE(a.correct_count,0)::int AS marks,COALESCE(a.total_count,0)::int AS total_marks,COALESCE(a.score,0)::numeric(10,2) AS percentage,COALESCE((SELECT string_agg(DISTINCT qq.subtopic, ' | ' ORDER BY qq.subtopic) FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid),'') AS subtopics FROM attempts a JOIN users u ON u.id=a.user_id WHERE ${whereSql} ORDER BY COALESCE(a.submitted_at,a.started_at) DESC,a.id DESC LIMIT $${pageParams.length-1} OFFSET $${pageParams.length}`,pageParams);

    const rows=rowsQ.rows.map(r=>({ ...r, topic:[...new Set(String(r.subtopics||'').split(' | ').map(group4TopicForSubtopic).filter(Boolean))].join(' | ') }));
    const c=countQ.rows[0]||{};
    const examsQ=await pool.query(`SELECT DISTINCT a.exam FROM attempts a WHERE a.status='SUBMITTED' ORDER BY a.exam`);
    res.json({ok:true,rows,total:Number(c.total||0),limit,page,exams:examsQ.rows.map(x=>x.exam).filter(Boolean),summary:{participants:Number(c.participants||0),attempts:Number(c.total||0),total_questions:Number(c.total_questions||0),average_pct:Number(c.average_pct||0),highest_pct:Number(c.highest_pct||0),lowest_pct:Number(c.lowest_pct||0)}});
  }catch(e){console.error('[ADMIN EXAM RESULTS]',e);sendError(res,500,'Exam results service error.');}
});

api.get('/admin/exam-results/export', requireAdmin, async (req,res)=>{
  try{
    const exam=String(req.query.exam||'').trim();
    const type=String(req.query.type||'').trim().toLowerCase();
    const subjectFilter=String(req.query.subject||'').trim();
    const from=String(req.query.from||'').trim();
    const to=String(req.query.to||'').trim();
    const requestedSubtopic=String(req.query.subtopic||'').trim();
    const requestedSubtopics=String(req.query.subtopics||'').split('|').map(x=>x.trim()).filter(Boolean);
    const requestedSubtopicCandidates=[...new Set([...requestedSubtopics,...requestedSubtopics.map(x=>GROUP4_SUBTOPIC_ALIASES[x]||'')].filter(Boolean))];
    const requestedSubtopicCandidatesSingle=requestedSubtopic?[...new Set([requestedSubtopic,GROUP4_SUBTOPIC_ALIASES[requestedSubtopic]||''].filter(Boolean))]:[];
    const minPct=req.query.min_pct===''||req.query.min_pct===undefined?0:Number(req.query.min_pct);
    const maxPct=req.query.max_pct===''||req.query.max_pct===undefined?100:Number(req.query.max_pct);
    if(!Number.isFinite(minPct)||!Number.isFinite(maxPct)||minPct<0||maxPct>100||minPct>maxPct)return sendError(res,400,'Invalid percentage range.');

    const where=[`a.status='SUBMITTED'`],params=[];
    const add=(sql,val)=>{params.push(val);where.push(sql.replace('?', '$'+params.length));};
    if(exam)add(`a.exam=?`,exam);
    if(subjectFilter){
      const subjectList=subjectCandidates(subjectFilter);
      where.push(`a.subject = ANY($${params.length+1}::text[])`);
      params.push(subjectList);
    }
    if(from)add(`a.submitted_at::date >= ?::date`,from);
    if(to)add(`a.submitted_at::date <= ?::date`,to);
    if(requestedSubtopic){
      where.push(`EXISTS (SELECT 1 FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic = ANY($${params.length+1}::text[]))`);
      params.push(requestedSubtopicCandidatesSingle);
    } else if(requestedSubtopics.length){
      where.push(`EXISTS (SELECT 1 FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic = ANY($${params.length+1}::text[]))`);
      params.push(requestedSubtopicCandidates);
    }
    where.push(`COALESCE(a.score,0) >= $${params.length+1}`);params.push(minPct);
    where.push(`COALESCE(a.score,0) <= $${params.length+1}`);params.push(maxPct);
    if(type && ['model','mock','practice','bank','10','20','50'].includes(type)){
      where.push(type==='model'?`lower(a.exam) LIKE '%model%'`:type==='mock'?`a.mode='mock'`:type==='bank'?`a.mode='bank'`:type==='10'?`a.total_count=10`:type==='20'?`a.total_count=20`:type==='50'?`a.total_count=50`:`(a.mode='practice' AND lower(a.exam) NOT LIKE '%model%' AND a.total_count NOT IN (10,20,50))`);
    }

    const typeSql=`CASE WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam' WHEN a.mode='mock' THEN 'Mock Test' WHEN a.mode='bank' THEN 'Question Bank' WHEN a.total_count=10 THEN '10 Questions' WHEN a.total_count=20 THEN '20 Questions' WHEN a.total_count=50 THEN '50 Questions' ELSE 'Practice' END`;
    const q=await pool.query(`SELECT a.id AS attempt_id,u.name,u.email,a.exam,${typeSql} AS exam_type,to_char(COALESCE(a.submitted_at,a.started_at),'DD-MM-YYYY HH24:MI') AS date,COALESCE(a.total_count,0)::int AS questions,COALESCE(a.correct_count,0)::int AS marks,COALESCE(a.total_count,0)::int AS total_marks,COALESCE(a.score,0)::numeric(10,2) AS percentage,COALESCE((SELECT string_agg(DISTINCT qq.subtopic, ' | ' ORDER BY qq.subtopic) FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid),'') AS subtopics FROM attempts a JOIN users u ON u.id=a.user_id WHERE ${where.join(' AND ')} ORDER BY COALESCE(a.submitted_at,a.started_at) DESC,a.id DESC`,params);

    const escXml=v=>String(v??'')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&apos;');
    const colName=n=>{
      let s=''; n=Number(n)+1;
      while(n){ const r=(n-1)%26; s=String.fromCharCode(65+r)+s; n=Math.floor((n-1)/26); }
      return s;
    };
    const inlineCell=(ref,value,style)=>{
      const text=escXml(value);
      return `<c r="${ref}" t="inlineStr"${style?` s="${style}"`:''}><is><t xml:space="preserve">${text}</t></is></c>`;
    };
    const numCell=(ref,value,style)=>`<c r="${ref}" t="n"${style?` s="${style}"`:''}><v>${Number(value)||0}</v></c>`;
    const sheetXml=(rows)=>{
      const headers=['Name','Email','Exam','Exam Type','Topic','Subtopics','Date','Questions','Marks','Total Marks','Percentage'];
      const out=[];
      out.push('<row r="1">'+headers.map((h,i)=>inlineCell(`${colName(i)}1`,h,1)).join('')+'</row>');
      rows.forEach((r,ri)=>{
        const rowNo=ri+2;
        const topic=[...new Set(String(r.subtopics||'').split(' | ').map(group4TopicForSubtopic).filter(Boolean))].join(' | ');
        const vals=[r.name,r.email,r.exam,r.exam_type,topic,r.subtopics,r.date];
        const cells=[];
        vals.forEach((v,i)=>cells.push(inlineCell(`${colName(i)}${rowNo}`,v)));
        cells.push(numCell(`H${rowNo}`,r.questions));
        cells.push(numCell(`I${rowNo}`,r.marks));
        cells.push(numCell(`J${rowNo}`,r.total_marks));
        cells.push(numCell(`K${rowNo}`,r.percentage));
        out.push(`<row r="${rowNo}">${cells.join('')}</row>`);
      });
      return `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"/></sheetViews><sheetFormatPr defaultRowHeight="15"/><cols><col min="1" max="1" width="24"/><col min="2" max="2" width="32"/><col min="3" max="4" width="18"/><col min="5" max="6" width="28"/><col min="7" max="7" width="20"/><col min="8" max="11" width="14"/></cols><sheetData>${out.join('')}</sheetData><autoFilter ref="A1:K${Math.max(1,rows.length+1)}"/></worksheet>`;
    };

    const safeSheetName=(name,used)=>{
      let n=String(name||'Exam').replace(/[\\\/\?\*\[\]:]/g,' ').trim()||'Exam';
      n=n.slice(0,31);
      const base=n; let i=2;
      while(used.has(n)){const suffix=` (${i++})`;n=base.slice(0,31-suffix.length)+suffix;}
      used.add(n);return n;
    };

    const groups=new Map();
    for(const r of q.rows){const key=String(r.exam||'Unknown Exam');if(!groups.has(key))groups.set(key,[]);groups.get(key).push(r);}
    if(!groups.size)groups.set('No Results',[]);

    const sheets=[]; const rels=[]; const content=[]; const usedNames=new Set();
    let idx=1;
    for(const [examName,rows] of groups.entries()){
      const sheetName=safeSheetName(examName,usedNames);
      sheets.push(`<sheet name="${escXml(sheetName)}" sheetId="${idx}" r:id="rId${idx}"/>`);
      rels.push(`<Relationship Id="rId${idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${idx}.xml"/>`);
      content.push(`<Override PartName="/xl/worksheets/sheet${idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`);
      idx++;
    }

    const files=[
      {name:'[Content_Types].xml',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${content.join('')}</Types>`},
      {name:'_rels/.rels',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
      {name:'xl/workbook.xml',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><bookViews><workbookView/></bookViews><sheets>${sheets.join('')}</sheets></workbook>`},
      {name:'xl/_rels/workbook.xml.rels',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${rels.join('')}<Relationship Id="rId${idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`},
      {name:'xl/styles.xml',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="10"/><name val="Arial"/></font><font><b/><sz val="10"/><name val="Arial"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0"/></cellXfs></styleSheet>`}
    ];
    idx=1;
    for(const [examName,rows] of groups.entries()){
      files.push({name:`xl/worksheets/sheet${idx}.xml`,data:sheetXml(rows)});idx++;
    }

    const crcTable=(()=>{const t=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);t[n]=c>>>0;}return t;})();
    const crc32=buf=>{let c=0xFFFFFFFF;for(const b of buf)c=crcTable[(c^b)&255]^(c>>>8);return (c^0xFFFFFFFF)>>>0;};
    const zipParts=[];const central=[];let offset=0;
    const now=new Date();const dosTime=(now.getHours()<<11)|(now.getMinutes()<<5)|Math.floor(now.getSeconds()/2);const dosDate=((now.getFullYear()-1980)<<9)|((now.getMonth()+1)<<5)|now.getDate();
    for(const f of files){
      const nameBuf=Buffer.from(f.name,'utf8'), dataBuf=Buffer.from(f.data,'utf8'), crc=crc32(dataBuf);
      const local=Buffer.alloc(30+nameBuf.length);local.writeUInt32LE(0x04034b50,0);local.writeUInt16LE(20,4);local.writeUInt16LE(0,6);local.writeUInt16LE(0,8);local.writeUInt16LE(dosTime,10);local.writeUInt16LE(dosDate,12);local.writeUInt32LE(crc,14);local.writeUInt32LE(dataBuf.length,18);local.writeUInt32LE(dataBuf.length,22);local.writeUInt16LE(nameBuf.length,26);local.writeUInt16LE(0,28);nameBuf.copy(local,30);zipParts.push(local,dataBuf);
      const c=Buffer.alloc(46+nameBuf.length);c.writeUInt32LE(0x02014b50,0);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(0,8);c.writeUInt16LE(0,10);c.writeUInt16LE(dosTime,12);c.writeUInt16LE(dosDate,14);c.writeUInt32LE(crc,16);c.writeUInt32LE(dataBuf.length,20);c.writeUInt32LE(dataBuf.length,24);c.writeUInt16LE(nameBuf.length,28);c.writeUInt16LE(0,30);c.writeUInt16LE(0,32);c.writeUInt16LE(0,34);c.writeUInt16LE(0,36);c.writeUInt32LE(0,38);c.writeUInt32LE(offset,42);nameBuf.copy(c,46);central.push(c);offset+=local.length+dataBuf.length;
    }
    const centralBuf=Buffer.concat(central);const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(0,4);end.writeUInt16LE(0,6);end.writeUInt16LE(files.length,8);end.writeUInt16LE(files.length,10);end.writeUInt32LE(centralBuf.length,12);end.writeUInt32LE(offset,16);end.writeUInt16LE(0,20);
    const xlsx=Buffer.concat([...zipParts,centralBuf,end]);
    const filename='thiral_exam_results_'+new Date().toISOString().slice(0,10)+'.xlsx';
    res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);
    res.setHeader('Content-Length',String(xlsx.length));
    res.end(xlsx);
  }catch(e){console.error('[ADMIN EXAM EXPORT]',e);sendError(res,500,'Exam export service error.');}
});

api.get('/admin/exam-results/:attemptId', requireAdmin, async (req,res)=>{
  try{
    const id=Number(req.params.attemptId);
    if(!Number.isInteger(id) || id<1) return sendError(res,400,'Invalid attempt ID.');
    const typeSql=`CASE WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam' WHEN a.mode='mock' THEN 'Mock Test' WHEN a.mode='bank' THEN 'Question Bank' WHEN a.total_count=10 THEN '10 Questions' WHEN a.total_count=20 THEN '20 Questions' WHEN a.total_count=50 THEN '50 Questions' ELSE 'Practice' END`;
    const q=await pool.query(`SELECT a.id AS attempt_id,u.name,u.email,a.exam,${typeSql} AS exam_type,to_char(COALESCE(a.submitted_at,a.started_at),'DD-MM-YYYY HH24:MI') AS date,COALESCE(a.total_count,0)::int AS questions,COALESCE(a.correct_count,0)::int AS correct,COALESCE(a.score,0)::numeric(10,2) AS percentage FROM attempts a JOIN users u ON u.id=a.user_id WHERE a.id=$1 AND a.status='SUBMITTED' LIMIT 1`,[id]);
    if(!q.rowCount) return sendError(res,404,'Result not found.');
    const r=q.rows[0];
    const subsQ=await pool.query(`SELECT DISTINCT qq.subtopic FROM unnest((SELECT question_ids FROM attempts WHERE id=$1)) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic IS NOT NULL ORDER BY qq.subtopic`,[id]);
    const subtopics=subsQ.rows.map(x=>x.subtopic).filter(Boolean);
    const topic=[...new Set(subtopics.map(group4TopicForSubtopic).filter(Boolean))].join(' | ');
    const eventQ=await pool.query(`SELECT metadata FROM activity_events WHERE event_type='ATTEMPT_SUBMITTED' AND metadata->>'attempt_id'=$1 ORDER BY id DESC LIMIT 1`,[String(id)]);
    const unanswered=eventQ.rowCount ? Math.max(0,Number(eventQ.rows[0].metadata?.unanswered||0)) : 0;
    const wrong=Math.max(0,Number(r.questions)-Number(r.correct)-unanswered);
    res.json({ok:true,result:{...r,wrong,unanswered,topic,subtopics:subtopics.join(' | ')}});
  }catch(e){console.error('[ADMIN EXAM RESULT DETAIL]',e);sendError(res,500,'Exam result detail service error.');}
});


api.get('/admin/usage-monitor', requireAdmin, async (req,res)=>{
  try{
    const summary = await pool.query(`
      SELECT
        (SELECT count(DISTINCT s.user_id)::int
           FROM sessions s
           JOIN users u ON u.id=s.user_id
          WHERE s.expires_at > now()
            AND u.role='STUDENT'
            AND u.is_active=true) AS active_now,
        (SELECT count(*)::int
           FROM users u
          WHERE u.role='STUDENT'
            AND u.is_active=true
            AND u.last_login_at >= current_date) AS active_today,
        (SELECT count(*)::int
           FROM users u
          WHERE u.role='STUDENT'
            AND u.is_active=true
            AND u.last_login_at >= now()-interval '24 hours') AS active_24h,
        (SELECT count(*)::int
           FROM attempts a
           JOIN users u ON u.id=a.user_id
          WHERE u.role='STUDENT'
            AND a.mode='practice'
            AND a.started_at >= now()-interval '24 hours') AS practice_sessions_24h,
        (SELECT count(*)::int
           FROM attempts a
           JOIN users u ON u.id=a.user_id
          WHERE u.role='STUDENT'
            AND a.mode='mock'
            AND a.started_at >= now()-interval '24 hours') AS mock_tests_24h
    `);

    const online = await pool.query(`
      SELECT DISTINCT ON (u.id)
        u.student_id,u.name,u.email,u.last_login_at,s.expires_at
      FROM sessions s
      JOIN users u ON u.id=s.user_id
      WHERE s.expires_at > now()
        AND u.role='STUDENT'
        AND u.is_active=true
      ORDER BY u.id,s.expires_at DESC
    `);

    const last24 = await pool.query(`
      SELECT
        u.student_id,u.name,u.email,
        u.last_login_at,
        count(DISTINCT a.id)::int AS activity_count,
        max(a.started_at) AS last_activity_at
      FROM users u
      LEFT JOIN attempts a
        ON a.user_id=u.id
       AND a.started_at >= now()-interval '24 hours'
      WHERE u.role='STUDENT'
        AND u.is_active=true
        AND (
          u.last_login_at >= now()-interval '24 hours'
          OR a.id IS NOT NULL
        )
      GROUP BY u.id,u.student_id,u.name,u.email,u.last_login_at
      ORDER BY COALESCE(u.last_login_at,'1970-01-01'::timestamptz) DESC,
               COALESCE(max(a.started_at),'1970-01-01'::timestamptz) DESC
    `);

    const practice = await pool.query(`
      SELECT
        u.student_id,u.name,u.email,
        count(a.id)::int AS session_count,
        min(a.started_at) AS first_started_at,
        max(a.started_at) AS last_started_at,
        count(*) FILTER (WHERE a.status='SUBMITTED')::int AS completed_count
      FROM attempts a
      JOIN users u ON u.id=a.user_id
      WHERE u.role='STUDENT'
        AND u.is_active=true
        AND a.mode='practice'
        AND a.started_at >= now()-interval '24 hours'
      GROUP BY u.id,u.student_id,u.name,u.email
      ORDER BY count(a.id) DESC,max(a.started_at) DESC
    `);

    const mock = await pool.query(`
      SELECT
        u.student_id,u.name,u.email,
        count(a.id)::int AS test_count,
        min(a.started_at) AS first_started_at,
        max(a.started_at) AS last_started_at,
        count(*) FILTER (WHERE a.status='SUBMITTED')::int AS completed_count,
        count(*) FILTER (WHERE a.status='SUBMITTED' AND a.score IS NOT NULL)::int AS scored_count
      FROM attempts a
      JOIN users u ON u.id=a.user_id
      WHERE u.role='STUDENT'
        AND u.is_active=true
        AND a.mode='mock'
        AND a.started_at >= now()-interval '24 hours'
      GROUP BY u.id,u.student_id,u.name,u.email
      ORDER BY count(a.id) DESC,max(a.started_at) DESC
    `);

    res.json({
      ok:true,
      active_now:Number(summary.rows[0]?.active_now||0),
      active_today:Number(summary.rows[0]?.active_today||0),
      active_24h:Number(summary.rows[0]?.active_24h||0),
      practice_sessions_24h:Number(summary.rows[0]?.practice_sessions_24h||0),
      mock_tests_24h:Number(summary.rows[0]?.mock_tests_24h||0),
      online_students:online.rows.map(x=>({
        student_id:x.student_id,
        name:x.name,
        email:x.email,
        last_login_at:x.last_login_at,
        session_expires_at:x.expires_at
      })),
      last24_students:last24.rows.map(x=>({
        student_id:x.student_id,
        name:x.name,
        email:x.email,
        last_login_at:x.last_login_at,
        activity_count:Number(x.activity_count||0),
        last_activity_at:x.last_activity_at
      })),
      practice_students:practice.rows.map(x=>({
        student_id:x.student_id,
        name:x.name,
        email:x.email,
        session_count:Number(x.session_count||0),
        completed_count:Number(x.completed_count||0),
        first_started_at:x.first_started_at,
        last_started_at:x.last_started_at
      })),
      mock_students:mock.rows.map(x=>({
        student_id:x.student_id,
        name:x.name,
        email:x.email,
        test_count:Number(x.test_count||0),
        completed_count:Number(x.completed_count||0),
        scored_count:Number(x.scored_count||0),
        first_started_at:x.first_started_at,
        last_started_at:x.last_started_at
      }))
    });
  }catch(e){
    console.error('[ADMIN USAGE] error:',e);
    sendError(res,500,'Usage monitor service error.');
  }
});
api.get('/admin/summary', requireAdmin, async (req,res)=>{
  try{
    const q=await pool.query(`SELECT
      count(*)::int AS total,
      count(*) FILTER (WHERE created_at::date=current_date)::int AS today,
      count(*) FILTER (WHERE date_trunc('month',created_at)=date_trunc('month',now()))::int AS month,
      count(*) FILTER (WHERE trim(COALESCE(gender,''))='ஆண்')::int AS male,
      count(*) FILTER (WHERE trim(COALESCE(gender,''))='பெண்')::int AS female,
      count(*) FILTER (WHERE trim(COALESCE(gender,''))='மூன்றாம் பாலினம்')::int AS third,
      max(last_login_at) AS last_login
      FROM users WHERE role='STUDENT' AND is_active=true`);
    res.json({students:{total:q.rows[0].total,today:q.rows[0].today,month:q.rows[0].month,male:q.rows[0].male,female:q.rows[0].female,third:q.rows[0].third,lastLogin:q.rows[0].last_login||null}});
  }catch(e){console.error(e);sendError(res,500,'Admin summary error.');}
});

api.get('/admin/students', requireAdmin, async (req,res)=>{
  try{
    const q=await pool.query(`SELECT student_id,name,email,phone,gender,dob,created_at,last_login_at,is_active,must_change_password FROM users WHERE role='STUDENT' ORDER BY is_active DESC, created_at DESC LIMIT 5000`);
    res.json({students:q.rows});
  }catch(e){console.error(e);sendError(res,500,'Admin students error.');}
});

api.patch('/admin/students/:studentId/status', requireAdmin, async (req,res)=>{
  const client = await pool.connect();
  try{
    const studentId = String(req.params.studentId || '').trim();
    const requestedActive = req.body?.is_active;

    if(!studentId || typeof requestedActive !== 'boolean'){
      return sendError(res,400,'Student ID and is_active are required.');
    }

    await client.query('BEGIN');

    const q = await client.query(
      `SELECT id,student_id,role,is_active FROM users WHERE student_id=$1 LIMIT 1 FOR UPDATE`,
      [studentId]
    );

    if(!q.rowCount){
      await client.query('ROLLBACK');
      return sendError(res,404,'Student not found.');
    }

    const target = q.rows[0];

    if(target.role !== 'STUDENT'){
      await client.query('ROLLBACK');
      return sendError(res,400,'Only STUDENT accounts can be changed here.');
    }

    if(target.id === req.user.id){
      await client.query('ROLLBACK');
      return sendError(res,400,'The logged-in Admin account cannot be changed here.');
    }

    await client.query(
      `UPDATE users SET is_active=$1 WHERE id=$2`,
      [requestedActive, target.id]
    );

    /* Deactivation immediately invalidates every active session for that student.
       Results, attempts, questions and other historical data are intentionally kept. */
    if(!requestedActive){
      await client.query(`DELETE FROM sessions WHERE user_id=$1`, [target.id]);
      await client.query(
        `INSERT INTO activity_events(user_id,event_type,metadata)
         VALUES($1,'ACCOUNT_DEACTIVATED',$2)`,
        [req.user.id, JSON.stringify({target_student_id:target.student_id})]
      );
    }else{
      await client.query(
        `INSERT INTO activity_events(user_id,event_type,metadata)
         VALUES($1,'ACCOUNT_REACTIVATED',$2)`,
        [req.user.id, JSON.stringify({target_student_id:target.student_id})]
      );
    }

    await client.query('COMMIT');

    res.json({
      ok:true,
      student_id:target.student_id,
      is_active:requestedActive
    });
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch(_){}
    console.error('Student status change error:',e);
    sendError(res,500,'Student status change service error.');
  }finally{
    client.release();
  }
});

api.get('/group4/question-status', requirePasswordReady, async (req,res)=>{
  try{
    const rows=await pool.query(`
      SELECT subject,language,count(*)::int AS total,
             count(*) FILTER (WHERE is_active=true)::int AS active
      FROM questions
      WHERE exam='group4'
      GROUP BY subject,language
      ORDER BY subject,language`);
    res.json({exam:'group4',rows:rows.rows});
  }catch(e){ console.error(e); sendError(res,500,'Question status service error.'); }
});

/* Security invariant: every /api/admin/* request must have a valid ADMIN session.
   Keep this server-side; hiding the Admin screen in HTML is not a security boundary. */
app.use('/api/admin', async (req, res, next) => {
  try {
    const user = await getUserFromSession(req);
    if (!user) return sendError(res, 401, 'ACCESS DENIED: Login required.');
    if (user.role !== 'ADMIN') return sendError(res, 403, 'ACCESS DENIED: Admin authorization required.');
    req.user = user;
    next();
  } catch (e) {
    console.error('Admin authorization error:', e);
    return sendError(res, 500, 'Authentication service error.');
  }
});

app.use('/api', api);

app.use(express.static(path.join(__dirname,'frontend'), { index:'index.html' }));

app.get('/{*splat}', (req,res)=>{
  res.sendFile(path.join(__dirname,'frontend','index.html'));
});

/* Create the history table/index without touching existing question data. */


async function ensureMustChangePasswordColumn(){
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false
  `);
}

async function ensurePasswordResetTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_otps (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL,
      email TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      verified_at TIMESTAMPTZ NULL,
      reset_token_hash TEXT NULL,
      used_at TIMESTAMPTZ NULL
    )
  `);

  await pool.query(`
    ALTER TABLE password_reset_otps
    ADD COLUMN IF NOT EXISTS email TEXT
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_password_reset_otps_user_created
    ON password_reset_otps(user_id, created_at DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_password_reset_otps_token
    ON password_reset_otps(reset_token_hash)
  `);
}

async function ensureQuestionHistory() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS question_history (
      user_id BIGINT NOT NULL,
      question_id BIGINT NOT NULL,
      mode VARCHAR(20) NOT NULL,
      seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (user_id, question_id, mode)
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_question_history_user_mode_question
    ON question_history(user_id, mode, question_id)
  `);
}


/*
   No database schema change is required for registration.
   Student IDs are allocated inside the registration transaction using a
   PostgreSQL advisory transaction lock. Existing users, questions,
   attempts, results and admin data are not deleted or rewritten.
*/

/* Backfill Last Login for older accounts from the server-side LOGIN audit trail.
   This does not touch passwords, registrations, results or attempts. */
async function backfillLastLoginFromAudit(){
  await pool.query(`
    UPDATE users u
       SET last_login_at = x.last_login
      FROM (
        SELECT user_id, MAX(created_at) AS last_login
          FROM activity_events
         WHERE event_type='LOGIN'
         GROUP BY user_id
      ) x
     WHERE u.id=x.user_id
       AND (u.last_login_at IS NULL OR u.last_login_at < x.last_login)
  `);
}

async function start(){
  try{
    await pool.query('SELECT 1');
    await ensureMustChangePasswordColumn();
    await ensurePasswordResetTables();
    await ensureQuestionHistory();
    await backfillLastLoginFromAudit();
    await ensureAdmin();
    app.listen(PORT,'0.0.0.0',()=>console.log(`Thiral V171 Secure Temporary Password + Gender Summary + Detailed Usage Monitor listening on port ${PORT}`));
  }catch(e){
    console.error('Startup failed:',e);
    process.exit(1);
  }
}

start();
