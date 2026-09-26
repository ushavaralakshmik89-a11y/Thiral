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
const THIRAL_SECURITY_VERSION = 'V166';
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
  '???? ?????':'gs','General Knowledge':'gs','general knowledge':'gs',
  'General Studies':'gs','general studies':'gs',
  'Aptitude':'apt','aptitude':'apt','?????':'tamil','Tamil':'tamil'
};
const GROUP4_SUBTOPIC_ALIASES = {
  '?????? ???????':'Ancient India','Ancient India':'?????? ???????',
  '???????? ???????':'Medieval India','Medieval India':'???????? ???????',
  '???? ???????':'Modern India','Modern India':'???? ???????',
  '?????????? ?????????':'Indian Freedom Movement','Indian Freedom Movement':'?????????? ?????????',
  '???? ?????':'Sangam Age','Sangam Age':'???? ?????',
  '?????':'Cholas','Cholas':'?????','?????????':'Pandyas','Pandyas':'?????????',
  '???????':'Pallavas','Pallavas':'???????','????????':'Nayaks','Nayaks':'????????',
  '????????????':'Constitution','Constitution':'????????????',
  '???????? ????????':'Fundamental Rights','Fundamental Rights':'???????? ????????',
  '????????????':'Parliament','Parliament':'????????????',
  '????? ????':'State Government','State Government':'????? ????',
  '?????????':'Local Government','Local Government':'?????????',
  '???????':'India','India':'???????','?????????':'Tamil Nadu','Tamil Nadu':'?????????',
  '??????':'Rivers','Rivers':'??????','??????':'Mountains','Mountains':'??????',
  '???????':'Resources','Resources':'???????','?????????':'Physics','Physics':'?????????',
  '?????????':'Chemistry','Chemistry':'?????????','????????':'Biology','Biology':'????????',
  '?????????????':'Environment','Environment':'?????????????',
  '???????? ???????????':'Basic Economics','Basic Economics':'???????? ???????????',
  '?????? ???????????':'Indian Economy','Indian Economy':'?????? ???????????',
  '????????? ???????????':'Tamil Nadu Economy','Tamil Nadu Economy':'????????? ???????????',
  '??????':'Numbers','Numbers':'??????','??????????':'Fractions','Fractions':'??????????',
  '???????':'Percentage','Percentage':'???????','???????':'Ratio','Ratio':'???????',
  '??????':'Average','Average':'??????','????????':'Area','Area':'????????',
  '????????':'Perimeter','Perimeter':'????????','??????':'Volume','Volume':'??????',
  '???????':'Units','Units':'???????','?????? ??????? ??????':'Profit and Loss','Profit and Loss':'?????? ??????? ??????',
  '?????':'Interest','Interest':'?????','????? ??????? ????':'Time and Work','Time and Work':'????? ??????? ????',
  '????? ??????? ?????':'Speed and Distance','Speed and Distance':'????? ??????? ?????',
  '??? ?????':'Number Series','Number Series':'??? ?????','????????? ?????':'Alphabet Series','Alphabet Series':'????????? ?????',
  '???????':'Analogy','Analogy':'???????','?????????????':'Classification','Classification':'?????????????',
  '????????':'Coding','Coding':'????????'
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
    res.json({ ok: true, service: 'Thiral V162 Secure OTP', database: 'ok', time: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ ok: false, service: 'Thiral V162 Secure OTP', database: 'error' });
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

api.get('/admin/summary', requireAdmin, async (req,res)=>{
  try{
    const q=await pool.query(`SELECT
      count(*)::int AS total,
      count(*) FILTER (WHERE created_at::date=current_date)::int AS today,
      count(*) FILTER (WHERE date_trunc('month',created_at)=date_trunc('month',now()))::int AS month,
      count(*) FILTER (WHERE gender='???')::int AS male,
      count(*) FILTER (WHERE gender='????')::int AS female,
      count(*) FILTER (WHERE gender='???????? ???????')::int AS third,
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
async function start(){
  try{
    await pool.query('SELECT 1');
    await ensureMustChangePasswordColumn();
    await ensurePasswordResetTables();
    await ensureQuestionHistory();
    await ensureAdmin();
    app.listen(PORT,'0.0.0.0',()=>console.log(`Thiral V166 Secure Temporary Password listening on port ${PORT}`));
  }catch(e){
    console.error('Startup failed:',e);
    process.exit(1);
  }
}

start();
