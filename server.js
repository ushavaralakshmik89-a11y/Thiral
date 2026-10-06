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
app.disable('x-powered-by');

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
const THIRAL_SECURITY_VERSION = 'V180_SECURITY_HARDENED';
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
  crossOriginEmbedderPolicy: false,
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: false } : false
}));
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

/* CSRF/origin guard for browser state-changing requests. The UI is hosted on
   the exact origin below. Same-origin/server-to-server requests without an
   Origin header are still allowed. */
app.use((req,res,next)=>{
  if(['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    const origin=String(req.headers.origin||'').trim();
    if(origin && !allowedOrigins.has(origin)) {
      return sendError(res,403,'ACCESS DENIED: Untrusted request origin.');
    }
  }
  next();
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false, skipSuccessfulRequests: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });

function sendError(res, status, error) {
  return res.status(status).json({ error });
}


function clientIp(req){
  return String(req.ip||'').trim() || 'unknown';
}

function clientUserAgent(req){
  return String(req.headers['user-agent']||'').slice(0,500);
}

async function logSecurityEvent({req,eventType,userId=null,email='',details='',sendAlert=false}){
  const ip=clientIp(req);
  const userAgent=clientUserAgent(req);
  try{
    await pool.query(
      `INSERT INTO security_events(event_type,user_id,email,ip,user_agent,details) VALUES($1,$2,$3,$4,$5,$6)`,
      [eventType,userId,email,ip,userAgent,details]
    );
  }catch(e){ console.error('Security event log failed:',e); }

  if(sendAlert){
    try{ await sendSecurityAlertEmail({eventType,email,ip,userAgent,details}); }
    catch(e){ console.error('Security alert email failed:',e.message||e); }
  }
}

async function sendSecurityAlertEmail({eventType,email,ip,userAgent,details}){
  const url=String(process.env.THIRAL_SECURITY_ALERT_URL || '').trim();
  const apiKey=String(process.env.THIRAL_API_KEY || '').trim();
  const to=String(process.env.THIRAL_SECURITY_ALERT_EMAIL || process.env.ADMIN_ID || '').trim().toLowerCase();
  if(!url || !apiKey || !to) return false;
  const subject=`Thiral Security Alert: ${eventType}`;
  const body=[
    `Security event: ${eventType}`,
    `Time: ${new Date().toISOString()}`,
    `Email: ${email || '-'}`,
    `IP: ${ip || '-'}`,
    `Browser: ${userAgent || '-'}`,
    `Details: ${details || '-'}`
  ].join('\n');
  const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},redirect:'follow',body:JSON.stringify({api_key:apiKey,to,subject,body,event_type:eventType})});
  const text=await response.text();
  let data={}; try{data=JSON.parse(text);}catch(_){ }
  if(!response.ok || data.ok!==true) throw new Error(`Security alert bridge failed (${response.status})`);
  return true;
}


/* Group 4 canonical subject/subtopic aliases. The database may contain either
   the Tamil UI key or its English label for bilingual rows. Never delete or
   rewrite existing question data: requests simply match both known labels. */
const SUBJECT_ALIASES = {
  '?????':'tamil','Tamil':'tamil',
  '???? ?????':'gs','General Knowledge':'gs','general knowledge':'gs',
  '???? ????? / General Studies':'gs','General Studies':'gs','general studies':'gs',
  '???????? / Aptitude':'apt','Aptitude':'apt','aptitude':'apt'
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
  '??????':'Rivers','Rivers':'??????','??????':'Mountains','Mountains':'??????','???????':'Resources','Resources':'???????',
  '?????????':'Physics','Physics':'?????????','?????????':'Chemistry','Chemistry':'?????????',
  '????????':'Biology','Biology':'????????','?????????????':'Environment','Environment':'?????????????',
  '???????? ???????????':'Basic Economics','Basic Economics':'???????? ???????????',
  '?????? ???????????':'Indian Economy','Indian Economy':'?????? ???????????',
  '????????? ???????????':'Tamil Nadu Economy','Tamil Nadu Economy':'????????? ???????????',
  '??????':'Numbers','Numbers':'??????','??????????':'Fractions','Fractions':'??????????',
  '???????':'Percentage','Percentage':'???????','???????':'Ratio','Ratio':'???????','??????':'Average','Average':'??????',
  '????????':'Area','Area':'????????','????????':'Perimeter','Perimeter':'????????',
  '??????':'Volume','Volume':'??????','???????':'Units','Units':'???????',
  '?????? ??????? ??????':'Profit and Loss','Profit and Loss':'?????? ??????? ??????',
  '?????':'Interest','Interest':'?????','????? ??????? ????':'Time and Work','Time and Work':'????? ??????? ????',
  '????? ??????? ?????':'Speed and Distance','Speed and Distance':'????? ??????? ?????',
  '??? ?????':'Number Series','Number Series':'??? ?????','????????? ?????':'Alphabet Series','Alphabet Series':'????????? ?????',
  '???????':'Analogy','Analogy':'???????','?????????????':'Classification','Classification':'?????????????',
  '????????':'Coding','Coding':'????????',
  '??????? ??????':'Letter Types','Letter Types':'??????? ??????','???? ??????':'Word Types','Word Types':'???? ??????',
  '????????':'Cases','Cases':'????????','??????????':'Verb','Verb':'??????????','?????????':'Sandhi','Sandhi':'?????????',
  '????????????????':'Synonyms','Synonyms':'????????????????','???????????':'Antonyms','Antonyms':'???????????',
  '?????????':'Related Words','Related Words':'?????????','???????????':'Idioms','Idioms':'???????????','?????????':'Technical Terms','Technical Terms':'?????????',
  '???? ?????????':'Sangam Literature','Sangam Literature':'???? ?????????','???????????????????':'Pathinenkilkanakku','Pathinenkilkanakku':'???????????????????',
  '????????????':'Epics','Epics':'????????????','????? ?????????':'Bhakti Literature','Bhakti Literature':'????? ?????????',
  '???? ?????????':'Modern Literature','Modern Literature':'???? ?????????','????????????':'Aram','Aram':'????????????',
  '??????????':'Porul','Porul':'??????????','??????????????':'Inbam','Inbam':'??????????????',
  '????? ??????':'Kural Meaning','Kural Meaning':'????? ??????','????? ??????? ??????????':'Kural Concepts','Kural Concepts':'????? ??????? ??????????'
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
const GROUP4_TAMIL_NEW_SUBTOPIC_ALIASES = {
  '?????????????????':'???????????????',
  '??.??.? (HCF)':'??.??.?',
  '??.??.? (LCM)':'??.??.??.?',
  '???? ?????':'????????',
  '?????? ?????':'?????? ?????',
  '?????? ???????':'????????????? ???????',
  '?????????':'?????????',
  '????':'????',
  '???????? ????????':'???????? ????????',
  '???-??????? ????????':'???????-??? ????????'
};

function subtopicCandidates(raw){
  const s=String(raw||'').trim();
  if(!s) return [];
  const a=[s, GROUP4_SUBTOPIC_ALIASES[s] || '', GROUP4_TAMIL_NEW_SUBTOPIC_ALIASES[s] || ''];
  return [...new Set(a.filter(Boolean))];
}

/* ===== GROUP 4 NEW GS 51 BILINGUAL SUBTOPIC MATCH =====
   The 51 newly added GS subtopics may exist in questions.subtopic as
   either the Tamil UI label, the English label, or one of the known
   imported English aliases. Match all known labels without rewriting data.
   This branch is limited to Group 4 + GS + these 51 subtopics.
*/
const GROUP4_NEW_GS_51_MAP = {
  '?????? ???????':'Indian Culture',
  '?????? ?????? ????????':'Indus Valley Civilization',
  '??????????':'Guptas',
  '?????? ???????????':'Delhi Sultanate',
  '???????????':'Mughals',
  '?????????????':'Marathas',
  '??????????? ??????':'South Indian History',
  '????? ???????????':'National Renaissance',
  '?????????????? ?????? ????? ??????????':'Early Uprisings against British Rule',
  '?????? ????? ?????????':'Indian National Congress',
  '????? ?????????':'National Leaders',
  '????????????? ?????????? ??????? ??????????':'Movements in Tamil Nadu Freedom Struggle',
  '?????? ??????????? ??????????????':'Characteristics of Indian Culture',
  '???????????? ???????':'Unity in Diversity',
  '??????????????':'Secularism',
  '????? ???? ??????':'History of Tamil Society',
  '????????? ????????????????':'Archaeological Discoveries',
  '???? ????? ????? ???? ????? ???????? ????? ?????????':'Tamil Literature from Sangam to Contemporary Times',
  '????? ??????? ??????? ???????????':'Tamil Culture and Heritage',
  '??????????? ??????? ???????? ??????????':'Thirukkural and Universal Values',
  '????????????? ?????????? ??????? ?????':'Role of Tamil Nadu in Freedom Struggle',
  '?????????????? ?????? ??????? ????????????':'Early Agitations against British Rule',
  '?????????? ????????????? ????????? ?????':'Role of Women in Freedom Struggle',
  '???? ??????????????????':'Social Reformers',
  '???? ??????????? ??????????':'Social Reform Movements',
  '????????????? ???? ??????????':'Social Transformation of Tamil Nadu',
  '???? ???? ??????????':'Social Justice Movements',
  '????-??????? ??????????':'Socio-Political Movements',
  '????????? ???????? ?????????':'Development Administration in Tamil Nadu',
  '?????? ??????????????? ??????':'Nature of Indian Economy',
  '?????????? ??????? ????????':'Planning and Development',
  '??????? ???? ??????? ???? ?????':'Planning Commission and NITI Aayog',
  '??????? ?????????':'Sources of Revenue',
  '?????? ??????? ?????':'Reserve Bank of India',
  '?????? ????':'Finance Commission',
  '??????-????? ???? ???????':'Resource Sharing between Union and State Governments',
  '?????? ??????? ???? ??? (GST)':'Goods and Services Tax (GST)',
  '???????????? ??????????':'Employment Generation',
  '????? ???????????????? ??????? ????????':'Land Reforms and Agriculture',
  '???????????? ???????? ??????? ?????????????':'Science and Technology in Agriculture',
  '?????? ????????':'Industrial Growth',
  '?????????? ??????????????':'Rural Welfare Programmes',
  '?????? ???? ??????? ?????? ????????????':'Population and Social Problems',
  '????? ???????':'Education System',
  '??????? ???????':'Health System',
  '???????????? ??????? ?????':'Employment and Poverty',
  '???? ???? ??????? ???? ???????????':'Social Justice and Social Harmony',
  '????????? ???? ??????????????':'Tamil Nadu Government Welfare Schemes',
  '????????????? ????????? ??????? ????????? ????????':'Geography of Tamil Nadu and Economic Growth',
  '????-????????? ????????????':'Socio-Economic Problems',
  '?????? ????-????????? ??????????':'Current Socio-Economic Issues',
};

const GROUP4_NEW_GS_51_EXTRA_ALIASES = {
  'Early Uprisings against British Rule':'Early Resistance to British Rule',
  'Early Agitations against British Rule':'Early Resistances against British Rule',
  'Early Resistances against British Rule':'Early Agitations against British Rule',
  'Early Resistances to British Rule':'Early Agitations against British Rule',
  'Role of Tamil Nadu in Freedom Struggle':'Role of Tamil Nadu in the Freedom Struggle',
  'Industrial Growth':'Industrial Development',
  'Rural Welfare Programmes':'Rural Welfare Schemes',
  'Population and Social Problems':'Population and Social Issues',
  'Government Welfare Schemes in Tamil Nadu':'Tamil Nadu Government Welfare Schemes',
  'Geography of Tamil Nadu and Economic Growth':'Geography and Economic Development of Tamil Nadu',
  'Current Socio-Economic Affairs':'Current Socio-Economic Events'
};

function group4NewGs51Candidates(raw) {
  const s=String(raw||'').trim();
  if(!s) return [];

  /*
     Build the complete alias family for the selected 51-GS subtopic.
     A row may have been imported with the Tamil label, the primary English
     label, or one of the older English aliases.  Follow aliases in both
     directions until no new label is found.  This is lookup-only: no DB row
     is changed and the language filter still decides Tamil vs English.
  */
  const out=new Set([s]);
  let changed=true;
  while(changed){
    changed=false;
    for(const ta of Object.keys(GROUP4_NEW_GS_51_MAP)){
      const en=GROUP4_NEW_GS_51_MAP[ta];
      if(out.has(ta) || out.has(en)){
        if(!out.has(ta)){ out.add(ta); changed=true; }
        if(!out.has(en)){ out.add(en); changed=true; }
      }
    }
    for(const [a,b] of Object.entries(GROUP4_NEW_GS_51_EXTRA_ALIASES)){
      if(out.has(a) || out.has(b)){
        if(!out.has(a)){ out.add(a); changed=true; }
        if(!out.has(b)){ out.add(b); changed=true; }
      }
    }
  }
  return [...out].filter(Boolean);
}

function isGroup4NewGs51(exam, subject, subtopic) {
  if(exam !== 'group4' || subject !== 'gs') return false;
  const s=String(subtopic||'').trim();
  if(!s) return false;
  return group4NewGs51Candidates(s).length > 0 &&
    (Object.prototype.hasOwnProperty.call(GROUP4_NEW_GS_51_MAP,s) ||
     Object.values(GROUP4_NEW_GS_51_MAP).includes(s) ||
     Object.prototype.hasOwnProperty.call(GROUP4_NEW_GS_51_EXTRA_ALIASES,s) ||
     Object.values(GROUP4_NEW_GS_51_EXTRA_ALIASES).includes(s));
}

function newSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function setSessionCookie(res, id) {
  res.cookie('thiral_session', id, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    maxAge: 20 * 60 * 1000,
    path: '/'
  });
}

function clearSessionCookie(res) {
  res.clearCookie('thiral_session', { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/' });
}

/* ===== LEGACY DEVICE-BINDING DATA =====
   login_device_hash / thiral_device are retained for backward compatibility,
   but Student Login no longer rejects a correct password because of device
   binding. Do not call enforceStudentDeviceBinding() from /auth/login.
*/
/* ===== ONE-STUDENT / ONE-DEVICE ACCOUNT BINDING =====
   Student credentials alone are not enough to move an account to another
   browser/device. The first successful student registration/login binds the
   account to a random httpOnly device cookie. A different device is rejected
   server-side. Admin accounts are intentionally excluded from this rule.
*/
const DEVICE_COOKIE_NAME = 'thiral_device';

function deviceBindingSecret(){
  return String(
    process.env.THIRAL_DEVICE_BINDING_SECRET ||
    process.env.THIRAL_API_KEY ||
    process.env.DATABASE_URL ||
    'thiral-device-binding-dev-only'
  );
}

function newDeviceId(){
  return crypto.randomBytes(32).toString('hex');
}

function hashDeviceId(deviceId){
  return crypto.createHmac('sha256', deviceBindingSecret())
    .update(String(deviceId || ''))
    .digest('hex');
}

function getOrCreateDeviceId(req, res){
  const existing=String(req.cookies?.[DEVICE_COOKIE_NAME] || '').trim();
  if(existing) return { id:existing, isNew:false };
  const id=newDeviceId();
  res.cookie(DEVICE_COOKIE_NAME,id,{
    httpOnly:true,
    secure:isProd,
    sameSite:'strict',
    maxAge:365*24*60*60*1000,
    path:'/'
  });
  return { id, isNew:true };
}

function setDeviceCookie(res, deviceId){
  res.cookie(DEVICE_COOKIE_NAME,String(deviceId||''),{
    httpOnly:true,
    secure:isProd,
    sameSite:'strict',
    maxAge:365*24*60*60*1000,
    path:'/'
  });
}

async function enforceStudentDeviceBinding({req,res,user}){
  if(!user || user.role !== 'STUDENT') return {ok:true};

  const device=String(req.cookies?.[DEVICE_COOKIE_NAME] || '').trim();
  if(!device){
    const created=newDeviceId();
    const boundHash=hashDeviceId(created);
    const bound=await pool.query(
      `UPDATE users
          SET login_device_hash=$1
        WHERE id=$2 AND role='STUDENT' AND login_device_hash IS NULL
      RETURNING id`,
      [boundHash,user.id]
    );
    if(bound.rowCount){
      setDeviceCookie(res,created);
      return {ok:true};
    }
    return {ok:false};
  }

  const current=await pool.query(
    `SELECT login_device_hash FROM users WHERE id=$1 AND role='STUDENT' LIMIT 1`,
    [user.id]
  );
  const stored=String(current.rows[0]?.login_device_hash || '').trim();

  if(!stored){
    const boundHash=hashDeviceId(device);
    await pool.query(
      `UPDATE users SET login_device_hash=$1
       WHERE id=$2 AND role='STUDENT' AND login_device_hash IS NULL`,
      [boundHash,user.id]
    );
    return {ok:true};
  }

  if(stored !== hashDeviceId(device)) return {ok:false};
  return {ok:true};
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
  await requireAuth(req, res, async () => {
    if (req.user.role !== 'ADMIN') {
      await logSecurityEvent({req,eventType:'UNAUTHORIZED_ADMIN_ACCESS',userId:req.user.id,email:req.user.email,details:`Attempted ${req.method} ${req.originalUrl}`,sendAlert:true});
      return sendError(res, 403, 'ACCESS DENIED: Admin authorization required.');
    }
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

async function isLoginTemporarilyBlocked(email, ip){
  const q=await pool.query(`
    SELECT count(*)::int AS n
    FROM security_events
    WHERE event_type='FAILED_LOGIN'
      AND created_at>=now()-interval '15 minutes'
      AND (lower(coalesce(email,''))=lower($1) OR ip=$2)`,[email,ip]);
  return Number(q.rows[0]?.n||0) >= 8;
}

api.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) return sendError(res, 400, 'ID/email and password are required.');
    const loginIp=clientIp(req);
    if(await isLoginTemporarilyBlocked(email,loginIp)){
      await logSecurityEvent({req,eventType:'LOGIN_BLOCKED',email,details:'Temporary login block after repeated failed attempts',sendAlert:true});
      return sendError(res,429,'Too many failed login attempts. Please try again later.');
    }
    const q = await pool.query(
      `SELECT id,student_id,name,email,password_hash,phone,dob,gender,role,is_active,must_change_password FROM users WHERE lower(email)=lower($1) LIMIT 1`, [email]
    );
    const u = q.rows[0];
    if (!u || !u.is_active) {
      await logSecurityEvent({req,eventType:'FAILED_LOGIN',email,details:'Unknown or inactive account',sendAlert:true});
      return sendError(res, 401, 'Invalid ID/email or password.');
    }
    const ok = await argon2.verify(u.password_hash, password);
    if (!ok) {
      await logSecurityEvent({req,eventType:'FAILED_LOGIN',userId:u.id,email:u.email,details:'Invalid password',sendAlert:true});
      return sendError(res, 401, 'Invalid ID/email or password.');
    }

    /*
     * Student login policy:
     * Password verification is sufficient for Student Login.
     * Do NOT block a correct password because of a previous browser/device.
     *
     * The old one-student/one-device check has intentionally been removed
     * from the login path. Existing login_device_hash values may remain in
     * the database, but they are no longer used to deny Student Login.
     */

    const sid = newSessionId();
    await pool.query(`DELETE FROM sessions WHERE expires_at <= now()`);
    await pool.query(`INSERT INTO sessions(id,user_id,expires_at) VALUES($1,$2,now()+interval '30 minutes')`, [sid, u.id]);
    await pool.query(`UPDATE users SET last_login_at=now() WHERE id=$1`, [u.id]);
    await pool.query(`INSERT INTO activity_events(user_id,event_type,metadata) VALUES($1,'LOGIN',$2)`, [u.id, JSON.stringify({ role: u.role })]);
    if(u.role==='ADMIN') await logSecurityEvent({req,eventType:'ADMIN_LOGIN_SUCCESS',userId:u.id,email:u.email,details:'Admin login successful',sendAlert:true});
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
    const registrationDeviceId=newDeviceId();
    const registrationDeviceHash=hashDeviceId(registrationDeviceId);

    const ins = await client.query(
      `INSERT INTO users(student_id,name,email,password_hash,phone,dob,gender,role,is_active,login_device_hash)
       VALUES($1,$2,$3,$4,$5,$6,$7,'STUDENT',true,$8)
       RETURNING id,student_id,name,email,phone,dob,gender,role,is_active,created_at,last_login_at`,
      [studentId, name, email, hash, phone, dob, gender, registrationDeviceHash]
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
    setDeviceCookie(res, registrationDeviceId);
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
        `UPDATE users SET password_hash=$1,login_device_hash=NULL WHERE id=$2`,
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
       SET password_hash=$1,must_change_password=false,login_device_hash=NULL
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
       SET password_hash=$1,must_change_password=true,login_device_hash=NULL
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

    /*
       ISOLATED FIX: NEW TAMIL GROUP 4 APTITUDE TOPICS ONLY.
       Every existing Tamil path, every English path, and every other subject
       keeps the original query logic. This special branch activates only for
       the ten newly imported Tamil Aptitude topics.
    */
    const NEW_TAMIL_G4_APT_MAP = {
      '?????????????????':'???????????????',
      '??.??.? (HCF)':'??.??.?',
      '??.??.? (LCM)':'??.??.??.?',
      '???? ?????':'????????',
      '?????? ?????':'?????? ?????',
      '?????? ???????':'????????????? ???????',
      '?????????':'?????????',
      '????':'????',
      '???????? ????????':'???????? ????????',
      '???-??????? ????????':'???????-??? ????????'
    };

    const isNewTamilG4Apt =
      exam === 'group4' &&
      subject === 'apt' &&
      language === 'ta' &&
      Object.prototype.hasOwnProperty.call(NEW_TAMIL_G4_APT_MAP, subtopic);

    const isNewGroup4Gs51 = isGroup4NewGs51(exam, subject, subtopic);

    /* Existing requests retain the original exact exam/subject behavior. */
    const where = isNewTamilG4Apt
      ? ['exam = ANY($1::text[])','subject = ANY($2::text[])','language=$3','is_active=true']
      : ['exam=$1','subject = ANY($2::text[])','language=$3','is_active=true'];

    const params = isNewTamilG4Apt
      ? [['group4','Group 4','Group4'], ['apt','Aptitude'], language]
      : [exam, subjectCandidatesList, language];

    let n = 4;
    const subCandidates = isNewTamilG4Apt
      ? [NEW_TAMIL_G4_APT_MAP[subtopic]]
      : isNewGroup4Gs51
        ? group4NewGs51Candidates(subtopic)
        : subtopicCandidates(subtopic);

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
      `SELECT id,exam,subject,subtopic,language,question,options,explanation,
              COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
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

    const NEW_TAMIL_G4_APT_MAP = {
      '?????????????????':'???????????????',
      '??.??.? (HCF)':'??.??.?',
      '??.??.? (LCM)':'??.??.??.?',
      '???? ?????':'????????',
      '?????? ?????':'?????? ?????',
      '?????? ???????':'????????????? ???????',
      '?????????':'?????????',
      '????':'????',
      '???????? ????????':'???????? ????????',
      '???-??????? ????????':'???????-??? ????????'
    };

    const isNewTamilG4Apt =
      exam === 'group4' &&
      subject === 'apt' &&
      language === 'ta' &&
      Object.prototype.hasOwnProperty.call(NEW_TAMIL_G4_APT_MAP, subtopic);

    const isNewGroup4Gs51 = isGroup4NewGs51(exam, subject, subtopic);

    const params = isNewTamilG4Apt
      ? [req.user.id, ['group4','Group 4','Group4'], ['apt','Aptitude'], language]
      : [req.user.id, exam, subjectCandidatesList, language];

    let n = 5;

    let where = `
      q.exam ${isNewTamilG4Apt ? '= ANY($2::text[])' : '= $2'}
      AND q.subject = ANY($3::text[])
      AND q.language = $4
      AND q.is_active = true
    `;

    const subCandidates = isNewTamilG4Apt
      ? [NEW_TAMIL_G4_APT_MAP[subtopic]]
      : isNewGroup4Gs51
        ? group4NewGs51Candidates(subtopic)
        : subtopicCandidates(subtopic);
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
  '?????': ['??????? ??????','???? ??????','????????','??????????','?????????','????????????????','???????????','?????????','???????????','?????????','???? ?????????','???????????????????','????????????','????? ?????????','???? ?????????','????????????','??????????','??????????????','????? ??????','????? ??????? ??????????'],
  '?????? ??????': ['?????? ???????','???????? ???????','???? ???????','?????????? ?????????'],
  '????????? ??????': ['???? ?????','?????','?????????','???????','????????'],
  '?????? ???????': ['????????????','???????? ????????','????????????','????? ????','?????????'],
  '?????????': ['???????','?????????','??????','??????','???????'],
  '????????': ['?????????','?????????','????????','?????????????'],
  '???????????': ['???????? ???????????','?????? ???????????','????????? ???????????'],
  '???????? ??????': ['??????','??????????','???????','???????','??????'],
  '???????': ['????????','????????','??????','???????'],
  '?????? ??????': ['?????? ??????? ??????','?????','????? ??????? ????','????? ??????? ?????'],
  '???????? ?????': ['??? ?????','????????? ?????','???????','?????????????','????????']
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

    /*
     * ALL EXAM TYPES:
     * The legacy attempts table contains Practice / Mock / Question Bank /
     * 10/20/50/100-question results, while Model Exam results live in
     * model_exam_results. Previously type="" queried only attempts, so Model
     * Exam disappeared when "?????????" was selected.
     *
     * Keep the existing type-specific branches unchanged. When type is empty,
     * fetch both sources, normalize them to the same row shape, merge, sort,
     * paginate, and combine their summaries.
     */
    if(!type || type==='all'){
      // ---------- Legacy attempts ----------
      const legacyWhere=[`a.status='SUBMITTED'`];
      const legacyParams=[];
      const addLegacy=(sql,val)=>{legacyParams.push(val);legacyWhere.push(sql.replace('?', '$'+legacyParams.length));};

      if(exam) addLegacy(`a.exam=?`,exam);
      if(subjectFilter){
        const subjectList=subjectCandidates(subjectFilter);
        legacyWhere.push(`a.subject = ANY($${legacyParams.length+1}::text[])`);
        legacyParams.push(subjectList);
      }
      if(from) addLegacy(`a.submitted_at::date >= ?::date`,from);
      if(to) addLegacy(`a.submitted_at::date <= ?::date`,to);

      if(requestedSubtopic){
        legacyWhere.push(`EXISTS (
          SELECT 1 FROM unnest(a.question_ids) AS aqid
          JOIN questions qq ON qq.id=aqid
          WHERE qq.subtopic = ANY($${legacyParams.length+1}::text[])
        )`);
        legacyParams.push(requestedSubtopicCandidatesSingle);
      }else if(requestedSubtopics.length){
        legacyWhere.push(`EXISTS (
          SELECT 1 FROM unnest(a.question_ids) AS aqid
          JOIN questions qq ON qq.id=aqid
          WHERE qq.subtopic = ANY($${legacyParams.length+1}::text[])
        )`);
        legacyParams.push(requestedSubtopicCandidates);
      }

      legacyWhere.push(`COALESCE(a.score,0) >= $${legacyParams.length+1}`); legacyParams.push(minPct);
      legacyWhere.push(`COALESCE(a.score,0) <= $${legacyParams.length+1}`); legacyParams.push(maxPct);

      const legacySql=legacyWhere.join(' AND ');
      const legacyRowsQ=await pool.query(`
        SELECT
          a.id AS attempt_id,
          u.name,u.email,
          a.exam,
          CASE
            WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam'
            WHEN a.mode='mock' THEN 'Mock Test'
            WHEN a.mode='bank' THEN 'Question Bank'
            WHEN a.total_count=10 THEN '10 Questions'
            WHEN a.total_count=20 THEN '20 Questions'
            WHEN a.total_count=50 THEN '50 Questions'
            WHEN a.total_count=100 THEN '100 Questions'
            ELSE 'Practice'
          END AS exam_type,
          to_char(COALESCE(a.submitted_at,a.started_at),'DD-MM-YYYY HH24:MI') AS date,
          COALESCE(a.total_count,0)::int AS questions,
          COALESCE(a.correct_count,0)::int AS marks,
          COALESCE(a.total_count,0)::int AS total_marks,
          COALESCE(a.score,0)::numeric(10,2) AS percentage,
          COALESCE((
            SELECT string_agg(DISTINCT qq.subtopic, ' | ' ORDER BY qq.subtopic)
            FROM unnest(a.question_ids) AS aqid
            JOIN questions qq ON qq.id=aqid
          ),'') AS subtopics,
          COALESCE(a.submitted_at,a.started_at) AS sort_date
        FROM attempts a
        JOIN users u ON u.id=a.user_id
        WHERE ${legacySql}
      `,legacyParams);

      // ---------- Model Exam results ----------
      const modelWhere=[];
      const modelParams=[];
      const addModel=(sql,val)=>{modelParams.push(val);modelWhere.push(sql.replace('?', '$'+modelParams.length));};

      if(exam) addModel(`(r.exam_id=? OR me.title=?)`,exam);
      if(subjectFilter){
        modelWhere.push(`EXISTS (
          SELECT 1 FROM model_exam_questions mq
          WHERE mq.exam_id=r.exam_id AND mq.subject = ANY($${modelParams.length+1}::text[])
        )`);
        modelParams.push(subjectCandidates(subjectFilter));
      }
      if(from) addModel(`r.submitted_at::date >= ?::date`,from);
      if(to) addModel(`r.submitted_at::date <= ?::date`,to);

      if(requestedSubtopic){
        modelWhere.push(`EXISTS (
          SELECT 1
          FROM model_exam_questions mq
          WHERE mq.exam_id=r.exam_id
            AND mq.topic IS NOT NULL
            AND (mq.topic = ANY($${modelParams.length+1}::text[]) OR mq.subject = ANY($${modelParams.length+1}::text[]))
        )`);
        modelParams.push(requestedSubtopicCandidatesSingle);
      }else if(requestedSubtopics.length){
        modelWhere.push(`EXISTS (
          SELECT 1
          FROM model_exam_questions mq
          WHERE mq.exam_id=r.exam_id
            AND (mq.topic = ANY($${modelParams.length+1}::text[]) OR mq.subject = ANY($${modelParams.length+1}::text[]))
        )`);
        modelParams.push(requestedSubtopicCandidates);
      }

      modelWhere.push(`COALESCE(r.percentage,0) >= $${modelParams.length+1}`); modelParams.push(minPct);
      modelWhere.push(`COALESCE(r.percentage,0) <= $${modelParams.length+1}`); modelParams.push(maxPct);

      const modelSql=modelWhere.length ? 'WHERE '+modelWhere.join(' AND ') : '';
      const modelRowsQ=await pool.query(`
        SELECT
          r.attempt_id,
          u.name,u.email,
          me.title AS exam,
          'Model Exam' AS exam_type,
          to_char(r.submitted_at,'DD-MM-YYYY HH24:MI') AS date,
          r.total_questions::int AS questions,
          r.marks::numeric AS marks,
          r.total_questions::numeric AS total_marks,
          r.percentage::numeric(10,2) AS percentage,
          '' AS subtopics,
          r.submitted_at AS sort_date
        FROM model_exam_results r
        JOIN model_exams me ON me.exam_id=r.exam_id
        JOIN users u ON u.id=r.user_id
        ${modelSql}
      `,modelParams);

      const allRows=[
        ...legacyRowsQ.rows.map(r=>({
          ...r,
          topic:[...new Set(String(r.subtopics||'').split(' | ').map(group4TopicForSubtopic).filter(Boolean))].join(' | ')
        })),
        ...modelRowsQ.rows.map(r=>({...r,topic:''}))
      ].sort((a,b)=>new Date(b.sort_date||0)-new Date(a.sort_date||0));

      const total=allRows.length;
      const participants=new Set(allRows.map(r=>String(r.email||'').toLowerCase()).filter(Boolean)).size;
      const totalQuestions=allRows.reduce((n,r)=>n+Number(r.questions||0),0);
      const averagePct=total ? allRows.reduce((n,r)=>n+Number(r.percentage||0),0)/total : 0;
      const highestPct=total ? Math.max(...allRows.map(r=>Number(r.percentage||0))) : 0;
      const lowestPct=total ? Math.min(...allRows.map(r=>Number(r.percentage||0))) : 0;

      const offset=(page-1)*limit;
      const rows=allRows.slice(offset,offset+limit).map(({sort_date,...r})=>r);

      // Union the exam dropdown values from both result stores.
      const legacyExams=await pool.query(`SELECT DISTINCT a.exam FROM attempts a WHERE a.status='SUBMITTED' ORDER BY a.exam`);
      const modelExams=await pool.query(`
        SELECT DISTINCT me.exam_id,me.title
        FROM model_exam_results r
        JOIN model_exams me ON me.exam_id=r.exam_id
        ORDER BY me.title
      `);
      const exams=[...new Set([
        ...legacyExams.rows.map(x=>x.exam).filter(Boolean),
        ...modelExams.rows.map(x=>x.exam_id||x.title).filter(Boolean)
      ])];

      return res.json({
        ok:true,
        rows,
        total,
        limit,
        page,
        exams,
        summary:{
          participants,
          attempts:total,
          total_questions:totalQuestions,
          average_pct:Number(averagePct.toFixed(2)),
          highest_pct:Number(highestPct.toFixed(2)),
          lowest_pct:Number(lowestPct.toFixed(2))
        }
      });
    }

    // ---------- Existing type-specific result handling ----------
    if(type === 'model'){
      const w=[];
      const p=[];
      if(exam){
        w.push(`(r.exam_id=$${p.length+1} OR me.title=$${p.length+1})`);
        p.push(exam);
      }
      if(subjectFilter){
        w.push(`EXISTS (SELECT 1 FROM model_exam_questions mq WHERE mq.exam_id=r.exam_id AND mq.subject=$${p.length+1})`);
        p.push(subjectFilter);
      }
      if(from){ w.push(`r.submitted_at::date >= $${p.length+1}::date`); p.push(from); }
      if(to){ w.push(`r.submitted_at::date <= $${p.length+1}::date`); p.push(to); }
      w.push(`r.percentage >= $${p.length+1}`); p.push(minPct);
      w.push(`r.percentage <= $${p.length+1}`); p.push(maxPct);

      const whereModel=w.length ? 'WHERE '+w.join(' AND ') : '';
      const count=await pool.query(`
        SELECT count(*)::int AS total,
               count(DISTINCT r.user_id)::int AS participants,
               COALESCE(sum(r.total_questions),0)::bigint AS total_questions,
               COALESCE(avg(r.percentage),0)::numeric(10,2) AS average_pct,
               COALESCE(max(r.percentage),0)::numeric(10,2) AS highest_pct,
               COALESCE(min(r.percentage),0)::numeric(10,2) AS lowest_pct
        FROM model_exam_results r
        JOIN model_exams me ON me.exam_id=r.exam_id
        ${whereModel}
      `,p);

      const pp=p.slice();
      pp.push(limit,(page-1)*limit);
      const rows=await pool.query(`
        SELECT r.attempt_id,
               u.name,u.email,
               me.title AS exam,
               'Model Exam' AS exam_type,
               to_char(r.submitted_at,'DD-MM-YYYY HH24:MI') AS date,
               r.total_questions::int AS questions,
               r.marks::numeric AS marks,
               r.total_questions::numeric AS total_marks,
               r.percentage::numeric(10,2) AS percentage,
               '' AS topic,
               '' AS subtopics
        FROM model_exam_results r
        JOIN model_exams me ON me.exam_id=r.exam_id
        JOIN users u ON u.id=r.user_id
        ${whereModel}
        ORDER BY r.submitted_at DESC,r.id DESC
        LIMIT $${pp.length-1} OFFSET $${pp.length}
      `,pp);

      const c=count.rows[0]||{};
      const examsQ=await pool.query(`
        SELECT DISTINCT me.exam_id,me.title
        FROM model_exam_results r
        JOIN model_exams me ON me.exam_id=r.exam_id
        ORDER BY me.title
      `);
      return res.json({
        ok:true,
        rows:rows.rows,
        total:Number(c.total||0),
        limit,page,
        exams:examsQ.rows.map(x=>x.exam_id||x.title).filter(Boolean),
        summary:{
          participants:Number(c.participants||0),
          attempts:Number(c.total||0),
          total_questions:Number(c.total_questions||0),
          average_pct:Number(c.average_pct||0),
          highest_pct:Number(c.highest_pct||0),
          lowest_pct:Number(c.lowest_pct||0)
        }
      });
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
      WHEN a.total_count=100 THEN '100 Questions'
      ELSE 'Practice'
    END`;
    if(type && ['model','mock','practice','bank','10','20','50','100'].includes(type)){
      const typeExpr=type==='model' ? `lower(a.exam) LIKE '%model%'` : type==='mock' ? `a.mode='mock'` : type==='bank' ? `a.mode='bank'` : type==='10' ? `a.total_count=10` : type==='20' ? `a.total_count=20` : type==='50' ? `a.total_count=50` : type==='100' ? `a.total_count=100` : `(a.mode='practice' AND lower(a.exam) NOT LIKE '%model%' AND a.total_count NOT IN (10,20,50,100))`;
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

    if(type === 'model'){
      const w=[];
      const p=[];
      if(exam){
        w.push(`(r.exam_id=$${p.length+1} OR me.title=$${p.length+1})`);
        p.push(exam);
      }
      if(subjectFilter){
        w.push(`EXISTS (SELECT 1 FROM model_exam_questions mq WHERE mq.exam_id=r.exam_id AND mq.subject=$${p.length+1})`);
        p.push(subjectFilter);
      }
      if(from){ w.push(`r.submitted_at::date >= $${p.length+1}::date`); p.push(from); }
      if(to){ w.push(`r.submitted_at::date <= $${p.length+1}::date`); p.push(to); }
      w.push(`r.percentage >= $${p.length+1}`); p.push(minPct);
      w.push(`r.percentage <= $${p.length+1}`); p.push(maxPct);

      const whereModel=w.length ? 'WHERE '+w.join(' AND ') : '';
      const q=await pool.query(`
        SELECT u.name,u.email,
               me.title AS exam,
               'Model Exam' AS exam_type,
               '' AS topic,
               '' AS subtopics,
               to_char(r.submitted_at,'DD-MM-YYYY HH24:MI') AS date,
               r.total_questions::int AS questions,
               r.marks::numeric AS marks,
               r.total_questions::numeric AS total_marks,
               r.percentage::numeric(10,2) AS percentage
        FROM model_exam_results r
        JOIN model_exams me ON me.exam_id=r.exam_id
        JOIN users u ON u.id=r.user_id
        ${whereModel}
        ORDER BY r.submitted_at DESC,r.id DESC
      `,p);

      /*
       * When Exam Type = All, append the legacy result sources to the same
       * export. Model-only export remains unchanged when type='model'.
       */
      if(type === '' || type === 'all'){
        const legacyWhere=[`a.status='SUBMITTED'`];
        const legacyParams=[];
        const addLegacy=(sql,val)=>{legacyParams.push(val);legacyWhere.push(sql.replace('?', '$'+legacyParams.length));};

        if(exam) addLegacy(`a.exam=?`,exam);
        if(subjectFilter){
          const subjectList=subjectCandidates(subjectFilter);
          legacyWhere.push(`a.subject = ANY($${legacyParams.length+1}::text[])`);
          legacyParams.push(subjectList);
        }
        if(from) addLegacy(`a.submitted_at::date >= ?::date`,from);
        if(to) addLegacy(`a.submitted_at::date <= ?::date`,to);
        if(requestedSubtopic){
          legacyWhere.push(`EXISTS (
            SELECT 1 FROM unnest(a.question_ids) AS aqid
            JOIN questions qq ON qq.id=aqid
            WHERE qq.subtopic = ANY($${legacyParams.length+1}::text[])
          )`);
          legacyParams.push(requestedSubtopicCandidatesSingle);
        }else if(requestedSubtopics.length){
          legacyWhere.push(`EXISTS (
            SELECT 1 FROM unnest(a.question_ids) AS aqid
            JOIN questions qq ON qq.id=aqid
            WHERE qq.subtopic = ANY($${legacyParams.length+1}::text[])
          )`);
          legacyParams.push(requestedSubtopicCandidates);
        }
        legacyWhere.push(`COALESCE(a.score,0) >= $${legacyParams.length+1}`); legacyParams.push(minPct);
        legacyWhere.push(`COALESCE(a.score,0) <= $${legacyParams.length+1}`); legacyParams.push(maxPct);

        const legacyTypeSql=`CASE
          WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam'
          WHEN a.mode='mock' THEN 'Mock Test'
          WHEN a.mode='bank' THEN 'Question Bank'
          WHEN a.total_count=10 THEN '10 Questions'
          WHEN a.total_count=20 THEN '20 Questions'
          WHEN a.total_count=50 THEN '50 Questions'
          WHEN a.total_count=100 THEN '100 Questions'
          ELSE 'Practice'
        END`;

        const legacyQ=await pool.query(`
          SELECT u.name,u.email,a.exam,
                 ${legacyTypeSql} AS exam_type,
                 '' AS topic,
                 COALESCE((
                   SELECT string_agg(DISTINCT qq.subtopic, ' | ' ORDER BY qq.subtopic)
                   FROM unnest(a.question_ids) AS aqid
                   JOIN questions qq ON qq.id=aqid
                 ),'') AS subtopics,
                 to_char(COALESCE(a.submitted_at,a.started_at),'DD-MM-YYYY HH24:MI') AS date,
                 COALESCE(a.total_count,0)::int AS questions,
                 COALESCE(a.correct_count,0)::int AS marks,
                 COALESCE(a.total_count,0)::int AS total_marks,
                 COALESCE(a.score,0)::numeric(10,2) AS percentage
          FROM attempts a
          JOIN users u ON u.id=a.user_id
          WHERE ${legacyWhere.join(' AND ')}
          ORDER BY COALESCE(a.submitted_at,a.started_at) DESC,a.id DESC
        `,legacyParams);

        for(const r of legacyQ.rows){
          r.topic=[...new Set(String(r.subtopics||'').split(' | ').map(group4TopicForSubtopic).filter(Boolean))].join(' | ');
          q.rows.push(r);
        }
      }

      /* Jump directly to the shared XLSX generator below. */
      const escXml=v=>String(v??'')
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/\"/g,'&quot;').replace(/'/g,'&apos;');
      const colName=n=>{
        let z=''; n=Number(n)+1;
        while(n){const rr=(n-1)%26;z=String.fromCharCode(65+rr)+z;n=Math.floor((n-1)/26);}
        return z;
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
          const vals=[r.name,r.email,r.exam,r.exam_type,r.topic,r.subtopics,r.date];
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
        let n=String(name||'Model Exam').replace(/[\\\/\?\*\[\]:]/g,' ').trim()||'Model Exam';
        n=n.slice(0,31); const base=n; let i=2;
        while(used.has(n)){const suffix=` (${i++})`;n=base.slice(0,31-suffix.length)+suffix;}
        used.add(n); return n;
      };
      const groups=new Map();
      for(const r of q.rows){const key=String(r.exam||'Model Exam');if(!groups.has(key))groups.set(key,[]);groups.get(key).push(r);}
      if(!groups.size)groups.set('No Results',[]);
      const sheets=[];const rels=[];const content=[];const usedNames=new Set();let idx=1;
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
      idx=1; for(const [examName,rows] of groups.entries()){files.push({name:`xl/worksheets/sheet${idx}.xml`,data:sheetXml(rows)});idx++;}
      const crcTable=(()=>{const t=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);t[n]=c>>>0;}return t;})();
      const crc32=buf=>{let c=0xFFFFFFFF;for(const b of buf)c=crcTable[(c^b)&255]^(c>>>8);return(c^0xFFFFFFFF)>>>0;};
      const zipParts=[];const central=[];let offset=0;const now=new Date();const dosTime=(now.getHours()<<11)|(now.getMinutes()<<5)|Math.floor(now.getSeconds()/2);const dosDate=((now.getFullYear()-1980)<<9)|((now.getMonth()+1)<<5)|now.getDate();
      for(const f of files){
        const nameBuf=Buffer.from(f.name,'utf8'),dataBuf=Buffer.from(f.data,'utf8'),crc=crc32(dataBuf);
        const local=Buffer.alloc(30+nameBuf.length);local.writeUInt32LE(0x04034b50,0);local.writeUInt16LE(20,4);local.writeUInt16LE(0,6);local.writeUInt16LE(0,8);local.writeUInt16LE(dosTime,10);local.writeUInt16LE(dosDate,12);local.writeUInt32LE(crc,14);local.writeUInt32LE(dataBuf.length,18);local.writeUInt32LE(dataBuf.length,22);local.writeUInt16LE(nameBuf.length,26);local.writeUInt16LE(0,28);nameBuf.copy(local,30);zipParts.push(local,dataBuf);
        const c=Buffer.alloc(46+nameBuf.length);c.writeUInt32LE(0x02014b50,0);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(0,8);c.writeUInt16LE(0,10);c.writeUInt16LE(dosTime,12);c.writeUInt16LE(dosDate,14);c.writeUInt32LE(crc,16);c.writeUInt32LE(dataBuf.length,20);c.writeUInt32LE(dataBuf.length,24);c.writeUInt16LE(nameBuf.length,28);c.writeUInt16LE(0,30);c.writeUInt16LE(0,32);c.writeUInt16LE(0,34);c.writeUInt16LE(0,36);c.writeUInt16LE(0,38);c.writeUInt32LE(offset,42);nameBuf.copy(c,46);central.push(c);offset+=local.length+dataBuf.length;
      }
      const centralBuf=Buffer.concat(central);const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(0,4);end.writeUInt16LE(0,6);end.writeUInt16LE(files.length,8);end.writeUInt16LE(files.length,10);end.writeUInt32LE(centralBuf.length,12);end.writeUInt32LE(offset,16);
      const xlsx=Buffer.concat([...zipParts,centralBuf,end]);
      const filename=(type===''?'thiral_all_exam_results_':'thiral_model_exam_results_')+new Date().toISOString().slice(0,10)+'.xlsx';
      res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);
      res.setHeader('Content-Length',String(xlsx.length));
      return res.end(xlsx);
    }

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
    if(type && ['model','mock','practice','bank','10','20','50','100'].includes(type)){
      where.push(type==='model'?`lower(a.exam) LIKE '%model%'`:type==='mock'?`a.mode='mock'`:type==='bank'?`a.mode='bank'`:type==='10'?`a.total_count=10`:type==='20'?`a.total_count=20`:type==='50'?`a.total_count=50`:type==='100'?`a.total_count=100`:`(a.mode='practice' AND lower(a.exam) NOT LIKE '%model%' AND a.total_count NOT IN (10,20,50,100))`);
    }

    const typeSql=`CASE WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam' WHEN a.mode='mock' THEN 'Mock Test' WHEN a.mode='bank' THEN 'Question Bank' WHEN a.total_count=10 THEN '10 Questions' WHEN a.total_count=20 THEN '20 Questions' WHEN a.total_count=50 THEN '50 Questions' WHEN a.total_count=100 THEN '100 Questions' ELSE 'Practice' END`;
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
    const typeSql=`CASE WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam' WHEN a.mode='mock' THEN 'Mock Test' WHEN a.mode='bank' THEN 'Question Bank' WHEN a.total_count=10 THEN '10 Questions' WHEN a.total_count=20 THEN '20 Questions' WHEN a.total_count=50 THEN '50 Questions' WHEN a.total_count=100 THEN '100 Questions' ELSE 'Practice' END`;
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


api.get('/admin/security/events', requireAdmin, async (req,res)=>{
  try{
    const limit=Math.min(Math.max(Number(req.query.limit)||100,1),200);
    const q=await pool.query(`
      SELECT id,event_type,created_at,email,ip,user_agent,details
      FROM security_events
      ORDER BY id DESC
      LIMIT $1`,[limit]);
    const s=await pool.query(`
      SELECT
        count(*) FILTER (WHERE created_at>=now()-interval '24 hours' AND event_type='FAILED_LOGIN')::int AS failed_logins,
        count(*) FILTER (WHERE created_at>=now()-interval '24 hours' AND event_type='ADMIN_LOGIN_SUCCESS')::int AS successful_admin_logins,
        count(*) FILTER (WHERE created_at>=now()-interval '24 hours' AND event_type='UNAUTHORIZED_ADMIN_ACCESS')::int AS unauthorized_admin_access
      FROM security_events`);
    res.json({events:q.rows,stats:s.rows[0]||{}});
  }catch(e){console.error('Security events error:',e);sendError(res,500,'Security monitor error.');}
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
      count(*) FILTER (WHERE trim(COALESCE(gender,''))='???')::int AS male,
      count(*) FILTER (WHERE trim(COALESCE(gender,''))='????')::int AS female,
      count(*) FILTER (WHERE trim(COALESCE(gender,''))='???????? ???????')::int AS third,
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

api.delete('/admin/students/:studentId', requireAdmin, async (req,res)=>{
  const client = await pool.connect();
  try{
    const studentId = String(req.params.studentId || '').trim();
    if(!studentId) return sendError(res,400,'Student ID is required.');

    await client.query('BEGIN');

    const q = await client.query(
      `SELECT id,student_id,role FROM users WHERE student_id=$1 LIMIT 1 FOR UPDATE`,
      [studentId]
    );

    if(!q.rowCount){
      await client.query('ROLLBACK');
      return sendError(res,404,'Student not found.');
    }

    const target = q.rows[0];
    if(target.role !== 'STUDENT'){
      await client.query('ROLLBACK');
      return sendError(res,400,'Only STUDENT accounts can be deleted here.');
    }
    if(target.id === req.user.id){
      await client.query('ROLLBACK');
      return sendError(res,400,'The logged-in Admin account cannot be deleted here.');
    }

    /* Delete only this student's account and student-owned records.
       Questions and Question Bank are never touched by this operation. */
    await client.query(`DELETE FROM sessions WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM question_history WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM password_reset_otps WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM attempts WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM activity_events WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM users WHERE id=$1 AND role='STUDENT'`, [target.id]);

    await client.query('COMMIT');
    res.json({ok:true,student_id:target.student_id});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch(_){ }
    console.error('[ADMIN] Student delete error:',e);
    sendError(res,500,'Student delete service error.');
  }finally{
    client.release();
  }
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
    if (!user) {
      const ip=clientIp(req);
      const recent=await pool.query(`SELECT count(*)::int AS n FROM security_events WHERE event_type='UNAUTHORIZED_ADMIN_ACCESS' AND ip=$1 AND created_at>=now()-interval '15 minutes'`,[ip]);
      const alert=Number(recent.rows[0]?.n||0)===0;
      await logSecurityEvent({req,eventType:'UNAUTHORIZED_ADMIN_ACCESS',details:`Blocked ${req.method} ${req.originalUrl}`,sendAlert:alert});
      return sendError(res, 401, 'ACCESS DENIED: Login required.');
    }
    if (user.role !== 'ADMIN') {
      await logSecurityEvent({req,eventType:'UNAUTHORIZED_ADMIN_ACCESS',userId:user.id,email:user.email,details:`Non-admin user attempted ${req.method} ${req.originalUrl}`,sendAlert:true});
      return sendError(res, 403, 'ACCESS DENIED: Admin authorization required.');
    }
    req.user = user;
    res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma','no-cache');
    res.setHeader('Vary','Cookie, Origin');
    next();
  } catch (e) {
    console.error('Admin authorization error:', e);
    return sendError(res, 500, 'Authentication service error.');
  }
});


/* ===== GROUP 4 MOCK ROTATION API =====
   Final Group 4 Mock selector.
   - Exactly 200 questions when the database has at least 200 unique unused rows.
   - Q1-Q100 Tamil; Q101-Q200 = 75 GS + 25 Aptitude.
   - Excludes this student's previous Mock history by both question ID and content.
   - Removes duplicate content even when duplicate DB rows have different IDs/options order.
   - Prefers Moderate/Hard/Very Hard questions and strongly penalizes short direct-fact items.
   - Never deletes or rewrites question-bank rows.
   - Practice 10/20/50/100 routes are not changed here.
*/
api.get('/mock/questions', requirePasswordReady, async (req,res)=>{
  const exam=String(req.query.exam||'').trim();
  const requestedLanguage=String(req.query.language||'ta').trim();
  if(exam!=='group4' || !['ta','en'].includes(requestedLanguage)){
    return sendError(res,400,'Invalid Group 4 Mock request.');
  }

  const client=await pool.connect();
  try{
    await client.query('BEGIN');

    /* Prevent two simultaneous Mock starts for the same student from taking
       overlapping fresh pools. */
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext($1))`,
      [`thiral-group4-mock:${req.user.id}`]
    );

    const specs=[
      {name:'tamil',candidates:['tamil','?????'],language:'ta'},
      {name:'gs',candidates:['???? ?????','General Knowledge','general knowledge','???? ????? / General Studies','General Studies','general studies'],language:requestedLanguage},
      {name:'apt',candidates:['apt','???????? / Aptitude','Aptitude','aptitude'],language:requestedLanguage}
    ];

    const all=[];
    for(const spec of specs){
      const r=await client.query(
        `SELECT id,exam,subject,subtopic,language,question,options,explanation,
                COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
           FROM questions
          WHERE exam=$1
            AND subject=ANY($2::text[])
            AND language=$3
            AND is_active=true
            AND NOT EXISTS (
              SELECT 1 FROM question_history h
               WHERE h.user_id=$4
                 AND h.question_id=questions.id
                 AND h.mode='mock'
            )
          ORDER BY id
          LIMIT 3000`,
        [exam,spec.candidates,spec.language,req.user.id]
      );
      all.push(...r.rows.map(q=>({...q,_mockSubject:spec.name})));
    }

    const normalizeText=(v)=>String(v??'')
      .normalize('NFKC')
      .replace(/[“”‘’]/g,'"')
      .replace(/[^\p{L}\p{N}]+/gu,' ')
      .replace(/\s+/g,' ')
      .trim()
      .toLowerCase();

    /* Content key intentionally sorts options, so changing A/B/C/D order does
       not create a fake new question. */
    const contentKey=(q)=>{
      const qKey=normalizeText(q.question);
      const opts=Array.isArray(q.options)
        ? q.options.map(normalizeText).filter(Boolean).sort()
        : [];
      return qKey+'|'+opts.join('|');
    };
    const questionOnlyKey=(q)=>normalizeText(q.question);

    const oldHistory=await client.query(
      `SELECT q.question,q.options
         FROM question_history h
         JOIN questions q ON q.id=h.question_id
        WHERE h.user_id=$1 AND h.mode='mock'`,
      [req.user.id]
    );

    const blockedContent=new Set();
    const blockedQuestion=new Set();
    for(const q of oldHistory.rows){
      blockedContent.add(contentKey(q));
      blockedQuestion.add(questionOnlyKey(q));
    }

    /* Remove duplicates in the current fresh pool and also block previous
       Mock content even when it exists under another database ID. */
    const seenContent=new Set(blockedContent);
    const seenQuestion=new Set(blockedQuestion);
    const unique=[];
    for(const q of all){
      const ck=contentKey(q);
      const qk=questionOnlyKey(q);
      if(!qk || seenContent.has(ck) || seenQuestion.has(qk)) continue;
      seenContent.add(ck);
      seenQuestion.add(qk);
      unique.push(q);
    }

    const shuffle=(rows)=>{
      const a=rows.slice();
      for(let i=a.length-1;i>0;i--){
        const j=Math.floor(Math.random()*(i+1));
        [a[i],a[j]]=[a[j],a[i]];
      }
      return a;
    };

    /* Difficulty is not inferred from the number of options. That was the
       previous problem: four options do not magically make a Taj Mahal fact
       question difficult. Explicit DB difficulty wins, but obvious direct-fact
       questions are capped at Moderate unless their wording has real complexity. */
    const difficultyInfo=(q)=>{
      const raw=String(q.difficulty||'').trim().toLowerCase();
      const text=normalizeText(q.question);
      const words=text.split(' ').filter(Boolean).length;
      const directFact=/^(who|where|when|what is|what was|which is|which was|identify|name the|who was|where was|when was)\b/.test(text)
        || /^(????|????|?????|???????|???|???|????|???????? ?????|????????)\b/.test(text);
      const complex=/statement|statements|assertion|reason|cause|effect|match|matching|pair|sequence|arrange|order|select the correct|which of the following|??????|?????????|??????|??????|?????????|?????|?????? ???|???????????????? ???|???????????????/.test(text);
      const quantitative=/percentage|ratio|average|profit|loss|interest|discount|time and work|speed|distance|mixture|age|probability|data interpretation|series|equation|fraction|???????|???????|??????|??????|??????|?????|????????|????|?????|?????|????|????|?????????|????|?????|????????|???????/.test(text);
      const long=words>=24 || text.length>=125;
      const optionText=Array.isArray(q.options)?q.options.map(normalizeText).join(' '):'';
      const richOptions=optionText.split(' ').filter(Boolean).length>=18;

      let score=0;
      if(complex) score+=3;
      if(quantitative) score+=3;
      if(long) score+=2;
      if(richOptions) score+=1;
      if(directFact && !complex && !quantitative && words<18) score-=3;

      let bucket=null;
      if(/very\s*hard|veryhard|???\s*??????|???????????/.test(raw)) bucket=3;
      else if(/\bhard\b|??????/.test(raw)) bucket=2;
      else if(/moderate|medium|normal|????????|????????/.test(raw)) bucket=1;
      else if(/easy|basic|?????|????????/.test(raw)) bucket=0;

      if(bucket===3 && score<2 && directFact) bucket=1;
      if(bucket===2 && score<1 && directFact) bucket=1;
      if(bucket===null){
        bucket=score>=5?3:score>=3?2:score>=1?1:0;
      }

      /* A ranking score is also kept, so when a preferred bucket is short the
         strongest available questions fill the remaining slots. */
      const rank=(bucket*20)+(score*5)+(complex?3:0)+(quantitative?3:0)+(long?2:0);
      return {bucket,rank};
    };

    const selectBest=(rows,count,quotas)=>{
      const meta=rows.map(q=>({q,info:difficultyInfo(q)}));
      const chosen=[];
      const used=new Set();

      const takeBucket=(bucket,n)=>{
        if(n<=0) return;
        meta.filter(x=>x.info.bucket===bucket)
          .sort((a,b)=>b.info.rank-a.info.rank || Math.random()-.5)
          .some(x=>{
            if(chosen.length>=count || used.has(String(x.q.id))) return false;
            chosen.push(x.q); used.add(String(x.q.id));
            return chosen.filter(y=>difficultyInfo(y).bucket===bucket).length>=n;
          });
      };

      /* Preferred distribution: Moderate 20%, Hard 60%, Very Hard 20%.
         If the DB has fewer genuinely difficult questions, fill from the next
         strongest unused questions instead of returning a broken Mock. */
      takeBucket(3,quotas[3]||0);
      takeBucket(2,quotas[2]||0);
      takeBucket(1,quotas[1]||0);

      if(chosen.length<count){
        meta.sort((a,b)=>b.info.rank-a.info.rank || Math.random()-.5);
        for(const x of meta){
          if(chosen.length>=count) break;
          const id=String(x.q.id);
          if(used.has(id)) continue;
          chosen.push(x.q); used.add(id);
        }
      }
      return chosen.slice(0,count);
    };

    let tamilRows=unique.filter(q=>q._mockSubject==='tamil');
    let gsRows=unique.filter(q=>q._mockSubject==='gs');
    let aptRows=unique.filter(q=>q._mockSubject==='apt');

    /* If this student has already consumed the fresh pool, do not leave the
       Mock screen empty. Reuse old Mock questions only after the fresh pool
       for that subject is exhausted. The current Mock still avoids duplicate
       content until its unique pool is exhausted. */
    const need={tamil:100,gs:75,apt:25};
    const freshCount={tamil:tamilRows.length,gs:gsRows.length,apt:aptRows.length};
    if(freshCount.tamil<100 || freshCount.gs<75 || freshCount.apt<25){
      const recycleAll=[];
      for(const spec of specs){
        const r=await client.query(
          `SELECT id,exam,subject,subtopic,language,question,options,explanation,
                  COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
             FROM questions
            WHERE exam=$1
              AND subject=ANY($2::text[])
              AND language=$3
              AND is_active=true
            ORDER BY id
            LIMIT 5000`,
          [exam,spec.candidates,spec.language]
        );
        recycleAll.push(...r.rows.map(q=>({...q,_mockSubject:spec.name})));
      }

      const addRecycled=(name,current,required)=>{
        if(current.length>=required) return current;
        const localSeen=new Set(current.map(contentKey));
        for(const q of recycleAll){
          if(q._mockSubject!==name) continue;
          const ck=contentKey(q);
          if(!ck || localSeen.has(ck)) continue;
          localSeen.add(ck);
          current.push(q);
          if(current.length>=required) break;
        }
        return current;
      };

      tamilRows=addRecycled('tamil',tamilRows,100);
      gsRows=addRecycled('gs',gsRows,75);
      aptRows=addRecycled('apt',aptRows,25);
    }

    /* A Mock must contain 200 slots. If a subject has fewer than its required
       number of unique questions even after recycling, cycle only after that
       subject's unique pool is exhausted. This prevents an empty Mock while
       preserving uniqueness for as long as the database permits. */
    const cycleTo=(rows,count)=>{
      if(!rows.length) return [];
      const out=[];
      for(let i=0;i<count;i++) out.push(rows[i%rows.length]);
      return out;
    };

    const tamilSelected=selectBest(tamilRows,Math.min(100,tamilRows.length),{1:20,2:60,3:20});
    const gsSelected=selectBest(gsRows,Math.min(75,gsRows.length),{1:15,2:45,3:15});
    const aptSelected=selectBest(aptRows,Math.min(25,aptRows.length),{1:5,2:15,3:5});

    const tamilFinal=tamilSelected.length>=100?tamilSelected:cycleTo(tamilRows,100);
    const gsFinal=gsSelected.length>=75?gsSelected:cycleTo(gsRows,75);
    const aptFinal=aptSelected.length>=25?aptSelected:cycleTo(aptRows,25);

    if(!tamilFinal.length || !gsFinal.length || !aptFinal.length){
      await client.query('ROLLBACK');
      return sendError(res,409,
        `Mock-???? ??????? ????????? ?????. ?????: ${tamilRows.length}, GS: ${gsRows.length}, Aptitude: ${aptRows.length}.` 
      );
    }

    /* Aptitude gets a second diversity pass across subtopics, without allowing
       a weaker question to displace a much stronger one unnecessarily. */
    const aptBySub=new Map();
    for(const q of aptSelected){
      const k=normalizeText(q.subtopic)||'__no_subtopic__';
      if(!aptBySub.has(k)) aptBySub.set(k,[]);
      aptBySub.get(k).push(q);
    }
    const aptTopics=shuffle(Array.from(aptBySub.keys()));
    const aptMixed=[];
    let more=true;
    while(more){
      more=false;
      for(const k of aptTopics){
        const arr=aptBySub.get(k);
        if(arr&&arr.length){aptMixed.push(arr.shift());more=true;}
      }
    }

    const selected=[
      ...shuffle(tamilFinal).slice(0,100),
      ...shuffle([...gsFinal.slice(0,75),...aptMixed.slice(0,25)])
    ];

    if(selected.length!==200){
      await client.query('ROLLBACK');
      return sendError(res,500,'Mock Test-???? 200 ????????? ???????? ???????????.');
    }

    const clean=selected.map(q=>Number(q.id));
    const ins=await client.query(
      `INSERT INTO attempts(user_id,exam,subject,mode,language,question_ids)
       VALUES($1,$2,'mixed','mock','mixed',$3)
       RETURNING id`,
      [req.user.id,exam,clean]
    );

    await client.query(
      `INSERT INTO question_history(user_id,question_id,mode)
       SELECT $1,x,'mock'
         FROM unnest($2::bigint[]) AS x
       ON CONFLICT(user_id,question_id,mode) DO NOTHING`,
      [req.user.id,clean]
    );

    await client.query('COMMIT');

    res.json({
      attemptId:ins.rows[0].id,
      questions:selected,
      count:200,
      recycled:0
    });
  }catch(e){
    try{await client.query('ROLLBACK');}catch(_){ }
    console.error('Group 4 Mock selection error:',e);
    sendError(res,500,'Mock question service error.');
  }finally{
    client.release();
  }
});



/* ========================= MODEL EXAM MODULE =========================
   This module is intentionally isolated from the master questions table.
   It creates its own exams, questions, attempts, answers, results and
   question backups. Existing practice/mock/question-bank data is untouched.
*/

function parseModelExamQuestions(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.map((item, idx) => {
    const options = Array.isArray(item.options)
      ? item.options.map(v => String(v ?? '').trim())
      : [];
    const correct = String(item.correct_answer ?? item.correct_option ?? '').trim().toUpperCase();
    return {
      question_no: Number(item.question_no || item.no || idx + 1),
      question: String(item.question || '').trim(),
      options,
      correct_answer: correct,
      explanation: String(item.explanation || '').trim(),
      subject: String(item.subject || '').trim(),
      topic: String(item.topic || item.subtopic || '').trim(),
      language: String(item.language || 'ta').trim()
    };
  });
}

function validateModelExamQuestions(rows) {
  if (!rows.length) return 'At least one Model Exam question is required.';
  const seenNos = new Set();
  const seenContent = new Set();
  for (const q of rows) {
    if (!Number.isInteger(q.question_no) || q.question_no < 1) return 'Invalid question number.';
    if (seenNos.has(q.question_no)) return `Duplicate question number: ${q.question_no}`;
    seenNos.add(q.question_no);
    if (!q.question) return `Question text is required for Q${String(q.question_no).padStart(3,'0')}.`;
    if (q.options.length !== 4 || q.options.some(x => !x)) return `Exactly 4 non-empty options are required for Q${String(q.question_no).padStart(3,'0')}.`;
    if (!['A','B','C','D'].includes(q.correct_answer)) return `Correct Answer must be A/B/C/D for Q${String(q.question_no).padStart(3,'0')}.`;
    if (!['ta','en'].includes(q.language)) return `Language must be ta or en for Q${String(q.question_no).padStart(3,'0')}.`;
    const contentKey = crypto.createHash('sha256').update(
      JSON.stringify([q.question, q.options.map(x => x.trim())])
    ).digest('hex');
    if (seenContent.has(contentKey)) return `Duplicate question content detected at Q${q.question_no}.`;
    seenContent.add(contentKey);
  }
  return null;
}

api.get('/admin/model-exams', requireAdmin, async (req,res)=>{
  try {
    const q = await pool.query(`
      SELECT e.exam_id,e.title,e.exam_date,e.start_time,e.availability_hours,
             e.duration_minutes,e.is_active,e.created_at,e.updated_at,
             COUNT(q.id)::int AS question_count
      FROM model_exams e
      LEFT JOIN model_exam_questions q ON q.exam_id=e.exam_id
      GROUP BY e.id
      ORDER BY e.exam_date DESC,e.start_time DESC,e.created_at DESC
      LIMIT 100
    `);
    res.json({ok:true,exams:q.rows});
  } catch(e) {
    console.error('[MODEL EXAM] admin list error:',e);
    sendError(res,500,'Model Exam list service error.');
  }
});

api.get('/admin/model-exams/:examId', requireAdmin, async (req,res)=>{
  try {
    const examId=String(req.params.examId||'').trim();
    const exam=await pool.query(`SELECT * FROM model_exams WHERE exam_id=$1 LIMIT 1`,[examId]);
    if(!exam.rowCount) return sendError(res,404,'Model Exam not found.');
    const questions=await pool.query(`
      SELECT question_no,question,options,correct_answer,explanation,subject,topic,language,created_at
      FROM model_exam_questions WHERE exam_id=$1 ORDER BY question_no
    `,[examId]);
    res.json({ok:true,exam:exam.rows[0],questions:questions.rows});
  } catch(e) {
    console.error('[MODEL EXAM] admin detail error:',e);
    sendError(res,500,'Model Exam detail service error.');
  }
});

/* Create a completely new Model Exam. Existing exam IDs are never overwritten. */
api.post('/admin/model-exams', requireAdmin, async (req,res)=>{
  const client=await pool.connect();
  try {
    const examId=String(req.body?.exam_id||'').trim();
    const title=String(req.body?.title||'').trim();
    const examDate=String(req.body?.exam_date||'').trim();
    const startTime=String(req.body?.start_time||'').trim();
    const availabilityHours=Number(req.body?.availability_hours ?? 24);
    const durationMinutes=Number(req.body?.duration_minutes ?? 180);
    const rows=parseModelExamQuestions(req.body?.questions);

    if(!examId || !title || !examDate || !startTime) return sendError(res,400,'Exam ID, title, date and start time are required.');
    if(!Number.isInteger(availabilityHours) || availabilityHours < 1 || availabilityHours > 168) return sendError(res,400,'Invalid availability hours.');
    if(durationMinutes !== 180) return sendError(res,400,'Model Exam duration must be 180 minutes.');
    const validation=validateModelExamQuestions(rows);
    if(validation) return sendError(res,400,validation);

    /* A Model Exam is a single immutable question-set container. Never overwrite
       an existing exam. A new revision gets a new exam_id. */
    await client.query('BEGIN');
    const existing=await client.query(`SELECT 1 FROM model_exams WHERE exam_id=$1 LIMIT 1`,[examId]);
    if(existing.rowCount){
      await client.query('ROLLBACK');
      return sendError(res,409,'This Exam ID already exists. Existing Model Exam data is never overwritten. Use a new Exam ID.');
    }

    await client.query(`
      INSERT INTO model_exams
        (exam_id,title,exam_date,start_time,availability_hours,duration_minutes,is_active,created_by)
      VALUES($1,$2,$3,$4,$5,$6,true,$7)
    `,[examId,title,examDate,startTime,availabilityHours,durationMinutes,req.user.id]);

    for(const q of rows){
      await client.query(`
        INSERT INTO model_exam_questions
          (exam_id,question_no,question,options,correct_answer,explanation,subject,topic,language)
        VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9)
      `,[examId,q.question_no,q.question,JSON.stringify(q.options),q.correct_answer,q.explanation,q.subject,q.topic,q.language]);
    }

    await client.query('COMMIT');
    res.status(201).json({ok:true,exam_id:examId,question_count:rows.length,message:'Model Exam saved successfully.'});
  } catch(e) {
    try{await client.query('ROLLBACK');}catch(_){ }
    console.error('[MODEL EXAM] save error:',e);
    sendError(res,500,'Model Exam save service error.');
  } finally { client.release(); }
});

/* Student can see only currently available exams. Correct answers are never returned. */
api.get('/model-exams/available', requirePasswordReady, async (req,res)=>{
  try {
    const q=await pool.query(`
      SELECT e.exam_id,e.title,e.exam_date,e.start_time,e.availability_hours,e.duration_minutes,
             COUNT(q.id)::int AS question_count
      FROM model_exams e
      JOIN model_exam_questions q ON q.exam_id=e.exam_id
      WHERE e.is_active=true
        AND now() >= (e.exam_date + e.start_time)
        AND now() <  (e.exam_date + e.start_time) + make_interval(hours => e.availability_hours)
      GROUP BY e.id
      HAVING COUNT(q.id) >= 1
      ORDER BY e.exam_date,e.start_time
    `);
    res.json({ok:true,exams:q.rows});
  } catch(e) {
    console.error('[MODEL EXAM] available error:',e);
    sendError(res,500,'Available Model Exam service error.');
  }
});

api.get('/model-exams/:examId/questions', requirePasswordReady, async (req,res)=>{
  try {
    const examId=String(req.params.examId||'').trim();
    const e=await pool.query(`
      SELECT exam_id,title,exam_date,start_time,availability_hours,duration_minutes
      FROM model_exams
      WHERE exam_id=$1 AND is_active=true
        AND now() >= (exam_date + start_time)
        AND now() <  (exam_date + start_time) + make_interval(hours => availability_hours)
      LIMIT 1
    `,[examId]);
    if(!e.rowCount) return sendError(res,404,'Model Exam is not currently available.');
    const q=await pool.query(`
      SELECT question_no,question,options,subject,topic,language
      FROM model_exam_questions WHERE exam_id=$1 ORDER BY question_no
    `,[examId]);
    res.json({ok:true,exam:e.rows[0],questions:q.rows});
  } catch(e) {
    console.error('[MODEL EXAM] question delivery error:',e);
    sendError(res,500,'Model Exam question service error.');
  }
});

api.post('/model-exams/:examId/start', requirePasswordReady, async (req,res)=>{
  const client=await pool.connect();
  try {
    const examId=String(req.params.examId||'').trim();
    await client.query('BEGIN');
    const e=await client.query(`
      SELECT * FROM model_exams
      WHERE exam_id=$1 AND is_active=true
        AND now() >= (exam_date + start_time)
        AND now() < (exam_date + start_time) + make_interval(hours => availability_hours)
      LIMIT 1 FOR SHARE
    `,[examId]);
    if(!e.rowCount){await client.query('ROLLBACK');return sendError(res,404,'Model Exam is not currently available.');}

    const existing=await client.query(`
      SELECT id,started_at,submitted_at FROM model_exam_attempts
      WHERE exam_id=$1 AND user_id=$2 ORDER BY started_at DESC LIMIT 1
    `,[examId,req.user.id]);
    if(existing.rowCount && !existing.rows[0].submitted_at){
      await client.query('COMMIT');
      return res.json({ok:true,attempt_id:existing.rows[0].id,resumed:true,started_at:existing.rows[0].started_at,duration_minutes:e.rows[0].duration_minutes});
    }

    const ins=await client.query(`
      INSERT INTO model_exam_attempts(exam_id,user_id,started_at,status)
      VALUES($1,$2,now(),'in_progress') RETURNING id,started_at
    `,[examId,req.user.id]);
    await client.query('COMMIT');
    res.status(201).json({ok:true,attempt_id:ins.rows[0].id,resumed:false,started_at:ins.rows[0].started_at,duration_minutes:e.rows[0].duration_minutes});
  } catch(e){
    try{await client.query('ROLLBACK');}catch(_){ }
    console.error('[MODEL EXAM] start error:',e);
    sendError(res,500,'Model Exam start service error.');
  } finally {client.release();}
});

api.post('/model-exams/:examId/answer', requirePasswordReady, async (req,res)=>{
  try {
    const examId=String(req.params.examId||'').trim();
    const attemptId=String(req.body?.attempt_id||'').trim();
    const questionNo=Number(req.body?.question_no);
    const answer=String(req.body?.answer||'').trim().toUpperCase();
    if(!attemptId || !Number.isInteger(questionNo) || !['A','B','C','D'].includes(answer)) return sendError(res,400,'Invalid Model Exam answer.');
    const a=await pool.query(`SELECT id FROM model_exam_attempts WHERE id=$1 AND exam_id=$2 AND user_id=$3 AND submitted_at IS NULL LIMIT 1`,[attemptId,examId,req.user.id]);
    if(!a.rowCount) return sendError(res,404,'Active Model Exam attempt not found.');
    const q=await pool.query(`SELECT id FROM model_exam_questions WHERE exam_id=$1 AND question_no=$2 LIMIT 1`,[examId,questionNo]);
    if(!q.rowCount) return sendError(res,404,'Question not found.');
    await pool.query(`
      INSERT INTO model_exam_answers(attempt_id,question_id,answer,updated_at)
      VALUES($1,$2,$3,now())
      ON CONFLICT(attempt_id,question_id) DO UPDATE SET answer=EXCLUDED.answer,updated_at=now()
    `,[attemptId,q.rows[0].id,answer]);
    res.json({ok:true});
  } catch(e){
    console.error('[MODEL EXAM] answer error:',e);
    sendError(res,500,'Model Exam answer service error.');
  }
});

api.post('/model-exams/:examId/submit', requirePasswordReady, async (req,res)=>{
  const client=await pool.connect();
  try {
    const examId=String(req.params.examId||'').trim();
    const attemptId=String(req.body?.attempt_id||'').trim();
    if(!attemptId) return sendError(res,400,'Attempt ID is required.');
    await client.query('BEGIN');
    const a=await client.query(`
      SELECT id,started_at,submitted_at FROM model_exam_attempts
      WHERE id=$1 AND exam_id=$2 AND user_id=$3 LIMIT 1 FOR UPDATE
    `,[attemptId,examId,req.user.id]);
    if(!a.rowCount){await client.query('ROLLBACK');return sendError(res,404,'Model Exam attempt not found.');}
    if(a.rows[0].submitted_at){await client.query('ROLLBACK');return sendError(res,409,'Model Exam already submitted.');}

    const rows=await client.query(`
      SELECT q.id,q.question_no,q.correct_answer,a.answer
      FROM model_exam_questions q
      LEFT JOIN model_exam_answers a ON a.question_id=q.id AND a.attempt_id=$1
      WHERE q.exam_id=$2 ORDER BY q.question_no
    `,[attemptId,examId]);
    const total=rows.rowCount;
    const attempted=rows.rows.filter(r=>r.answer).length;
    const correct=rows.rows.filter(r=>r.answer && r.answer===r.correct_answer).length;
    const notAttempted=total-attempted;
    const percentage=total ? Number(((correct/total)*100).toFixed(2)) : 0;

    await client.query(`
      UPDATE model_exam_attempts
      SET submitted_at=now(),status='submitted',total_questions=$1,attempted=$2,not_attempted=$3,marks=$4,percentage=$5
      WHERE id=$6
    `,[total,attempted,notAttempted,correct,percentage,attemptId]);
    await client.query(`
      INSERT INTO model_exam_results(attempt_id,exam_id,user_id,total_questions,attempted,not_attempted,marks,percentage,submitted_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,now())
      ON CONFLICT(attempt_id) DO NOTHING
    `,[attemptId,examId,req.user.id,total,attempted,notAttempted,correct,percentage]);
    await client.query('COMMIT');
    res.json({ok:true,total_questions:total,attempted,not_attempted,marks:correct,percentage});
  } catch(e){
    try{await client.query('ROLLBACK');}catch(_){ }
    console.error('[MODEL EXAM] submit error:',e);
    sendError(res,500,'Model Exam submit service error.');
  } finally {client.release();}
});

/* Admin-only question clear. It backs up the questions first and never deletes
   attempts, answers or results. */
api.delete('/admin/model-exams/:examId/questions', requireAdmin, async (req,res)=>{
  const client=await pool.connect();
  try {
    const examId=String(req.params.examId||'').trim();
    await client.query('BEGIN');
    const q=await client.query(`SELECT * FROM model_exam_questions WHERE exam_id=$1 ORDER BY question_no FOR UPDATE`,[examId]);
    if(!q.rowCount){await client.query('ROLLBACK');return sendError(res,404,'No Model Exam questions found.');}
    for(const row of q.rows){
      await client.query(`
        INSERT INTO model_exam_question_backups
          (original_question_id,exam_id,question_no,question,options,correct_answer,explanation,subject,topic,language,deleted_by)
        VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11)
      `,[row.id,row.exam_id,row.question_no,row.question,JSON.stringify(row.options),row.correct_answer,row.explanation,row.subject,row.topic,row.language,req.user.id]);
    }
    await client.query(`DELETE FROM model_exam_questions WHERE exam_id=$1`,[examId]);
    await client.query('COMMIT');
    res.json({ok:true,deleted_questions:q.rowCount,backup_created:true,message:'Questions deleted. Student attempts, answers and results were preserved.'});
  } catch(e){
    try{await client.query('ROLLBACK');}catch(_){ }
    console.error('[MODEL EXAM] question delete error:',e);
    sendError(res,500,'Model Exam question delete service error.');
  } finally {client.release();}
});

api.get('/admin/model-exams/:examId/question-backups', requireAdmin, async (req,res)=>{
  try {
    const examId=String(req.params.examId||'').trim();
    const q=await pool.query(`
      SELECT id,original_question_id,exam_id,question_no,question,options,correct_answer,explanation,subject,topic,language,deleted_at
      FROM model_exam_question_backups WHERE exam_id=$1 ORDER BY deleted_at DESC,question_no
    `,[examId]);
    res.json({ok:true,backups:q.rows});
  } catch(e){
    console.error('[MODEL EXAM] backup list error:',e);
    sendError(res,500,'Model Exam backup service error.');
  }
});

api.get('/admin/model-exams/:examId/results', requireAdmin, async (req,res)=>{
  try {
    const examId=String(req.params.examId||'').trim();
    const q=await pool.query(`
      SELECT r.id,r.attempt_id,r.user_id,r.total_questions,r.attempted,r.not_attempted,r.marks,r.percentage,r.submitted_at,
             u.student_id,u.name,u.email
      FROM model_exam_results r
      JOIN users u ON u.id=r.user_id
      WHERE r.exam_id=$1 ORDER BY r.submitted_at DESC
    `,[examId]);
    res.json({ok:true,results:q.rows});
  } catch(e){
    console.error('[MODEL EXAM] results error:',e);
    sendError(res,500,'Model Exam results service error.');
  }
});

app.use('/api', api);

app.use(express.static(path.join(__dirname,'frontend'), { index:'index.html' }));

app.get('/{*splat}', (req,res)=>{
  res.sendFile(path.join(__dirname,'frontend','index.html'));
});

/* Create the history table/index without touching existing question data. */


async function ensureSecurityEventsTable(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS security_events (
      id BIGSERIAL PRIMARY KEY,
      event_type VARCHAR(80) NOT NULL,
      user_id BIGINT NULL,
      email TEXT NULL,
      ip TEXT NULL,
      user_agent TEXT NULL,
      details TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type,created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_security_events_ip_created ON security_events(ip,created_at DESC)`);
}

async function ensureMustChangePasswordColumn(){
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false
  `);
}


async function ensureLoginDeviceBindingColumn(){
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS login_device_hash TEXT NULL
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



async function ensureModelExamTables(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exams (
      id BIGSERIAL PRIMARY KEY,
      exam_id TEXT NOT NULL UNIQUE,
      title TEXT NOT NULL,
      exam_date DATE NOT NULL,
      start_time TIME NOT NULL,
      availability_hours INTEGER NOT NULL DEFAULT 24 CHECK (availability_hours > 0 AND availability_hours <= 168),
      duration_minutes INTEGER NOT NULL DEFAULT 180 CHECK (duration_minutes = 180),
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_by BIGINT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_model_exams_schedule ON model_exams(exam_date,start_time,is_active)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exam_questions (
      id BIGSERIAL PRIMARY KEY,
      exam_id TEXT NOT NULL REFERENCES model_exams(exam_id) ON DELETE CASCADE,
      question_no INTEGER NOT NULL,
      question TEXT NOT NULL,
      options JSONB NOT NULL,
      correct_answer CHAR(1) NOT NULL CHECK (correct_answer IN ('A','B','C','D')),
      explanation TEXT NOT NULL DEFAULT '',
      subject TEXT NOT NULL DEFAULT '',
      topic TEXT NOT NULL DEFAULT '',
      language CHAR(2) NOT NULL DEFAULT 'ta' CHECK (language IN ('ta','en')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(exam_id,question_no)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_model_exam_questions_exam ON model_exam_questions(exam_id,question_no)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exam_question_backups (
      id BIGSERIAL PRIMARY KEY,
      original_question_id BIGINT NOT NULL,
      exam_id TEXT NOT NULL,
      question_no INTEGER NOT NULL,
      question TEXT NOT NULL,
      options JSONB NOT NULL,
      correct_answer CHAR(1) NOT NULL,
      explanation TEXT NOT NULL DEFAULT '',
      subject TEXT NOT NULL DEFAULT '',
      topic TEXT NOT NULL DEFAULT '',
      language CHAR(2) NOT NULL DEFAULT 'ta',
      deleted_by BIGINT NULL,
      deleted_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_model_exam_question_backups_exam ON model_exam_question_backups(exam_id,deleted_at DESC)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exam_attempts (
      id BIGSERIAL PRIMARY KEY,
      exam_id TEXT NOT NULL REFERENCES model_exams(exam_id) ON DELETE RESTRICT,
      user_id BIGINT NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      submitted_at TIMESTAMPTZ NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'in_progress' CHECK(status IN ('in_progress','submitted','expired')),
      total_questions INTEGER NOT NULL DEFAULT 0,
      attempted INTEGER NOT NULL DEFAULT 0,
      not_attempted INTEGER NOT NULL DEFAULT 0,
      marks NUMERIC(10,2) NOT NULL DEFAULT 0,
      percentage NUMERIC(6,2) NOT NULL DEFAULT 0
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_model_exam_attempts_user_exam ON model_exam_attempts(user_id,exam_id,started_at DESC)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exam_answers (
      id BIGSERIAL PRIMARY KEY,
      attempt_id BIGINT NOT NULL REFERENCES model_exam_attempts(id) ON DELETE CASCADE,
      question_id BIGINT NULL REFERENCES model_exam_questions(id) ON DELETE SET NULL,
      answer CHAR(1) NOT NULL CHECK(answer IN ('A','B','C','D')),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(attempt_id,question_id)
    )
  `);
  /* Migration safety for a prior Model Exam test schema. Questions may be
     deleted after backup, so answers must survive with question_id nulled. */
  await pool.query(`ALTER TABLE model_exam_answers ALTER COLUMN question_id DROP NOT NULL`);
  await pool.query(`ALTER TABLE model_exam_answers DROP CONSTRAINT IF EXISTS model_exam_answers_question_id_fkey`);
  await pool.query(`ALTER TABLE model_exam_answers ADD CONSTRAINT model_exam_answers_question_id_fkey FOREIGN KEY(question_id) REFERENCES model_exam_questions(id) ON DELETE SET NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_model_exam_answers_attempt ON model_exam_answers(attempt_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exam_results (
      id BIGSERIAL PRIMARY KEY,
      attempt_id BIGINT NOT NULL UNIQUE REFERENCES model_exam_attempts(id) ON DELETE RESTRICT,
      exam_id TEXT NOT NULL REFERENCES model_exams(exam_id) ON DELETE RESTRICT,
      user_id BIGINT NOT NULL,
      total_questions INTEGER NOT NULL,
      attempted INTEGER NOT NULL,
      not_attempted INTEGER NOT NULL,
      marks NUMERIC(10,2) NOT NULL,
      percentage NUMERIC(6,2) NOT NULL,
      submitted_at TIMESTAMPTZ NOT NULL
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_model_exam_results_exam ON model_exam_results(exam_id,submitted_at DESC)`);
}

async function start(){
  try{
    await pool.query('SELECT 1');
    await ensureSecurityEventsTable();
    await ensureMustChangePasswordColumn();
    await ensureLoginDeviceBindingColumn();
    await ensurePasswordResetTables();
    await ensureQuestionHistory();
    await ensureModelExamTables();
    await backfillLastLoginFromAudit();
    await ensureAdmin();
    app.listen(PORT,'0.0.0.0',()=>console.log(`Thiral V171 Secure Temporary Password + Gender Summary + Detailed Usage Monitor listening on port ${PORT}`));
  }catch(e){
    console.error('Startup failed:',e);
    process.exit(1);
  }
}

start();
