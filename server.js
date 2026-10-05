/* ===== GS51 LOOKUP-ONLY NORMALIZATION =====
   Database rows are already correct. This layer only normalizes incoming
   lookup values and provides known bilingual subtopic aliases. No question
   data is inserted, updated, deleted, or rewritten. */
function normalizedSqlCandidates(values){
  return [...new Set((Array.isArray(values)?values:[])
    .map(v=>String(v??'').normalize('NFKC').trim().replace(/\s+/g,' ').toLowerCase())
    .filter(Boolean))];
}

function examLookupCandidates(raw){
  const s=String(raw||'').normalize('NFKC').trim().replace(/\s+/g,' ');
  if(!s) return [];
  if(/^group ?4$/i.test(s)) return ['group4','group 4','group4','Group 4'];
  return [s];
}

const GROUP4_GS51_SUBTOPIC_ALIASES = {
  /* English UI label -> actual imported database label where they differ. */
  'Early Uprisings against British Rule':'Early Resistance to British Rule',
  'Early Agitations against British Rule':'Early Resistances to British Rule',
  'Role of Tamil Nadu in Freedom Struggle':'Role of Tamil Nadu in the Freedom Struggle',
  'Industrial Growth':'Industrial Development',
  'Rural Welfare Programmes':'Rural Welfare Schemes',
  'Population and Social Problems':'Population and Social Issues',
  'Tamil Nadu Government Welfare Schemes':'Tamil Nadu Government Welfare Schemes',
  'Government Welfare Schemes in Tamil Nadu':'Tamil Nadu Government Welfare Schemes',
  'Geography of Tamil Nadu and Economic Growth':'Geography and Economic Development of Tamil Nadu',
  'Current Socio-Economic Affairs':'Current Socio-Economic Events'
};

function gs51SubtopicCandidates(raw){
  const s=String(raw||'').normalize('NFKC').trim().replace(/\s+/g,' ');
  if(!s) return [];
  const out=[s];
  const alias=GROUP4_GS51_SUBTOPIC_ALIASES[s];
  if(alias) out.push(alias);
  /* Reverse lookup also allows an English DB label to be requested safely. */
  for(const [ui,db] of Object.entries(GROUP4_GS51_SUBTOPIC_ALIASES)){
    if(String(db).normalize('NFKC').trim().replace(/\s+/g,' ').toLowerCase()===s.toLowerCase()) out.push(ui,db);
  }
  return [...new Set(out.filter(Boolean))];
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

    if (!exam || !subject || !['ta','en'].includes(language)) {
      return sendError(res,400,'Invalid question request.');
    }

    /* LOOKUP ONLY: tolerate group4/Group 4 and subject label differences. */
    const examSqlCandidates = normalizedSqlCandidates(examLookupCandidates(exam));
    const subjectSqlCandidates = normalizedSqlCandidates([
      ...subjectCandidatesList,
      'General Studies',
      'gs',
      'பொது அறிவு'
    ]);
    const subSqlCandidates = normalizedSqlCandidates(gs51SubtopicCandidates(subtopic));

    const where = [
      'LOWER(BTRIM(exam)) = ANY($1::text[])',
      'LOWER(BTRIM(subject)) = ANY($2::text[])',
      'LOWER(BTRIM(language)) = $3',
      'is_active=true'
    ];
    const params = [examSqlCandidates, subjectSqlCandidates, language.toLowerCase()];
    let n = 4;

    if (subSqlCandidates.length === 1) {
      where.push(`LOWER(BTRIM(subtopic))=$${n++}`);
      params.push(subSqlCandidates[0]);
    } else if (subSqlCandidates.length > 1) {
      where.push(`LOWER(BTRIM(subtopic)) = ANY($${n}::text[])`);
      params.push(subSqlCandidates);
      n++;
    }

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

    const countQ = await pool.query(
      `SELECT count(*)::int AS total FROM questions WHERE ${where.join(' AND ')}`,
      params
    );
    const total = Number(countQ.rows[0]?.total || 0);

    const dataParams = [...params, limit, offset];
    const q = await pool.query(
      `SELECT id,exam,subject,subtopic,language,question,options,explanation,
              COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
       FROM questions
       WHERE ${where.join(' AND ')}
       ORDER BY id LIMIT $${n} OFFSET $${n+1}`,
      dataParams
    );

    const nextOffset = offset + q.rows.length;
    res.json({
      questions:q.rows,
      pagination:{limit,offset,returned:q.rows.length,total,hasMore:nextOffset<total,nextOffset}
    });
  } catch(e) {
    console.error(e);
    sendError(res,500,'Question service error.');
  }
});

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

    if (!exam || !subject || !['ta','en'].includes(language)) {
      return sendError(res,400,'Invalid question request.');
    }

    const examSqlCandidates = normalizedSqlCandidates(examLookupCandidates(exam));
    const subjectSqlCandidates = normalizedSqlCandidates([
      ...subjectCandidatesList,
      'General Studies',
      'gs',
      'பொது அறிவு'
    ]);
    const subSqlCandidates = normalizedSqlCandidates(gs51SubtopicCandidates(subtopic));

    const params = [req.user.id, examSqlCandidates, subjectSqlCandidates, language.toLowerCase()];
    let n = 5;
    let where = `
      LOWER(BTRIM(q.exam)) = ANY($2::text[])
      AND LOWER(BTRIM(q.subject)) = ANY($3::text[])
      AND LOWER(BTRIM(q.language)) = $4
      AND q.is_active = true
    `;

    if (subSqlCandidates.length === 1) {
      where += ` AND LOWER(BTRIM(q.subtopic)) = $${n}`;
      params.push(subSqlCandidates[0]);
      n++;
    } else if (subSqlCandidates.length > 1) {
      where += ` AND LOWER(BTRIM(q.subtopic)) = ANY($${n}::text[])`;
      params.push(subSqlCandidates);
      n++;
    }

    params.push(limit);

    const sql = `
      SELECT q.id,q.exam,q.subject,q.subtopic,q.language,q.question,q.options,q.explanation
      FROM questions q
      WHERE ${where}
        AND NOT EXISTS (
          SELECT 1 FROM question_history h
          WHERE h.user_id = $1
            AND h.question_id = q.id
            AND h.mode = 'practice'
        )
      ORDER BY random()
      LIMIT $${n}
    `;

    const result = await pool.query(sql,params);

    if (result.rows.length < limit) {
      return sendError(
        res,
        409,
        `Practice question bank has only ${result.rows.length} unused questions.`
      );
    }

    res.json({questions:result.rows,count:result.rows.length});
  } catch(e) {
    console.error('Practice question error:',e);
    sendError(res,500,'Practice question service error.');
  }
});

