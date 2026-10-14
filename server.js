const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const Database = require('better-sqlite3');

const { setupOIDC, getAuthorizationUrl, handleCallback, getEndSessionUrl } = require('./auth');
const uni = require('./university');
const wa = require('./webauthn');

/* ---------------- Config ---------------- */
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'attendance.db');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '';
const QR_STEP_SECONDS = parseInt(process.env.QR_STEP_SECONDS || '10', 10);
const QR_TOLERANCE_SECONDS = parseInt(process.env.QR_TOLERANCE_SECONDS || '8', 10);
const EXP_GRACE_SECONDS = parseInt(process.env.EXP_GRACE_SECONDS || '3', 10);
const SYNC_TTL = parseInt(process.env.SYNC_TTL || '300', 10);
const BIO_WINDOW_SECONDS = parseInt(process.env.BIO_WINDOW_SECONDS || '120', 10);
const BIO_REQUIRED = (process.env.BIO_REQUIRED || 'true') !== 'false';
const MAX_CREDENTIALS = parseInt(process.env.MAX_CREDENTIALS || '5', 10);

/* ---------------- Helpers ---------------- */
const now = () => Math.floor(Date.now() / 1000);
const rid = (p) => p + '_' + crypto.randomBytes(8).toString('hex');
const b64url = (buf) => Buffer.from(buf).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function errorPage(res, status, message) {
  res.status(status).send(`<!DOCTYPE html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>خطا</title>
<style>body{font-family:Tahoma,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f7fa}
.c{background:#fff;padding:32px;border-radius:16px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:420px;text-align:center}
h2{color:#c0392b;margin-top:0}a{color:#1F4E79}</style></head>
<body><div class="c"><h2>⚠️ خطا</h2><p>${message}</p><p><a href="/">بازگشت به صفحه‌ی ورود</a></p></div></body></html>`);
}

/* ---------------- DB ---------------- */
const dbDir = path.dirname(DB_FILE);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS teachers (
  id TEXT PRIMARY KEY, name TEXT, email TEXT, last_sync INTEGER
);
CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY, name TEXT, email TEXT, last_sync INTEGER
);
CREATE TABLE IF NOT EXISTS courses (
  id TEXT PRIMARY KEY, name TEXT, teacher_id TEXT,
  term TEXT, student_count INTEGER, last_sync INTEGER
);
CREATE TABLE IF NOT EXISTS enrollments (
  course_id TEXT, student_id TEXT,
  PRIMARY KEY (course_id, student_id)
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, course_id TEXT, teacher_id TEXT, secret TEXT,
  step_seconds INTEGER, tolerance_seconds INTEGER,
  started_at INTEGER, closed_at INTEGER, status TEXT DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS attendance (
  session_id TEXT, student_id TEXT, status TEXT,
  credential_id TEXT, device_id TEXT, scanned_at INTEGER, qr_exp INTEGER,
  PRIMARY KEY (session_id, student_id)
);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  credential_id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  device_type TEXT,
  backed_up INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_attendance_credential ON attendance(credential_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_courses_teacher ON courses(teacher_id);
CREATE INDEX IF NOT EXISTS idx_enrollments_student ON enrollments(student_id);
`);

// مهاجرت دیتابیس‌های قدیمی
const attCols = db.prepare('PRAGMA table_info(attendance)').all().map(c => c.name);
if (!attCols.includes('credential_id')) db.exec('ALTER TABLE attendance ADD COLUMN credential_id TEXT');

/* ---------------- App ---------------- */
if (!process.env.SESSION_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('❌ SESSION_SECRET الزامی است'); process.exit(1);
  }
  console.warn('⚠️ SESSION_SECRET تنظیم نشده — فقط برای توسعه قابل قبول است');
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// '*' با credentials سازگار نیست؛ فرانت و بک‌اند هم‌مبلا هستند و CORS اساساً لازم نیست
if (CORS_ORIGIN && CORS_ORIGIN !== '*') {
  app.use(cors({ origin: CORS_ORIGIN.split(','), credentials: true }));
} else if (CORS_ORIGIN === '*') {
  app.use(cors());
}

app.use(express.json({ limit: '32kb' }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-only-insecure-secret',
  name: 'att.sid',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

// پاسخ‌های API هیچ‌وقت کش نشوند (QR پویاست)
app.use('/api', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

// فقط صفحه‌ی عمومی static است؛ پنل‌ها از views/ و پشت auth سرو می‌شوند
app.use(express.static(path.join(__dirname, 'public')));

/* ---------------- Auth middleware ---------------- */
function isBioFresh(req) {
  return !!req.session.bioVerifiedAt &&
    (now() - req.session.bioVerifiedAt) <= BIO_WINDOW_SECONDS;
}

function requireAuth(role) {
  return (req, res, next) => {
    if (!req.session.user) {
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'unauthorized' });
      return res.redirect('/auth/login');
    }
    if (role && req.session.role !== role) {
      if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'forbidden_role' });
      return res.redirect('/');
    }
    next();
  };
}

/* ---------------- Pages (باگ ۴۰۴ رفع شد) ---------------- */
app.get('/teacher', requireAuth('teacher'), (_req, res) =>
  res.sendFile(path.join(__dirname, 'views', 'teacher.html')));
app.get('/student', requireAuth('student'), (_req, res) =>
  res.sendFile(path.join(__dirname, 'views', 'student.html')));

/* ---------------- OIDC routes ---------------- */
app.get('/auth/login', (req, res) => {
  try { res.redirect(getAuthorizationUrl(req)); }
  catch (e) { errorPage(res, 500, 'ورود در دسترس نیست: ' + e.message); }
});

app.get('/auth/callback', async (req, res) => {
  try {
    const tokenSet = await handleCallback(req);
    const claims = tokenSet.claims();

    let role;
    try {
      role = await determineRole(claims.sub);
    } catch (e) {
      if (e.kind === 'api_down')
        return errorPage(res, 502, 'API دانشگاه در دسترس نیست. چند لحظه بعد دوباره وارد شوید.');
      throw e;
    }
    if (!role)
      return errorPage(res, 403, 'نقش کاربری شما در سیستم دانشگاه شناسایی نشد. با IT دانشگاه تماس بگیرید.');

    const idToken = tokenSet.id_token;
    // جلوگیری از session fixation
    req.session.regenerate((err) => {
      if (err) return errorPage(res, 500, 'خطای نشست');
      req.session.user = claims;
      req.session.role = role;
      req.session.id_token = idToken;
      const dest = role === 'teacher' ? '/teacher' : '/student';
      const syncP = role === 'teacher' ? syncTeacher(claims) : syncStudent(claims);
      Promise.resolve(syncP)
        .catch(e => console.warn('sync پس از ورود:', e.message))
        .finally(() => res.redirect(dest));
    });
  } catch (err) {
    console.error('OIDC callback error:', err);
    errorPage(res, 401, 'ورود ناموفق بود. دوباره تلاش کنید.');
  }
});

app.get('/auth/logout', (req, res) => {
  const idToken = req.session.id_token;
  req.session.destroy(() => {
    res.clearCookie('att.sid');
    res.redirect(getEndSessionUrl(idToken) || '/');
  });
});

/* ---------------- تعیین نقش ----------------
 * 404        → واقعاً در این نقش نیست
 * بقیه خطاها  → API مشکل دارد (نه اینکه کاربر وجود ندارد)
 */
async function determineRole(id) {
  try {
    await uni.getTeacherInfo(id);
    return 'teacher';
  } catch (e) {
    if (!e.notFound) { const err = new Error('api_down'); err.kind = 'api_down'; throw err; }
  }
  try {
    await uni.getStudentInfo(id);
    return 'student';
  } catch (e) {
    if (!e.notFound) { const err = new Error('api_down'); err.kind = 'api_down'; throw err; }
    return null;
  }
}

/* ---------------- Sync با API دانشگاه ---------------- */
async function syncTeacher(claims) {
  const id = claims.sub;

  // api — اطلاعات استاد
  let info = null;
  try { info = await uni.getTeacherInfo(id); }
  catch (e) { console.warn('teacherInfo:', e.message); }

  const name = (info && info.name) || claims.name || claims.preferred_username || 'استاد';
  const email = (info && info.email) || claims.email || null;

  db.prepare(`
    INSERT INTO teachers(id, name, email, last_sync) VALUES (?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name, email = excluded.email, last_sync = excluded.last_sync
  `).run(id, name, email, now());

  // api — درس‌های استاد
  const courses = await uni.getTeacherCourses(id);

  const upsert = db.prepare(`
    INSERT INTO courses(id, name, teacher_id, term, student_count, last_sync)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name, teacher_id = excluded.teacher_id,
      term = excluded.term, student_count = excluded.student_count,
      last_sync = excluded.last_sync
  `);
  const tx = db.transaction((list) => {
    for (const c of list) upsert.run(c.id, c.name, id, c.term, c.studentCount || 0, now());
  });
  tx(courses);

  console.log(`✅ ${courses.length} درس برای استاد ${id} sync شد`);
}

async function syncStudent(claims) {
  const id = claims.sub;

  // api — اطلاعات دانشجو
  let info = null;
  try { info = await uni.getStudentInfo(id); }
  catch (e) { console.warn('studentInfo:', e.message); }

  const name = (info && info.name) || claims.name || null;
  const email = (info && info.email) || claims.email || null;

  db.prepare(`
    INSERT INTO students(id, name, email, last_sync) VALUES (?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name = COALESCE(excluded.name, students.name),
      email = COALESCE(excluded.email, students.email),
      last_sync = excluded.last_sync
  `).run(id, name, email, now());

  console.log(`✅ دانشجو ${id} sync شد`);
}

/* ---------------- QR core ---------------- */
function signQR(secret, sid, exp, nonce) {
  return b64url(crypto.createHmac('sha256', secret)
    .update(`${sid}|${exp}|${nonce}`).digest());
}

function buildQR(session) {
  const step = session.step_seconds;
  const slot = Math.floor(now() / step);
  const exp = (slot + 1) * step + session.tolerance_seconds;
  const nonce = b64url(crypto.createHmac('sha256', session.secret)
    .update('nonce|' + slot).digest()).slice(0, 12);
  const sig = signQR(session.secret, session.id, exp, nonce);
  return { v: 1, sid: session.id, exp, expires_in: Math.max(1, exp - now()), nonce, sig };
}

const QRP = { nonce: /^[A-Za-z0-9_-]{1,64}$/, sig: /^[A-Za-z0-9_-]{1,128}$/ };
function verifyQR(secret, sid, payload) {
  if (!payload || typeof payload !== 'object' || payload.v !== 1 || payload.sid !== sid)
    return { ok: false, reason: 'malformed' };
  const { exp, nonce, sig } = payload;
  // type-check سخت‌گیرانه — ورودی خراب نباید exception بدهد
  if (typeof exp !== 'number' || !Number.isInteger(exp) || exp <= 0 ||
      typeof nonce !== 'string' || !QRP.nonce.test(nonce) ||
      typeof sig !== 'string' || !QRP.sig.test(sig))
    return { ok: false, reason: 'malformed' };
  const expected = signQR(secret, sid, exp, nonce);
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
    return { ok: false, reason: 'bad_signature' };
  if (now() > exp + EXP_GRACE_SECONDS) return { ok: false, reason: 'expired' };
  return { ok: true };
}

/* ---------------- Teacher API ---------------- */
app.get('/api/teacher/me', requireAuth('teacher'), (req, res) => {
  const t = db.prepare('SELECT id, name, email FROM teachers WHERE id=?')
    .get(req.session.user.sub);
  res.json(t || { id: req.session.user.sub, name: 'استاد' });
});

app.get('/api/teacher/courses', requireAuth('teacher'), async (req, res) => {
  const id = req.session.user.sub;

  // کش TTL — هر ۵ دقیقه یک بار sync
  const t = db.prepare('SELECT last_sync FROM teachers WHERE id=?').get(id);
  const stale = !t || !t.last_sync || (now() - t.last_sync) > SYNC_TTL;
  if (stale) {
    try { await syncTeacher(req.session.user); }
    catch (e) { console.warn('sync قبل از دوره‌ها:', e.message); }
  }

  res.json(db.prepare(`
    SELECT id, name, term, student_count FROM courses WHERE teacher_id=? ORDER BY name
  `).all(id));
});

app.post('/api/session/start', requireAuth('teacher'), async (req, res) => {
  const { course_id } = req.body || {};
  const teacherId = req.session.user.sub;

  if (typeof course_id !== 'string' || !course_id)
    return res.status(400).json({ error: 'course_id_required' });

  const course = db.prepare('SELECT * FROM courses WHERE id=? AND teacher_id=?')
    .get(course_id, teacherId);
  if (!course) return res.status(404).json({ error: 'course_not_found' });

  // api — sync دانشجوهای این درس قبل از شروع
  try {
    const students = await uni.getCourseStudents(course_id);
    const upsertStudent = db.prepare(`
      INSERT INTO students(id, name, email, last_sync) VALUES (?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = COALESCE(excluded.name, students.name),
        email = COALESCE(excluded.email, students.email),
        last_sync = excluded.last_sync
    `);
    const insertEnroll = db.prepare(
      'INSERT OR IGNORE INTO enrollments(course_id, student_id) VALUES (?, ?)'
    );
    const tx = db.transaction((list) => {
      for (const s of list) {
        if (!s.id) continue;
        upsertStudent.run(s.id, s.name || 'دانشجو', s.email || null, now());
        insertEnroll.run(course_id, s.id);
      }
    });
    tx(students);
    db.prepare('UPDATE courses SET student_count=?, last_sync=? WHERE id=?')
      .run(students.length, now(), course_id);
    console.log(`✅ ${students.length} دانشجو برای درس ${course_id}`);
  } catch (e) {
    console.warn('student sync failed, using cache:', e.message);
  }

  // بستن جلسه‌ی قبلی همان درس
  db.prepare(`UPDATE sessions SET status='closed', closed_at=? WHERE course_id=? AND status='open'`)
    .run(now(), course_id);

  const sid = rid('ses');
  const secret = crypto.randomBytes(32).toString('hex');

  db.prepare(`
    INSERT INTO sessions(id, course_id, teacher_id, secret, step_seconds, tolerance_seconds, started_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
  `).run(sid, course_id, teacherId, secret, QR_STEP_SECONDS, QR_TOLERANCE_SECONDS, now());

  // ⚠️ secret دیگر به کلاینت فرستاده نمی‌شود — QR سمت سرور ساخته می‌شود
  res.json({
    session_id: sid,
    step_seconds: QR_STEP_SECONDS,
    tolerance_seconds: QR_TOLERANCE_SECONDS,
    started_at: now(),
    course_name: course.name,
  });
});

app.get('/api/session/:sid/qr', requireAuth('teacher'), (req, res) => {
  const s = db.prepare(`SELECT * FROM sessions WHERE id=? AND status='open'`).get(req.params.sid);
  if (!s) return res.status(404).json({ error: 'session_not_open' });
  if (s.teacher_id !== req.session.user.sub) return res.status(403).json({ error: 'forbidden' });
  res.json(buildQR(s));
});

app.post('/api/session/:sid/close', requireAuth('teacher'), (req, res) => {
  const s = db.prepare('SELECT * FROM sessions WHERE id=?').get(req.params.sid);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.teacher_id !== req.session.user.sub) return res.status(403).json({ error: 'forbidden' });
  db.prepare(`UPDATE sessions SET status='closed', closed_at=? WHERE id=?`)
    .run(now(), req.params.sid);
  res.json({ ok: true });
});

app.get('/api/session/:sid/report', requireAuth('teacher'), (req, res) => {
  const s = db.prepare('SELECT * FROM sessions WHERE id=?').get(req.params.sid);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.teacher_id !== req.session.user.sub) return res.status(403).json({ error: 'forbidden' });

  const present = db.prepare(`
    SELECT a.student_id, st.name, a.status, a.scanned_at
    FROM attendance a JOIN students st ON st.id = a.student_id
    WHERE a.session_id=? AND a.status='present'
    ORDER BY a.scanned_at ASC
  `).all(req.params.sid);

  const enrolled = db.prepare(`
    SELECT s.id, s.name FROM enrollments e JOIN students s ON s.id = e.student_id
    WHERE e.course_id=?
  `).all(s.course_id);

  const presentIds = new Set(present.map(p => p.student_id));
  const absent = enrolled.filter(s => !presentIds.has(s.id));

  res.json({
    session_id: s.id, course_id: s.course_id, status: s.status,
    started_at: s.started_at, closed_at: s.closed_at,
    total_enrolled: enrolled.length, present_count: present.length,
    present, absent,
  });
});

/* ---------------- Student API ---------------- */
app.get('/api/student/me', requireAuth('student'), (req, res) => {
  const s = db.prepare('SELECT id, name, email FROM students WHERE id=?')
    .get(req.session.user.sub);
  res.json(s || { id: req.session.user.sub, name: 'دانشجو' });
});

app.get('/api/student/courses', requireAuth('student'), async (req, res) => {
  const id = req.session.user.sub;
  // api — درس‌های دانشجو (university.js شکل را normalize می‌کند)
  try {
    return res.json(await uni.getStudentCourses(id));
  } catch (e) {
    console.warn('studentCourses API:', e.message);
    // fallback به دیتابیس محلی
    return res.json(db.prepare(`
      SELECT c.id, c.name, c.term
      FROM enrollments e JOIN courses c ON c.id = e.course_id
      WHERE e.student_id=?
    `).all(id));
  }
});

app.post('/api/attendance/scan', requireAuth('student'), (req, res) => {
  const { qr } = req.body || {};
  const studentId = req.session.user.sub;

  // بیومتریک = assertion وب‌آتن که قبلاً سمت سرور verify شده (نه ادعای کلاینت)
  if (BIO_REQUIRED && !isBioFresh(req))
    return res.status(401).json({ error: 'biometric_required' });

  if (!qr || typeof qr !== 'object' || typeof qr.sid !== 'string')
    return res.status(400).json({ error: 'qr_missing' });

  const session = db.prepare(`SELECT * FROM sessions WHERE id=? AND status='open'`).get(qr.sid);
  if (!session) return res.status(400).json({ error: 'session_not_open' });

  const v = verifyQR(session.secret, session.id, qr);
  if (!v.ok) return res.status(400).json({ error: v.reason });

  const enrolled = db.prepare(
    'SELECT 1 FROM enrollments WHERE course_id=? AND student_id=?'
  ).get(session.course_id, studentId);
  if (!enrolled) return res.status(403).json({ error: 'not_enrolled' });

  const credentialId = req.session.wa_credential_id || null;

  // چک تداخل + ثبت، داخل یک transaction اتمیک (بدون race)
  const outcome = db.transaction(() => {
    if (credentialId) {
      // این دستگاه (credential) قبلاً برای دانشجوی دیگری حضور ثبت کرده؟
      const clash = db.prepare(
        'SELECT student_id FROM attendance WHERE credential_id=? AND student_id<>? LIMIT 1'
      ).get(credentialId, studentId);
      if (clash) return 'credential_bound_to_another_student';
    }
    const dup = db.prepare(
      'SELECT 1 FROM attendance WHERE session_id=? AND student_id=?'
    ).get(session.id, studentId);
    if (dup) return 'already_recorded';
    db.prepare(`
      INSERT INTO attendance(session_id, student_id, status, credential_id, scanned_at, qr_exp)
      VALUES (?, ?, 'present', ?, ?, ?)
    `).run(session.id, studentId, credentialId, now(), qr.exp);
    return 'ok';
  })();

  if (outcome === 'credential_bound_to_another_student')
    return res.status(403).json({ error: outcome });
  if (outcome === 'already_recorded')
    return res.json({ ok: true, status: 'present', note: 'already_recorded' });
  res.json({ ok: true, status: 'present' });
});

/* ---------------- WebAuthn (بیومتریک واقعی سمت سرور) ---------------- */
app.get('/api/webauthn/status', requireAuth('student'), (req, res) => {
  const { n } = db.prepare(
    'SELECT COUNT(*) AS n FROM webauthn_credentials WHERE student_id=?'
  ).get(req.session.user.sub);
  res.json({
    registered: n > 0, credentials: n,
    bio_required: BIO_REQUIRED, bio_fresh: isBioFresh(req),
    window_seconds: BIO_WINDOW_SECONDS,
  });
});

app.post('/api/webauthn/register/options', requireAuth('student'), async (req, res) => {
  const id = req.session.user.sub;
  const { n } = db.prepare(
    'SELECT COUNT(*) AS n FROM webauthn_credentials WHERE student_id=?'
  ).get(id);
  if (n >= MAX_CREDENTIALS) return res.status(409).json({ error: 'too_many_credentials' });

  const creds = db.prepare('SELECT credential_id FROM webauthn_credentials WHERE student_id=?').all(id);
  const options = await wa.registrationOptions({
    excludeCredentials: creds,
    studentId: id,
    userName: req.session.user.name,
  });
  req.session.wa_challenge = options.challenge;
  req.session.wa_mode = 'register';
  res.json(options);
});

app.post('/api/webauthn/register/verify', requireAuth('student'), async (req, res) => {
  try {
    const expected = req.session.wa_challenge;
    if (req.session.wa_mode !== 'register' || !expected)
      return res.status(400).json({ error: 'no_challenge' });
    req.session.wa_challenge = null; req.session.wa_mode = null;

    const v = await wa.verifyRegistration({ response: req.body, expectedChallenge: expected });
    if (!v.verified || !v.registrationInfo)
      return res.status(400).json({ error: 'registration_failed' });

    const ri = v.registrationInfo;
    const credId = wa.u8ToB64(ri.credentialID);
    db.prepare(`
      INSERT INTO webauthn_credentials
        (credential_id, student_id, public_key, counter, device_type, backed_up, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(credential_id) DO UPDATE SET
        public_key=excluded.public_key, counter=excluded.counter,
        device_type=excluded.device_type, backed_up=excluded.backed_up
    `).run(credId, req.session.user.sub, Buffer.from(ri.credentialPublicKey),
           ri.counter || 0, ri.credentialDeviceType || 'singleDevice',
           ri.credentialBackedUp ? 1 : 0, now());

    req.session.bioVerifiedAt = now();
    req.session.wa_credential_id = credId;
    res.json({ ok: true, fresh_seconds: BIO_WINDOW_SECONDS });
  } catch (e) {
    console.warn('webauthn register verify:', e.message);
    res.status(400).json({ error: 'registration_failed' });
  }
});

app.post('/api/webauthn/auth/options', requireAuth('student'), async (req, res) => {
  const creds = db.prepare(
    'SELECT credential_id FROM webauthn_credentials WHERE student_id=?'
  ).all(req.session.user.sub);
  if (!creds.length) return res.status(400).json({ error: 'not_registered' });

  const options = await wa.authenticationOptions({ allowCredentials: creds });
  req.session.wa_challenge = options.challenge;
  req.session.wa_mode = 'auth';
  res.json(options);
});

app.post('/api/webauthn/auth/verify', requireAuth('student'), async (req, res) => {
  try {
    const expected = req.session.wa_challenge;
    if (req.session.wa_mode !== 'auth' || !expected)
      return res.status(400).json({ error: 'no_challenge' });
    req.session.wa_challenge = null; req.session.wa_mode = null;

    const credId = req.body && req.body.id;
    if (typeof credId !== 'string') return res.status(400).json({ error: 'bad_request' });

    const cred = db.prepare(
      'SELECT * FROM webauthn_credentials WHERE credential_id=? AND student_id=?'
    ).get(credId, req.session.user.sub);
    if (!cred) return res.status(403).json({ error: 'credential_not_found' });

    const v = await wa.verifyAuthentication({
      response: req.body,
      expectedChallenge: expected,
      credential: { credential_id: cred.credential_id, public_key: cred.public_key, counter: cred.counter },
    });
    if (!v.verified) return res.status(401).json({ error: 'verification_failed' });

    db.prepare('UPDATE webauthn_credentials SET counter=? WHERE credential_id=?')
      .run(v.authenticationInfo.newCounter, cred.credential_id);

    req.session.bioVerifiedAt = now();
    req.session.wa_credential_id = cred.credential_id;
    res.json({ ok: true, fresh_seconds: BIO_WINDOW_SECONDS });
  } catch (e) {
    console.warn('webauthn auth verify:', e.message);
    res.status(401).json({ error: 'verification_failed' });
  }
});

/* ---------------- Misc ---------------- */
app.get('/health', (_req, res) => res.json({ ok: true, time: now() }));

app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
app.use((err, _req, res, _next) => {
  if (err && (err.type === 'entity.parse.failed' || err.status === 400))
    return res.status(400).json({ error: 'bad_request' });
  console.error(err);
  res.status(500).json({ error: 'internal_error' });
});

/* ---------------- Start ---------------- */
(async () => {
  // retry — چون ممکن است IdP/API دانشگاه لحظه‌ی deploy در دسترس نباشد
  const maxRetries = 5, delayMs = 5000;
  let started = false;
  for (let i = 1; i <= maxRetries && !started; i++) {
    try {
      await setupOIDC();
      wa.setupWebAuthn();
      started = true;
    } catch (e) {
      console.error(`❌ راه‌اندازی (تلاش ${i}/${maxRetries}):`, e.message);
      if (i === maxRetries) { console.error('❌ راه‌اندازی ناموفق — خروج'); process.exit(1); }
      await new Promise(r => setTimeout(r, delayMs));
    }
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server on port ${PORT}`);
    console.log(`   DB  : ${DB_FILE}`);
    console.log(`   SSO : ${process.env.OIDC_ISSUER}`);
    console.log(`   Uni : ${process.env.UNIVERSITY_API_BASE}`);
  });

  // خطاهای async سرگردان، سرور را نمی‌اندازند
  process.on('unhandledRejection', (r) => console.error('unhandledRejection:', r));

  /* ---- Graceful shutdown ----
   * Railway موقع stop/redeploy سیگنال SIGTERM می‌فرستد؛
   * اینجا درخواست‌های جاری را تمام و دیتابیس را تمیز می‌بندیم.
   */
  let shuttingDown = false;
  function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} دریافت شد — خاموشی تدریجی…`);
    server.close(() => {
      try { db.close(); console.log('🗄️ دیتابیس بسته شد'); } catch (e) { console.warn(e.message); }
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
})();