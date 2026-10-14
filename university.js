/**
 * کلاینت API دانشگاه (فرضی)
 * تنها فایلی که شکل API دانشگاه را «می‌شناسد».
 * normalize کردن پاسخ‌ها اینجاست؛ بقیه‌ی پروژه شکل تمیز و ثابت می‌گیرد.
 */

const BASE = process.env.UNIVERSITY_API_BASE || 'https://api.university.ac.ir/v1';
const API_KEY = process.env.UNIVERSITY_API_KEY || '';
const TIMEOUT_MS = parseInt(process.env.UNI_API_TIMEOUT_MS || '8000', 10);
// بعضی APIها به‌جای 404 کد دیگری برای «پیدا نشد» برمی‌گردانند
const NOT_FOUND = new Set(
  (process.env.UNI_NOT_FOUND_STATUS || '404').split(',').map(s => parseInt(s.trim(), 10))
);

class UniversityApiError extends Error {
  constructor(status, path, body) {
    super(`University API ${status} ${path}${body ? ': ' + body : ''}`);
    this.status = status || 0;
    this.notFound = NOT_FOUND.has(this.status); // ← تشخیص «پیدا نشد» از «API خراب است»
  }
}

async function apiFetch(path) {
  // api — درخواست به سرور دانشگاه (با timeout)
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  let res;
  try {
    res = await fetch(BASE + path, {
      headers: { 'Authorization': `Bearer ${API_KEY}`, 'Accept': 'application/json' },
      signal: ctrl.signal,
    });
  } catch (e) {
    throw new UniversityApiError(0, path, e.message); // خطای شبکه/timeout
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new UniversityApiError(res.status, path, txt.slice(0, 200));
  }
  return res.json();
}

/* ---- normalize: اگر نام فیلدها در API فرق داشت، فقط همین‌جا را عوض کن ---- */
function normCourse(c) {
  return {
    id: String(c.id ?? c.courseId ?? c.course_id),
    name: c.name ?? c.title ?? c.courseName ?? String(c.id),
    term: c.term ?? c.semester ?? null,
    studentCount: c.studentCount ?? c.student_count ?? 0,
  };
}
function normPerson(p) {
  return {
    id: String(p.id ?? p.sub ?? p.userId ?? p.studentId ?? p.teacherId ?? ''),
    name: p.name ?? p.fullName ?? p.title ?? null,
    email: p.email ?? null,
  };
}
function asList(r, key) {
  return Array.isArray(r) ? r : (r && Array.isArray(r[key]) ? r[key] : []);
}

// api — اطلاعات استاد
async function getTeacherInfo(id) { return normPerson(await apiFetch(`/teachers/${encodeURIComponent(id)}`)); }
// api — درس‌های استاد در ترم جاری
async function getTeacherCourses(id) {
  return asList(await apiFetch(`/teachers/${encodeURIComponent(id)}/courses?term=current`), 'courses').map(normCourse);
}
// api — دانشجوهای یک درس
async function getCourseStudents(courseId) {
  return asList(await apiFetch(`/courses/${encodeURIComponent(courseId)}/students`), 'students').map(normPerson);
}
// api — اطلاعات دانشجو
async function getStudentInfo(id) { return normPerson(await apiFetch(`/students/${encodeURIComponent(id)}`)); }
// api — درس‌های دانشجو
async function getStudentCourses(id) {
  return asList(await apiFetch(`/students/${encodeURIComponent(id)}/courses?term=current`), 'courses').map(normCourse);
}

module.exports = { getTeacherInfo, getTeacherCourses, getCourseStudents, getStudentInfo, getStudentCourses };