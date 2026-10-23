// api.js — Vercel Function API routes
// Deploy at: /api/index.js (Vercel will route /api/* here per vercel.json)
import { sql } from '@vercel/postgres';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

// ---------- Config (validated at module load) ----------
const SECRET = process.env.SESSION_SECRET;
if (!SECRET || SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be set (32+ chars)');
}
const EXEC_URL = process.env.EXECUTION_SERVICE_URL || '';
const EXEC_SECRET = process.env.EXECUTION_SERVICE_SECRET || '';
const MAX_DEPLOYMENTS_FREE = parseInt(process.env.FREE_MAX_DEPLOYMENTS || '2');
const MAX_MEMORY_MB_FREE = parseInt(process.env.FREE_MAX_MEMORY_MB || '256');

// ---------- Helpers ----------
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function parseCookies(req) {
  const h = req.headers.get('cookie') || '';
  const out = {};
  h.split(';').forEach(p => {
    const [k, ...v] = p.trim().split('=');
    if (k) out[k] = decodeURIComponent(v.join('='));
  });
  return out;
}

function signSession(userId) {
  const payload = `${userId}.${Date.now()}`;
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifySession(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [uid, ts, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(`${uid}.${ts}`).digest('hex');
  if (sig !== expected) return null;
  // 7 day expiry
  if (Date.now() - parseInt(ts) > 7 * 86400 * 1000) return null;
  return parseInt(uid);
}

async function getAuthUser(req) {
  const cookies = parseCookies(req);
  const uid = verifySession(cookies.aman_session);
  if (!uid) return null;
  const r = await sql`SELECT id, email, display_name, role, is_active, plan, storage_used_bytes FROM users WHERE id = ${uid}`;
  if (!r.rows.length || !r.rows[0].is_active) return null;
  return r.rows[0];
}

function setSessionCookie(userId) {
  const token = signSession(userId);
  return `aman_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 86400}`;
}

function clearSessionCookie() {
  return `aman_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

async function callExecution(path, method = 'GET', body = null) {
  if (!EXEC_URL) throw new Error('Execution service not configured');
  const opts = {
    method,
    headers: { 'Authorization': `Bearer ${EXEC_SECRET}`, 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(EXEC_URL + path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(data.error || 'execution error'), { status: r.status });
  return data;
}

// ---------- DB init (idempotent) ----------
let dbReady = false;
async function ensureDb() {
  if (dbReady) return;
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT DEFAULT '',
      role TEXT DEFAULT 'user',
      is_active BOOLEAN DEFAULT TRUE,
      plan TEXT DEFAULT 'free',
      storage_used_bytes BIGINT DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS deployments (
      id SERIAL PRIMARY KEY,
      owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      runtime TEXT NOT NULL,
      entrypoint TEXT DEFAULT '',
      status TEXT DEFAULT 'created',
      pid INT,
      exit_code INT,
      last_error TEXT,
      memory_limit_mb INT DEFAULT 256,
      restart_count INT DEFAULT 0,
      last_started_at TIMESTAMPTZ,
      last_stopped_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS deployment_files (
      id SERIAL PRIMARY KEY,
      deployment_id INT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
      path TEXT NOT NULL,
      size BIGINT DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(deployment_id, path)
    );
    CREATE TABLE IF NOT EXISTS env_vars (
      id SERIAL PRIMARY KEY,
      deployment_id INT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
      key TEXT NOT NULL,
      value TEXT NOT NULL,
      UNIQUE(deployment_id, key)
    );
    CREATE TABLE IF NOT EXISTS log_entries (
      id SERIAL PRIMARY KEY,
      deployment_id INT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
      stream TEXT DEFAULT 'stdout',
      line TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `;
  await sql`INSERT INTO app_settings (key, value) VALUES ('maintenance_mode', '0') ON CONFLICT DO NOTHING`;
  // Bootstrap admin
  const adminEmail = process.env.BOOTSTRAP_ADMIN_EMAIL;
  const adminPwd = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (adminEmail && adminPwd) {
    const existing = await sql`SELECT id FROM users WHERE email = ${adminEmail.toLowerCase()}`;
    if (!existing.rows.length) {
      const hash = await bcrypt.hash(adminPwd, 10);
      await sql`INSERT INTO users (email, password_hash, display_name, role) VALUES (${adminEmail.toLowerCase()}, ${hash}, 'Admin', 'admin')`;
    }
  }
  dbReady = true;
}

// ---------- Route table ----------
export default async function handler(req) {
  await ensureDb();
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, '') || '/';
  const method = req.method;
  const cookies = parseCookies(req);

  // ----- Health -----
  if (path === '/healthz') {
    return json({ ok: true, execution_available: !!EXEC_URL });
  }

  // ----- AUTH -----
  if (path === '/auth/register' && method === 'POST') {
    const body = await req.json();
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';
    if (!email.includes('@') || password.length < 8) {
      return json({ error: 'Valid email and 8+ char password required' }, 400);
    }
    const existing = await sql`SELECT id FROM users WHERE email = ${email}`;
    if (existing.rows.length) return json({ error: 'Email already registered' }, 409);
    const hash = await bcrypt.hash(password, 10);
    const r = await sql`INSERT INTO users (email, password_hash, display_name) VALUES (${email}, ${hash}, ${body.display_name || email.split('@')[0]}) RETURNING id, email, display_name, role, plan`;
    const user = r.rows[0];
    return json({ ok: true, user, execution_available: !!EXEC_URL }, 201);
  }

  if (path === '/auth/login' && method === 'POST') {
    const body = await req.json();
    const email = (body.email || '').trim().toLowerCase();
    const r = await sql`SELECT id, email, password_hash, display_name, role, is_active, plan FROM users WHERE email = ${email}`;
    if (!r.rows.length) return json({ error: 'Invalid credentials' }, 401);
    const u = r.rows[0];
    if (!u.is_active) return json({ error: 'Account suspended' }, 403);
    const ok = await bcrypt.compare(body.password || '', u.password_hash);
    if (!ok) return json({ error: 'Invalid credentials' }, 401);
    const token = signSession(u.id);
    const resp = json({ ok: true, user: { id: u.id, email: u.email, display_name: u.display_name, role: u.role, plan: u.plan }, execution_available: !!EXEC_URL });
    resp.headers.set('Set-Cookie', `aman_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 86400}`);
    return resp;
  }

  if (path === '/auth/logout' && method === 'POST') {
    const resp = json({ ok: true });
    resp.headers.set('Set-Cookie', clearSessionCookie());
    return resp;
  }

  if (path === '/auth/me' && method === 'GET') {
    const user = await getAuthUser(req);
    if (!user) return json({ error: 'unauthorized' }, 401);
    return json({ user, execution_available: !!EXEC_URL });
  }

  // ----- Everything below requires auth -----
  const user = await getAuthUser(req);
  if (!user) return json({ error: 'unauthorized' }, 401);

  // ----- DEPLOYMENTS LIST/CREATE -----
  if (path === '/deployments' && method === 'GET') {
    const r = await sql`SELECT * FROM deployments WHERE owner_id = ${user.id} ORDER BY id DESC`;
    const limits = user.role === 'admin'
      ? { max_deployments: 999, memory_mb: 2048 }
      : { max_deployments: MAX_DEPLOYMENTS_FREE, memory_mb: MAX_MEMORY_MB_FREE };
    return json({ deployments: r.rows, limits });
  }

  if (path === '/deployments' && method === 'POST') {
    const body = await req.json();
    const name = (body.name || '').trim().slice(0, 80);
    const runtime = body.runtime;
    if (!name) return json({ error: 'Name required' }, 400);
    if (!['python', 'node', 'static'].includes(runtime)) return json({ error: 'Invalid runtime' }, 400);
    const count = await sql`SELECT COUNT(*)::int AS n FROM deployments WHERE owner_id = ${user.id}`;
    const max = user.role === 'admin' ? 999 : MAX_DEPLOYMENTS_FREE;
    if (count.rows[0].n >= max) return json({ error: `Limit reached (${count.rows[0].n}/${max})` }, 403);
    const entry = (body.entrypoint || '').trim() || { python: 'main.py', node: 'index.js', static: 'index.html' }[runtime];
    const mem = user.role === 'admin' ? 2048 : MAX_MEMORY_MB_FREE;
    const r = await sql`INSERT INTO deployments (owner_id, name, runtime, entrypoint, memory_limit_mb) VALUES (${user.id}, ${name}, ${runtime}, ${entry}, ${mem}) RETURNING *`;
    return json({ ok: true, deployment: r.rows[0] }, 201);
  }

  // ----- SINGLE DEPLOYMENT -----
  const depMatch = path.match(/^\/deployments\/(\d+)(\/.*)?$/);
  if (depMatch) {
    const depId = parseInt(depMatch[1]);
    const sub = depMatch[2] || '';
    const depR = await sql`SELECT * FROM deployments WHERE id = ${depId}`;
    if (!depR.rows.length) return json({ error: 'not found' }, 404);
    const dep = depR.rows[0];
    if (dep.owner_id !== user.id && user.role !== 'admin') return json({ error: 'forbidden' }, 403);

    // GET single
    if (sub === '' && method === 'GET') {
      let running = false;
      if (EXEC_URL && dep.pid) {
        try { const s = await callExecution(`/deployments/${depId}/status`); running = s.running; } catch(e){}
      }
      return json({ deployment: { ...dep, running } });
    }

    // PATCH
    if (sub === '' && method === 'PATCH') {
      const body = await req.json();
      const name = (body.name || dep.name).trim().slice(0, 80);
      const entry = (body.entrypoint || dep.entrypoint).trim();
      await sql`UPDATE deployments SET name = ${name}, entrypoint = ${entry} WHERE id = ${depId}`;
      return json({ ok: true });
    }

    // DELETE
    if (sub === '' && method === 'DELETE') {
      // Ask execution service to stop first if running
      if (EXEC_URL && dep.pid) { try { await callExecution(`/deployments/${depId}/stop`, 'POST'); } catch(e){} }
      await sql`DELETE FROM deployments WHERE id = ${depId}`;
      return json({ ok: true });
    }

    // START
    if (sub === '/start' && method === 'POST') {
      if (!EXEC_URL) return json({ ok: false, message: 'Execution service not configured. Set EXECUTION_SERVICE_URL.' }, 400);
      try {
        await callExecution(`/deployments/${depId}/start`, 'POST');
        await sql`UPDATE deployments SET status = 'starting', last_started_at = NOW() WHERE id = ${depId}`;
        return json({ ok: true, message: 'Starting...' });
      } catch (e) {
        await sql`UPDATE deployments SET status = 'failed', last_error = ${e.message} WHERE id = ${depId}`;
        return json({ ok: false, message: e.message }, 400);
      }
    }

    // STOP
    if (sub === '/stop' && method === 'POST') {
      if (!EXEC_URL) return json({ ok: false, message: 'Execution service not configured.' }, 400);
      try {
        await callExecution(`/deployments/${depId}/stop`, 'POST');
        await sql`UPDATE deployments SET status = 'stopped', pid = NULL, last_stopped_at = NOW() WHERE id = ${depId}`;
        return json({ ok: true, message: 'Stopped.' });
      } catch (e) {
        return json({ ok: false, message: e.message }, 400);
      }
    }

    // RESTART
    if (sub === '/restart' && method === 'POST') {
      if (!EXEC_URL) return json({ ok: false, message: 'Execution service not configured.' }, 400);
      try {
        await callExecution(`/deployments/${depId}/restart`, 'POST');
        await sql`UPDATE deployments SET status = 'starting', restart_count = restart_count + 1, last_started_at = NOW() WHERE id = ${depId}`;
        return json({ ok: true, message: 'Restarting...' });
      } catch (e) {
        return json({ ok: false, message: e.message }, 400);
      }
    }

    // FILES
    if (sub === '/files' && method === 'GET') {
      const dir = url.searchParams.get('dir') || '';
      if (!EXEC_URL) return json({ dir, items: [] });
      try {
        const r = await callExecution(`/deployments/${depId}/files?dir=${encodeURIComponent(dir)}`);
        return json(r);
      } catch (e) { return json({ error: e.message }, 502); }
    }

    if (sub === '/files' && method === 'POST') {
      if (!EXEC_URL) return json({ error: 'Execution service not configured.' }, 400);
      const form = await req.formData();
      const file = form.get('file');
      if (!file) return json({ error: 'No file' }, 400);
      const buf = Buffer.from(await file.arrayBuffer());
      const b64 = buf.toString('base64');
      try {
        const r = await callExecution(`/deployments/${depId}/files/upload`, 'POST', { filename: file.name, data: b64 });
        return json({ ok: true, result: r });
      } catch (e) { return json({ error: e.message }, 502); }
    }

    if (sub === '/files/read' && method === 'GET') {
      const p = url.searchParams.get('path') || '';
      if (!EXEC_URL) return json({ error: 'Execution service not configured.' }, 400);
      try { return json(await callExecution(`/deployments/${depId}/files/read?path=${encodeURIComponent(p)}`)); }
      catch (e) { return json({ error: e.message }, 502); }
    }

    if (sub === '/files/write' && method === 'POST') {
      if (!EXEC_URL) return json({ error: 'Execution service not configured.' }, 400);
      const body = await req.json();
      try { return json(await callExecution(`/deployments/${depId}/files/write`, 'POST', body)); }
      catch (e) { return json({ error: e.message }, 502); }
    }

    if (sub === '/files/delete' && method === 'POST') {
      if (!EXEC_URL) return json({ error: 'Execution service not configured.' }, 400);
      const body = await req.json();
      try { return json(await callExecution(`/deployments/${depId}/files/delete`, 'POST', body)); }
      catch (e) { return json({ error: e.message }, 502); }
    }

    if (sub === '/files/download' && method === 'GET') {
      if (!EXEC_URL) return json({ error: 'Execution service not configured.' }, 400);
      const p = url.searchParams.get('path') || '';
      try {
        const r = await fetch(`${EXEC_URL}/deployments/${depId}/files/download?path=${encodeURIComponent(p)}`, {
          headers: { 'Authorization': `Bearer ${EXEC_SECRET}` },
        });
        if (!r.ok) return json({ error: 'not found' }, 404);
        const buf = await r.arrayBuffer();
        return new Response(buf, {
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': `attachment; filename="${p.split('/').pop()}"`,
          },
        });
      } catch (e) { return json({ error: e.message }, 502); }
    }

    // LOGS
    if (sub === '/logs' && method === 'GET') {
      const after = parseInt(url.searchParams.get('after') || '0');
      const r = await sql`SELECT id, stream, line, created_at FROM log_entries WHERE deployment_id = ${depId} AND id > ${after} ORDER BY id ASC LIMIT 200`;
      return json({ logs: r.rows });
    }

    // METRICS
    if (sub === '/metrics' && method === 'GET') {
      let metrics = { available: false, cpu: null, rss: null, memory_limit_mb: dep.memory_limit_mb, restart_count: dep.restart_count, exit_code: dep.exit_code, last_error: dep.last_error, storage_used: null, storage_limit_mb: null };
      let running = false;
      if (EXEC_URL && dep.pid) {
        try {
          const r = await callExecution(`/deployments/${depId}/metrics`);
          metrics = { ...metrics, ...r };
          running = r.running || false;
        } catch(e) {}
      }
      return json({ metrics, running });
    }

    // ENV VARS
    if (sub === '/env' && method === 'GET') {
      const r = await sql`SELECT key FROM env_vars WHERE deployment_id = ${depId} ORDER BY key`;
      return json({ keys: r.rows.map(x => x.key), count: r.rows.length });
    }

    if (sub === '/env' && method === 'POST') {
      const body = await req.json();
      const key = (body.key || '').trim();
      if (!key || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) return json({ error: 'Invalid key' }, 400);
      await sql`INSERT INTO env_vars (deployment_id, key, value) VALUES (${depId}, ${key}, ${String(body.value || '')}) ON CONFLICT (deployment_id, key) DO UPDATE SET value = EXCLUDED.value`;
      return json({ ok: true });
    }

    const envDelMatch = sub.match(/^\/env\/(.+)$/);
    if (envDelMatch && method === 'DELETE') {
      await sql`DELETE FROM env_vars WHERE deployment_id = ${depId} AND key = ${decodeURIComponent(envDelMatch[1])}`;
      return json({ ok: true });
    }
  }

  // ----- ADMIN -----
  if (path.startsWith('/admin/')) {
    if (user.role !== 'admin') return json({ error: 'admin required' }, 403);

    if (path === '/admin/users' && method === 'GET') {
      const r = await sql`SELECT id, email, display_name, role, is_active, plan, created_at FROM users ORDER BY id`;
      return json({ users: r.rows });
    }

    const activeMatch = path.match(/^\/admin\/users\/(\d+)\/active$/);
    if (activeMatch && method === 'POST') {
      const body = await req.json();
      await sql`UPDATE users SET is_active = ${!!body.active} WHERE id = ${parseInt(activeMatch[1])}`;
      return json({ ok: true });
    }

    if (path === '/admin/health' && method === 'GET') {
      const maint = await sql`SELECT value FROM app_settings WHERE key = 'maintenance_mode'`;
      const depCount = await sql`SELECT COUNT(*)::int AS n FROM deployments`;
      const userCount = await sql`SELECT COUNT(*)::int AS n FROM users`;
      return json({
        execution_available: !!EXEC_URL,
        maintenance: maint.rows[0]?.value === '1',
        deployment_count: depCount.rows[0].n,
        user_count: userCount.rows[0].n,
        worker_configured: !!EXEC_URL,
      });
    }

    if (path === '/admin/maintenance' && method === 'POST') {
      const body = await req.json();
      await sql`UPDATE app_settings SET value = ${body.enabled ? '1' : '0'} WHERE key = 'maintenance_mode'`;
      return json({ ok: true, enabled: !!body.enabled });
    }
  }

  return json({ error: 'not found' }, 404);
}

export const config = { runtime: 'nodejs20.x' };
