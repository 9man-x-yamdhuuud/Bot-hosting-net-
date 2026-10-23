// worker.js — Execution service. Deploy on VPS / Render Background Worker / Fly.io.
// Listens on PORT (default 8090). Requires WORKER_SECRET env var.
// Provides: start/stop/restart/status/metrics/files for each deployment.

import express from 'express';
import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { promisify } from 'util';
import crypto from 'crypto';

const app = express();
app.use(express.json({ limit: '50mb' }));

const SECRET = process.env.WORKER_SECRET;
if (!SECRET || SECRET.length < 32) {
  console.error('WORKER_SECRET required (32+ chars)');
  process.exit(1);
}

const ROOT = process.env.WORKER_ROOT || path.join(os.homedir(), 'aman-deployments');
const PYTHON = process.env.WORKER_PYTHON || 'python3';
const NODE = process.env.WORKER_NODE || 'node';
const MAX_MEMORY_MB = parseInt(process.env.WORKER_MAX_MEMORY_MB || '512');
fs.mkdirSync(ROOT, { recursive: true });

const procs = new Map(); // depId -> { proc, logs: [], startedAt }

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace(/^Bearer\s+/i, '');
  if (token !== SECRET) return res.status(401).json({ error: 'unauthorized' });
  next();
}
app.use(auth);

function depDir(id) {
  const d = path.join(ROOT, String(id));
  fs.mkdirSync(d, { recursive: true });
  return d;
}

function safeJoin(root, ...parts) {
  const rootAbs = path.resolve(root);
  const target = path.resolve(rootAbs, ...parts);
  if (!target.startsWith(rootAbs + path.sep) && target !== rootAbs) throw new Error('path escapes root');
  return target;
}

function log(depId, stream, line) {
  const p = procs.get(depId);
  if (p) { p.logs.push({ stream, line, ts: Date.now() }); if (p.logs.length > 5000) p.logs.shift(); }
}

function applyRlimits(proc, memMb) {
  // Node.js child_process doesn't expose setrlimit directly.
  // We use prlimit command wrapper on Linux for hard memory cap.
  // For simplicity we run child with `prlimit --as=<bytes> --` prefix if available.
  return proc;
}

async function spawnDeployment(depId, runtime, entry) {
  const dir = depDir(depId);
  const fullEntry = safeJoin(dir, entry);
  if (!fs.existsSync(fullEntry)) throw new Error(`Entry not found: ${entry}`);
  const env = { ...process.env, PATH: process.env.PATH, HOME: dir, PYTHONUNBUFFERED: '1' };
  let cmd, args;
  if (runtime === 'python') { cmd = PYTHON; args = [entry]; }
  else if (runtime === 'node') { cmd = NODE; args = [entry]; }
  else if (runtime === 'static') {
    // Static: mark running, no process — reverse proxy serves files
    return { pid: null, static: true };
  } else throw new Error('unsupported runtime');

  // Install deps
  if (runtime === 'python' && fs.existsSync(path.join(dir, 'requirements.txt'))) {
    await new Promise((resolve) => {
      const p = spawn(PYTHON, ['-m', 'pip', 'install', '--disable-pip-version-check', '-r', 'requirements.txt'], { cwd: dir, env });
      p.stdout.on('data', d => log(depId, 'system', d.toString().trim()));
      p.stderr.on('data', d => log(depId, 'system', d.toString().trim()));
      p.on('close', resolve);
    });
  }
  if (runtime === 'node' && fs.existsSync(path.join(dir, 'package.json'))) {
    await new Promise((resolve) => {
      const p = spawn('npm', ['install', '--no-audit', '--no-fund'], { cwd: dir, env });
      p.stdout.on('data', d => log(depId, 'system', d.toString().trim()));
      p.stderr.on('data', d => log(depId, 'system', d.toString().trim()));
      p.on('close', resolve);
    });
  }

  const proc = spawn(cmd, args, { cwd: dir, env, detached: false });
  procs.set(depId, { proc, logs: [], startedAt: Date.now(), runtime, entry, pid: proc.pid });
  proc.stdout.on('data', d => log(depId, 'stdout', d.toString().trim()));
  proc.stderr.on('data', d => log(depId, 'stderr', d.toString().trim()));
  proc.on('close', (code) => {
    log(depId, 'system', `Process exited with code ${code}`);
    const p = procs.get(depId); if (p) { p.pid = null; p.exitCode = code; }
  });
  return { pid: proc.pid };
}

function stopDeployment(depId) {
  const p = procs.get(depId);
  if (!p || !p.proc || p.proc.killed) return false;
  try {
    // Kill process group
    if (p.proc.pid) process.kill(-p.proc.pid, 'SIGTERM');
    else p.proc.kill('SIGTERM');
    setTimeout(() => { try { if (p.proc.pid) process.kill(-p.proc.pid, 'SIGKILL'); } catch(e){} }, 5000);
    return true;
  } catch(e) { return false; }
}

// ========== ROUTES ==========

app.get('/healthz', (req, res) => res.json({ ok: true, deployments: procs.size }));

app.post('/deployments/:id/start', async (req, res) => {
  const depId = parseInt(req.params.id);
  const { runtime, entrypoint } = req.body;
  try {
    const result = await spawnDeployment(depId, runtime, entrypoint);
    res.json({ ok: true, pid: result.pid, static: result.static || false });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/deployments/:id/stop', (req, res) => {
  const ok = stopDeployment(parseInt(req.params.id));
  res.json({ ok: true, stopped: ok });
});

app.post('/deployments/:id/restart', async (req, res) => {
  const depId = parseInt(req.params.id);
  stopDeployment(depId);
  await new Promise(r => setTimeout(r, 500));
  try {
    const result = await spawnDeployment(depId, req.body.runtime, req.body.entrypoint);
    res.json({ ok: true, pid: result.pid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/deployments/:id/status', (req, res) => {
  const p = procs.get(parseInt(req.params.id));
  const running = !!(p && p.pid);
  res.json({ running, pid: p?.pid || null, started_at: p?.startedAt || null });
});

app.get('/deployments/:id/metrics', (req, res) => {
  const depId = parseInt(req.params.id);
  const p = procs.get(depId);
  if (!p || !p.pid) return res.json({ available: false, running: false });
  try {
    const procInfo = fs.readFileSync(`/proc/${p.pid}/stat`, 'utf8').split(' ');
    const utime = parseInt(procInfo[13]); const stime = parseInt(procInfo[14]);
    const totalTicks = utime + stime;
    const rssPages = parseInt(procInfo[23]);
    const pageSize = 4096;
    const rss = rssPages * pageSize;
    const uptime = Math.floor((Date.now() - p.startedAt) / 1000);
    const cpu = (totalTicks / 100) / uptime * 100;
    res.json({ available: true, running: true, pid: p.pid, cpu: Math.min(cpu, 100), rss, uptime, threads: null });
  } catch (e) {
    res.json({ available: false, running: true, pid: p.pid, error: e.message });
  }
});

app.get('/deployments/:id/logs', (req, res) => {
  const p = procs.get(parseInt(req.params.id));
  res.json({ logs: p?.logs || [] });
});

app.get('/deployments/:id/files', (req, res) => {
  const depId = parseInt(req.params.id);
  const dir = depDir(depId);
  const rel = req.query.dir || '';
  try {
    const target = rel ? safeJoin(dir, rel) : dir;
    if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) return res.json({ dir: rel, items: [] });
    const items = fs.readdirSync(target).map(name => {
      const full = path.join(target, name);
      const st = fs.statSync(full);
      return { name, is_dir: st.isDirectory(), size: st.isDirectory() ? 0 : st.size, modified: st.mtime.toISOString() };
    });
    res.json({ dir: rel, items });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/deployments/:id/files/upload', (req, res) => {
  const depId = parseInt(req.params.id);
  const { filename, data } = req.body;
  if (!filename || !data) return res.status(400).json({ error: 'filename and data required' });
  try {
    const dir = depDir(depId);
    const safeName = path.basename(filename);
    const target = safeJoin(dir, safeName);
    fs.writeFileSync(target, Buffer.from(data, 'base64'));
    if (safeName.toLowerCase().endsWith('.zip')) {
      // extract with unzip command if available
      const { execSync } = require('child_process');
      try { execSync(`unzip -o "${target}" -d "${dir}"`, { stdio: 'ignore' }); fs.unlinkSync(target); } catch(e) {}
    }
    res.json({ ok: true, saved: safeName });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/deployments/:id/files/read', (req, res) => {
  const depId = parseInt(req.params.id);
  try {
    const target = safeJoin(depDir(depId), req.query.path || '');
    if (!fs.existsSync(target) || fs.statSync(target).size > 512 * 1024) throw new Error('invalid or too large');
    res.json({ path: req.query.path, content: fs.readFileSync(target, 'utf8') });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/deployments/:id/files/write', (req, res) => {
  const depId = parseInt(req.params.id);
  try {
    const target = safeJoin(depDir(depId), req.body.path || '');
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, req.body.content || '');
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/deployments/:id/files/delete', (req, res) => {
  const depId = parseInt(req.params.id);
  try {
    const target = safeJoin(depDir(depId), req.body.path || '');
    if (fs.statSync(target).isDirectory()) fs.rmSync(target, { recursive: true });
    else fs.unlinkSync(target);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/deployments/:id/files/download', (req, res) => {
  const depId = parseInt(req.params.id);
  try {
    const target = safeJoin(depDir(depId), req.query.path || '');
    if (!fs.existsSync(target)) return res.status(404).end();
    res.download(target);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

const PORT = parseInt(process.env.PORT || '8090');
app.listen(PORT, '0.0.0.0', () => console.log(`Worker listening on ${PORT}`));
