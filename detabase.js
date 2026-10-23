// database.js — Shared DB helpers. Optional: api.js uses @vercel/postgres directly.
// This file documents the schema and provides reusable query helpers.

import { sql } from '@vercel/postgres';

export async function initSchema() {
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
  `;
  await sql`
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
  `;
  // ... (same tables as api.js ensureDb — see api.js for full schema)
}

export async function getUserByEmail(email) {
  const r = await sql`SELECT * FROM users WHERE email = ${email.toLowerCase()}`;
  return r.rows[0] || null;
}

export async function getDeployment(depId) {
  const r = await sql`SELECT * FROM deployments WHERE id = ${depId}`;
  return r.rows[0] || null;
}

export async function listUserDeployments(ownerId) {
  const r = await sql`SELECT * FROM deployments WHERE owner_id = ${ownerId} ORDER BY id DESC`;
  return r.rows;
}

export async function createDeployment(ownerId, name, runtime, entrypoint, memMb) {
  const r = await sql`INSERT INTO deployments (owner_id, name, runtime, entrypoint, memory_limit_mb) VALUES (${ownerId}, ${name}, ${runtime}, ${entrypoint}, ${memMb}) RETURNING *`;
  return r.rows[0];
}

export async function updateDeploymentStatus(depId, status, fields = {}) {
  const sets = ['status = $1'];
  // ... complex dynamic update — use explicit queries in api.js
}

export async function getLogs(depId, afterId = 0) {
  const r = await sql`SELECT id, stream, line, created_at FROM log_entries WHERE deployment_id = ${depId} AND id > ${afterId} ORDER BY id ASC LIMIT 200`;
  return r.rows;
}
