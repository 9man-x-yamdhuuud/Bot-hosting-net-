// config.js — Validated environment configuration.
// Import and call validateConfig() at startup if you prefer centralized validation.

export function validateConfig() {
  const required = ['SESSION_SECRET'];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) throw new Error(`Missing env vars: ${missing.join(', ')}`);

  if (process.env.SESSION_SECRET.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters');
  }

  const executionUrl = process.env.EXECUTION_SERVICE_URL || '';
  const executionSecret = process.env.EXECUTION_SERVICE_SECRET || '';
  if (executionUrl && !executionSecret) {
    throw new Error('EXECUTION_SERVICE_SECRET required when EXECUTION_SERVICE_URL is set');
  }

  return {
    secret: process.env.SESSION_SECRET,
    executionUrl,
    executionSecret,
    bootstrapAdminEmail: process.env.BOOTSTRAP_ADMIN_EMAIL || '',
    bootstrapAdminPassword: process.env.BOOTSTRAP_ADMIN_PASSWORD || '',
    freeMaxDeployments: parseInt(process.env.FREE_MAX_DEPLOYMENTS || '2'),
    freeMaxMemoryMb: parseInt(process.env.FREE_MAX_MEMORY_MB || '256'),
    databaseUrl: process.env.POSTGRES_URL || process.env.DATABASE_URL || '',
  };
}

export const EXECUTION_AVAILABLE = !!process.env.EXECUTION_SERVICE_URL;
