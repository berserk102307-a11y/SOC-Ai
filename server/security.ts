import crypto from 'node:crypto';

export type UserRole = 'ANALYST' | 'APPROVER' | 'ADMIN';

export interface User {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  passwordSalt: string;
  passwordHash: string;
  department: string;
  createdAt: string;
}

export interface Session {
  token: string;
  userId: string;
  email: string;
  role: UserRole;
  name: string;
  ip: string;
  userAgent: string;
  createdAt: number;
  expiresAt: number;
}

export interface StoredApiKey {
  id: string;
  name: string;
  host: string;
  keyPrefix: string; // e.g. "soc-mon-a1b2..."
  keyHash: string;   // SHA-256 of full key
  createdAt: string;
  lastUsedAt: string | null;
  revoked: boolean;
  revokedAt: string | null;
}

// Password hashing helper (PBKDF2 SHA-256 with 10,000 iterations)
export function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha256').toString('hex');
}

export function createPasswordRecord(password: string): { salt: string; hash: string } {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  return { salt, hash };
}

// Seed Users for SOC Roles
const analystCreds = createPasswordRecord('Analyst@2026!');
const approverCreds = createPasswordRecord('Approver@2026!');
const adminCreds = createPasswordRecord('Admin@2026!');

export const USERS: Map<string, User> = new Map([
  [
    'analyst@soc.corp',
    {
      id: 'usr_analyst_01',
      email: 'analyst@soc.corp',
      name: 'Maya Lin (SOC Analyst)',
      role: 'ANALYST',
      passwordSalt: analystCreds.salt,
      passwordHash: analystCreds.hash,
      department: 'Tier-1 Threat Intelligence',
      createdAt: '2026-10-01T08:00:00Z',
    },
  ],
  [
    'approver@soc.corp',
    {
      id: 'usr_approver_01',
      email: 'approver@soc.corp',
      name: 'David Chen (Incident Commander)',
      role: 'APPROVER',
      passwordSalt: approverCreds.salt,
      passwordHash: approverCreds.hash,
      department: 'SOC Operations & Approvals',
      createdAt: '2026-10-01T08:00:00Z',
    },
  ],
  [
    'admin@soc.corp',
    {
      id: 'usr_admin_01',
      email: 'admin@soc.corp',
      name: 'Sarah Connor (Security Admin)',
      role: 'ADMIN',
      passwordSalt: adminCreds.salt,
      passwordHash: adminCreds.hash,
      department: 'Enterprise Cyber Defense',
      createdAt: '2026-10-01T08:00:00Z',
    },
  ],
]);

// In-memory active sessions
export const SESSIONS: Map<string, Session> = new Map();

// Rate limiting state: IP/User -> { attempts: number, lockoutUntil: number }
interface RateLimitRecord {
  attempts: number;
  firstAttempt: number;
  lockoutUntil: number;
}
const LOGIN_RATE_LIMITS: Map<string, RateLimitRecord> = new Map();

const MAX_LOGIN_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const LOCKOUT_DURATION_MS = 3 * 60 * 1000; // 3 minutes lockout

export function checkLoginRateLimit(identifier: string): { allowed: boolean; remainingAttempts: number; retryAfterSec?: number } {
  const now = Date.now();
  const record = LOGIN_RATE_LIMITS.get(identifier);

  if (!record) {
    return { allowed: true, remainingAttempts: MAX_LOGIN_ATTEMPTS };
  }

  if (record.lockoutUntil > now) {
    const retryAfterSec = Math.ceil((record.lockoutUntil - now) / 1000);
    return { allowed: false, remainingAttempts: 0, retryAfterSec };
  }

  // If window expired, reset attempts
  if (now - record.firstAttempt > RATE_LIMIT_WINDOW_MS) {
    LOGIN_RATE_LIMITS.delete(identifier);
    return { allowed: true, remainingAttempts: MAX_LOGIN_ATTEMPTS };
  }

  if (record.attempts >= MAX_LOGIN_ATTEMPTS) {
    record.lockoutUntil = now + LOCKOUT_DURATION_MS;
    const retryAfterSec = Math.ceil(LOCKOUT_DURATION_MS / 1000);
    return { allowed: false, remainingAttempts: 0, retryAfterSec };
  }

  return { allowed: true, remainingAttempts: MAX_LOGIN_ATTEMPTS - record.attempts };
}

export function recordFailedLogin(identifier: string): { lockedOut: boolean; attempts: number; lockoutSeconds?: number } {
  const now = Date.now();
  const record = LOGIN_RATE_LIMITS.get(identifier) || { attempts: 0, firstAttempt: now, lockoutUntil: 0 };
  record.attempts += 1;

  if (record.attempts >= MAX_LOGIN_ATTEMPTS) {
    record.lockoutUntil = now + LOCKOUT_DURATION_MS;
    LOGIN_RATE_LIMITS.set(identifier, record);
    return { lockedOut: true, attempts: record.attempts, lockoutSeconds: Math.ceil(LOCKOUT_DURATION_MS / 1000) };
  }

  LOGIN_RATE_LIMITS.set(identifier, record);
  return { lockedOut: false, attempts: record.attempts };
}

export function resetLoginRateLimit(identifier: string): void {
  LOGIN_RATE_LIMITS.delete(identifier);
}

export function clearAllLoginRateLimits(): void {
  LOGIN_RATE_LIMITS.clear();
}

// -------------------------------------------------------------
// Monitor API Key Security & Constant-Time Verification
// -------------------------------------------------------------

// Active API Keys stored by SHA-256 hash
export const API_KEYS: Map<string, StoredApiKey> = new Map();

// Helper to calculate SHA-256
export function sha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Constant-time string comparison preventing timing attack vulnerabilities
export function timingSafeEqualString(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    // Perform dummy comparison to equalize timing
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// Initialize seed monitor API key for the Windows Event Monitor agent
export function initializeSeedApiKey(): { rawKey: string; keyInfo: StoredApiKey } {
  // Initial 32-byte secure hex key
  const rawKey = 'soc_mon_live_649f8b2c4e1a7d903e5f2a1b8c7d6e5f';
  const keyHash = sha256(rawKey);
  const keyRecord: StoredApiKey = {
    id: 'key_win_sensor_01',
    name: 'Windows Sensor Lab VM-01',
    host: 'WIN-DC-01.lab.local',
    keyPrefix: rawKey.substring(0, 16) + '...',
    keyHash,
    createdAt: '2026-10-15T10:00:00Z',
    lastUsedAt: '2026-10-28T18:00:00Z',
    revoked: false,
    revokedAt: null,
  };
  API_KEYS.set(keyHash, keyRecord);
  return { rawKey, keyInfo: keyRecord };
}

// Generate new 32-byte secure key
export function generateApiKey(name: string, host: string): { rawKey: string; keyRecord: StoredApiKey } {
  const randomBytes = crypto.randomBytes(32).toString('hex');
  const rawKey = `soc_mon_${randomBytes}`;
  const keyHash = sha256(rawKey);
  const keyRecord: StoredApiKey = {
    id: `key_${crypto.randomUUID().substring(0, 8)}`,
    name,
    host,
    keyPrefix: rawKey.substring(0, 16) + '...',
    keyHash,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revoked: false,
    revokedAt: null,
  };
  API_KEYS.set(keyHash, keyRecord);
  return { rawKey, keyRecord };
}

export function revokeApiKey(keyId: string): boolean {
  for (const [hash, key] of API_KEYS.entries()) {
    if (key.id === keyId) {
      key.revoked = true;
      key.revokedAt = new Date().toISOString();
      return true;
    }
  }
  return false;
}

export function verifyMonitorApiKey(providedKey: string | undefined): { valid: boolean; keyRecord?: StoredApiKey; reason?: string } {
  if (!providedKey || typeof providedKey !== 'string') {
    return { valid: false, reason: 'MISSING_API_KEY' };
  }

  const computedHash = sha256(providedKey.trim());

  // Search stored keys with constant-time comparison
  for (const [storedHash, keyRecord] of API_KEYS.entries()) {
    if (timingSafeEqualString(computedHash, storedHash)) {
      if (keyRecord.revoked) {
        return { valid: false, reason: 'KEY_REVOKED', keyRecord };
      }
      keyRecord.lastUsedAt = new Date().toISOString();
      return { valid: true, keyRecord };
    }
  }

  return { valid: false, reason: 'INVALID_API_KEY' };
}
