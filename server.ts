import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'node:crypto';
import {
  USERS,
  SESSIONS,
  checkLoginRateLimit,
  recordFailedLogin,
  resetLoginRateLimit,
  clearAllLoginRateLimits,
  hashPassword,
  initializeSeedApiKey,
  API_KEYS,
  generateApiKey,
  revokeApiKey,
  verifyMonitorApiKey,
  type UserRole,
  type Session,
} from './server/security.ts';
import { auditChain } from './server/auditChain.ts';
import { approvalManager, type ActionParameters } from './server/approvalEngine.ts';
import { INCIDENT_FIXTURES } from './server/fixtures.ts';
import { investigationEngine } from './server/investigationService.ts';
import { runPlatformSecuritySuite } from './server/testSuite.ts';
import {
  RISK_LADDER,
  DETERMINISTIC_POLICIES,
  evaluateActionSafety,
  simulateActionExecution,
  AUTO_EXECUTE_MAX,
  APPROVAL_REQUIRED_MIN,
  NEVER_AUTONOMOUS,
} from './server/policyAndSafety.ts';
import {
  wazuhStore,
  ATTACK_SCENARIOS,
  mapWazuhSeverity,
  type WazuhAlert,
} from './server/scenarios.ts';
import { backendCallTracker } from './server/backendCallTracker.ts';
import { ollamaService } from './server/ollamaService.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize seed monitor key at startup
const seedApiKey = initializeSeedApiKey();
console.log(`[AI-SOC] Seed Monitor Key initialized for WIN-DC-01: ${seedApiKey.rawKey}`);

async function startServer() {
  const app = express();
  app.use(express.json());

  // Security Headers Middleware
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });

  // Backend API Call & Error Tracker Middleware for Ollama Diagnosis
  app.use('/api', (req, res, next) => {
    // Avoid tracking internal diagnostic status polling to keep log clean
    if (req.path.startsWith('/ai/ollama/backend-calls') || req.path.startsWith('/ai/ollama/status')) {
      return next();
    }

    const start = Date.now();
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    // Safe sanitized request body snippet (redact passwords, tokens, keys)
    let requestSnippet = '{}';
    if (req.body && typeof req.body === 'object') {
      try {
        const cloned = { ...req.body };
        if (cloned.password) cloned.password = '[REDACTED]';
        if (cloned.token) cloned.token = '[REDACTED]';
        if (cloned.rawKey) cloned.rawKey = '[REDACTED]';
        requestSnippet = JSON.stringify(cloned).substring(0, 160);
      } catch {
        requestSnippet = '{ "error": "unserializable" }';
      }
    }

    res.on('finish', () => {
      const durationMs = Date.now() - start;
      const statusCode = res.statusCode;
      const hasError = statusCode >= 400;

      let userEmail: string | undefined;
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const session = SESSIONS.get(authHeader.substring(7).trim());
        if (session) userEmail = session.email;
      }
      if (!userEmail && req.body?.email) {
        userEmail = String(req.body.email);
      }

      let errorMessage: string | undefined;
      if (hasError) {
        if (statusCode === 401) errorMessage = 'Unauthorized / Credential verification failed';
        else if (statusCode === 403) errorMessage = 'Forbidden / Insufficient RBAC permission';
        else if (statusCode === 404) errorMessage = 'Resource not found';
        else if (statusCode === 429) errorMessage = 'Security rate-limit lockout active';
        else if (statusCode >= 500) errorMessage = 'Internal server exception occurred';
      }

      backendCallTracker.recordCall({
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.originalUrl || req.path,
        statusCode,
        durationMs,
        clientIp,
        userEmail,
        hasError,
        errorMessage,
        requestSnippet,
      });
    });

    next();
  });

  // Helper to extract session from Authorization header
  function getSession(req: express.Request): Session | null {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    const token = authHeader.substring(7).trim();
    const session = SESSIONS.get(token);
    if (!session) return null;
    if (session.expiresAt < Date.now()) {
      SESSIONS.delete(token);
      return null;
    }
    return session;
  }

  // -------------------------------------------------------------
  // AUTHENTICATION & SESSION ENDPOINTS
  // -------------------------------------------------------------

  // Reset Rate Limit / Unlock Account Endpoint
  app.post('/api/auth/reset-ratelimit', (req, res) => {
    const { email } = req.body || {};
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    if (email) {
      resetLoginRateLimit(`${clientIp}:${email.toLowerCase().trim()}`);
    }
    clearAllLoginRateLimits();
    auditChain.append('USER', email || 'operator', 'AUTH_RATE_LIMIT_MANUALLY_RESET', {
      clientIp,
      reason: 'Manual or UI unlock requested',
    });
    return res.json({ success: true, message: 'Rate limits and lockouts cleared successfully.' });
  });

  // Quick 1-Click Role Login Endpoint (bypasses lockouts for verified test roles)
  app.post('/api/auth/quick-login', (req, res) => {
    const { role } = req.body || {};
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    
    // Clear any rate-limit state so the user is never locked out on instant access
    clearAllLoginRateLimits();

    const targetEmail =
      role === 'ADMIN' ? 'admin@soc.corp' : (role === 'APPROVER' ? 'approver@soc.corp' : 'analyst@soc.corp');
    const user = USERS.get(targetEmail);
    if (!user) {
      return res.status(404).json({ error: 'Role user not found' });
    }

    const sessionToken = `soc_sess_${crypto.randomBytes(24).toString('hex')}`;
    const session: Session = {
      token: sessionToken,
      userId: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      ip: clientIp,
      userAgent: (req.headers['user-agent'] as string) || 'Unknown Browser',
      createdAt: Date.now(),
      expiresAt: Date.now() + 2 * 60 * 60 * 1000,
    };
    SESSIONS.set(sessionToken, session);

    auditChain.append('USER', user.email, 'AUTH_LOGIN_SUCCESS', {
      userId: user.id,
      role: user.role,
      department: user.department,
      clientIp,
      method: 'ONE_CLICK_PORTAL_ACCESS',
      sessionTokenPrefix: sessionToken.substring(0, 16) + '...',
    });

    return res.json({
      token: sessionToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        department: user.department,
      },
      permissions: {
        canViewDashboard: true,
        canViewAuditLog: true,
        canSubmitFeedback: true,
        canApproveRemediation: user.role === 'APPROVER' || user.role === 'ADMIN',
        canManageApiKeys: user.role === 'ADMIN',
        canManageSystemConfig: user.role === 'ADMIN',
      },
    });
  });

  app.post('/api/auth/login', (req, res) => {
    const { email, password, resetLockout } = req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const rateLimitKey = `${clientIp}:${email || 'unknown'}`;

    if (resetLockout) {
      resetLoginRateLimit(rateLimitKey);
      clearAllLoginRateLimits();
    }

    // 1. Check rate limit
    const rateCheck = checkLoginRateLimit(rateLimitKey);
    if (!rateCheck.allowed) {
      auditChain.append('USER', email || 'anonymous', 'AUTH_RATE_LIMIT_TRIGGERED', {
        clientIp,
        email,
        lockoutSeconds: rateCheck.retryAfterSec,
        reason: 'Too many consecutive failed login attempts',
      });
      return res.status(429).json({
        error: `Account temporarily locked due to repeated authentication failures. Please retry in ${rateCheck.retryAfterSec} seconds.`,
        retryAfter: rateCheck.retryAfterSec,
      });
    }

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = USERS.get(email.toLowerCase().trim());
    if (!user) {
      const failure = recordFailedLogin(rateLimitKey);
      auditChain.append('USER', email, 'AUTH_LOGIN_FAILED', {
        clientIp,
        reason: 'USER_NOT_FOUND',
        attemptCount: failure.attempts,
      });
      return res.status(401).json({
        error: 'Invalid credentials. User not found in authorized SOC personnel directory.',
        remainingAttempts: Math.max(0, 5 - failure.attempts),
      });
    }

    // 2. Validate password with PBKDF2 hash
    const computedHash = hashPassword(password, user.passwordSalt);
    if (computedHash !== user.passwordHash) {
      const failure = recordFailedLogin(rateLimitKey);
      auditChain.append('USER', email, 'AUTH_LOGIN_FAILED', {
        userId: user.id,
        role: user.role,
        clientIp,
        reason: 'BAD_PASSWORD',
        attemptCount: failure.attempts,
      });
      return res.status(401).json({
        error: 'Invalid password. Check credentials.',
        remainingAttempts: Math.max(0, 5 - failure.attempts),
      });
    }

    // 3. Login successful - clear rate limiter & issue session
    resetLoginRateLimit(rateLimitKey);
    const sessionToken = `soc_sess_${crypto.randomBytes(24).toString('hex')}`;
    const session: Session = {
      token: sessionToken,
      userId: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      ip: clientIp,
      userAgent: req.headers['user-agent'] || 'Unknown Browser',
      createdAt: Date.now(),
      expiresAt: Date.now() + 2 * 60 * 60 * 1000, // 2 hour session
    };
    SESSIONS.set(sessionToken, session);

    auditChain.append('USER', user.email, 'AUTH_LOGIN_SUCCESS', {
      userId: user.id,
      role: user.role,
      department: user.department,
      clientIp,
      sessionTokenPrefix: sessionToken.substring(0, 16) + '...',
    });

    return res.json({
      token: sessionToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        department: user.department,
      },
      permissions: {
        canViewDashboard: true,
        canViewAuditLog: true,
        canSubmitFeedback: true,
        canApproveRemediation: user.role === 'APPROVER' || user.role === 'ADMIN',
        canManageApiKeys: user.role === 'ADMIN',
        canManageSystemConfig: user.role === 'ADMIN',
      },
    });
  });

  app.post('/api/auth/logout', (req, res) => {
    const session = getSession(req);
    if (session) {
      SESSIONS.delete(session.token);
      auditChain.append('USER', session.email, 'AUTH_LOGOUT', {
        userId: session.userId,
        role: session.role,
        sessionAgeSeconds: Math.floor((Date.now() - session.createdAt) / 1000),
      });
    }
    res.json({ success: true, message: 'Logged out successfully.' });
  });

  app.get('/api/auth/me', (req, res) => {
    const session = getSession(req);
    if (!session) {
      return res.status(401).json({ authenticated: false });
    }
    const user = USERS.get(session.email);
    return res.json({
      authenticated: true,
      user: {
        id: session.userId,
        email: session.email,
        name: session.name,
        role: session.role,
        department: user?.department || 'SOC Security Staff',
      },
      permissions: {
        canViewDashboard: true,
        canViewAuditLog: true,
        canSubmitFeedback: true,
        canApproveRemediation: session.role === 'APPROVER' || session.role === 'ADMIN',
        canManageApiKeys: session.role === 'ADMIN',
        canManageSystemConfig: session.role === 'ADMIN',
      },
    });
  });

  // Quick switch role endpoint for evaluation and presentation convenience
  app.post('/api/auth/switch-role', (req, res) => {
    const { role } = req.body;
    let targetEmail = 'analyst@soc.corp';
    if (role === 'APPROVER') targetEmail = 'approver@soc.corp';
    if (role === 'ADMIN') targetEmail = 'admin@soc.corp';

    const user = USERS.get(targetEmail)!;
    const sessionToken = `soc_sess_${crypto.randomBytes(24).toString('hex')}`;
    const session: Session = {
      token: sessionToken,
      userId: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      ip: '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'SOC Workstation',
      createdAt: Date.now(),
      expiresAt: Date.now() + 2 * 60 * 60 * 1000,
    };
    SESSIONS.set(sessionToken, session);

    auditChain.append('USER', user.email, 'ROLE_SWITCH_ACTIVE', {
      switchedToRole: user.role,
      user: user.name,
    });

    return res.json({
      token: sessionToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        department: user.department,
      },
      permissions: {
        canViewDashboard: true,
        canViewAuditLog: true,
        canSubmitFeedback: true,
        canApproveRemediation: user.role === 'APPROVER' || user.role === 'ADMIN',
        canManageApiKeys: user.role === 'ADMIN',
        canManageSystemConfig: user.role === 'ADMIN',
      },
    });
  });

  // -------------------------------------------------------------
  // MONITOR API KEY MANAGEMENT & INGESTION GATEWAY
  // -------------------------------------------------------------

  app.get('/api/api-keys', (req, res) => {
    const keys = Array.from(API_KEYS.values()).map(k => ({
      id: k.id,
      name: k.name,
      host: k.host,
      keyPrefix: k.keyPrefix,
      keyHashPreview: `${k.keyHash.substring(0, 12)}...${k.keyHash.substring(56)}`,
      createdAt: k.createdAt,
      lastUsedAt: k.lastUsedAt,
      revoked: k.revoked,
      revokedAt: k.revokedAt,
    }));
    res.json({ keys, seedRawKey: seedApiKey.rawKey });
  });

  app.post('/api/api-keys', (req, res) => {
    const session = getSession(req);
    if (!session || session.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Permission denied: Only ADMIN role can issue new Monitor API keys.' });
    }

    const { name, host } = req.body;
    if (!name || !host) {
      return res.status(400).json({ error: 'Sensor name and host are required.' });
    }

    const { rawKey, keyRecord } = generateApiKey(name, host);

    auditChain.append('USER', session.email, 'API_KEY_CREATED', {
      keyId: keyRecord.id,
      sensorName: name,
      host,
      keyHash: keyRecord.keyHash,
    });

    res.json({
      message: 'New 32-byte Monitor API key generated. Save this key; the server only stores its SHA-256 hash.',
      rawKey,
      keyRecord: {
        id: keyRecord.id,
        name: keyRecord.name,
        host: keyRecord.host,
        keyPrefix: keyRecord.keyPrefix,
        keyHashPreview: `${keyRecord.keyHash.substring(0, 12)}...`,
        createdAt: keyRecord.createdAt,
      },
    });
  });

  app.delete('/api/api-keys/:id', (req, res) => {
    const session = getSession(req);
    if (!session || session.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Permission denied: Only ADMIN role can revoke Monitor API keys.' });
    }

    const { id } = req.params;
    const success = revokeApiKey(id);
    if (!success) {
      return res.status(404).json({ error: 'API key not found.' });
    }

    auditChain.append('USER', session.email, 'API_KEY_REVOKED', {
      keyId: id,
      revokedBy: session.email,
    });

    res.json({ success: true, message: `API Key ${id} has been revoked.` });
  });

  // Windows Event Ingest Endpoint (Protected by X-Monitor-API-Key)
  app.post('/api/alerts/ingest', (req, res) => {
    const apiKey = (req.headers['x-monitor-api-key'] as string) || (req.query.apiKey as string);

    // Constant-time API Key verification
    const verification = verifyMonitorApiKey(apiKey);
    if (!verification.valid) {
      auditChain.append('SYSTEM', 'INGEST_GATEWAY', 'ALERT_INGEST_UNAUTHORIZED', {
        reason: verification.reason,
        providedKeyPrefix: apiKey ? apiKey.substring(0, 8) + '...' : 'NONE',
        remoteAddr: req.ip || req.socket.remoteAddress,
        blocked: true,
      });

      return res.status(401).json({
        error: 'Unauthorized: Missing or invalid X-Monitor-API-Key header.',
        code: verification.reason,
      });
    }

    const { eventRecordId, eventId, sourceIp, targetUser, logonType, subStatus } = req.body;

    if (!eventRecordId || !sourceIp || !targetUser) {
      return res.status(400).json({ error: 'Missing required alert attributes (eventRecordId, sourceIp, targetUser).' });
    }

    auditChain.append('MONITOR', verification.keyRecord!.host, 'ALERT_INGESTED', {
      eventRecordId: Number(eventRecordId),
      eventId: Number(eventId) || 4625,
      sourceIp,
      targetUser,
      logonType: Number(logonType) || 3,
      subStatus: subStatus || '0xC000006A',
    });

    res.status(201).json({
      message: 'Alert authenticated and ingested successfully.',
      sensorHost: verification.keyRecord!.host,
      eventRecordId: Number(eventRecordId),
    });
  });

  // -------------------------------------------------------------
  // AUDIT LOG & CRYPTOGRAPHIC HASH CHAIN ENDPOINTS
  // -------------------------------------------------------------

  app.get('/api/audit-log', (req, res) => {
    const actor = req.query.actor as string | undefined;
    const eventType = req.query.eventType as string | undefined;
    const search = req.query.search as string | undefined;

    const events = auditChain.getEvents({ actor, eventType, search });
    const verification = auditChain.verifyIntegrity();

    res.json({
      totalCount: events.length,
      isTampered: auditChain.getIsTampered(),
      integrity: verification,
      events,
    });
  });

  app.get('/api/audit-log/verify', (req, res) => {
    const verification = auditChain.verifyIntegrity();
    res.json(verification);
  });

  app.post('/api/audit-log/tamper', (req, res) => {
    const { index, field, value } = req.body;
    const targetIdx = index !== undefined ? Number(index) : 1;
    const targetField = field || 'targetUser';
    const targetVal = value || 'TAMPERED_INJECTED_ATTACKER_ACCOUNT';

    const ok = auditChain.simulateTamper(targetIdx, targetField, targetVal);
    if (!ok) {
      return res.status(400).json({ error: 'Invalid event index.' });
    }

    const verificationAfterTamper = auditChain.verifyIntegrity();
    res.json({
      success: true,
      message: `Audit entry #${targetIdx} field '${targetField}' was modified in database. Verification now fails.`,
      tamperReport: verificationAfterTamper,
    });
  });

  app.post('/api/audit-log/restore', (req, res) => {
    const ok = auditChain.restoreChain();
    const verification = auditChain.verifyIntegrity();
    res.json({
      success: ok,
      message: 'Audit chain restored to pristine cryptographic baseline.',
      verification,
    });
  });

  // -------------------------------------------------------------
  // APPROVALS & REMEDIATION DECISION WORKFLOW
  // -------------------------------------------------------------

  app.get('/api/approvals', (req, res) => {
    const approvals = approvalManager.getAll();
    res.json({ approvals });
  });

  app.post('/api/approvals/:id/decide', (req, res) => {
    const session = getSession(req);
    if (!session) {
      return res.status(401).json({ error: 'Authentication required to decide approvals.' });
    }

    const { id } = req.params;
    const { decision, reason, clientParameters } = req.body;

    if (!decision || (decision !== 'APPROVE' && decision !== 'REJECT')) {
      return res.status(400).json({ error: 'Valid decision (APPROVE or REJECT) is required.' });
    }
    if (!reason || reason.trim().length === 0) {
      return res.status(400).json({ error: 'A justification reason is mandatory for all approval decisions.' });
    }

    const outcome = approvalManager.decide(
      id,
      decision,
      reason,
      session.email,
      session.role,
      (clientParameters as ActionParameters) || approvalManager.getById(id)?.parameters
    );

    if (!outcome.success) {
      const statusCode = outcome.error?.includes('Permission denied')
        ? 403
        : outcome.error?.includes('tampered')
        ? 409
        : 400;
      return res.status(statusCode).json({ error: outcome.error });
    }

    res.json({
      success: true,
      approval: outcome.approval,
      message: `Action ${outcome.approval?.actionType} has been ${outcome.approval?.status} by ${session.email}.`,
    });
  });

  // -------------------------------------------------------------
  // INCIDENT FIXTURES & INVESTIGATION PIPELINE
  // -------------------------------------------------------------

  app.get('/api/incidents', (req, res) => {
    res.json({ incidents: INCIDENT_FIXTURES });
  });

  app.get('/api/incidents/:id', (req, res) => {
    const fixture = INCIDENT_FIXTURES.find(f => f.id === req.params.id);
    if (!fixture) {
      return res.status(404).json({ error: 'Incident fixture not found.' });
    }
    const history = investigationEngine.getHistory(req.params.id);
    res.json({ incident: fixture, history });
  });

  app.post('/api/incidents/:id/investigate', (req, res) => {
    const session = getSession(req);
    if (!session) {
      return res.status(401).json({ error: 'Authentication required to trigger investigation.' });
    }
    const { mode } = req.body; // 'VALIDATED_LLM' | 'FALLBACK' | 'MOCK'
    try {
      const result = investigationEngine.runInvestigation(req.params.id, mode || 'VALIDATED_LLM');
      res.json({ success: true, result });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // -------------------------------------------------------------
  // AUTOMATED PLATFORM SECURITY TEST SUITE
  // -------------------------------------------------------------

  app.get('/api/security/test-matrix', async (req, res) => {
    const report = await runPlatformSecuritySuite();
    res.json(report);
  });

  // -------------------------------------------------------------
  // POLICY ENGINE & L0-L7 SAFETY GATE ENDPOINTS
  // -------------------------------------------------------------

  app.get('/api/policy/config', (req, res) => {
    res.json({
      ladder: RISK_LADDER,
      policies: DETERMINISTIC_POLICIES.map(p => ({
        id: p.id,
        action: p.action,
        name: p.name,
        enforce: p.enforce,
      })),
      thresholds: {
        autoExecuteMax: AUTO_EXECUTE_MAX,
        approvalRequiredMin: APPROVAL_REQUIRED_MIN,
        neverAutonomous: NEVER_AUTONOMOUS,
      },
    });
  });

  app.post('/api/policy/evaluate', (req, res) => {
    const session = getSession(req);
    const actorEmail = session ? session.email : 'system-safety-gate';
    const { actionName, parameters, forensicsComplete, incidentSeverity } = req.body;

    if (!actionName) {
      return res.status(400).json({ error: 'actionName is required' });
    }

    const evaluation = evaluateActionSafety({
      actionName,
      parameters: parameters || {},
      forensicsComplete: Boolean(forensicsComplete),
      incidentSeverity: incidentSeverity || 'MEDIUM',
      analystRole: session?.role,
    });

    // Record safety evaluation in the cryptographic audit ledger
    auditChain.append(
      session ? 'USER' : 'SYSTEM',
      actorEmail,
      'POLICY_EVALUATION_PERFORMED',
      {
        actionName,
        parameters: parameters || {},
        decision: evaluation.decision,
        level: evaluation.level,
        tier: evaluation.tier,
        policyRuleTriggered: evaluation.policyRuleTriggered,
        reason: evaluation.reason,
      }
    );

    res.json(evaluation);
  });

  app.post('/api/policy/execute-simulated', (req, res) => {
    const session = getSession(req);
    if (!session) {
      return res.status(401).json({ error: 'Authentication required to execute actions.' });
    }

    const { actionName, parameters, forensicsComplete } = req.body;
    if (!actionName) {
      return res.status(400).json({ error: 'actionName is required' });
    }

    // Always run through safety evaluation first
    const evaluation = evaluateActionSafety({
      actionName,
      parameters: parameters || {},
      forensicsComplete: Boolean(forensicsComplete),
      analystRole: session.role,
    });

    if (evaluation.decision === 'BLOCKED') {
      auditChain.append('SYSTEM', session.email, 'ACTION_EXECUTION_BLOCKED', {
        actionName,
        reason: evaluation.reason,
        policyRuleTriggered: evaluation.policyRuleTriggered,
      });
      return res.status(403).json({
        error: `Action blocked: ${evaluation.reason}`,
        evaluation,
      });
    }

    if (evaluation.decision === 'REQUIRE_APPROVAL') {
      return res.status(400).json({
        error: `Action requires human operator approval via the Remediation Approval Inbox.`,
        evaluation,
      });
    }

    // Auto-allowed execution
    const execution = simulateActionExecution(actionName, parameters || {});
    auditChain.append('USER', session.email, 'ACTION_AUTONOMOUSLY_EXECUTED', {
      actionName,
      parameters: parameters || {},
      output: execution.output,
    });

    res.json({
      success: true,
      evaluation,
      execution,
    });
  });

  // -------------------------------------------------------------
  // WAZUH SIEM INGESTION & ALERTS ENDPOINTS
  // -------------------------------------------------------------

  app.get('/api/wazuh/alerts', (req, res) => {
    const limit = Number(req.query.limit) || 100;
    const severity = req.query.severity as string | undefined;
    const search = (req.query.search as string || '').toLowerCase().trim();

    let alerts = wazuhStore.getAlerts(limit);
    if (severity && severity !== 'ALL') {
      alerts = alerts.filter(a => a.severity === severity);
    }
    if (search) {
      alerts = alerts.filter(
        a =>
          a.rule.description.toLowerCase().includes(search) ||
          a.agent.name.toLowerCase().includes(search) ||
          a.id.toLowerCase().includes(search) ||
          String(a.rule.id).includes(search) ||
          (a.data?.srcip && a.data.srcip.includes(search))
      );
    }

    res.json({ alerts, total: alerts.length });
  });

  app.get('/api/wazuh/stats', (req, res) => {
    res.json(wazuhStore.getStats());
  });

  app.post('/api/wazuh/ingest', (req, res) => {
    const rawAlert = req.body;
    if (!rawAlert.rule || !rawAlert.agent) {
      return res.status(400).json({ error: 'Invalid Wazuh alert schema. "rule" and "agent" required.' });
    }

    const ruleLevel = Number(rawAlert.rule.level) || 5;
    const alert: WazuhAlert = {
      id: rawAlert.id || `wazuh-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: rawAlert.timestamp || new Date().toISOString(),
      rule: {
        id: Number(rawAlert.rule.id) || 100000,
        level: ruleLevel,
        description: rawAlert.rule.description || 'Custom Ingested Alert',
        mitre: rawAlert.rule.mitre,
      },
      agent: rawAlert.agent,
      data: rawAlert.data,
      full_log: rawAlert.full_log || 'Manual ingestion via SIEM API',
      severity: mapWazuhSeverity(ruleLevel),
    };

    wazuhStore.addAlert(alert);

    auditChain.append('MONITOR', `agent:${alert.agent.name}`, 'WAZUH_ALERT_INGESTED', {
      alertId: alert.id,
      ruleId: alert.rule.id,
      severity: alert.severity,
      description: alert.rule.description,
    });

    res.json({ success: true, alert });
  });

  // -------------------------------------------------------------
  // ATTACK SCENARIO REPLAY ENDPOINTS
  // -------------------------------------------------------------

  app.get('/api/scenarios', (req, res) => {
    const list = Object.values(ATTACK_SCENARIOS).map(s => ({
      id: s.id,
      title: s.title,
      mitreTechnique: s.mitreTechnique,
      mitreTactic: s.mitreTactic,
      wazuhRuleId: s.wazuhRuleId,
      wazuhLevel: s.wazuhLevel,
      severity: s.severity,
      targetAgent: s.targetAgent,
      sourceIp: s.sourceIp,
      description: s.description,
      recommendedActions: s.recommendedActions,
      expectedSafetyGate: s.expectedSafetyGate,
      policyRulesTriggered: s.policyRulesTriggered,
    }));
    res.json({ scenarios: list });
  });

  app.post('/api/scenarios/replay', (req, res) => {
    const session = getSession(req);
    const actorEmail = session ? session.email : 'soc-drill-operator';
    const { scenarioId, autoQueueApproval } = req.body;

    const scenario = ATTACK_SCENARIOS[scenarioId];
    if (!scenario) {
      return res.status(404).json({ error: `Scenario "${scenarioId}" not recognized.` });
    }

    // 1. Generate alerts and push to Wazuh store
    const generatedAlerts = scenario.generateAlerts();
    wazuhStore.addMultiple(generatedAlerts);

    // 2. Log scenario replay in audit ledger
    auditChain.append('USER', actorEmail, 'SCENARIO_REPLAY_TRIGGERED', {
      scenarioId: scenario.id,
      scenarioTitle: scenario.title,
      mitreTechnique: scenario.mitreTechnique,
      alertsCount: generatedAlerts.length,
      targetAgent: scenario.targetAgent,
      sourceIp: scenario.sourceIp,
    });

    // 3. Evaluate recommended actions through Safety Gate
    const actionEvaluations = scenario.recommendedActions.map(actionName => {
      const evaluation = evaluateActionSafety({
        actionName,
        parameters: {
          ip: scenario.sourceIp,
          host: scenario.targetAgent.split(' ')[0],
          account: 'CORP\\service_mgr',
          pid: 4892,
        },
        forensicsComplete: false,
        incidentSeverity: scenario.severity,
      });

      // If required approval and autoQueueApproval is enabled, automatically register approval request
      let createdApprovalId: string | null = null;
      if (evaluation.decision === 'REQUIRE_APPROVAL' && autoQueueApproval) {
        const mappedActionType = (actionName.toUpperCase() as any);
        const approvalReq = approvalManager.createRequest(
          `INC-SCENARIO-${Date.now().toString().slice(-4)}`,
          mappedActionType,
          {
            target: scenario.targetAgent.split(' ')[0],
            actionType: mappedActionType,
            ttlMinutes: 30,
            ip: scenario.sourceIp,
            pid: 4892,
            reason: `Generated from ${scenario.title} drill`,
          },
          `Remediation action evaluated as L${evaluation.level} disruptive. Policy reason: ${evaluation.reason}`,
          `Triggered by automated attack drill: ${scenario.title}`,
          scenario.mitreTechnique
        );
        createdApprovalId = approvalReq.id;
      }

      return {
        actionName,
        evaluation,
        createdApprovalId,
      };
    });

    res.json({
      success: true,
      scenario: {
        id: scenario.id,
        title: scenario.title,
        severity: scenario.severity,
      },
      alertsGenerated: generatedAlerts.length,
      alerts: generatedAlerts,
      actionEvaluations,
    });
  });

  // -------------------------------------------------------------
  // SOC DASHBOARD UNIFIED OVERVIEW
  // -------------------------------------------------------------

  app.get('/api/dashboard/overview', (req, res) => {
    const wazuhStats = wazuhStore.getStats();
    const verification = auditChain.verifyIntegrity();
    const allApprovals = approvalManager.getAll();
    const pendingApprovals = allApprovals.filter(a => a.status === 'PENDING');

    res.json({
      timestamp: new Date().toISOString(),
      wazuhStats,
      auditLedger: {
        totalBlocks: auditChain.getLength(),
        valid: verification.valid,
        isTampered: auditChain.getIsTampered(),
        lastHash: auditChain.getHeadHash(),
      },
      approvals: {
        pendingCount: pendingApprovals.length,
        totalCount: allApprovals.length,
        pending: pendingApprovals.slice(0, 5),
      },
      incidents: {
        totalCount: INCIDENT_FIXTURES.length,
        fixtures: INCIDENT_FIXTURES.map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          alertsCount: f.evidencePack.totalAlerts,
        })),
      },
      recentAlerts: wazuhStore.getAlerts(6),
      recentAuditEvents: auditChain.getEvents().slice(-6),
    });
  });

  // -------------------------------------------------------------
  // OLLAMA FREE MODEL AI BACKEND & LOG DIAGNOSTIC ENDPOINTS
  // -------------------------------------------------------------

  // 1. Get Ollama Service Status and Installed Models
  app.get('/api/ai/ollama/status', async (req, res) => {
    try {
      const status = await ollamaService.checkStatus();
      const callStats = backendCallTracker.getStats();
      return res.json({
        ...status,
        callStats,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Failed to check Ollama status' });
    }
  });

  // 2. Configure Ollama Host and Model
  app.post('/api/ai/ollama/configure', async (req, res) => {
    try {
      const { host, model } = req.body || {};
      ollamaService.updateConfig(host, model);
      const status = await ollamaService.checkStatus();
      auditChain.append('USER', 'soc_operator', 'OLLAMA_SERVICE_CONFIGURED', {
        host: status.host,
        activeModel: status.activeModel,
        connected: status.connected,
      });
      return res.json({
        ...status,
        success: true,
        message: `Ollama configuration updated to ${status.host} (${status.activeModel})`,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Failed to configure Ollama' });
    }
  });

  // 3. Analyze SIEM Log, Wazuh Alert, or Audit Event using Ollama AI
  app.post('/api/ai/ollama/analyze-log', async (req, res) => {
    try {
      const { logText, wazuhAlert, auditEvent, context } = req.body || {};
      if (!logText && !wazuhAlert && !auditEvent) {
        return res.status(400).json({ error: 'Please provide logText, wazuhAlert, or auditEvent to analyze.' });
      }

      const analysis = await ollamaService.analyzeLog({
        logText,
        wazuhAlert,
        auditEvent,
        context,
      });

      return res.json({
        success: true,
        analysis,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Log analysis failed' });
    }
  });

  // 4. Analyze Backend API Call or Error with Ollama AI
  app.post('/api/ai/ollama/analyze-call', async (req, res) => {
    try {
      const { callId } = req.body || {};
      if (!callId) {
        return res.status(400).json({ error: 'callId is required.' });
      }

      const analysis = await ollamaService.analyzeBackendCall(callId);
      return res.json({
        success: true,
        analysis,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Backend call analysis failed' });
    }
  });

  // 5. Retrieve Live Backend Calls & Errors
  app.get('/api/ai/ollama/backend-calls', (req, res) => {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 40));
    const errorsOnly = req.query.errorsOnly === 'true';
    const calls = backendCallTracker.getRecentCalls(limit, errorsOnly);
    const stats = backendCallTracker.getStats();
    return res.json({
      calls,
      stats,
    });
  });

  // 6. Simulate a Backend Security Event / Error Call to Test Ollama AI Detection
  app.post('/api/ai/ollama/simulate-call', async (req, res) => {
    try {
      const { scenario } = req.body || {};
      let simulated: any;
      const now = new Date().toISOString();

      if (scenario === 'RATE_LIMIT') {
        simulated = {
          timestamp: now,
          method: 'POST',
          path: '/api/auth/login',
          statusCode: 429,
          durationMs: 14,
          clientIp: '198.51.100.44',
          userEmail: 'analyst@soc.corp',
          hasError: true,
          errorMessage: 'Account locked: 5 consecutive failed logins detected within 60s sliding window.',
          requestSnippet: '{"email":"analyst@soc.corp","reason":"RateLimitSimulation"}',
        };
      } else if (scenario === 'TAMPER_INJECTION') {
        simulated = {
          timestamp: now,
          method: 'POST',
          path: '/api/audit/tamper-test',
          statusCode: 400,
          durationMs: 38,
          clientIp: '203.0.113.199',
          userEmail: 'unknown_prober',
          hasError: true,
          errorMessage: 'Cryptographic HMAC mismatch: Parameter hash does not match canonical action payload.',
          requestSnippet: '{"target":"10.0.0.1","actionType":"OVERRIDE_ROOT","hash":"invalid_hex"}',
        };
      } else if (scenario === 'SERVER_500') {
        simulated = {
          timestamp: now,
          method: 'GET',
          path: '/api/system/kernel-metrics',
          statusCode: 500,
          durationMs: 210,
          clientIp: '10.0.4.5',
          userEmail: 'admin@soc.corp',
          hasError: true,
          errorMessage: 'EADDRINUSE / NullPointer: IPC socket connection dropped unexpectedly.',
          requestSnippet: '{"probe":"ipc_socket"}',
        };
      } else {
        // Default: Brute-Force Password Spray probe
        simulated = {
          timestamp: now,
          method: 'POST',
          path: '/api/auth/login',
          statusCode: 401,
          durationMs: 76,
          clientIp: '198.51.100.105',
          userEmail: 'root@soc.corp',
          hasError: true,
          errorMessage: 'Invalid credentials. User not found in authorized SOC personnel directory.',
          requestSnippet: '{"email":"root@soc.corp","password":"[REDACTED]"}',
        };
      }

      const record = backendCallTracker.recordCall(simulated);
      const analysis = await ollamaService.analyzeBackendCall(record.id);

      return res.json({
        success: true,
        callRecord: backendCallTracker.getCallById(record.id),
        analysis,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Simulation failed' });
    }
  });

  // 7. Clear Call History
  app.post('/api/ai/ollama/clear-calls', (req, res) => {
    backendCallTracker.clear();
    return res.json({ success: true, message: 'Backend call logs cleared.' });
  });

  // -------------------------------------------------------------
  // VITE DEV MIDDLEWARE / STATIC SERVING
  // -------------------------------------------------------------

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log(`[AI-SOC] Server running on http://0.0.0.0:${port}`);
  });
}

startServer().catch(err => {
  console.error('[AI-SOC] Fatal server error:', err);
  process.exit(1);
});
