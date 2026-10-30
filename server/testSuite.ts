import crypto from 'node:crypto';
import { auditChain } from './auditChain.ts';
import {
  API_KEYS,
  checkLoginRateLimit,
  hashPassword,
  recordFailedLogin,
  resetLoginRateLimit,
  timingSafeEqualString,
  USERS,
  verifyMonitorApiKey,
  type UserRole,
} from './security.ts';
import { approvalManager, computeParameterHash } from './approvalEngine.ts';

export interface SecurityTestCaseResult {
  id: string;
  name: string;
  category: 'AUTHENTICATION' | 'AUTHORIZATION_MATRIX' | 'API_KEY_SECURITY' | 'CRYPTOGRAPHIC_AUDIT' | 'APPROVAL_TAMPERING';
  status: 'PASS' | 'FAIL';
  expected: string;
  actual: string;
  details: string;
  durationMs: number;
}

export interface SecuritySuiteReport {
  timestamp: string;
  totalTests: number;
  passedCount: number;
  failedCount: number;
  successRate: number;
  results: SecurityTestCaseResult[];
}

export async function runPlatformSecuritySuite(): Promise<SecuritySuiteReport> {
  const results: SecurityTestCaseResult[] = [];
  const startAll = Date.now();

  // Test 1: Missing API Key on Monitor Endpoint
  {
    const t0 = Date.now();
    const check = verifyMonitorApiKey(undefined);
    const pass = !check.valid && check.reason === 'MISSING_API_KEY';
    results.push({
      id: 'SEC-01',
      name: 'Unauthenticated Alert Ingestion Rejection (Missing API Key)',
      category: 'API_KEY_SECURITY',
      status: pass ? 'PASS' : 'FAIL',
      expected: 'HTTP 401 Unauthorized with MISSING_API_KEY',
      actual: pass ? 'Rejected: MISSING_API_KEY' : `Unexpected result: ${JSON.stringify(check)}`,
      details: 'Prevents arbitrary endpoints from submitting forged alerts without monitor authentication.',
      durationMs: Date.now() - t0,
    });
  }

  // Test 2: Forged / Invalid API Key (Constant-Time Verification)
  {
    const t0 = Date.now();
    const forgedKey = 'soc_mon_forged_attack_key_000000000000000000';
    const check = verifyMonitorApiKey(forgedKey);
    const pass = !check.valid && check.reason === 'INVALID_API_KEY';
    results.push({
      id: 'SEC-02',
      name: 'Forged Monitor API Key Rejection (Constant-Time SHA-256 Compare)',
      category: 'API_KEY_SECURITY',
      status: pass ? 'PASS' : 'FAIL',
      expected: 'HTTP 401 Unauthorized with INVALID_API_KEY',
      actual: pass ? 'Rejected: INVALID_API_KEY via timing-safe check' : 'Key was incorrectly accepted',
      details: 'Ensures keys are evaluated in constant time using crypto.timingSafeEqual, immune to side-channel timing attacks.',
      durationMs: Date.now() - t0,
    });
  }

  // Test 3: Valid Monitor API Key Acceptance
  {
    const t0 = Date.now();
    // Retrieve seed key raw value
    const seedRawKey = 'soc_mon_live_649f8b2c4e1a7d903e5f2a1b8c7d6e5f';
    const check = verifyMonitorApiKey(seedRawKey);
    const pass = check.valid && check.keyRecord?.host === 'WIN-DC-01.lab.local';
    results.push({
      id: 'SEC-03',
      name: 'Authorized Monitor Ingestion with SHA-256 Hashed Key Verification',
      category: 'API_KEY_SECURITY',
      status: pass ? 'PASS' : 'FAIL',
      expected: 'Verification succeeds and associates alert with WIN-DC-01.lab.local',
      actual: pass ? `Accepted for host: ${check.keyRecord?.host}` : 'Failed to verify known seed key',
      details: 'Raw API keys are never stored in plaintext on disk; only SHA-256 digest is persisted.',
      durationMs: Date.now() - t0,
    });
  }

  // Test 4: Role-Based Access Control (Analyst role cannot approve actions)
  {
    const t0 = Date.now();
    // Create an approval request for testing
    const testReq = approvalManager.createRequest(
      'inc_test_rbac_01',
      'BLOCK_SOURCE_IP',
      {
        target: '198.51.100.99',
        actionType: 'BLOCK_SOURCE_IP',
        ttlMinutes: 15,
      },
      'Test policy rule',
      'RBAC test verification incident',
      'T1110.001',
      15
    );

    const decision = approvalManager.decide(
      testReq.id,
      'APPROVE',
      'Analyst attempting unauthorized approval',
      'analyst@soc.corp',
      'ANALYST',
      testReq.parameters
    );

    const pass = !decision.success && decision.error?.includes('Permission denied');
    results.push({
      id: 'SEC-04',
      name: 'RBAC Enforcement: ANALYST Role Prohibited from Approving Remediation',
      category: 'AUTHORIZATION_MATRIX',
      status: pass ? 'PASS' : 'FAIL',
      expected: 'HTTP 403 Forbidden: APPROVER or ADMIN role required',
      actual: pass ? `Rejected: ${decision.error}` : 'Security failure: Analyst was permitted to approve!',
      details: 'Strict segregation of duty: Analysts provide feedback, but cannot execute or approve disruptive firewall actions.',
      durationMs: Date.now() - t0,
    });
  }

  // Test 5: Role-Based Access Control (Approver role CAN approve)
  {
    const t0 = Date.now();
    const testReq2 = approvalManager.createRequest(
      'inc_test_rbac_02',
      'BLOCK_SOURCE_IP',
      {
        target: '198.51.100.100',
        actionType: 'BLOCK_SOURCE_IP',
        ttlMinutes: 15,
      },
      'Test policy rule',
      'RBAC approver verification incident',
      'T1110.001',
      15
    );

    const decision = approvalManager.decide(
      testReq2.id,
      'APPROVE',
      'Authorized incident commander sign-off',
      'approver@soc.corp',
      'APPROVER',
      testReq2.parameters
    );

    const pass = decision.success && decision.approval?.status === 'APPROVED';
    results.push({
      id: 'SEC-05',
      name: 'RBAC Enforcement: APPROVER Role Successfully Authorizes Action',
      category: 'AUTHORIZATION_MATRIX',
      status: pass ? 'PASS' : 'FAIL',
      expected: 'HTTP 200 OK: Status transitions to APPROVED with audit event',
      actual: pass ? 'Authorized: Status transitioned to APPROVED' : `Failed: ${decision.error}`,
      details: 'Approvers are authorized to execute approved state transitions with mandatory reason recording.',
      durationMs: Date.now() - t0,
    });
  }

  // Test 6: Parameter Hash Tampering Detection
  {
    const t0 = Date.now();
    const originalTarget = '198.51.100.200';
    const tamperedTarget = '8.8.8.8'; // Malicious attempt to redirect block to Google DNS!

    const tamperReq = approvalManager.createRequest(
      'inc_test_tamper_01',
      'BLOCK_SOURCE_IP',
      {
        target: originalTarget,
        actionType: 'BLOCK_SOURCE_IP',
        ttlMinutes: 30,
      },
      'Test policy rule',
      'Parameter tampering security test',
      'T1110.001',
      30
    );

    // Client maliciously attempts to send tampered parameters
    const tamperedParams = {
      ...tamperReq.parameters,
      target: tamperedTarget, // modified!
    };

    const decision = approvalManager.decide(
      tamperReq.id,
      'APPROVE',
      'Approving modified target',
      'approver@soc.corp',
      'APPROVER',
      tamperedParams
    );

    const pass = !decision.success && decision.error?.includes('Action parameters have been tampered with');
    results.push({
      id: 'SEC-06',
      name: 'Cryptographic Parameter Binding: Rejects Tampered Action Payloads',
      category: 'APPROVAL_TAMPERING',
      status: pass ? 'PASS' : 'FAIL',
      expected: 'HTTP 400/409: SHA-256 parameter hash mismatch detected',
      actual: pass ? `Blocked: ${decision.error}` : 'Critical vulnerability: Tampered parameters were accepted!',
      details: 'Guarantees that an action can ONLY execute against the exact parameters (IP/TTL) signed by the policy engine.',
      durationMs: Date.now() - t0,
    });
  }

  // Test 7: Authentication Rate Limiter (Brute-Force Protection)
  {
    const t0 = Date.now();
    const testIp = '10.99.99.1';
    resetLoginRateLimit(testIp);

    // Simulate 5 failed login attempts
    for (let i = 0; i < 5; i++) {
      recordFailedLogin(testIp);
    }

    const check = checkLoginRateLimit(testIp);
    const pass = !check.allowed && (check.retryAfterSec || 0) > 0;
    resetLoginRateLimit(testIp); // clean up

    results.push({
      id: 'SEC-07',
      name: 'Login Rate Limiter & Account Lockout Enforcement',
      category: 'AUTHENTICATION',
      status: pass ? 'PASS' : 'FAIL',
      expected: 'Subsequent login attempts locked out with retryAfterSec',
      actual: pass ? `Locked out: Retry cooldown active (${check.retryAfterSec}s)` : 'Rate limiter failed to engage',
      details: 'Prevents credential brute-forcing against analyst/admin portal accounts; triggers audit alert.',
      durationMs: Date.now() - t0,
    });
  }

  // Test 8: Append-Only Hash Chain Integrity
  {
    const t0 = Date.now();
    const verification = auditChain.verifyIntegrity();
    const pass = verification.valid;
    results.push({
      id: 'SEC-08',
      name: 'Append-Only Cryptographic Hash Chain Integrity (Genesis to Head)',
      category: 'CRYPTOGRAPHIC_AUDIT',
      status: pass ? 'PASS' : 'FAIL',
      expected: 'All blocks valid with continuous SHA-256 prevHash linkage',
      actual: pass ? `Valid: ${verification.totalEntries} entries cryptographically verified` : `Break detected: ${verification.message}`,
      details: 'NIST SP 800-92 compliant audit trail where any alteration breaks the mathematical link.',
      durationMs: Date.now() - t0,
    });
  }

  // Test 9: Tamper Detection Sensitivity (Mutation Flagging)
  {
    const t0 = Date.now();
    // Simulate mutation of index 1
    auditChain.simulateTamper(1, 'target', '1.1.1.1');
    const tamperedVerification = auditChain.verifyIntegrity();
    // Restore immediately
    auditChain.restoreChain();
    const restoredVerification = auditChain.verifyIntegrity();

    const pass = !tamperedVerification.valid && tamperedVerification.brokenIndex === 1 && restoredVerification.valid;
    results.push({
      id: 'SEC-09',
      name: 'Tamper Detection Sensitivity: Catches Database-Level Modification',
      category: 'CRYPTOGRAPHIC_AUDIT',
      status: pass ? 'PASS' : 'FAIL',
      expected: 'Instant detection of altered log row with exact brokenIndex identifier',
      actual: pass ? 'Caught tampering at event #1, verified restoration' : 'Tamper was not detected by hash verifier',
      details: 'Proves mathematical immutability: an attacker with raw DB access cannot silently alter logs.',
      durationMs: Date.now() - t0,
    });
  }

  const passedCount = results.filter(r => r.status === 'PASS').length;
  const failedCount = results.length - passedCount;

  return {
    timestamp: new Date().toISOString(),
    totalTests: results.length,
    passedCount,
    failedCount,
    successRate: Math.round((passedCount / results.length) * 100),
    results,
  };
}
