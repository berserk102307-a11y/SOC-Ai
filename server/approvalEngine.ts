import crypto from 'node:crypto';
import { auditChain, canonicalJsonStringify } from './auditChain.ts';
import { timingSafeEqualString, type UserRole } from './security.ts';

export type ActionType = 'BLOCK_SOURCE_IP' | 'DISABLE_TEST_ACCOUNT' | 'ISOLATE_HOST';
export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';

export interface ActionParameters {
  target: string;
  actionType: ActionType;
  ttlMinutes: number;
  firewallTable?: string;
  scope?: string;
  reason?: string;
  [key: string]: unknown;
}

export interface ApprovalRequest {
  id: string;
  incidentId: string;
  actionType: ActionType;
  parameters: ActionParameters;
  parameterHash: string; // Cryptographic SHA-256 commitment of the exact parameters shown to the approver
  status: ApprovalStatus;
  requestedAt: string;
  expiresAt: string;
  decidedBy?: string;
  decidedRole?: UserRole;
  decidedAt?: string;
  decisionReason?: string;
  policyReason: string;
  incidentSummary: string;
  mitreTechnique: string;
}

export function computeParameterHash(params: ActionParameters): string {
  const canonical = canonicalJsonStringify(params);
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

class ApprovalManager {
  private approvals: Map<string, ApprovalRequest> = new Map();

  constructor() {
    this.seedApprovals();
  }

  private seedApprovals() {
    // 1. Pending Approval for an external attack IP
    const params1: ActionParameters = {
      target: '198.51.100.42',
      actionType: 'BLOCK_SOURCE_IP',
      ttlMinutes: 30,
      firewallTable: 'WIN_ADV_FIREWALL_INBOUND',
      scope: 'Host-Only Lab VM',
      reason: 'Sustained Windows Event 4625 brute-force attack detected on port 3389 (RDP)',
    };
    const hash1 = computeParameterHash(params1);

    const now = Date.now();
    this.approvals.set('appr_2026_001', {
      id: 'appr_2026_001',
      incidentId: 'inc_win_2026_001',
      actionType: 'BLOCK_SOURCE_IP',
      parameters: params1,
      parameterHash: hash1,
      status: 'PENDING',
      requestedAt: new Date(now - 10 * 60 * 1000).toISOString(),
      expiresAt: new Date(now + 20 * 60 * 1000).toISOString(), // 20 mins remaining
      policyReason: 'Disruptive network action requires verified human approval before firewall execution',
      incidentSummary: 'Single-source RDP brute-force (18 failed logon attempts within 2 minutes) on Administrator account.',
      mitreTechnique: 'T1110.001 (Password Guessing)',
    });

    // 2. Already Approved historical request
    const params2: ActionParameters = {
      target: '203.0.113.88',
      actionType: 'BLOCK_SOURCE_IP',
      ttlMinutes: 60,
      firewallTable: 'WIN_ADV_FIREWALL_INBOUND',
      scope: 'Host-Only Lab VM',
      reason: 'Distributed password spray targeting 14 Active Directory user accounts',
    };
    const hash2 = computeParameterHash(params2);

    this.approvals.set('appr_2026_002', {
      id: 'appr_2026_002',
      incidentId: 'inc_win_2026_002',
      actionType: 'BLOCK_SOURCE_IP',
      parameters: params2,
      parameterHash: hash2,
      status: 'APPROVED',
      requestedAt: '2026-10-28T12:00:00.000Z',
      expiresAt: '2026-10-28T12:30:00.000Z',
      decidedBy: 'approver@soc.corp',
      decidedRole: 'APPROVER',
      decidedAt: '2026-10-28T12:06:14.000Z',
      decisionReason: 'Verified malicious external IP; temporary 60-minute firewall block authorized.',
      policyReason: 'Verified multi-account spray threshold exceeded',
      incidentSummary: 'Password spraying against svc_backup, sql_admin, and 12 standard users.',
      mitreTechnique: 'T1110.003 (Password Spraying)',
    });

    // 3. Pending Approval for compromised test account disable
    const params3: ActionParameters = {
      target: 'test_contractor_jdoe',
      actionType: 'DISABLE_TEST_ACCOUNT',
      ttlMinutes: 120,
      scope: 'Active Directory Lab Domain',
      reason: 'LogonType 3 network failed logons followed by suspicious successful logon at 03:00 AM',
    };
    const hash3 = computeParameterHash(params3);

    this.approvals.set('appr_2026_003', {
      id: 'appr_2026_003',
      incidentId: 'inc_win_2026_003',
      actionType: 'DISABLE_TEST_ACCOUNT',
      parameters: params3,
      parameterHash: hash3,
      status: 'PENDING',
      requestedAt: new Date(now - 5 * 60 * 1000).toISOString(),
      expiresAt: new Date(now + 25 * 60 * 1000).toISOString(),
      policyReason: 'Account disablement requires SOC Approver sign-off to prevent unauthorized denial-of-service',
      incidentSummary: 'Success-after-failures anomaly detected on contractor test account.',
      mitreTechnique: 'T1078.002 (Domain Accounts)',
    });
  }

  public getAll(): ApprovalRequest[] {
    const now = Date.now();
    // Auto-update any expired approvals
    for (const req of this.approvals.values()) {
      if (req.status === 'PENDING' && new Date(req.expiresAt).getTime() < now) {
        req.status = 'EXPIRED';
        auditChain.append('SYSTEM', 'APPROVAL_ENGINE', 'APPROVAL_REQUEST_EXPIRED', {
          approvalId: req.id,
          incidentId: req.incidentId,
          parameterHash: req.parameterHash,
        });
      }
    }
    return Array.from(this.approvals.values()).sort(
      (a, b) => new Date(b.requestedAt).getTime() - new Date(a.requestedAt).getTime()
    );
  }

  public getById(id: string): ApprovalRequest | undefined {
    return this.approvals.get(id);
  }

  public createRequest(
    incidentId: string,
    actionType: ActionType,
    params: ActionParameters,
    policyReason: string,
    incidentSummary: string,
    mitreTechnique: string,
    ttlMinutes = 30
  ): ApprovalRequest {
    const id = `appr_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
    const parameterHash = computeParameterHash(params);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlMinutes * 60 * 1000);

    const req: ApprovalRequest = {
      id,
      incidentId,
      actionType,
      parameters: params,
      parameterHash,
      status: 'PENDING',
      requestedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      policyReason,
      incidentSummary,
      mitreTechnique,
    };

    this.approvals.set(id, req);

    auditChain.append('SYSTEM', 'APPROVAL_ENGINE', 'APPROVAL_REQUEST_CREATED', {
      approvalId: id,
      incidentId,
      actionType,
      target: params.target,
      ttlMinutes,
      parameterHash,
    });

    return req;
  }

  public decide(
    approvalId: string,
    decision: 'APPROVE' | 'REJECT',
    reason: string,
    decidedByEmail: string,
    userRole: UserRole,
    clientParameters: ActionParameters
  ): { success: boolean; error?: string; approval?: ApprovalRequest } {
    const req = this.approvals.get(approvalId);
    if (!req) {
      return { success: false, error: 'Approval request not found.' };
    }

    // Role check: Only APPROVER or ADMIN can approve/reject
    if (userRole !== 'APPROVER' && userRole !== 'ADMIN') {
      auditChain.append('USER', decidedByEmail, 'SECURITY_VIOLATION_UNAUTHORIZED_APPROVAL_ATTEMPT', {
        approvalId,
        userRole,
        actionType: req.actionType,
        target: req.parameters.target,
        blocked: true,
        reason: `Role '${userRole}' does not possess APPROVER authorization`,
      });
      return {
        success: false,
        error: `Permission denied: Role '${userRole}' cannot authorize or reject remediation actions. APPROVER or ADMIN role required.`,
      };
    }

    // Status check
    if (req.status !== 'PENDING') {
      return { success: false, error: `Cannot decide approval request with status: ${req.status}` };
    }

    // Expiry check
    if (new Date(req.expiresAt).getTime() < Date.now()) {
      req.status = 'EXPIRED';
      return { success: false, error: 'Approval request has expired and can no longer be processed.' };
    }

    // Cryptographic Parameter Hash Verification:
    // Protects against parameter tampering between when the policy engine drafted the action and when the human clicked approve
    const submittedHash = computeParameterHash(clientParameters);
    const hashMatches = timingSafeEqualString(submittedHash, req.parameterHash);

    if (!hashMatches) {
      auditChain.append('USER', decidedByEmail, 'SECURITY_VIOLATION_PARAMETER_TAMPERING_DETECTED', {
        approvalId,
        storedParameterHash: req.parameterHash,
        submittedParameterHash: submittedHash,
        target: clientParameters.target,
        storedTarget: req.parameters.target,
        blocked: true,
        message: 'Parameters submitted with approval decision do not match the cryptographically signed request!',
      });
      return {
        success: false,
        error: 'Cryptographic verification failed: Action parameters have been tampered with or do not match the original proposal.',
      };
    }

    // Record decision
    req.status = decision === 'APPROVE' ? 'APPROVED' : 'REJECTED';
    req.decidedBy = decidedByEmail;
    req.decidedRole = userRole;
    req.decidedAt = new Date().toISOString();
    req.decisionReason = reason;

    auditChain.append('USER', decidedByEmail, decision === 'APPROVE' ? 'ACTION_APPROVED' : 'ACTION_REJECTED', {
      approvalId,
      incidentId: req.incidentId,
      actionType: req.actionType,
      target: req.parameters.target,
      parameterHash: req.parameterHash,
      approverRole: userRole,
      reason,
      status: req.status,
    });

    return { success: true, approval: req };
  }
}

export const approvalManager = new ApprovalManager();
