export type UserRole = 'ANALYST' | 'APPROVER' | 'ADMIN';

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  department: string;
}

export interface UserPermissions {
  canViewDashboard: boolean;
  canViewAuditLog: boolean;
  canSubmitFeedback: boolean;
  canApproveRemediation: boolean;
  canManageApiKeys: boolean;
  canManageSystemConfig: boolean;
}

export type AuditActor = 'SYSTEM' | 'MODEL' | 'USER' | 'MONITOR';

export interface AuditEvent {
  index: number;
  id: string;
  timestamp: string;
  actor: AuditActor;
  actorId: string;
  eventType: string;
  payload: Record<string, any>;
  prevHash: string;
  hash: string;
}

export interface ChainVerificationResult {
  valid: boolean;
  totalEntries: number;
  lastVerifiedAt: string;
  brokenIndex?: number;
  expectedHash?: string;
  actualHash?: string;
  message: string;
}

export interface StoredApiKeyItem {
  id: string;
  name: string;
  host: string;
  keyPrefix: string;
  keyHashPreview: string;
  createdAt: string;
  lastUsedAt: string | null;
  revoked: boolean;
  revokedAt: string | null;
}

export interface EvidenceItem {
  id: number;
  claim: string;
  rawEvidence: string;
}

export interface ComputedEvidencePack {
  incidentId: string;
  totalAlerts: number;
  timeSpanSeconds: number;
  firstSeen: string;
  lastSeen: string;
  distinctSourceIps: string[];
  distinctAccounts: string[];
  logonTypes: number[];
  logonTypeNames: string[];
  failureReasons: string[];
  hasSubsequentSuccess: boolean;
  ruleFired: string;
  targetHost: string;
  evidenceItems: EvidenceItem[];
}

export interface GroundingCheckItem {
  name: string;
  passed: boolean;
  detail: string;
}

export interface ValidationReport {
  schemaValid: boolean;
  grounded: boolean;
  consistencyValid: boolean;
  finalStatus: 'VERIFIED' | 'NEEDS_REVIEW' | 'FALLBACK';
  checks: GroundingCheckItem[];
  warnings: string[];
  confidenceClamped: boolean;
}

export interface InvestigationResult {
  version: string;
  source: 'LLM' | 'FALLBACK' | 'MOCK';
  model: string;
  status: 'COMPLETED' | 'FALLBACK' | 'NEEDS_REVIEW';
  classification:
    | 'brute_force'
    | 'password_spraying'
    | 'compromise_suspected'
    | 'benign_user_error'
    | 'misconfiguration'
    | 'insufficient_evidence';
  summary: string;
  findings: string[];
  hypotheses: string[];
  recommendedAction: 'none' | 'monitor' | 'notify' | 'block_source_ip' | 'disable_account';
  confidence: number;
  uncertainties: string[];
  latencyMs: number;
  validationReport: ValidationReport;
}

export interface IncidentFixture {
  id: string;
  title: string;
  rule: string;
  mitreTechnique: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'PENDING_APPROVAL' | 'RESOLVED';
  firstSeen: string;
  lastSeen: string;
  evidencePack: ComputedEvidencePack;
  investigation: InvestigationResult;
}

export type ActionType = 'BLOCK_SOURCE_IP' | 'DISABLE_TEST_ACCOUNT' | 'ISOLATE_HOST';
export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';

export interface ActionParameters {
  target: string;
  actionType: ActionType;
  ttlMinutes: number;
  firewallTable?: string;
  scope?: string;
  reason?: string;
  [key: string]: any;
}

export interface ApprovalRequest {
  id: string;
  incidentId: string;
  actionType: ActionType;
  parameters: ActionParameters;
  parameterHash: string;
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

export type RiskTier = 'LOOK' | 'ENRICH' | 'UNDOABLE' | 'DISRUPTIVE' | 'DESTRUCTIVE';

export interface ActionDefinition {
  name: string;
  level: number;
  tier: RiskTier;
  description: string;
  defaultAutonomous: boolean;
}

export interface DeterministicPolicy {
  id: string;
  action: string;
  name: string;
  enforce: 'REQUIRE_APPROVAL' | 'BLOCK';
}

export interface SafetyEvaluation {
  action: string;
  level: number;
  tier: RiskTier;
  decision: 'AUTO_ALLOWED' | 'REQUIRE_APPROVAL' | 'BLOCKED';
  policyRuleTriggered: string | null;
  reason: string;
  requiresHumanSignoff: boolean;
  canExecuteAutonomously: boolean;
  timestamp: string;
}

export interface WazuhAlert {
  id: string;
  timestamp: string;
  rule: {
    id: number;
    level: number;
    description: string;
    mitre?: {
      id: string[];
      tactic: string[];
      technique: string[];
    };
  };
  agent: {
    id: string;
    name: string;
    ip?: string;
  };
  data?: {
    srcip?: string;
    dstip?: string;
    srcuser?: string;
    dstuser?: string;
    command?: string;
    process?: string;
    pid?: number;
  };
  full_log: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  scenarioTag?: 'SSH_BRUTE_FORCE' | 'POWERSHELL_EXEC' | 'PRIVILEGE_ESCALATION';
}

export interface WazuhStats {
  totalAlerts: number;
  severityCounts: { LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number };
  topRules: { ruleId: number; description: string; count: number }[];
}

export interface ScenarioDefinition {
  id: 'SSH_BRUTE_FORCE' | 'POWERSHELL_EXEC' | 'PRIVILEGE_ESCALATION';
  title: string;
  mitreTechnique: string;
  mitreTactic: string;
  wazuhRuleId: number;
  wazuhLevel: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  targetAgent: string;
  sourceIp: string;
  description: string;
  recommendedActions: string[];
  expectedSafetyGate: 'AUTO_ALLOWED' | 'REQUIRE_APPROVAL' | 'BLOCKED';
  policyRulesTriggered: string[];
}

export interface DashboardOverviewData {
  timestamp: string;
  wazuhStats: WazuhStats;
  auditLedger: {
    totalBlocks: number;
    valid: boolean;
    isTampered: boolean;
    lastHash: string;
  };
  approvals: {
    pendingCount: number;
    totalCount: number;
    pending: ApprovalRequest[];
  };
  incidents: {
    totalCount: number;
    fixtures: {
      id: string;
      title: string;
      severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      alertsCount: number;
    }[];
  };
  recentAlerts: WazuhAlert[];
  recentAuditEvents: AuditEvent[];
}

export interface BackendCallRecord {
  id: string;
  timestamp: string;
  method: string;
  path: string;
  statusCode: number;
  durationMs: number;
  clientIp: string;
  userEmail?: string;
  hasError: boolean;
  errorMessage?: string;
  requestSnippet?: string;
  aiAnalysis?: {
    analyzedAt: string;
    model: string;
    source: 'OLLAMA' | 'GEMINI' | 'DETERMINISTIC_RULES';
    verdict: 'BENIGN' | 'SUSPICIOUS' | 'ATTACK_PROBE' | 'SYSTEM_BUG' | 'POLICY_VIOLATION';
    confidence: number;
    explanation: string;
    mitigation: string;
    mitreTactic?: string;
    autonomousDecision: string;
  };
}

export interface BackendCallStats {
  totalCallsTracked: number;
  totalErrors: number;
  analyzedByAi: number;
  errorRatePercent: number;
}

export interface OllamaStatusResult {
  connected: boolean;
  host: string;
  activeModel: string;
  availableModels: string[];
  latencyMs: number;
  engineMode: 'OLLAMA_LIVE' | 'FALLBACK_STANDBY';
  message: string;
  callStats?: BackendCallStats;
}

export interface AiLogAnalysisResult {
  analysisId: string;
  analyzedAt: string;
  engineSource: 'OLLAMA' | 'GEMINI' | 'DETERMINISTIC';
  modelUsed: string;
  targetType: 'SIEM_LOG' | 'BACKEND_CALL_ERROR' | 'AUDIT_RECORD' | 'GENERIC_LOG';
  targetSummary: string;
  classification:
    | 'BRUTE_FORCE_PROBE'
    | 'AUTHENTICATION_LOCKOUT'
    | 'UNAUTHORIZED_ACCESS'
    | 'SUSPICIOUS_LATERAL_MOVE'
    | 'SYSTEM_API_EXCEPTION'
    | 'PARAMETER_TAMPERING'
    | 'POLICY_VIOLATION'
    | 'BENIGN_TELEMETRY';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  rootCause: string;
  threatDescription: string;
  mitreTechnique: string;
  autonomousDecision:
    | 'ALLOW_PASS'
    | 'QUARANTINE_SOURCE_IP'
    | 'ENFORCE_LOCKOUT_POLICY'
    | 'REQUIRE_HUMAN_APPROVAL'
    | 'BLOCK_IMMEDIATELY'
    | 'DISMISS_BENIGN';
  safetyTier: 'L0_OBSERVE' | 'L1_ENRICH' | 'L2_RATE_LIMIT' | 'L3_QUARANTINE' | 'L4_ISOLATE' | 'L5_TERMINATE' | 'L6_CONTAIN' | 'L7_LOCKDOWN';
  recommendedRemediation: string;
  remediationCommands: string[];
}

