import type {
  UserProfile,
  UserPermissions,
  AuditEvent,
  ChainVerificationResult,
  StoredApiKeyItem,
  IncidentFixture,
  ApprovalRequest,
  SecuritySuiteReport,
  ActionParameters,
  InvestigationResult,
} from '../types/index.ts';

const SESSION_KEY = 'ai_soc_session_token';

export function getStoredToken(): string | null {
  return localStorage.getItem(SESSION_KEY);
}

export function setStoredToken(token: string) {
  localStorage.setItem(SESSION_KEY, token);
}

export function clearStoredToken() {
  localStorage.removeItem(SESSION_KEY);
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers = new Headers(options.headers || {});

  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(endpoint, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const errorMsg = data.error || `HTTP error ${response.status}: ${response.statusText}`;
    const error: any = new Error(errorMsg);
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data as T;
}

export const api = {
  // Authentication & Sessions
  async login(
    email: string,
    password: string,
    resetLockout?: boolean
  ): Promise<{ token: string; user: UserProfile; permissions: UserPermissions }> {
    const res = await request<{ token: string; user: UserProfile; permissions: UserPermissions }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, resetLockout }),
    });
    setStoredToken(res.token);
    return res;
  },

  async quickLogin(
    role: 'ANALYST' | 'APPROVER' | 'ADMIN'
  ): Promise<{ token: string; user: UserProfile; permissions: UserPermissions }> {
    const res = await request<{ token: string; user: UserProfile; permissions: UserPermissions }>('/api/auth/quick-login', {
      method: 'POST',
      body: JSON.stringify({ role }),
    });
    setStoredToken(res.token);
    return res;
  },

  async resetRateLimit(email?: string): Promise<{ success: boolean; message: string }> {
    return request('/api/auth/reset-ratelimit', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  async logout(): Promise<void> {
    try {
      await request('/api/auth/logout', { method: 'POST' });
    } finally {
      clearStoredToken();
    }
  },

  async getMe(): Promise<{ authenticated: boolean; user?: UserProfile; permissions?: UserPermissions }> {
    return request('/api/auth/me');
  },

  async switchRole(role: 'ANALYST' | 'APPROVER' | 'ADMIN'): Promise<{ token: string; user: UserProfile; permissions: UserPermissions }> {
    const res = await request<{ token: string; user: UserProfile; permissions: UserPermissions }>('/api/auth/switch-role', {
      method: 'POST',
      body: JSON.stringify({ role }),
    });
    setStoredToken(res.token);
    return res;
  },

  // Audit Log & Cryptographic Verification
  async getAuditLog(params?: { actor?: string; eventType?: string; search?: string }): Promise<{
    totalCount: number;
    isTampered: boolean;
    integrity: ChainVerificationResult;
    events: AuditEvent[];
  }> {
    const query = new URLSearchParams();
    if (params?.actor) query.set('actor', params.actor);
    if (params?.eventType) query.set('eventType', params.eventType);
    if (params?.search) query.set('search', params.search);
    return request(`/api/audit-log?${query.toString()}`);
  },

  async verifyAuditChain(): Promise<ChainVerificationResult> {
    return request('/api/audit-log/verify');
  },

  async simulateTamper(index: number, field: string, value: any): Promise<{
    success: boolean;
    message: string;
    tamperReport: ChainVerificationResult;
  }> {
    return request('/api/audit-log/tamper', {
      method: 'POST',
      body: JSON.stringify({ index, field, value }),
    });
  },

  async restoreAuditChain(): Promise<{
    success: boolean;
    message: string;
    verification: ChainVerificationResult;
  }> {
    return request('/api/audit-log/restore', { method: 'POST' });
  },

  // Monitor Sensor API Keys
  async getApiKeys(): Promise<{ keys: StoredApiKeyItem[]; seedRawKey: string }> {
    return request('/api/api-keys');
  },

  async createApiKey(name: string, host: string): Promise<{
    message: string;
    rawKey: string;
    keyRecord: StoredApiKeyItem;
  }> {
    return request('/api/api-keys', {
      method: 'POST',
      body: JSON.stringify({ name, host }),
    });
  },

  async revokeApiKey(id: string): Promise<{ success: boolean; message: string }> {
    return request(`/api/api-keys/${id}`, { method: 'DELETE' });
  },

  // Incident Fixtures & Investigation Service
  async getIncidents(): Promise<{ incidents: IncidentFixture[] }> {
    return request('/api/incidents');
  },

  async getIncidentDetails(id: string): Promise<{ incident: IncidentFixture; history: InvestigationResult[] }> {
    return request(`/api/incidents/${id}`);
  },

  async triggerInvestigation(
    id: string,
    mode: 'VALIDATED_LLM' | 'FALLBACK' | 'MOCK'
  ): Promise<{ success: boolean; result: InvestigationResult }> {
    return request(`/api/incidents/${id}/investigate`, {
      method: 'POST',
      body: JSON.stringify({ mode }),
    });
  },

  // Approvals & Remediation Authorizations
  async getApprovals(): Promise<{ approvals: ApprovalRequest[] }> {
    return request('/api/approvals');
  },

  async decideApproval(
    id: string,
    decision: 'APPROVE' | 'REJECT',
    reason: string,
    clientParameters?: ActionParameters
  ): Promise<{ success: boolean; approval: ApprovalRequest; message: string }> {
    return request(`/api/approvals/${id}/decide`, {
      method: 'POST',
      body: JSON.stringify({ decision, reason, clientParameters }),
    });
  },

  // Security Test Suite Runner
  async getSecurityTestMatrix(): Promise<SecuritySuiteReport> {
    return request('/api/security/test-matrix');
  },

  // SOC Command Dashboard
  async getDashboardOverview(): Promise<import('../types/index.ts').DashboardOverviewData> {
    return request('/api/dashboard/overview');
  },

  // Wazuh SIEM Ingestion & Alerts
  async getWazuhAlerts(params?: {
    limit?: number;
    severity?: string;
    search?: string;
  }): Promise<{ alerts: import('../types/index.ts').WazuhAlert[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.severity) query.set('severity', params.severity);
    if (params?.search) query.set('search', params.search);
    return request(`/api/wazuh/alerts?${query.toString()}`);
  },

  async getWazuhStats(): Promise<import('../types/index.ts').WazuhStats> {
    return request('/api/wazuh/stats');
  },

  async ingestWazuhAlert(rawAlert: any): Promise<{ success: boolean; alert: import('../types/index.ts').WazuhAlert }> {
    return request('/api/wazuh/ingest', {
      method: 'POST',
      body: JSON.stringify(rawAlert),
    });
  },

  // Deterministic Policy & L0-L7 Safety Gate
  async getPolicyConfig(): Promise<{
    ladder: Record<string, import('../types/index.ts').ActionDefinition>;
    policies: import('../types/index.ts').DeterministicPolicy[];
    thresholds: {
      autoExecuteMax: number;
      approvalRequiredMin: number;
      neverAutonomous: number;
    };
  }> {
    return request('/api/policy/config');
  },

  async evaluatePolicy(payload: {
    actionName: string;
    parameters?: Record<string, any>;
    forensicsComplete?: boolean;
    incidentSeverity?: string;
  }): Promise<import('../types/index.ts').SafetyEvaluation> {
    return request('/api/policy/evaluate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async executeSimulatedAction(payload: {
    actionName: string;
    parameters?: Record<string, any>;
    forensicsComplete?: boolean;
  }): Promise<{
    success: boolean;
    evaluation: import('../types/index.ts').SafetyEvaluation;
    execution: {
      success: boolean;
      executedAt: string;
      output: string;
      action: string;
    };
  }> {
    return request('/api/policy/execute-simulated', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Attack Scenario Replay
  async getScenarios(): Promise<{ scenarios: import('../types/index.ts').ScenarioDefinition[] }> {
    return request('/api/scenarios');
  },

  async replayScenario(
    scenarioId: string,
    autoQueueApproval = true
  ): Promise<{
    success: boolean;
    scenario: { id: string; title: string; severity: string };
    alertsGenerated: number;
    alerts: import('../types/index.ts').WazuhAlert[];
    actionEvaluations: Array<{
      actionName: string;
      evaluation: import('../types/index.ts').SafetyEvaluation;
      createdApprovalId: string | null;
    }>;
  }> {
    return request('/api/scenarios/replay', {
      method: 'POST',
      body: JSON.stringify({ scenarioId, autoQueueApproval }),
    });
  },

  // Ollama Free Model AI Diagnostics & Backend Calls
  async getOllamaStatus(): Promise<import('../types/index.ts').OllamaStatusResult> {
    return request('/api/ai/ollama/status');
  },

  async configureOllama(
    host?: string,
    model?: string
  ): Promise<import('../types/index.ts').OllamaStatusResult & { success: boolean; message: string }> {
    return request('/api/ai/ollama/configure', {
      method: 'POST',
      body: JSON.stringify({ host, model }),
    });
  },

  async analyzeLogWithOllama(payload: {
    logText?: string;
    wazuhAlert?: any;
    auditEvent?: any;
    context?: string;
  }): Promise<{ success: boolean; analysis: import('../types/index.ts').AiLogAnalysisResult }> {
    return request('/api/ai/ollama/analyze-log', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async analyzeBackendCallWithOllama(
    callId: string
  ): Promise<{ success: boolean; analysis: import('../types/index.ts').AiLogAnalysisResult }> {
    return request('/api/ai/ollama/analyze-call', {
      method: 'POST',
      body: JSON.stringify({ callId }),
    });
  },

  async getBackendCalls(params?: {
    limit?: number;
    errorsOnly?: boolean;
  }): Promise<{
    calls: import('../types/index.ts').BackendCallRecord[];
    stats: import('../types/index.ts').BackendCallStats;
  }> {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.errorsOnly) query.set('errorsOnly', 'true');
    return request(`/api/ai/ollama/backend-calls?${query.toString()}`);
  },

  async simulateBackendCall(
    scenario: 'BRUTE_FORCE' | 'RATE_LIMIT' | 'SERVER_500' | 'TAMPER_INJECTION'
  ): Promise<{
    success: boolean;
    callRecord: import('../types/index.ts').BackendCallRecord;
    analysis: import('../types/index.ts').AiLogAnalysisResult;
  }> {
    return request('/api/ai/ollama/simulate-call', {
      method: 'POST',
      body: JSON.stringify({ scenario }),
    });
  },

  async clearBackendCalls(): Promise<{ success: boolean; message: string }> {
    return request('/api/ai/ollama/clear-calls', {
      method: 'POST',
    });
  },
};

