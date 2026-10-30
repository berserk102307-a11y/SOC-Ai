import crypto from 'node:crypto';

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

class BackendCallTracker {
  private calls: BackendCallRecord[] = [];
  private readonly maxEntries = 120;

  constructor() {
    // Seed initial historical backend calls for immediate visibility
    this.seedInitialCalls();
  }

  private seedInitialCalls() {
    const now = Date.now();
    const seedEvents: Omit<BackendCallRecord, 'id'>[] = [
      {
        timestamp: new Date(now - 1000 * 60 * 12).toISOString(),
        method: 'POST',
        path: '/api/auth/login',
        statusCode: 401,
        durationMs: 84,
        clientIp: '198.51.100.22',
        userEmail: 'admin@soc.corp',
        hasError: true,
        errorMessage: 'Invalid credentials. PBKDF2 hash mismatch.',
        requestSnippet: '{"email":"admin@soc.corp","password":"[REDACTED]"}',
        aiAnalysis: {
          analyzedAt: new Date(now - 1000 * 60 * 11).toISOString(),
          model: 'llama3:latest',
          source: 'OLLAMA',
          verdict: 'ATTACK_PROBE',
          confidence: 0.92,
          explanation: 'External untrusted IP 198.51.100.22 attempted brute-force password guess against admin@soc.corp.',
          mitigation: 'Enforce rate-limiting bucket; isolate IP if threshold > 5 within 60s.',
          mitreTactic: 'T1110.001 - Brute Force: Password Guessing',
          autonomousDecision: 'TRACK_RATE_LIMIT',
        },
      },
      {
        timestamp: new Date(now - 1000 * 60 * 8).toISOString(),
        method: 'POST',
        path: '/api/auth/login',
        statusCode: 429,
        durationMs: 12,
        clientIp: '198.51.100.22',
        userEmail: 'admin@soc.corp',
        hasError: true,
        errorMessage: 'Account temporarily locked due to repeated authentication failures.',
        requestSnippet: '{"email":"admin@soc.corp"}',
        aiAnalysis: {
          analyzedAt: new Date(now - 1000 * 60 * 7).toISOString(),
          model: 'llama3:latest',
          source: 'OLLAMA',
          verdict: 'POLICY_VIOLATION',
          confidence: 0.98,
          explanation: 'Consecutive credential failures triggered automated 300s security lockout.',
          mitigation: 'Execute Policy P001: Temporary IP block and notify SOC on-call officer.',
          mitreTactic: 'T1110 - Brute Force Attack Blocked',
          autonomousDecision: 'ENFORCE_LOCKOUT_POLICY_P001',
        },
      },
      {
        timestamp: new Date(now - 1000 * 60 * 5).toISOString(),
        method: 'GET',
        path: '/api/wazuh/alerts',
        statusCode: 200,
        durationMs: 24,
        clientIp: '10.0.4.15',
        userEmail: 'analyst@soc.corp',
        hasError: false,
        requestSnippet: '{}',
      },
      {
        timestamp: new Date(now - 1000 * 60 * 2).toISOString(),
        method: 'POST',
        path: '/api/safety/execute-action',
        statusCode: 200,
        durationMs: 46,
        clientIp: '10.0.4.15',
        userEmail: 'approver@soc.corp',
        hasError: false,
        requestSnippet: '{"actionType":"BLOCK_SOURCE_IP","target":"203.0.113.88"}',
      },
    ];

    for (const item of seedEvents) {
      this.calls.push({
        id: `call_${crypto.randomBytes(8).toString('hex')}`,
        ...item,
      });
    }
  }

  public recordCall(record: Omit<BackendCallRecord, 'id'>): BackendCallRecord {
    const fullRecord: BackendCallRecord = {
      id: `call_${crypto.randomBytes(8).toString('hex')}`,
      ...record,
    };
    this.calls.unshift(fullRecord);
    if (this.calls.length > this.maxEntries) {
      this.calls.length = this.maxEntries;
    }
    return fullRecord;
  }

  public getRecentCalls(limit = 50, filterErrorsOnly = false): BackendCallRecord[] {
    if (filterErrorsOnly) {
      return this.calls.filter((c) => c.hasError).slice(0, limit);
    }
    return this.calls.slice(0, limit);
  }

  public getCallById(id: string): BackendCallRecord | undefined {
    return this.calls.find((c) => c.id === id);
  }

  public updateAnalysis(id: string, analysis: BackendCallRecord['aiAnalysis']): boolean {
    const call = this.getCallById(id);
    if (!call) return false;
    call.aiAnalysis = analysis;
    return true;
  }

  public getStats() {
    const total = this.calls.length;
    const errors = this.calls.filter((c) => c.hasError).length;
    const analyzed = this.calls.filter((c) => !!c.aiAnalysis).length;
    const errorRate = total > 0 ? Math.round((errors / total) * 100) : 0;
    return {
      totalCallsTracked: total,
      totalErrors: errors,
      analyzedByAi: analyzed,
      errorRatePercent: errorRate,
    };
  }

  public clear() {
    this.calls = [];
  }
}

export const backendCallTracker = new BackendCallTracker();
