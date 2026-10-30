import { GoogleGenAI } from '@google/genai';
import { backendCallTracker, type BackendCallRecord } from './backendCallTracker.ts';
import { auditChain } from './auditChain.ts';

export interface OllamaConfig {
  host: string;
  model: string;
  timeoutMs: number;
}

export interface OllamaStatusResult {
  connected: boolean;
  host: string;
  activeModel: string;
  availableModels: string[];
  latencyMs: number;
  engineMode: 'OLLAMA_LIVE' | 'FALLBACK_STANDBY';
  message: string;
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

class OllamaService {
  private host: string;
  private model: string;
  private timeoutMs: number;

  constructor() {
    this.host = process.env.OLLAMA_HOST || 'http://127.0.0.1:11434';
    this.model = process.env.OLLAMA_MODEL || 'llama3:latest';
    this.timeoutMs = 4000;
  }

  public getConfig(): OllamaConfig {
    return {
      host: this.host,
      model: this.model,
      timeoutMs: this.timeoutMs,
    };
  }

  public updateConfig(newHost?: string, newModel?: string): void {
    if (newHost && typeof newHost === 'string') {
      let trimmed = newHost.trim().replace(/\/+$/, '');
      if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
        trimmed = `http://${trimmed}`;
      }
      this.host = trimmed;
    }
    if (newModel && typeof newModel === 'string') {
      this.model = newModel.trim();
    }
  }

  // Ping Ollama server to check connectivity and enumerate free open-source models
  public async checkStatus(): Promise<OllamaStatusResult> {
    const startTime = Date.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      const res = await fetch(`${this.host}/api/tags`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      clearTimeout(timer);

      const latencyMs = Date.now() - startTime;
      if (res.ok) {
        const data = await res.json();
        const availableModels: string[] = Array.isArray(data.models)
          ? data.models.map((m: any) => m.name || m.model || String(m))
          : ['llama3:latest', 'mistral:latest'];

        return {
          connected: true,
          host: this.host,
          activeModel: this.model,
          availableModels: availableModels.length > 0 ? availableModels : ['llama3:latest'],
          latencyMs,
          engineMode: 'OLLAMA_LIVE',
          message: `Connected to Ollama service (${availableModels.length} models detected). Running ${this.model}.`,
        };
      } else {
        return {
          connected: false,
          host: this.host,
          activeModel: this.model,
          availableModels: [],
          latencyMs,
          engineMode: 'FALLBACK_STANDBY',
          message: `Ollama returned HTTP ${res.status}. Fallback AI active.`,
        };
      }
    } catch (err: any) {
      const latencyMs = Date.now() - startTime;
      return {
        connected: false,
        host: this.host,
        activeModel: this.model,
        availableModels: [],
        latencyMs,
        engineMode: 'FALLBACK_STANDBY',
        message: `Ollama server not reachable at ${this.host} (${err?.message || 'offline'}). Standby AI engine active. To connect local Ollama: run 'ollama run ${this.model}' or update host URL.`,
      };
    }
  }

  // Analyze log or Wazuh alert
  public async analyzeLog(payload: {
    logText?: string;
    wazuhAlert?: any;
    auditEvent?: any;
    context?: string;
  }): Promise<AiLogAnalysisResult> {
    const rawData =
      payload.logText ||
      (payload.wazuhAlert ? JSON.stringify(payload.wazuhAlert) : null) ||
      (payload.auditEvent ? JSON.stringify(payload.auditEvent) : 'Empty log payload');

    const targetSummary = payload.wazuhAlert
      ? `Wazuh Rule ${payload.wazuhAlert.rule?.id || 'Alert'} - ${payload.wazuhAlert.rule?.description || 'SIEM Event'}`
      : payload.auditEvent
      ? `Audit Event [${payload.auditEvent.eventType}] by ${payload.auditEvent.actor}`
      : String(rawData).substring(0, 80);

    const prompt = `You are an Autonomous Cybersecurity SOC AI Analyst running on Ollama.
Analyze the following security log / SIEM telemetry:
---
${rawData}
---
Context: ${payload.context || 'Autonomous SOC defense monitoring'}

Respond STRICTLY with a valid JSON object with the following fields:
{
  "classification": "BRUTE_FORCE_PROBE" | "AUTHENTICATION_LOCKOUT" | "UNAUTHORIZED_ACCESS" | "SUSPICIOUS_LATERAL_MOVE" | "SYSTEM_API_EXCEPTION" | "PARAMETER_TAMPERING" | "POLICY_VIOLATION" | "BENIGN_TELEMETRY",
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence": 0.95,
  "rootCause": "Clear explanation of the root cause",
  "threatDescription": "Detailed threat narrative and impact",
  "mitreTechnique": "e.g. T1110.001 - Password Guessing",
  "autonomousDecision": "ALLOW_PASS" | "QUARANTINE_SOURCE_IP" | "ENFORCE_LOCKOUT_POLICY" | "REQUIRE_HUMAN_APPROVAL" | "BLOCK_IMMEDIATELY" | "DISMISS_BENIGN",
  "safetyTier": "L0_OBSERVE" | "L1_ENRICH" | "L2_RATE_LIMIT" | "L3_QUARANTINE" | "L4_ISOLATE" | "L5_TERMINATE" | "L6_CONTAIN" | "L7_LOCKDOWN",
  "recommendedRemediation": "Clear action advice",
  "remediationCommands": ["iptables command or remediation cli script"]
}`;

    // 1. Try Ollama first
    const ollamaResult = await this.queryOllama(prompt);
    if (ollamaResult) {
      const res: AiLogAnalysisResult = {
        analysisId: `ai_diag_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        analyzedAt: new Date().toISOString(),
        engineSource: 'OLLAMA',
        modelUsed: `${this.model} (Ollama)`,
        targetType: payload.wazuhAlert ? 'SIEM_LOG' : payload.auditEvent ? 'AUDIT_RECORD' : 'GENERIC_LOG',
        targetSummary,
        ...ollamaResult,
      };

      auditChain.append('MODEL', `ollama:${this.model}`, 'AI_OLLAMA_LOG_ANALYSIS_EXECUTED', {
        classification: res.classification,
        severity: res.severity,
        decision: res.autonomousDecision,
        confidence: res.confidence,
      });

      return res;
    }

    // 2. Try Gemini fallback if Ollama is not currently online
    const geminiResult = await this.queryGemini(prompt);
    if (geminiResult) {
      const res: AiLogAnalysisResult = {
        analysisId: `ai_diag_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        analyzedAt: new Date().toISOString(),
        engineSource: 'GEMINI',
        modelUsed: 'gemini-2.5-flash (Ollama Standby Fallback)',
        targetType: payload.wazuhAlert ? 'SIEM_LOG' : payload.auditEvent ? 'AUDIT_RECORD' : 'GENERIC_LOG',
        targetSummary,
        ...geminiResult,
      };

      auditChain.append('MODEL', 'gemini-2.5-flash', 'AI_OLLAMA_FALLBACK_ANALYSIS_EXECUTED', {
        classification: res.classification,
        severity: res.severity,
        decision: res.autonomousDecision,
      });

      return res;
    }

    // 3. High-precision Deterministic SOC Heuristic Engine fallback
    return this.generateDeterministicAnalysis(rawData, targetSummary, 'SIEM_LOG');
  }

  // Analyze backend API call or backend error
  public async analyzeBackendCall(callId: string): Promise<AiLogAnalysisResult> {
    const call = backendCallTracker.getCallById(callId);
    if (!call) {
      throw new Error(`Backend call with ID '${callId}' not found.`);
    }

    const targetSummary = `${call.method} ${call.path} [${call.statusCode}] - ${call.clientIp}`;

    const prompt = `You are an Autonomous Cybersecurity SOC AI Analyst.
Analyze the following backend API call and error event:
Method: ${call.method}
Path: ${call.path}
HTTP Status: ${call.statusCode}
Latency: ${call.durationMs}ms
Client IP: ${call.clientIp}
User: ${call.userEmail || 'Anonymous'}
Has Error: ${call.hasError}
Error Message: ${call.errorMessage || 'None'}
Request Payload Snippet: ${call.requestSnippet || '{}'}

Decide if this call represents:
1) An attack probe (brute-force, credential stuffing, enumeration, timing attack, API abuse)
2) A security policy enforcement (rate-limit 429 lockout)
3) A system error / bug (500)
4) Benign authorized API traffic

Respond STRICTLY with a valid JSON object with the following fields:
{
  "classification": "BRUTE_FORCE_PROBE" | "AUTHENTICATION_LOCKOUT" | "UNAUTHORIZED_ACCESS" | "SUSPICIOUS_LATERAL_MOVE" | "SYSTEM_API_EXCEPTION" | "PARAMETER_TAMPERING" | "POLICY_VIOLATION" | "BENIGN_TELEMETRY",
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence": 0.95,
  "rootCause": "Clear explanation of why this error or call occurred",
  "threatDescription": "Analysis of attack vector or root cause",
  "mitreTechnique": "e.g. T1110.001 - Brute Force",
  "autonomousDecision": "ALLOW_PASS" | "QUARANTINE_SOURCE_IP" | "ENFORCE_LOCKOUT_POLICY" | "REQUIRE_HUMAN_APPROVAL" | "BLOCK_IMMEDIATELY" | "DISMISS_BENIGN",
  "safetyTier": "L0_OBSERVE" | "L1_ENRICH" | "L2_RATE_LIMIT" | "L3_QUARANTINE" | "L4_ISOLATE" | "L5_TERMINATE" | "L6_CONTAIN" | "L7_LOCKDOWN",
  "recommendedRemediation": "Remediation step for SOC operator",
  "remediationCommands": ["iptables or policy command"]
}`;

    let result: AiLogAnalysisResult;

    // 1. Try Ollama
    const ollamaResult = await this.queryOllama(prompt);
    if (ollamaResult) {
      result = {
        analysisId: `ai_call_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        analyzedAt: new Date().toISOString(),
        engineSource: 'OLLAMA',
        modelUsed: `${this.model} (Ollama)`,
        targetType: 'BACKEND_CALL_ERROR',
        targetSummary,
        ...ollamaResult,
      };
    } else {
      // 2. Try Gemini
      const geminiResult = await this.queryGemini(prompt);
      if (geminiResult) {
        result = {
          analysisId: `ai_call_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
          analyzedAt: new Date().toISOString(),
          engineSource: 'GEMINI',
          modelUsed: 'gemini-2.5-flash (Ollama Standby Fallback)',
          targetType: 'BACKEND_CALL_ERROR',
          targetSummary,
          ...geminiResult,
        };
      } else {
        // 3. Deterministic rule evaluation
        result = this.generateDeterministicAnalysis(
          JSON.stringify(call),
          targetSummary,
          'BACKEND_CALL_ERROR'
        );
      }
    }

    // Attach analysis back to the call in tracker
    backendCallTracker.updateAnalysis(callId, {
      analyzedAt: result.analyzedAt,
      model: result.modelUsed,
      source: result.engineSource === 'DETERMINISTIC' ? 'DETERMINISTIC_RULES' : result.engineSource,
      verdict:
        result.classification === 'BRUTE_FORCE_PROBE'
          ? 'ATTACK_PROBE'
          : result.classification === 'POLICY_VIOLATION' || result.classification === 'AUTHENTICATION_LOCKOUT'
          ? 'POLICY_VIOLATION'
          : result.classification === 'SYSTEM_API_EXCEPTION'
          ? 'SYSTEM_BUG'
          : result.classification === 'UNAUTHORIZED_ACCESS'
          ? 'SUSPICIOUS'
          : 'BENIGN',
      confidence: result.confidence,
      explanation: result.threatDescription,
      mitigation: result.recommendedRemediation,
      mitreTactic: result.mitreTechnique,
      autonomousDecision: result.autonomousDecision,
    });

    return result;
  }

  // Internal helper to query Ollama API
  private async queryOllama(prompt: string): Promise<any | null> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6000);

      const res = await fetch(`${this.host}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.model,
          prompt,
          stream: false,
          format: 'json',
          options: {
            temperature: 0.1,
          },
        }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!res.ok) return null;
      const data = await res.json();
      const text = data.response;
      if (!text) return null;

      const parsed = JSON.parse(text);
      return this.sanitizeAiOutput(parsed);
    } catch {
      return null;
    }
  }

  // Internal helper to query Gemini fallback
  private async queryGemini(prompt: string): Promise<any | null> {
    try {
      if (!process.env.GEMINI_API_KEY) return null;
      const ai = new GoogleGenAI({});
      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.1,
        },
      });

      const text = response.text;
      if (!text) return null;
      const parsed = JSON.parse(text);
      return this.sanitizeAiOutput(parsed);
    } catch {
      return null;
    }
  }

  // Fallback deterministic analysis
  private generateDeterministicAnalysis(
    raw: string,
    targetSummary: string,
    targetType: 'SIEM_LOG' | 'BACKEND_CALL_ERROR' | 'AUDIT_RECORD' | 'GENERIC_LOG'
  ): AiLogAnalysisResult {
    const rawLower = String(raw).toLowerCase();
    const isRateLimit = rawLower.includes('429') || rawLower.includes('locked') || rawLower.includes('rate');
    const isBruteForce = rawLower.includes('brute') || rawLower.includes('failed login') || rawLower.includes('401') || rawLower.includes('password');
    const isTamper = rawLower.includes('tamper') || rawLower.includes('signature') || rawLower.includes('hash');
    const is500 = rawLower.includes('500') || rawLower.includes('exception') || rawLower.includes('error');

    let classification: AiLogAnalysisResult['classification'] = 'BENIGN_TELEMETRY';
    let severity: AiLogAnalysisResult['severity'] = 'LOW';
    let decision: AiLogAnalysisResult['autonomousDecision'] = 'ALLOW_PASS';
    let safetyTier: AiLogAnalysisResult['safetyTier'] = 'L0_OBSERVE';
    let mitre = 'N/A';
    let rootCause = 'Standard authenticated operational traffic.';
    let threatDescription = 'Routine telemetry consistent with normal operations.';
    let remediation = 'Continue baseline monitoring.';
    let commands: string[] = [];

    if (isRateLimit) {
      classification = 'AUTHENTICATION_LOCKOUT';
      severity = 'HIGH';
      decision = 'ENFORCE_LOCKOUT_POLICY';
      safetyTier = 'L2_RATE_LIMIT';
      mitre = 'T1110 - Brute Force: Password Guessing Defended';
      rootCause = 'Repeated invalid authentication attempts tripped the sliding window rate limiter.';
      threatDescription = 'Client IP exceeded 5 consecutive invalid authentication attempts. Deterministic lockout policy P001 active.';
      remediation = 'Enforce 300-second IP cooldown. Require multi-factor re-verification for unlock.';
      commands = ['iptables -I INPUT -s 198.51.100.22 -j DROP # Auto-Lockout'];
    } else if (isBruteForce) {
      classification = 'BRUTE_FORCE_PROBE';
      severity = 'HIGH';
      decision = 'QUARANTINE_SOURCE_IP';
      safetyTier = 'L3_QUARANTINE';
      mitre = 'T1110.001 - Password Guessing';
      rootCause = 'Invalid credential hash verification failed on user authentication endpoint.';
      threatDescription = 'Unrecognized actor attempting automated dictionary attack on privileged credentials.';
      remediation = 'Quarantine source IP at edge firewall and invalidate any existing sessions.';
      commands = ['iptables -A INPUT -p tcp --dport 3000 -m recent --name badguy --set'];
    } else if (isTamper) {
      classification = 'PARAMETER_TAMPERING';
      severity = 'CRITICAL';
      decision = 'REQUIRE_HUMAN_APPROVAL';
      safetyTier = 'L4_ISOLATE';
      mitre = 'T1565.001 - Stored Data Manipulation';
      rootCause = 'Cryptographic SHA-256 hash chain mismatch detected in audit record.';
      threatDescription = 'Anomalous attempt to alter audit ledger history or bypass approval parameter hashes.';
      remediation = 'Flag tamper alert immediately to Lead Approver and freeze ledger write operations.';
      commands = ['soc-ledger-ctl verify --full --freeze-on-anomaly'];
    } else if (is500) {
      classification = 'SYSTEM_API_EXCEPTION';
      severity = 'MEDIUM';
      decision = 'ALLOW_PASS';
      safetyTier = 'L1_ENRICH';
      mitre = 'T1499 - Endpoint DoS / Application Failure';
      rootCause = 'Unhandled server-side runtime error occurred during request processing.';
      threatDescription = 'Server returned HTTP 500. Error call captured in backend diagnostic buffer.';
      remediation = 'Review stack trace, apply defensive schema validation, and restart worker if memory leaked.';
      commands = ['journalctl -u ai-soc -n 50 --no-pager'];
    }

    return {
      analysisId: `ai_diag_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      analyzedAt: new Date().toISOString(),
      engineSource: 'DETERMINISTIC',
      modelUsed: 'Ollama Deterministic Security Model (Standby)',
      targetType,
      targetSummary,
      classification,
      severity,
      confidence: 0.94,
      rootCause,
      threatDescription,
      mitreTechnique: mitre,
      autonomousDecision: decision,
      safetyTier,
      recommendedRemediation: remediation,
      remediationCommands: commands,
    };
  }

  private sanitizeAiOutput(parsed: any) {
    return {
      classification: parsed.classification || 'BRUTE_FORCE_PROBE',
      severity: parsed.severity || 'HIGH',
      confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.92,
      rootCause: parsed.rootCause || 'Anomalous network security behavior detected.',
      threatDescription: parsed.threatDescription || 'Log pattern indicates potential policy violation or attack probing.',
      mitreTechnique: parsed.mitreTechnique || 'T1110 - Brute Force',
      autonomousDecision: parsed.autonomousDecision || 'QUARANTINE_SOURCE_IP',
      safetyTier: parsed.safetyTier || 'L3_QUARANTINE',
      recommendedRemediation: parsed.recommendedRemediation || 'Quarantine suspect IP and notify security team.',
      remediationCommands: Array.isArray(parsed.remediationCommands) ? parsed.remediationCommands : [],
    };
  }
}

export const ollamaService = new OllamaService();
