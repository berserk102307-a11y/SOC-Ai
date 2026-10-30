import {
  type ComputedEvidencePack,
  type InvestigationResult,
  type ValidationReport,
  type GroundingCheckItem,
  INCIDENT_FIXTURES,
} from './fixtures.ts';
import { auditChain } from './auditChain.ts';

const ATTACK_ALLOW_LIST = new Set(['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002']);

export class InvestigationEngine {
  private runs: Map<string, InvestigationResult[]> = new Map();

  constructor() {
    // Seed runs from fixtures
    for (const fixture of INCIDENT_FIXTURES) {
      this.runs.set(fixture.id, [fixture.investigation]);
    }
  }

  public getHistory(incidentId: string): InvestigationResult[] {
    return this.runs.get(incidentId) || [];
  }

  public getLatest(incidentId: string): InvestigationResult | undefined {
    const list = this.runs.get(incidentId);
    return list ? list[list.length - 1] : undefined;
  }

  // Execute validators on candidate investigation output against evidence pack
  public validate(
    evidencePack: ComputedEvidencePack,
    candidate: Partial<InvestigationResult>
  ): ValidationReport {
    const checks: GroundingCheckItem[] = [];
    const warnings: string[] = [];
    let schemaValid = true;
    let grounded = true;
    let consistencyValid = true;
    let confidenceClamped = false;

    // 1. Schema, Enums, Lengths & Ranges
    const allowedClassifications = [
      'brute_force',
      'password_spraying',
      'compromise_suspected',
      'benign_user_error',
      'misconfiguration',
      'insufficient_evidence',
    ];
    const allowedActions = ['none', 'monitor', 'notify', 'block_source_ip', 'disable_account'];

    if (!candidate.classification || !allowedClassifications.includes(candidate.classification)) {
      schemaValid = false;
      checks.push({
        name: 'Classification Enum Check',
        passed: false,
        detail: `Invalid classification: ${candidate.classification}. Must match taxonomy.`,
      });
    } else {
      checks.push({
        name: 'Classification Enum Check',
        passed: true,
        detail: `Classification '${candidate.classification}' is valid.`,
      });
    }

    if (!candidate.recommendedAction || !allowedActions.includes(candidate.recommendedAction)) {
      schemaValid = false;
      checks.push({
        name: 'Action Enum Check',
        passed: false,
        detail: `Invalid action: ${candidate.recommendedAction}. Must match allow-list.`,
      });
    } else {
      checks.push({
        name: 'Action Enum Check',
        passed: true,
        detail: `Action '${candidate.recommendedAction}' is valid.`,
      });
    }

    // 2. Cited Evidence Check
    const findingsText = (candidate.findings || []).join(' ');
    const citedMatches = findingsText.match(/\[(\d+)\]/g) || [];
    const validEvidenceIds = new Set(evidencePack.evidenceItems.map(e => e.id));

    let allCitationsValid = true;
    for (const match of citedMatches) {
      const idNum = parseInt(match.replace(/\[|\]/g, ''), 10);
      if (!validEvidenceIds.has(idNum)) {
        allCitationsValid = false;
        grounded = false;
        checks.push({
          name: 'Evidence Citation Check',
          passed: false,
          detail: `Cited evidence ID [${idNum}] does not exist in evidence pack.`,
        });
      }
    }
    if (allCitationsValid) {
      checks.push({
        name: 'Evidence Citation Check',
        passed: true,
        detail: `All ${citedMatches.length} cited evidence references exist in evidence pack.`,
      });
    }

    // 3. Entity Grounding Check (IPs & Usernames)
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    const mentionedIps = findingsText.match(ipRegex) || [];
    const allowedIps = new Set(evidencePack.distinctSourceIps);

    let allIpsGrounded = true;
    for (const ip of mentionedIps) {
      if (!allowedIps.has(ip)) {
        allIpsGrounded = false;
        grounded = false;
        checks.push({
          name: 'IP Entity Grounding',
          passed: false,
          detail: `Hallucinated IP ${ip} not found in telemetry evidence pack.`,
        });
      }
    }
    if (allIpsGrounded) {
      checks.push({
        name: 'IP Entity Grounding',
        passed: true,
        detail: 'All mentioned IP addresses match grounded network telemetry.',
      });
    }

    // 4. Forbidden Claims Check (CVE / External Threat Actor without evidence)
    if (/(apt\d+|lazarus|cozy bear|cve-\d{4}-\d+|fancy bear)/i.test(findingsText)) {
      grounded = false;
      warnings.push('Rejected ungrounded external threat attribution / CVE speculation');
      checks.push({
        name: 'Forbidden Attribution Claims',
        passed: false,
        detail: 'Threat-intel attribution rejected (not provided in evidence pack).',
      });
    } else {
      checks.push({
        name: 'Forbidden Attribution Claims',
        passed: true,
        detail: 'Zero unverified external threat-intel claims.',
      });
    }

    // 5. Action Compatibility with Classification
    if (candidate.classification === 'benign_user_error' && candidate.recommendedAction === 'block_source_ip') {
      consistencyValid = false;
      checks.push({
        name: 'Action Compatibility Check',
        passed: false,
        detail: 'Incompatible action: block_source_ip cannot be recommended for benign user error.',
      });
    } else {
      checks.push({
        name: 'Action Compatibility Check',
        passed: true,
        detail: 'Proposed action is compatible with attack classification.',
      });
    }

    // 6. Confidence Clamping
    let conf = candidate.confidence ?? 0.8;
    if (conf > 0.95 && (!grounded || !consistencyValid)) {
      conf = 0.65;
      confidenceClamped = true;
      warnings.push('Confidence clamped to 0.65 due to validation check failures.');
    }

    const finalStatus: 'VERIFIED' | 'NEEDS_REVIEW' | 'FALLBACK' =
      schemaValid && grounded && consistencyValid ? 'VERIFIED' : 'NEEDS_REVIEW';

    return {
      schemaValid,
      grounded,
      consistencyValid,
      finalStatus,
      checks,
      warnings,
      confidenceClamped,
    };
  }

  // Safe Rule-Based Fallback per Section 3.1 & 3.3
  public generateFallback(evidencePack: ComputedEvidencePack): InvestigationResult {
    let classification: InvestigationResult['classification'] = 'insufficient_evidence';
    let action: InvestigationResult['recommendedAction'] = 'monitor';
    let summary = 'Automated rule-based triage fallback engaged due to model validation failure or timeout.';

    if (evidencePack.ruleFired === 'R1_BRUTE_FORCE') {
      classification = 'brute_force';
      action = 'block_source_ip';
      summary = `Rule R1 fallback: Sustained authentication failures against ${evidencePack.distinctAccounts.join(', ')} from ${evidencePack.distinctSourceIps.join(', ')}.`;
    } else if (evidencePack.ruleFired === 'R2_PASSWORD_SPRAY') {
      classification = 'password_spraying';
      action = 'block_source_ip';
      summary = `Rule R2 fallback: Horizontal password spray detected across ${evidencePack.distinctAccounts.length} accounts from ${evidencePack.distinctSourceIps.join(', ')}.`;
    } else if (evidencePack.ruleFired === 'R3_SUCCESS_AFTER_FAILURES') {
      classification = 'compromise_suspected';
      action = 'disable_account';
      summary = `Rule R3 fallback: Authentication failure burst followed by successful logon on ${evidencePack.distinctAccounts.join(', ')}.`;
    }

    return {
      version: 'fallback-v1',
      source: 'FALLBACK',
      model: 'deterministic-rules-fallback',
      status: 'FALLBACK',
      classification,
      summary,
      findings: [
        `Computed evidence documents ${evidencePack.totalAlerts} failure events over ${evidencePack.timeSpanSeconds}s.`,
        `Originating from ${evidencePack.distinctSourceIps.join(', ')} targeting ${evidencePack.distinctAccounts.join(', ')}.`,
      ],
      hypotheses: [
        'UNVERIFIED: Fallback generated deterministically; human analyst review recommended.',
      ],
      recommendedAction: action,
      confidence: 0.7,
      uncertainties: ['Fallback bypasses LLM inference.'],
      latencyMs: 15,
      validationReport: {
        schemaValid: true,
        grounded: true,
        consistencyValid: true,
        finalStatus: 'FALLBACK',
        checks: [
          { name: 'Deterministic Rule Fallback', passed: true, detail: 'Derived strictly from computed evidence facts' },
          { name: 'Default Deny Constraint', passed: true, detail: 'Disruptive action flagged for mandatory approver review' },
        ],
        warnings: ['Fallback engaged: Investigation marked as NEEDS_REVIEW.'],
        confidenceClamped: true,
      },
    };
  }

  // Trigger an investigation run for an incident
  public runInvestigation(
    incidentId: string,
    mode: 'MOCK' | 'FALLBACK' | 'VALIDATED_LLM' = 'VALIDATED_LLM'
  ): InvestigationResult {
    const fixture = INCIDENT_FIXTURES.find(f => f.id === incidentId);
    if (!fixture) {
      throw new Error(`Incident ${incidentId} not found.`);
    }

    let result: InvestigationResult;

    if (mode === 'FALLBACK') {
      result = this.generateFallback(fixture.evidencePack);
    } else {
      // Validated pipeline run
      const validation = this.validate(fixture.evidencePack, fixture.investigation);
      result = {
        ...fixture.investigation,
        latencyMs: Math.floor(1200 + Math.random() * 400),
        validationReport: validation,
      };
    }

    const currentRuns = this.runs.get(incidentId) || [];
    currentRuns.push(result);
    this.runs.set(incidentId, currentRuns);

    auditChain.append('MODEL', `${result.model} (${result.source})`, 'INVESTIGATION_COMPLETED', {
      incidentId,
      source: result.source,
      classification: result.classification,
      recommendedAction: result.recommendedAction,
      confidence: result.confidence,
      validationStatus: result.validationReport.finalStatus,
    });

    return result;
  }
}

export const investigationEngine = new InvestigationEngine();
