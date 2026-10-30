import crypto from 'node:crypto';

export type AuditActor = 'SYSTEM' | 'MODEL' | 'USER' | 'MONITOR';

export interface AuditEvent {
  index: number;
  id: string;
  timestamp: string;
  actor: AuditActor;
  actorId: string;
  eventType: string;
  payload: Record<string, unknown>;
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

const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// Deterministic canonical stringification to avoid key ordering differences
export function canonicalJsonStringify(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return '{' + keys.map(k => `${JSON.stringify(k)}:${canonicalJsonStringify((obj as Record<string, unknown>)[k])}`).join(',') + '}';
}

// Compute SHA-256 for a block in the chain
export function calculateBlockContentHash(
  index: number,
  timestamp: string,
  actor: AuditActor,
  actorId: string,
  eventType: string,
  payload: Record<string, unknown>,
  prevHash: string
): string {
  const content = `${index}|${timestamp}|${actor}|${actorId}|${eventType}|${canonicalJsonStringify(payload)}|${prevHash}`;
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

class AuditLogChainManager {
  private chain: AuditEvent[] = [];
  private backupOriginalChain: AuditEvent[] | null = null;
  private isTampered = false;

  constructor() {
    this.initGenesisAndSeedLogs();
  }

  private initGenesisAndSeedLogs() {
    // Block 0: Genesis block
    const genesisTime = '2026-10-28T10:00:00.000Z';
    const genesisPayload = {
      message: 'AI-SOC Security Platform Audit Chain Initialized',
      standard: 'NIST SP 800-92 Cryptographic Audit Standard',
      hashAlgorithm: 'SHA-256 Cryptographic Chaining',
    };
    const genesisHash = calculateBlockContentHash(
      0,
      genesisTime,
      'SYSTEM',
      'KERNEL',
      'AUDIT_GENESIS_INITIALIZED',
      genesisPayload,
      GENESIS_PREV_HASH
    );

    const genesisEvent: AuditEvent = {
      index: 0,
      id: 'aud_gen_00000',
      timestamp: genesisTime,
      actor: 'SYSTEM',
      actorId: 'KERNEL',
      eventType: 'AUDIT_GENESIS_INITIALIZED',
      payload: genesisPayload,
      prevHash: GENESIS_PREV_HASH,
      hash: genesisHash,
    };

    this.chain = [genesisEvent];

    // Seed realistic SOC operational and security audit entries
    this.appendRaw(
      '2026-10-28T10:05:00.000Z',
      'SYSTEM',
      'sec_admin_provisioner',
      'SECURITY_POLICY_LOADED',
      {
        policyVersion: 'v2.4.1',
        defaultAction: 'DENY',
        protectedSubnets: ['10.0.0.0/8', '192.168.0.0/16', '127.0.0.1'],
        requireApprovalForDisruptiveActions: true,
      }
    );

    this.appendRaw(
      '2026-10-28T10:15:22.000Z',
      'MONITOR',
      'WIN-DC-01.lab.local',
      'API_KEY_VERIFIED',
      {
        keyId: 'key_win_sensor_01',
        host: 'WIN-DC-01.lab.local',
        remoteAddr: '192.168.56.10',
        verifiedWith: 'CONSTANT_TIME_SHA256',
      }
    );

    this.appendRaw(
      '2026-10-28T11:42:15.000Z',
      'USER',
      'analyst@soc.corp',
      'AUTH_LOGIN_SUCCESS',
      {
        userId: 'usr_analyst_01',
        role: 'ANALYST',
        ip: '10.0.1.45',
        authMethod: 'PBKDF2_PASSWORD',
        sessionDurationMin: 120,
      }
    );

    this.appendRaw(
      '2026-10-28T14:20:30.000Z',
      'MONITOR',
      'WIN-DC-01.lab.local',
      'ALERT_INGESTED',
      {
        eventId: '4625',
        logonType: 3,
        sourceIp: '198.51.100.42',
        targetUser: 'Administrator',
        failureReason: '0xC000006A (Bad Password)',
        workstationName: 'EXT-ATTACK-VM',
      }
    );

    this.appendRaw(
      '2026-10-28T14:25:10.000Z',
      'MODEL',
      'qwen2.5:3b (Schema Validated)',
      'INVESTIGATION_COMPLETED',
      {
        incidentId: 'inc_win_2026_001',
        classification: 'brute_force',
        confidence: 0.94,
        evidencePackVerified: true,
        groundingCheck: 'PASSED',
        proposedAction: 'BLOCK_SOURCE_IP',
        targetIp: '198.51.100.42',
      }
    );

    this.appendRaw(
      '2026-10-28T14:25:12.000Z',
      'SYSTEM',
      'POLICY_ENGINE',
      'APPROVAL_REQUESTED',
      {
        incidentId: 'inc_win_2026_001',
        actionType: 'BLOCK_SOURCE_IP',
        actionTarget: '198.51.100.42',
        ttlMinutes: 30,
        parameterHash: crypto.createHash('sha256').update(JSON.stringify({ target: '198.51.100.42', ttl: 30 })).digest('hex'),
        policyResult: 'REQUIRE_APPROVAL',
        reason: 'Disruptive network action requires verified human approval',
      }
    );

    this.appendRaw(
      '2026-10-28T14:28:44.000Z',
      'USER',
      'approver@soc.corp',
      'ACTION_APPROVED',
      {
        approvalId: 'appr_2026_001',
        incidentId: 'inc_win_2026_001',
        approverRole: 'APPROVER',
        verifiedParamHash: true,
        reason: 'Confirmed sustained brute-force attack from external IP on Domain Controller',
      }
    );
  }

  private appendRaw(
    timestamp: string,
    actor: AuditActor,
    actorId: string,
    eventType: string,
    payload: Record<string, unknown>
  ): AuditEvent {
    const prev = this.chain[this.chain.length - 1];
    const index = this.chain.length;
    const prevHash = prev.hash;

    const hash = calculateBlockContentHash(
      index,
      timestamp,
      actor,
      actorId,
      eventType,
      payload,
      prevHash
    );

    const event: AuditEvent = {
      index,
      id: `aud_${Date.now().toString(36)}_${index}`,
      timestamp,
      actor,
      actorId,
      eventType,
      payload,
      prevHash,
      hash,
    };

    this.chain.push(event);
    return event;
  }

  // Public append-only method (strictly no updates or deletes)
  public append(
    actor: AuditActor,
    actorId: string,
    eventType: string,
    payload: Record<string, unknown>
  ): AuditEvent {
    return this.appendRaw(
      new Date().toISOString(),
      actor,
      actorId,
      eventType,
      payload
    );
  }

  public getEvents(filter?: { actor?: string; eventType?: string; search?: string }): AuditEvent[] {
    let list = [...this.chain];
    if (filter) {
      if (filter.actor) {
        list = list.filter(e => e.actor.toUpperCase() === filter.actor?.toUpperCase());
      }
      if (filter.eventType) {
        list = list.filter(e => e.eventType.toLowerCase().includes(filter.eventType!.toLowerCase()));
      }
      if (filter.search) {
        const q = filter.search.toLowerCase();
        list = list.filter(e =>
          e.actorId.toLowerCase().includes(q) ||
          e.eventType.toLowerCase().includes(q) ||
          JSON.stringify(e.payload).toLowerCase().includes(q) ||
          e.hash.toLowerCase().includes(q)
        );
      }
    }
    return list;
  }

  public getEventByIndex(index: number): AuditEvent | undefined {
    return this.chain[index];
  }

  // Verify the entire cryptographic hash chain
  public verifyIntegrity(): ChainVerificationResult {
    const now = new Date().toISOString();

    if (this.chain.length === 0) {
      return {
        valid: false,
        totalEntries: 0,
        lastVerifiedAt: now,
        message: 'Audit chain is empty.',
      };
    }

    for (let i = 0; i < this.chain.length; i++) {
      const current = this.chain[i];

      // Verify sequence index
      if (current.index !== i) {
        return {
          valid: false,
          totalEntries: this.chain.length,
          lastVerifiedAt: now,
          brokenIndex: i,
          message: `Sequence mismatch at position ${i}: expected index ${i}, found ${current.index}`,
        };
      }

      // Verify prevHash link
      if (i === 0) {
        if (current.prevHash !== GENESIS_PREV_HASH) {
          return {
            valid: false,
            totalEntries: this.chain.length,
            lastVerifiedAt: now,
            brokenIndex: 0,
            expectedHash: GENESIS_PREV_HASH,
            actualHash: current.prevHash,
            message: 'Genesis block prevHash does not match standard genesis marker.',
          };
        }
      } else {
        const prev = this.chain[i - 1];
        if (current.prevHash !== prev.hash) {
          return {
            valid: false,
            totalEntries: this.chain.length,
            lastVerifiedAt: now,
            brokenIndex: i,
            expectedHash: prev.hash,
            actualHash: current.prevHash,
            message: `Hash chain break at event #${i}: prevHash does not match hash of event #${i - 1}.`,
          };
        }
      }

      // Re-calculate hash from content
      const recalculatedHash = calculateBlockContentHash(
        current.index,
        current.timestamp,
        current.actor,
        current.actorId,
        current.eventType,
        current.payload,
        current.prevHash
      );

      if (recalculatedHash !== current.hash) {
        return {
          valid: false,
          totalEntries: this.chain.length,
          lastVerifiedAt: now,
          brokenIndex: i,
          expectedHash: recalculatedHash,
          actualHash: current.hash,
          message: `Cryptographic tamper detected at event #${i} (${current.eventType}): payload/metadata content was altered without recalculating the hash.`,
        };
      }
    }

    return {
      valid: true,
      totalEntries: this.chain.length,
      lastVerifiedAt: now,
      message: `Hash chain verified: all ${this.chain.length} audit entries cryptographically intact and unbroken.`,
    };
  }

  // Demonstration feature: simulate unauthorized tampering of an existing log entry
  public simulateTamper(targetIndex: number, alteredField: string, alteredValue: unknown): boolean {
    if (targetIndex < 0 || targetIndex >= this.chain.length) {
      return false;
    }

    if (!this.backupOriginalChain) {
      // Create deep copy backup
      this.backupOriginalChain = JSON.parse(JSON.stringify(this.chain));
    }

    const event = this.chain[targetIndex];
    if (alteredField === 'eventType') {
      event.eventType = String(alteredValue);
    } else if (alteredField === 'actorId') {
      event.actorId = String(alteredValue);
    } else {
      event.payload = {
        ...event.payload,
        [alteredField]: alteredValue,
      };
    }

    this.isTampered = true;
    return true;
  }

  // Restore chain from backup
  public restoreChain(): boolean {
    if (this.backupOriginalChain) {
      this.chain = JSON.parse(JSON.stringify(this.backupOriginalChain));
      this.backupOriginalChain = null;
      this.isTampered = false;
      return true;
    }
    return false;
  }

  public getIsTampered(): boolean {
    return this.isTampered;
  }

  public getLength(): number {
    return this.chain.length;
  }

  public getHeadHash(): string {
    return this.chain[this.chain.length - 1]?.hash || GENESIS_PREV_HASH;
  }
}

export const auditChain = new AuditLogChainManager();

