/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Wazuh SIEM Ingestion, Severity Normalization, and Attack Scenario Replay
 * Derived from AI-SOC Architecture specifications
 */

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

/**
 * Maps Wazuh rule severity levels (0-15) to SOC severity tiers
 * 0 - 7   : LOW
 * 8 - 11  : MEDIUM
 * 12 - 14 : HIGH
 * 15      : CRITICAL
 */
export function mapWazuhSeverity(ruleLevel: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (ruleLevel >= 15) return 'CRITICAL';
  if (ruleLevel >= 12) return 'HIGH';
  if (ruleLevel >= 8) return 'MEDIUM';
  return 'LOW';
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
  generateAlerts: () => WazuhAlert[];
}

export const ATTACK_SCENARIOS: Record<string, ScenarioDefinition> = {
  SSH_BRUTE_FORCE: {
    id: 'SSH_BRUTE_FORCE',
    title: 'SSH Authentication Brute Force Attack',
    mitreTechnique: 'T1110 - Brute Force',
    mitreTactic: 'Credential Access',
    wazuhRuleId: 5716,
    wazuhLevel: 10,
    severity: 'MEDIUM',
    targetAgent: 'SRV-UBUNTU-PROD (002)',
    sourceIp: '198.51.100.44',
    description: 'Rapid sequential SSH authentication failures followed by root password guessing from external IP.',
    recommendedActions: ['block_ip', 'notify_analyst'],
    expectedSafetyGate: 'AUTO_ALLOWED',
    policyRulesTriggered: [],
    generateAlerts: () => {
      const now = Date.now();
      const alerts: WazuhAlert[] = [];
      const users = ['root', 'admin', 'ubuntu', 'deploy', 'backup'];

      users.forEach((u, idx) => {
        const ts = new Date(now - (users.length - idx) * 3000).toISOString();
        alerts.push({
          id: `wazuh-ssh-${idx + 1}-${Date.now().toString().slice(-4)}`,
          timestamp: ts,
          rule: {
            id: 5716,
            level: 5,
            description: `SSHD authentication failed for user ${u}`,
            mitre: {
              id: ['T1110'],
              tactic: ['Credential Access'],
              technique: ['Brute Force'],
            },
          },
          agent: { id: '002', name: 'SRV-UBUNTU-PROD', ip: '10.0.1.15' },
          data: {
            srcip: '198.51.100.44',
            dstip: '10.0.1.15',
            srcuser: u,
          },
          full_log: `sshd[10928]: Failed password for invalid user ${u} from 198.51.100.44 port 49812 ssh2`,
          severity: mapWazuhSeverity(5),
          scenarioTag: 'SSH_BRUTE_FORCE',
        });
      });

      // Culminating threshold rule
      alerts.push({
        id: `wazuh-ssh-agg-${Date.now().toString().slice(-4)}`,
        timestamp: new Date(now).toISOString(),
        rule: {
          id: 5715,
          level: 10,
          description: 'SSHD brute force trying to get access to the system.',
          mitre: {
            id: ['T1110'],
            tactic: ['Credential Access'],
            technique: ['Brute Force'],
          },
        },
        agent: { id: '002', name: 'SRV-UBUNTU-PROD', ip: '10.0.1.15' },
        data: {
          srcip: '198.51.100.44',
          dstip: '10.0.1.15',
        },
        full_log: 'ossec: Host 198.51.100.44 reached SSH authentication failure threshold (25 events in 60s).',
        severity: mapWazuhSeverity(10),
        scenarioTag: 'SSH_BRUTE_FORCE',
      });

      return alerts;
    },
  },

  POWERSHELL_EXEC: {
    id: 'POWERSHELL_EXEC',
    title: 'Suspicious Encoded PowerShell Execution',
    mitreTechnique: 'T1059.001 - Command and Scripting Interpreter: PowerShell',
    mitreTactic: 'Execution / Defense Evasion',
    wazuhRuleId: 92651,
    wazuhLevel: 13,
    severity: 'HIGH',
    targetAgent: 'WIN-DC-01 (001)',
    sourceIp: '10.0.4.52',
    description: 'Endpoint executed hidden window PowerShell with base64 encoded payload downloading remote stage2 payload.',
    recommendedActions: ['kill_process', 'isolate_host'],
    expectedSafetyGate: 'REQUIRE_APPROVAL',
    policyRulesTriggered: ['P001'],
    generateAlerts: () => {
      const now = Date.now();
      return [
        {
          id: `wazuh-ps-1-${Date.now().toString().slice(-4)}`,
          timestamp: new Date(now - 8000).toISOString(),
          rule: {
            id: 92651,
            level: 13,
            description: 'Sysmon - Event 1: Suspicious PowerShell execution with -EncodedCommand and -WindowStyle Hidden',
            mitre: {
              id: ['T1059.001', 'T1027'],
              tactic: ['Execution', 'Defense Evasion'],
              technique: ['PowerShell', 'Obfuscated Files or Information'],
            },
          },
          agent: { id: '001', name: 'WIN-DC-01', ip: '10.0.4.10' },
          data: {
            srcip: '10.0.4.52',
            dstip: '10.0.4.10',
            srcuser: 'CORP\\service_mgr',
            process: 'powershell.exe',
            pid: 4892,
            command: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...==',
          },
          full_log: 'Microsoft-Windows-Sysmon/Operational: Process Create: CommandLine: powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFg... Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe User: CORP\\service_mgr Parent: explorer.exe',
          severity: mapWazuhSeverity(13),
          scenarioTag: 'POWERSHELL_EXEC',
        },
      ];
    },
  },

  PRIVILEGE_ESCALATION: {
    id: 'PRIVILEGE_ESCALATION',
    title: 'Unauthorized Sudoers Privilege Escalation',
    mitreTechnique: 'T1068 - Exploitation for Privilege Escalation',
    mitreTactic: 'Privilege Escalation',
    wazuhRuleId: 5402,
    wazuhLevel: 14,
    severity: 'HIGH',
    targetAgent: 'SRV-K8S-MASTER (003)',
    sourceIp: '10.0.8.21',
    description: 'Compromised service account attempted unauthorized sudoers rule addition and passwordless root switch.',
    recommendedActions: ['disable_account', 'collect_logs', 'recover_system'],
    expectedSafetyGate: 'REQUIRE_APPROVAL',
    policyRulesTriggered: ['P002', 'P005'],
    generateAlerts: () => {
      const now = Date.now();
      return [
        {
          id: `wazuh-priv-1-${Date.now().toString().slice(-4)}`,
          timestamp: new Date(now - 12000).toISOString(),
          rule: {
            id: 5402,
            level: 14,
            description: 'Linux PAM: Sudo unauthorized command attempt by service account',
            mitre: {
              id: ['T1068', 'T1078'],
              tactic: ['Privilege Escalation', 'Initial Access'],
              technique: ['Exploitation for Privilege Escalation', 'Valid Accounts'],
            },
          },
          agent: { id: '003', name: 'SRV-K8S-MASTER', ip: '10.0.8.2' },
          data: {
            srcip: '10.0.8.21',
            dstip: '10.0.8.2',
            srcuser: 'svc_jenkins',
            dstuser: 'root',
            command: 'sudo /bin/bash -c "echo \'svc_jenkins ALL=(ALL) NOPASSWD:ALL\' >> /etc/sudoers"',
          },
          full_log: 'sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1003 euid=0 tty=/dev/pts/2 ruser=svc_jenkins rhost=10.0.8.21 user=svc_jenkins',
          severity: mapWazuhSeverity(14),
          scenarioTag: 'PRIVILEGE_ESCALATION',
        },
      ];
    },
  },
};

export class WazuhAlertStore {
  private alerts: WazuhAlert[] = [];

  constructor() {
    this.seedInitialAlerts();
  }

  private seedInitialAlerts() {
    // Populate realistic baseline Wazuh alerts
    const baseline: WazuhAlert[] = [
      {
        id: 'wazuh-init-001',
        timestamp: new Date(Date.now() - 3600000 * 3).toISOString(),
        rule: {
          id: 5710,
          level: 5,
          description: 'sshd: Attempt to login using a non-existent user',
          mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] },
        },
        agent: { id: '002', name: 'SRV-UBUNTU-PROD', ip: '10.0.1.15' },
        data: { srcip: '192.0.2.14', srcuser: 'test' },
        full_log: 'sshd[4102]: Invalid user test from 192.0.2.14 port 55102',
        severity: 'LOW',
      },
      {
        id: 'wazuh-init-002',
        timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
        rule: {
          id: 60105,
          level: 9,
          description: 'Windows Defender: Antivirus definition signature updated successfully',
        },
        agent: { id: '001', name: 'WIN-DC-01', ip: '10.0.4.10' },
        full_log: 'Microsoft-Windows-Windows Defender/Operational: Signature update 1.398.112.0 installed',
        severity: 'MEDIUM',
      },
      {
        id: 'wazuh-init-003',
        timestamp: new Date(Date.now() - 3600000 * 1).toISOString(),
        rule: {
          id: 92651,
          level: 13,
          description: 'Sysmon - Event 1: Suspicious PowerShell execution with -EncodedCommand',
          mitre: { id: ['T1059.001'], tactic: ['Execution'], technique: ['PowerShell'] },
        },
        agent: { id: '001', name: 'WIN-DC-01', ip: '10.0.4.10' },
        data: {
          srcip: '10.0.4.52',
          dstip: '10.0.4.10',
          process: 'powershell.exe',
          pid: 4892,
        },
        full_log: 'Sysmon: Process Create: powershell.exe -Enc SQBFAFgA...',
        severity: 'HIGH',
        scenarioTag: 'POWERSHELL_EXEC',
      },
      {
        id: 'wazuh-init-004',
        timestamp: new Date(Date.now() - 1800000).toISOString(),
        rule: {
          id: 5715,
          level: 10,
          description: 'SSHD brute force threshold exceeded on host',
          mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] },
        },
        agent: { id: '002', name: 'SRV-UBUNTU-PROD', ip: '10.0.1.15' },
        data: { srcip: '198.51.100.44' },
        full_log: 'ossec: Host 198.51.100.44 reached SSH authentication failure threshold',
        severity: 'MEDIUM',
        scenarioTag: 'SSH_BRUTE_FORCE',
      },
      {
        id: 'wazuh-init-005',
        timestamp: new Date(Date.now() - 900000).toISOString(),
        rule: {
          id: 5402,
          level: 14,
          description: 'Linux PAM: Sudo authentication failure for service account',
          mitre: { id: ['T1068'], tactic: ['Privilege Escalation'], technique: ['Exploitation for Privilege Escalation'] },
        },
        agent: { id: '003', name: 'SRV-K8S-MASTER', ip: '10.0.8.2' },
        data: { srcip: '10.0.8.21', srcuser: 'svc_jenkins' },
        full_log: 'sudo: pam_unix(sudo:auth): authentication failure; user=svc_jenkins',
        severity: 'HIGH',
        scenarioTag: 'PRIVILEGE_ESCALATION',
      },
      {
        id: 'wazuh-init-006',
        timestamp: new Date(Date.now() - 450000).toISOString(),
        rule: {
          id: 80710,
          level: 15,
          description: 'Ransomware behavioral canary file modified in network share',
          mitre: { id: ['T1486'], tactic: ['Impact'], technique: ['Data Encrypted for Impact'] },
        },
        agent: { id: '001', name: 'WIN-DC-01', ip: '10.0.4.10' },
        data: { process: 'vssadmin.exe', command: 'vssadmin.exe delete shadows /all /quiet' },
        full_log: 'FIM alert: Volume shadow copies targeted for deletion by unauthorized process',
        severity: 'CRITICAL',
      },
    ];

    this.alerts = baseline;
  }

  public getAlerts(limit = 100): WazuhAlert[] {
    return [...this.alerts].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, limit);
  }

  public addAlert(alert: WazuhAlert): void {
    this.alerts.unshift(alert);
    if (this.alerts.length > 500) {
      this.alerts.pop();
    }
  }

  public addMultiple(alerts: WazuhAlert[]): void {
    this.alerts = [...alerts, ...this.alerts];
    if (this.alerts.length > 500) {
      this.alerts = this.alerts.slice(0, 500);
    }
  }

  public getStats(): {
    totalAlerts: number;
    severityCounts: { LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number };
    topRules: { ruleId: number; description: string; count: number }[];
  } {
    const counts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    const ruleMap = new Map<number, { description: string; count: number }>();

    for (const a of this.alerts) {
      counts[a.severity] = (counts[a.severity] || 0) + 1;
      const current = ruleMap.get(a.rule.id) || { description: a.rule.description, count: 0 };
      current.count += 1;
      ruleMap.set(a.rule.id, current);
    }

    const topRules = Array.from(ruleMap.entries())
      .map(([ruleId, data]) => ({ ruleId, description: data.description, count: data.count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      totalAlerts: this.alerts.length,
      severityCounts: counts,
      topRules,
    };
  }
}

export const wazuhStore = new WazuhAlertStore();
