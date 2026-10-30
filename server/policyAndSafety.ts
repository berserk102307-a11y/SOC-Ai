/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Deterministic Policy Engine and L0-L7 Autonomous Safety Gate
 * Derived from AI-SOC Architecture specifications (Wazuh SIEM + Autonomous Action Constraints)
 */

export type RiskLevel = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;

export interface ActionDefinition {
  name: string;
  level: RiskLevel;
  tier: 'LOOK' | 'ENRICH' | 'UNDOABLE' | 'DISRUPTIVE' | 'DESTRUCTIVE';
  description: string;
  defaultAutonomous: boolean;
}

export const RISK_LADDER: Record<string, ActionDefinition> = {
  notify_analyst: {
    name: 'notify_analyst',
    level: 0,
    tier: 'LOOK',
    description: 'Dispatch notification to on-duty SOC analyst via webhook/email',
    defaultAutonomous: true,
  },
  search_logs: {
    name: 'search_logs',
    level: 1,
    tier: 'LOOK',
    description: 'Query SIEM/Wazuh indices for corroborating audit events',
    defaultAutonomous: true,
  },
  ioc_enrichment: {
    name: 'ioc_enrichment',
    level: 2,
    tier: 'ENRICH',
    description: 'Query threat intelligence feeds (VirusTotal, AbuseIPDB, AlienVault)',
    defaultAutonomous: true,
  },
  create_record: {
    name: 'create_record',
    level: 3,
    tier: 'UNDOABLE',
    description: 'Create security incident ticket in tracking management system',
    defaultAutonomous: true,
  },
  tag_ioc: {
    name: 'tag_ioc',
    level: 3,
    tier: 'UNDOABLE',
    description: 'Tag IP/hash indicator in threat intelligence database',
    defaultAutonomous: true,
  },
  collect_logs: {
    name: 'collect_logs',
    level: 4,
    tier: 'UNDOABLE',
    description: 'Extract forensic event logs and system artifacts from endpoint',
    defaultAutonomous: true,
  },
  block_ip: {
    name: 'block_ip',
    level: 4,
    tier: 'UNDOABLE',
    description: 'Insert temporary ingress drop rule at edge firewall / iptables',
    defaultAutonomous: true,
  },
  kill_process: {
    name: 'kill_process',
    level: 5,
    tier: 'DISRUPTIVE',
    description: 'Send SIGKILL to malicious executable or suspicious process PID',
    defaultAutonomous: false,
  },
  isolate_host: {
    name: 'isolate_host',
    level: 5,
    tier: 'DISRUPTIVE',
    description: 'Sever network connectivity of endpoint leaving only SOC management interface',
    defaultAutonomous: false,
  },
  disable_account: {
    name: 'disable_account',
    level: 6,
    tier: 'DISRUPTIVE',
    description: 'Disable user identity in Active Directory / LDAP authentication provider',
    defaultAutonomous: false,
  },
  recover_system: {
    name: 'recover_system',
    level: 6,
    tier: 'DISRUPTIVE',
    description: 'Rebuild system image or restore configuration from golden baseline',
    defaultAutonomous: false,
  },
  shutdown_server: {
    name: 'shutdown_server',
    level: 7,
    tier: 'DESTRUCTIVE',
    description: 'Perform ACPI hardware shutdown / power cut to production host',
    defaultAutonomous: false,
  },
  delete_data: {
    name: 'delete_data',
    level: 7,
    tier: 'DESTRUCTIVE',
    description: 'Purge file records or drop database tables from storage volume',
    defaultAutonomous: false,
  },
};

export const AUTO_EXECUTE_MAX: RiskLevel = 4;
export const APPROVAL_REQUIRED_MIN: RiskLevel = 5;
export const NEVER_AUTONOMOUS: RiskLevel = 7;

export interface PolicyRule {
  id: string;
  action: string;
  name: string;
  check: (context: EvaluationContext) => { matched: boolean; reason?: string };
  enforce: 'REQUIRE_APPROVAL' | 'BLOCK';
}

export interface EvaluationContext {
  actionName: string;
  parameters: Record<string, unknown>;
  forensicsComplete?: boolean;
  incidentSeverity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  analystRole?: string;
}

export interface SafetyEvaluationResult {
  action: string;
  level: RiskLevel;
  tier: string;
  decision: 'AUTO_ALLOWED' | 'REQUIRE_APPROVAL' | 'BLOCKED';
  policyRuleTriggered: string | null;
  reason: string;
  requiresHumanSignoff: boolean;
  canExecuteAutonomously: boolean;
  timestamp: string;
}

export const DETERMINISTIC_POLICIES: PolicyRule[] = [
  {
    id: 'P001',
    action: 'isolate_host',
    name: 'Host Isolation Gate',
    check: (ctx) => ({
      matched: ctx.actionName === 'isolate_host',
      reason: 'P001 Enforced: Host network isolation disconnects enterprise assets and disrupts business continuity.',
    }),
    enforce: 'REQUIRE_APPROVAL',
  },
  {
    id: 'P002',
    action: 'disable_account',
    name: 'Account Disabling Gate',
    check: (ctx) => ({
      matched: ctx.actionName === 'disable_account',
      reason: 'P002 Enforced: Account lockout may disrupt critical enterprise services and requires authorized confirmation.',
    }),
    enforce: 'REQUIRE_APPROVAL',
  },
  {
    id: 'P003',
    action: 'shutdown_server',
    name: 'Server Shutdown Prohibition',
    check: (ctx) => ({
      matched: ctx.actionName === 'shutdown_server',
      reason: 'P003 Enforced: Hard server shutdown is strictly prohibited by SOC autonomous safety rules.',
    }),
    enforce: 'BLOCK',
  },
  {
    id: 'P004',
    action: 'delete_data',
    name: 'Data Deletion Prohibition',
    check: (ctx) => ({
      matched: ctx.actionName === 'delete_data',
      reason: 'P004 Enforced: Data deletion carries catastrophic operational risk and permanent evidence destruction.',
    }),
    enforce: 'BLOCK',
  },
  {
    id: 'P005',
    action: 'recover_system',
    name: 'Forensic Preservation Guard',
    check: (ctx) => {
      if (ctx.actionName !== 'recover_system') {
        return { matched: false };
      }
      if (!ctx.forensicsComplete) {
        return {
          matched: true,
          reason: 'P005 Enforced: System recovery before completing digital forensics destroys critical incident evidence.',
        };
      }
      return { matched: false };
    },
    enforce: 'BLOCK',
  },
];

/**
 * Evaluates an action through the deterministic policy rules and L0-L7 safety gate
 */
export function evaluateActionSafety(ctx: EvaluationContext): SafetyEvaluationResult {
  const definition = RISK_LADDER[ctx.actionName] || {
    name: ctx.actionName,
    level: 7 as RiskLevel,
    tier: 'DESTRUCTIVE',
    description: 'Unknown or unclassified security action',
    defaultAutonomous: false,
  };

  const timestamp = new Date().toISOString();

  // 1. Evaluate Deterministic Policy Rules (P001 - P005)
  for (const rule of DETERMINISTIC_POLICIES) {
    const { matched, reason } = rule.check(ctx);
    if (matched) {
      if (rule.enforce === 'BLOCK') {
        return {
          action: ctx.actionName,
          level: definition.level,
          tier: definition.tier,
          decision: 'BLOCKED',
          policyRuleTriggered: rule.id,
          reason: reason || `Action blocked by deterministic policy ${rule.id}`,
          requiresHumanSignoff: false,
          canExecuteAutonomously: false,
          timestamp,
        };
      } else if (rule.enforce === 'REQUIRE_APPROVAL') {
        return {
          action: ctx.actionName,
          level: definition.level,
          tier: definition.tier,
          decision: 'REQUIRE_APPROVAL',
          policyRuleTriggered: rule.id,
          reason: reason || `Approval required by deterministic policy ${rule.id}`,
          requiresHumanSignoff: true,
          canExecuteAutonomously: false,
          timestamp,
        };
      }
    }
  }

  // 2. Evaluate L0 - L7 Risk Ladder Thresholds
  if (definition.level >= NEVER_AUTONOMOUS) {
    return {
      action: ctx.actionName,
      level: definition.level,
      tier: definition.tier,
      decision: 'BLOCKED',
      policyRuleTriggered: 'L7_SAFETY_CEILING',
      reason: `Action at risk level L${definition.level} is categorized as destructive and cannot be executed autonomously.`,
      requiresHumanSignoff: false,
      canExecuteAutonomously: false,
      timestamp,
    };
  }

  if (definition.level >= APPROVAL_REQUIRED_MIN) {
    return {
      action: ctx.actionName,
      level: definition.level,
      tier: definition.tier,
      decision: 'REQUIRE_APPROVAL',
      policyRuleTriggered: `L${definition.level}_DISRUPTIVE_GATE`,
      reason: `Action at risk level L${definition.level} (${definition.tier}) requires human operator approval before execution.`,
      requiresHumanSignoff: true,
      canExecuteAutonomously: false,
      timestamp,
    };
  }

  // L0 - L4: Auto-executable tier
  return {
    action: ctx.actionName,
    level: definition.level,
    tier: definition.tier,
    decision: 'AUTO_ALLOWED',
    policyRuleTriggered: null,
    reason: `Action at risk level L${definition.level} (${definition.tier}) is safe for automated execution within defined operational constraints.`,
    requiresHumanSignoff: false,
    canExecuteAutonomously: true,
    timestamp,
  };
}

/**
 * Simulates the execution of an approved action
 */
export function simulateActionExecution(action: string, parameters: Record<string, unknown>): {
  success: boolean;
  executedAt: string;
  output: string;
  action: string;
} {
  const executedAt = new Date().toISOString();
  switch (action) {
    case 'block_ip':
      return {
        success: true,
        executedAt,
        action,
        output: `iptables -I INPUT -s ${parameters.ip || '198.51.100.23'} -j DROP [Rule applied to edge perimeter]`,
      };
    case 'isolate_host':
      return {
        success: true,
        executedAt,
        action,
        output: `Endpoint ${parameters.host || 'WIN-DC-01'} network adapters disabled; management tunnel preserved on TCP 443.`,
      };
    case 'kill_process':
      return {
        success: true,
        executedAt,
        action,
        output: `Process PID ${parameters.pid || 4892} terminated with SIGKILL (status 137). Process tree analyzed and freed.`,
      };
    case 'disable_account':
      return {
        success: true,
        executedAt,
        action,
        output: `Active Directory account "${parameters.account || 'CORP\\svc_backup'}" locked; all active Kerberos TGTs revoked.`,
      };
    case 'collect_logs':
      return {
        success: true,
        executedAt,
        action,
        output: `Forensic bundle collected from ${parameters.host || 'WIN-DC-01'}: 14,290 EventLog entries packaged to /var/soc/evidence/`,
      };
    case 'notify_analyst':
      return {
        success: true,
        executedAt,
        action,
        output: `High-priority alert dispatched to SOC Slack channel #soc-alerts and on-call pager.`,
      };
    default:
      return {
        success: true,
        executedAt,
        action,
        output: `Action "${action}" successfully executed with parameters: ${JSON.stringify(parameters)}`,
      };
  }
}
