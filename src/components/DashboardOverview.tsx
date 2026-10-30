/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCcw,
  Clock,
  Terminal,
  Activity,
  ChevronRight,
  Server,
  Zap,
  Lock,
  FileCheck2,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Cpu,
} from 'lucide-react';
import type {
  DashboardOverviewData,
  WazuhAlert,
  UserProfile,
  UserPermissions,
  ScenarioDefinition,
} from '../types/index.ts';
import { api } from '../services/api.ts';

interface DashboardOverviewProps {
  overviewData: DashboardOverviewData | null;
  scenarios: ScenarioDefinition[];
  user: UserProfile | null;
  permissions: UserPermissions | null;
  onNavigateTab: (tab: string) => void;
  onRefreshData: () => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  overviewData,
  scenarios,
  user,
  permissions,
  onNavigateTab,
  onRefreshData,
}) => {
  const [runningScenario, setRunningScenario] = useState<string | null>(null);
  const [scenarioResult, setScenarioResult] = useState<{
    title: string;
    alertsCount: number;
    evaluations: any[];
  } | null>(null);
  const [autoQueueApprovals, setAutoQueueApprovals] = useState(true);

  const handleRunScenario = async (scenarioId: string) => {
    setRunningScenario(scenarioId);
    try {
      const res = await api.replayScenario(scenarioId, autoQueueApprovals);
      setScenarioResult({
        title: res.scenario.title,
        alertsCount: res.alertsGenerated,
        evaluations: res.actionEvaluations,
      });
      onRefreshData();
    } catch (err: any) {
      alert(`Scenario execution error: ${err.message}`);
    } finally {
      setRunningScenario(null);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30';
      case 'LOW':
      default:
        return 'bg-slate-500/10 text-slate-300 border-slate-500/30';
    }
  };

  const stats = overviewData?.wazuhStats || {
    totalAlerts: 0,
    severityCounts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    topRules: [],
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / System Status */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900/80 border border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold text-white font-mono">SOC COMMAND CENTER</h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                ACTIVE
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Wazuh SIEM Ingestion • Deterministic Policy Rules (P001–P005) • NIST SP 800-92 Hash Ledger
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end md:self-auto">
          <button
            onClick={() => onNavigateTab('ollama')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-cyan-950/70 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800/60 transition font-mono shadow-sm"
          >
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            Ollama AI Diagnostics
          </button>
          <button
            onClick={onRefreshData}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Wazuh Alerts */}
        <div
          onClick={() => onNavigateTab('wazuh')}
          className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
            <span>INGESTED ALERTS</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{stats.totalAlerts}</div>
          <div className="mt-2 flex items-center gap-1.5 text-[11px] font-mono">
            <span className="text-rose-400 font-semibold">{stats.severityCounts.CRITICAL} Crit</span>
            <span className="text-slate-600">•</span>
            <span className="text-amber-400 font-semibold">{stats.severityCounts.HIGH} High</span>
            <span className="text-slate-600">•</span>
            <span className="text-yellow-400">{stats.severityCounts.MEDIUM} Med</span>
            <span className="text-slate-600">•</span>
            <span className="text-slate-400">{stats.severityCounts.LOW} Low</span>
          </div>
        </div>

        {/* Pending Approvals */}
        <div
          onClick={() => onNavigateTab('approvals')}
          className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
            <span>PENDING APPROVALS</span>
            <FileCheck2 className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-300 font-mono">
            {overviewData?.approvals.pendingCount ?? 0}
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1">
            <span>Disruptive L5/L6 remediations queued</span>
            <ArrowRight className="w-3 h-3 text-slate-500" />
          </div>
        </div>

        {/* Audit Ledger Integrity */}
        <div
          onClick={() => onNavigateTab('audit')}
          className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
            <span>AUDIT LEDGER</span>
            <Lock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">
            {overviewData?.auditLedger.totalBlocks ?? 0}{' '}
            <span className="text-xs font-normal text-slate-400">Blocks</span>
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-[11px] font-mono">
            {overviewData?.auditLedger.valid ? (
              <span className="text-emerald-400 flex items-center gap-1 font-semibold">
                <CheckCircle2 className="w-3 h-3" /> SHA-256 Valid
              </span>
            ) : (
              <span className="text-rose-400 flex items-center gap-1 font-semibold">
                <XCircle className="w-3 h-3" /> TAMPER DETECTED
              </span>
            )}
          </div>
        </div>

        {/* Triage Incidents */}
        <div
          onClick={() => onNavigateTab('investigations')}
          className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
            <span>ACTIVE INCIDENTS</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">
            {overviewData?.incidents.totalCount ?? 0}
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1">
            <span>Evidence pack &amp; grounding verified</span>
            <ArrowRight className="w-3 h-3 text-slate-500" />
          </div>
        </div>
      </div>

      {/* Attack Scenario Replay Bar */}
      <div className="p-4 rounded-lg bg-slate-900/70 border border-slate-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-white font-mono">ATTACK DRILL &amp; SCENARIO REPLAY</h3>
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoQueueApprovals}
              onChange={e => setAutoQueueApprovals(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span>Auto-queue disruptive actions to Approval Inbox</span>
          </label>
        </div>

        <p className="text-xs text-slate-400">
          Simulate multi-stage cyber attacks to test Wazuh rule correlation, L0–L7 risk thresholds, deterministic policies (P001–P005), and cryptographic parameter hashing.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
          {scenarios.map(sc => (
            <div
              key={sc.id}
              className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-1.5">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadge(sc.severity)}`}>
                    {sc.severity}
                  </span>
                  <span className="text-[11px] font-mono text-slate-500">Rule {sc.wazuhRuleId} (L{sc.wazuhLevel})</span>
                </div>
                <h4 className="text-xs font-semibold text-slate-200 mb-1">{sc.title}</h4>
                <div className="text-[11px] font-mono text-cyan-400 mb-2">{sc.mitreTechnique}</div>
                <p className="text-[11px] text-slate-400 line-clamp-2 mb-3">{sc.description}</p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between gap-2">
                <div className="text-[10px] font-mono text-slate-500">
                  Target: {sc.targetAgent.split(' ')[0]}
                </div>
                <button
                  disabled={runningScenario === sc.id}
                  onClick={() => handleRunScenario(sc.id)}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-medium bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition"
                >
                  {runningScenario === sc.id ? (
                    <>
                      <RotateCcw className="w-3 h-3 animate-spin" />
                      <span>Replaying...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3 h-3 fill-current" />
                      <span>Replay Drill</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Drill Output Modal/Feedback Banner */}
        {scenarioResult && (
          <div className="p-3.5 rounded-lg bg-cyan-950/40 border border-cyan-800/50 text-xs text-cyan-200 animate-in fade-in">
            <div className="flex items-center justify-between font-mono font-semibold text-cyan-300 mb-2">
              <span>DRILL EXECUTED: {scenarioResult.title}</span>
              <button
                onClick={() => setScenarioResult(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            <div className="text-slate-300 text-[11px] mb-2">
              Ingested <strong className="text-white">{scenarioResult.alertsCount}</strong> Wazuh syslog alerts into active store and ledger.
            </div>
            <div className="space-y-1.5">
              {scenarioResult.evaluations.map((ev, i) => (
                <div key={i} className="flex flex-wrap items-center gap-2 font-mono text-[11px] bg-slate-900/80 p-2 rounded border border-slate-800">
                  <span className="text-slate-400">Action:</span>
                  <span className="text-white font-semibold">{ev.actionName}</span>
                  <span className="text-slate-600">→</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] ${
                      ev.evaluation.decision === 'AUTO_ALLOWED'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : ev.evaluation.decision === 'REQUIRE_APPROVAL'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    }`}
                  >
                    {ev.evaluation.decision}
                  </span>
                  <span className="text-slate-400 text-[10px]">({ev.evaluation.reason})</span>
                  {ev.createdApprovalId && (
                    <span className="text-cyan-400 text-[10px] ml-auto">
                      Approval #{ev.createdApprovalId} Created
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Two-Column Telemetry: Recent Alerts & Pending Approvals */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: Recent Wazuh Alerts */}
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white font-mono">LIVE WAZUH INGESTION FEED</h3>
              </div>
              <button
                onClick={() => onNavigateTab('wazuh')}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <span>View Full Stream</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="divide-y divide-slate-800/80 mt-2">
              {overviewData?.recentAlerts && overviewData.recentAlerts.length > 0 ? (
                overviewData.recentAlerts.map(alert => (
                  <div key={alert.id} className="py-2.5 flex items-start justify-between gap-3 text-xs">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 font-mono">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        <span className="text-slate-300 font-medium">Rule {alert.rule.id}</span>
                        <span className="text-slate-500 text-[11px]">[{alert.agent.name}]</span>
                      </div>
                      <p className="text-slate-300 text-xs">{alert.rule.description}</p>
                      <div className="text-[10px] font-mono text-slate-500">
                        {alert.data?.srcip && `Src: ${alert.data.srcip} • `}
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-8 text-center text-xs text-slate-500">No alerts ingested yet.</div>
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800/80 mt-4 flex items-center justify-between text-xs text-slate-400">
            <span>Severity rules 0-15 mapped to LOW/MED/HIGH/CRIT</span>
            <button
              onClick={() => onNavigateTab('safety')}
              className="text-cyan-400 hover:underline font-mono text-[11px]"
            >
              Test Safety Gate →
            </button>
          </div>
        </div>

        {/* Right Column: Pending Approvals & Policy Gate Status */}
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-amber-400" />
                <h3 className="text-sm font-semibold text-white font-mono">PENDING REMEDIATION APPROVALS</h3>
              </div>
              <button
                onClick={() => onNavigateTab('approvals')}
                className="text-xs font-mono text-amber-400 hover:text-amber-300 flex items-center gap-1"
              >
                <span>Open Inbox</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="divide-y divide-slate-800/80 mt-2">
              {overviewData?.approvals.pending && overviewData.approvals.pending.length > 0 ? (
                overviewData.approvals.pending.map(req => (
                  <div key={req.id} className="py-2.5 flex items-start justify-between gap-3 text-xs">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 font-mono">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                          {req.actionType}
                        </span>
                        <span className="text-slate-300 font-medium">Target: {req.parameters.target}</span>
                      </div>
                      <p className="text-slate-400 text-[11px]">{req.policyReason}</p>
                      <div className="text-[10px] font-mono text-slate-500">
                        SHA-256: {req.parameterHash.substring(0, 16)}...
                      </div>
                    </div>
                    <button
                      onClick={() => onNavigateTab('approvals')}
                      className="px-2 py-1 rounded text-[11px] font-medium bg-amber-600 hover:bg-amber-500 text-white transition self-center"
                    >
                      Review
                    </button>
                  </div>
                ))
              ) : (
                <div className="py-8 text-center text-xs text-slate-500">
                  No disruptive actions pending operator approval.
                </div>
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800/80 mt-4 flex items-center justify-between text-xs text-slate-400">
            <span>Deterministic Policy P001 &amp; P002 Enforced</span>
            <span className="font-mono text-emerald-400 text-[11px]">L5/L6 Gated</span>
          </div>
        </div>
      </div>
    </div>
  );
};
