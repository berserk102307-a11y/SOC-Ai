/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCcw,
  Sliders,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Lock,
  ArrowRight,
  Send,
} from 'lucide-react';
import type { ActionDefinition, DeterministicPolicy, SafetyEvaluation, UserProfile } from '../types/index.ts';
import { api } from '../services/api.ts';

interface SafetyGateSimulatorProps {
  user: UserProfile | null;
  onRefreshApprovals?: () => void;
  onNavigateTab?: (tab: string) => void;
}

export const SafetyGateSimulator: React.FC<SafetyGateSimulatorProps> = ({
  user,
  onRefreshApprovals,
  onNavigateTab,
}) => {
  const [ladder, setLadder] = useState<Record<string, ActionDefinition>>({});
  const [policies, setPolicies] = useState<DeterministicPolicy[]>([]);
  const [selectedAction, setSelectedAction] = useState<string>('block_ip');
  const [forensicsComplete, setForensicsComplete] = useState<boolean>(false);
  const [severity, setSeverity] = useState<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('MEDIUM');
  const [targetHost, setTargetHost] = useState<string>('WIN-DC-01');
  const [targetIp, setTargetIp] = useState<string>('198.51.100.23');
  const [targetAccount, setTargetAccount] = useState<string>('CORP\\svc_backup');
  const [targetPid, setTargetPid] = useState<string>('4892');

  const [evaluation, setEvaluation] = useState<SafetyEvaluation | null>(null);
  const [executionResult, setExecutionResult] = useState<any | null>(null);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [queueFeedback, setQueueFeedback] = useState<string | null>(null);

  useEffect(() => {
    api.getPolicyConfig().then(cfg => {
      setLadder(cfg.ladder);
      setPolicies(cfg.policies);
    }).catch(console.error);
  }, []);

  const handleEvaluate = async () => {
    setIsEvaluating(true);
    setExecutionResult(null);
    setQueueFeedback(null);
    try {
      const res = await api.evaluatePolicy({
        actionName: selectedAction,
        parameters: {
          host: targetHost,
          ip: targetIp,
          account: targetAccount,
          pid: Number(targetPid) || 4892,
        },
        forensicsComplete,
        incidentSeverity: severity,
      });
      setEvaluation(res);
    } catch (err: any) {
      alert(`Evaluation error: ${err.message}`);
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleExecuteSimulated = async () => {
    if (!evaluation || evaluation.decision !== 'AUTO_ALLOWED') return;
    setIsExecuting(true);
    try {
      const res = await api.executeSimulatedAction({
        actionName: selectedAction,
        parameters: {
          host: targetHost,
          ip: targetIp,
          account: targetAccount,
          pid: Number(targetPid) || 4892,
        },
        forensicsComplete,
      });
      setExecutionResult(res.execution);
    } catch (err: any) {
      alert(`Execution error: ${err.message}`);
    } finally {
      setIsExecuting(false);
    }
  };

  const currentActionDef = ladder[selectedAction];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800">
        <div className="flex items-center gap-2 mb-1">
          <Sliders className="w-4 h-4 text-cyan-400" />
          <h2 className="text-base font-semibold text-white font-mono">
            AUTONOMOUS SAFETY GATE &amp; POLICY EVALUATOR
          </h2>
        </div>
        <p className="text-xs text-slate-400">
          Evaluates remediation actions against the L0–L7 Risk Ladder and Deterministic Policies (P001–P005). Enforces strict autonomy ceilings (<span className="text-slate-200 font-mono">L0–L4 auto-run</span>, <span className="text-amber-400 font-mono">L5–L6 human approval</span>, <span className="text-rose-400 font-mono">L7 blocked</span>).
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Interactive Action Tester */}
        <div className="lg:col-span-7 space-y-4">
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
            <h3 className="text-xs font-semibold text-slate-300 font-mono flex items-center justify-between">
              <span>TEST SECURITY ACTION</span>
              {currentActionDef && (
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                  currentActionDef.level <= 4
                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                    : currentActionDef.level <= 6
                    ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    : 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                }`}>
                  Risk L{currentActionDef.level} • {currentActionDef.tier}
                </span>
              )}
            </h3>

            {/* Action Select */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Target Remediation Action:
              </label>
              <select
                value={selectedAction}
                onChange={e => {
                  setSelectedAction(e.target.value);
                  setEvaluation(null);
                  setExecutionResult(null);
                }}
                className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-700 text-xs text-white font-mono focus:border-cyan-500 focus:outline-none"
              >
                <optgroup label="L0–L2: Look & Enrich (Auto-run)">
                  <option value="notify_analyst">notify_analyst (L0 - Look)</option>
                  <option value="search_logs">search_logs (L1 - Look)</option>
                  <option value="ioc_enrichment">ioc_enrichment (L2 - Enrich)</option>
                </optgroup>
                <optgroup label="L3–L4: Undoable Changes (Auto-run permitted)">
                  <option value="create_record">create_record (L3 - Undoable)</option>
                  <option value="tag_ioc">tag_ioc (L3 - Undoable)</option>
                  <option value="collect_logs">collect_logs (L4 - Undoable)</option>
                  <option value="block_ip">block_ip (L4 - Undoable)</option>
                </optgroup>
                <optgroup label="L5–L6: Disruptive Actions (Approval Required)">
                  <option value="kill_process">kill_process (L5 - Disruptive)</option>
                  <option value="isolate_host">isolate_host (L5 - Disruptive • P001)</option>
                  <option value="disable_account">disable_account (L6 - Disruptive • P002)</option>
                  <option value="recover_system">recover_system (L6 - Disruptive • P005)</option>
                </optgroup>
                <optgroup label="L7: Destructive Actions (Strictly Blocked)">
                  <option value="shutdown_server">shutdown_server (L7 - Destructive • P003)</option>
                  <option value="delete_data">delete_data (L7 - Destructive • P004)</option>
                </optgroup>
              </select>
              {currentActionDef && (
                <p className="mt-1.5 text-[11px] text-slate-400">
                  {currentActionDef.description}
                </p>
              )}
            </div>

            {/* Parameters Grid */}
            <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-800">
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">Target Host:</label>
                <input
                  type="text"
                  value={targetHost}
                  onChange={e => setTargetHost(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-white font-mono"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">Source / Target IP:</label>
                <input
                  type="text"
                  value={targetIp}
                  onChange={e => setTargetIp(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-white font-mono"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">Target User Account:</label>
                <input
                  type="text"
                  value={targetAccount}
                  onChange={e => setTargetAccount(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-white font-mono"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">Process PID (if applicable):</label>
                <input
                  type="text"
                  value={targetPid}
                  onChange={e => setTargetPid(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-white font-mono"
                />
              </div>
            </div>

            {/* Special Forensics Toggle for Rule P005 */}
            <div className="p-3 rounded bg-slate-950/80 border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                  Digital Forensics Preservation State (Rule P005)
                </span>
                <p className="text-[11px] text-slate-400">
                  Controls whether evidence collection and disk memory capture is verified complete.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setForensicsComplete(!forensicsComplete)}
                className={`px-3 py-1 rounded text-xs font-mono font-medium transition border ${
                  forensicsComplete
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                    : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                }`}
              >
                {forensicsComplete ? 'FORENSICS COMPLETE' : 'FORENSICS INCOMPLETE'}
              </button>
            </div>

            {/* Evaluate Button */}
            <button
              onClick={handleEvaluate}
              disabled={isEvaluating}
              className="w-full py-2.5 px-4 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-mono text-xs font-semibold transition flex items-center justify-center gap-2"
            >
              {isEvaluating ? (
                <>
                  <RotateCcw className="w-4 h-4 animate-spin" />
                  <span>Evaluating Safety Matrix...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Evaluate Action Through Safety Gate</span>
                </>
              )}
            </button>
          </div>

          {/* Evaluation Outcome Display */}
          {evaluation && (
            <div className={`p-4 rounded-lg border animate-in fade-in space-y-3 ${
              evaluation.decision === 'AUTO_ALLOWED'
                ? 'bg-emerald-950/20 border-emerald-500/40'
                : evaluation.decision === 'REQUIRE_APPROVAL'
                ? 'bg-amber-950/20 border-amber-500/40'
                : 'bg-rose-950/20 border-rose-500/40'
            }`}>
              <div className="flex items-center justify-between font-mono">
                <div className="flex items-center gap-2">
                  {evaluation.decision === 'AUTO_ALLOWED' && <CheckCircle2 className="w-5 h-5 text-emerald-400" />}
                  {evaluation.decision === 'REQUIRE_APPROVAL' && <AlertTriangle className="w-5 h-5 text-amber-400" />}
                  {evaluation.decision === 'BLOCKED' && <XCircle className="w-5 h-5 text-rose-400" />}
                  <span className={`text-sm font-bold ${
                    evaluation.decision === 'AUTO_ALLOWED'
                      ? 'text-emerald-300'
                      : evaluation.decision === 'REQUIRE_APPROVAL'
                      ? 'text-amber-300'
                      : 'text-rose-300'
                  }`}>
                    GATE DECISION: {evaluation.decision}
                  </span>
                </div>
                <span className="text-xs text-slate-400 font-mono">
                  L{evaluation.level} • {evaluation.tier}
                </span>
              </div>

              <div className="text-xs text-slate-300 bg-slate-950/60 p-3 rounded border border-slate-800/80 font-mono">
                {evaluation.reason}
              </div>

              {evaluation.policyRuleTriggered && (
                <div className="text-[11px] font-mono text-cyan-400 flex items-center gap-1.5">
                  <span>Policy Enforced:</span>
                  <span className="font-semibold text-white px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700">
                    {evaluation.policyRuleTriggered}
                  </span>
                </div>
              )}

              {/* Action Buttons based on decision */}
              <div className="pt-2 flex items-center justify-between gap-3">
                {evaluation.decision === 'AUTO_ALLOWED' && (
                  <button
                    onClick={handleExecuteSimulated}
                    disabled={isExecuting}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition"
                  >
                    {isExecuting ? 'Executing...' : 'Simulate Autonomous Execution'}
                  </button>
                )}

                {evaluation.decision === 'REQUIRE_APPROVAL' && (
                  <button
                    onClick={() => {
                      if (onNavigateTab) onNavigateTab('approvals');
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-medium bg-amber-600 hover:bg-amber-500 text-white transition"
                  >
                    <span>View Remediation Approvals Queue</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}

                {evaluation.decision === 'BLOCKED' && (
                  <div className="text-xs text-rose-400 font-mono font-medium">
                    Strictly prohibited by safety policy. Cannot be bypassed.
                  </div>
                )}
              </div>

              {/* Simulation Result Output */}
              {executionResult && (
                <div className="mt-3 p-3 rounded bg-slate-950 border border-emerald-500/30 text-xs font-mono text-emerald-300">
                  <div className="text-[10px] text-slate-400 mb-1">EXECUTION SIMULATOR OUTPUT:</div>
                  <div>{executionResult.output}</div>
                  <div className="text-[10px] text-slate-500 mt-1">Logged to SHA-256 Audit Ledger at {executionResult.executedAt}</div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column: Policy Architecture Rules Reference */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
            <h3 className="text-xs font-semibold text-slate-300 font-mono">
              DETERMINISTIC POLICIES (P001–P005)
            </h3>
            <div className="space-y-2 text-xs">
              <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800">
                <div className="flex items-center justify-between font-mono mb-1">
                  <span className="font-semibold text-cyan-400">P001: isolate_host</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    REQUIRE_APPROVAL
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Host network isolation disrupts enterprise services and client connectivity. Must have human sign-off.
                </p>
              </div>

              <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800">
                <div className="flex items-center justify-between font-mono mb-1">
                  <span className="font-semibold text-cyan-400">P002: disable_account</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    REQUIRE_APPROVAL
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Account lockouts may disrupt business processes or automated jobs.
                </p>
              </div>

              <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800">
                <div className="flex items-center justify-between font-mono mb-1">
                  <span className="font-semibold text-rose-400">P003: shutdown_server</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    BLOCK
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Hard ACPI shutdown of production hosts is strictly prohibited autonomously.
                </p>
              </div>

              <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800">
                <div className="flex items-center justify-between font-mono mb-1">
                  <span className="font-semibold text-rose-400">P004: delete_data</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    BLOCK
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Irreversible file or database purge causes catastrophic operational loss and evidence destruction.
                </p>
              </div>

              <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800">
                <div className="flex items-center justify-between font-mono mb-1">
                  <span className="font-semibold text-amber-400">P005: recover_system</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    BLOCK if Forensics Incomplete
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Reimaging or recovering before digital forensics preservation destroys incident evidence required for root-cause analysis.
                </p>
              </div>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2 text-xs">
            <h3 className="font-semibold text-slate-300 font-mono">RISK LADDER THRESHOLDS</h3>
            <ul className="space-y-1.5 text-slate-400 font-mono text-[11px]">
              <li className="flex items-center justify-between">
                <span>_AUTO_EXECUTE_MAX</span>
                <span className="text-emerald-400 font-bold">Level 4 (Undoable)</span>
              </li>
              <li className="flex items-center justify-between">
                <span>_APPROVAL_REQUIRED_MIN</span>
                <span className="text-amber-400 font-bold">Level 5 (Disruptive)</span>
              </li>
              <li className="flex items-center justify-between">
                <span>_NEVER_AUTONOMOUS</span>
                <span className="text-rose-400 font-bold">Level 7 (Destructive)</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
