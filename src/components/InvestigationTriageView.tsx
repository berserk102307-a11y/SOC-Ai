import React, { useState } from 'react';
import {
  FileText,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Check,
  Cpu,
  Clock,
  ExternalLink,
  ChevronRight,
  HelpCircle,
} from 'lucide-react';
import { api } from '../services/api.ts';
import type { IncidentFixture, InvestigationResult, UserProfile } from '../types/index.ts';

interface InvestigationTriageViewProps {
  incidents: IncidentFixture[];
  currentUser: UserProfile | null;
  onRefresh: () => void;
  onAuditUpdated: () => void;
}

export const InvestigationTriageView: React.FC<InvestigationTriageViewProps> = ({
  incidents,
  currentUser,
  onRefresh,
  onAuditUpdated,
}) => {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(
    incidents[0]?.id || ''
  );
  const [filterRule, setFilterRule] = useState<string>('ALL');
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);

  const selectedIncident = incidents.find(i => i.id === selectedIncidentId) || incidents[0];

  const filteredIncidents = incidents.filter(i => {
    if (filterRule !== 'ALL' && i.rule !== filterRule) return false;
    return true;
  });

  const handleRunInvestigation = async (mode: 'VALIDATED_LLM' | 'FALLBACK') => {
    if (!selectedIncident) return;
    setLoadingAction(mode);
    setFeedbackMsg(null);
    try {
      const res = await api.triggerInvestigation(selectedIncident.id, mode);
      setFeedbackMsg(
        mode === 'FALLBACK'
          ? 'Rule-based fallback triage executed. Status flagged as FALLBACK / NEEDS_REVIEW.'
          : 'Validated LLM investigation executed. Output passed all grounding checks.'
      );
      onRefresh();
      onAuditUpdated();
    } catch (err: any) {
      setFeedbackMsg(`Error: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  const severityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-300 border-red-800';
      case 'HIGH':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'MEDIUM':
        return 'bg-yellow-950 text-yellow-300 border-yellow-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const statusBadge = (st: string) => {
    switch (st) {
      case 'PENDING_APPROVAL':
        return 'bg-amber-900/40 text-amber-300 border-amber-700';
      case 'RESOLVED':
        return 'bg-emerald-900/40 text-emerald-300 border-emerald-700';
      case 'OPEN':
        return 'bg-blue-900/40 text-blue-300 border-blue-700';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const sourceBadge = (src: string) => {
    switch (src) {
      case 'LLM':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'FALLBACK':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'MOCK':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <FileText className="w-4 h-4 text-slate-400" />
              <span>Incident Triage &amp; Evidence Grounding Console</span>
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Deterministic evidence extraction and schema-validated triage pipeline. Facts (counts, IPs, time delta) are computed in code before evaluation.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-500 font-mono">Filter Rule:</span>
            {['ALL', 'R1_BRUTE_FORCE', 'R2_PASSWORD_SPRAY', 'R3_SUCCESS_AFTER_FAILURES'].map(rule => (
              <button
                key={rule}
                onClick={() => setFilterRule(rule)}
                className={`px-2 py-1 rounded text-[11px] font-mono transition ${
                  filterRule === rule
                    ? 'bg-slate-700 text-slate-100 font-medium'
                    : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {rule === 'ALL' ? 'All' : rule.split('_')[0]}
              </button>
            ))}
          </div>
        </div>

        {feedbackMsg && (
          <div className="mt-3 p-2.5 rounded bg-slate-950 border border-slate-700 text-xs text-slate-300 flex items-center gap-2 font-mono">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
            <span>{feedbackMsg}</span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column: Incidents List */}
        <div className="lg:col-span-4 space-y-2">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider px-1">
            Incident Fixtures ({filteredIncidents.length})
          </div>

          <div className="space-y-1.5">
            {filteredIncidents.map(inc => {
              const isSelected = selectedIncident?.id === inc.id;
              return (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncidentId(inc.id)}
                  className={`p-3 rounded-lg border cursor-pointer text-xs transition ${
                    isSelected
                      ? 'bg-slate-800 border-slate-600 shadow-sm'
                      : 'bg-slate-900 border-slate-800 hover:border-slate-700 hover:bg-slate-850'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-slate-300 font-medium text-[11px]">
                      {inc.id}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${severityBadge(inc.severity)}`}>
                        {inc.severity}
                      </span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${statusBadge(inc.status)}`}>
                        {inc.status}
                      </span>
                    </div>
                  </div>

                  <div className="text-slate-200 font-medium text-xs leading-snug">
                    {inc.title}
                  </div>

                  <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>{inc.rule}</span>
                    <span className="text-slate-300">{inc.evidencePack.totalAlerts} alerts</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Evidence Pack & Investigation Report */}
        {selectedIncident && (
          <div className="lg:col-span-8 space-y-4">
            {/* Incident Header & Execution Actions */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-4">
              <div className="flex flex-wrap items-start justify-between gap-3 pb-3 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                    <span className="text-slate-200 font-semibold">{selectedIncident.id}</span>
                    <span>•</span>
                    <span>Host: {selectedIncident.evidencePack.targetHost}</span>
                    <span>•</span>
                    <span className="text-slate-300">ATT&amp;CK: {selectedIncident.mitreTechnique}</span>
                  </div>
                  <h2 className="text-sm font-semibold text-slate-100 mt-1">
                    {selectedIncident.title}
                  </h2>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleRunInvestigation('VALIDATED_LLM')}
                    disabled={!!loadingAction}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 disabled:opacity-50 transition"
                  >
                    <Play className="w-3 h-3 text-emerald-400" />
                    <span>{loadingAction === 'VALIDATED_LLM' ? 'Running...' : 'Run Investigation'}</span>
                  </button>

                  <button
                    onClick={() => handleRunInvestigation('FALLBACK')}
                    disabled={!!loadingAction}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 disabled:opacity-50 transition"
                    title="Simulate model validation failure and test the deterministic fallback path"
                  >
                    <RotateCcw className="w-3 h-3 text-amber-400" />
                    <span>Test Fallback</span>
                  </button>
                </div>
              </div>

              {/* Evidence Pack (Deterministic Computed Facts) */}
              <div>
                <div className="text-xs font-semibold text-slate-300 mb-2">
                  Computed Facts (Deterministic Pre-Processing)
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono mb-3">
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500">Failed Logons:</div>
                    <div className="text-sm font-semibold text-slate-200">{selectedIncident.evidencePack.totalAlerts}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500">Time Window:</div>
                    <div className="text-sm font-semibold text-slate-200">{selectedIncident.evidencePack.timeSpanSeconds}s</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500">Distinct Source IPs:</div>
                    <div className="text-sm font-semibold text-slate-200 truncate">{selectedIncident.evidencePack.distinctSourceIps.join(', ')}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500">Distinct Accounts:</div>
                    <div className="text-sm font-semibold text-slate-200 truncate">{selectedIncident.evidencePack.distinctAccounts.join(', ')}</div>
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="text-[11px] text-slate-400 font-medium">Numbered Evidence Items:</div>
                  {selectedIncident.evidencePack.evidenceItems.map(item => (
                    <div
                      key={item.id}
                      className="p-2 rounded bg-slate-950 border border-slate-800/80 text-xs flex items-start gap-2"
                    >
                      <span className="font-mono text-slate-400 font-semibold px-1 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px]">
                        [{item.id}]
                      </span>
                      <div className="text-slate-300">
                        <span>{item.claim}</span>
                        <span className="text-slate-500 font-mono text-[10px] ml-2">({item.rawEvidence})</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Investigation Output */}
              <div className="pt-3 border-t border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5 text-slate-400" />
                    <span>Investigation Assessment</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${sourceBadge(selectedIncident.investigation.source)}`}>
                      Source: {selectedIncident.investigation.source} ({selectedIncident.investigation.model})
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Confidence: {(selectedIncident.investigation.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>

                <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-2 text-xs">
                  <div>
                    <span className="text-slate-400 font-medium">Summary: </span>
                    <span className="text-slate-200">{selectedIncident.investigation.summary}</span>
                  </div>

                  {/* Findings with citations */}
                  <div className="pt-1.5 space-y-1">
                    <div className="text-[11px] font-medium text-slate-400">Grounded Findings (Citing Evidence):</div>
                    {selectedIncident.investigation.findings.map((f, idx) => (
                      <div key={idx} className="text-slate-300 text-[11px] pl-3 border-l-2 border-slate-700">
                        {f}
                      </div>
                    ))}
                  </div>

                  {/* Segregated Hypotheses */}
                  <div className="pt-1.5 space-y-1">
                    <div className="text-[11px] font-medium text-amber-400 flex items-center gap-1">
                      <HelpCircle className="w-3 h-3" />
                      <span>Unverified Hypotheses (Segregated from Facts):</span>
                    </div>
                    {selectedIncident.investigation.hypotheses.map((h, idx) => (
                      <div key={idx} className="text-amber-200/80 text-[11px] pl-3 border-l-2 border-amber-800 italic">
                        {h}
                      </div>
                    ))}
                  </div>

                  <div className="pt-1 flex items-center justify-between text-[11px] font-mono text-slate-400 border-t border-slate-800/80">
                    <span>Proposed Action: <code className="text-slate-200 font-bold">{selectedIncident.investigation.recommendedAction}</code></span>
                    <span>Latency: {selectedIncident.investigation.latencyMs}ms</span>
                  </div>
                </div>
              </div>

              {/* Grounding Validation Report */}
              <div className="pt-3 border-t border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-semibold text-slate-300">
                    Grounding &amp; Consistency Validation Report
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                      selectedIncident.investigation.validationReport.finalStatus === 'VERIFIED'
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                        : 'bg-amber-950 text-amber-300 border-amber-800'
                    }`}
                  >
                    {selectedIncident.investigation.validationReport.finalStatus}
                  </span>
                </div>

                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs space-y-1 font-mono">
                  {selectedIncident.investigation.validationReport.checks.map((chk, idx) => (
                    <div key={idx} className="flex items-center justify-between text-[11px] py-0.5">
                      <span className="text-slate-400">{chk.name}:</span>
                      <span className={chk.passed ? 'text-emerald-400 flex items-center gap-1' : 'text-rose-400'}>
                        {chk.passed ? <Check className="w-3 h-3" /> : '✕'} {chk.detail}
                      </span>
                    </div>
                  ))}
                  {selectedIncident.investigation.validationReport.warnings.map((w, idx) => (
                    <div key={idx} className="text-[11px] text-amber-400 pt-1">
                      {w}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
