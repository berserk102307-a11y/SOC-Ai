import React, { useState } from 'react';
import {
  FileCheck2,
  Clock,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  Hash,
  Info,
  Bug,
} from 'lucide-react';
import { api } from '../services/api.ts';
import type { ApprovalRequest, UserProfile, ActionParameters } from '../types/index.ts';

interface ApprovalInboxProps {
  approvals: ApprovalRequest[];
  currentUser: UserProfile | null;
  onRefresh: () => void;
  onAuditUpdated: () => void;
}

export const ApprovalInbox: React.FC<ApprovalInboxProps> = ({
  approvals,
  currentUser,
  onRefresh,
  onAuditUpdated,
}) => {
  const [decisionModal, setDecisionModal] = useState<{
    req: ApprovalRequest;
    decision: 'APPROVE' | 'REJECT';
  } | null>(null);
  const [decisionReason, setDecisionReason] = useState('');
  const [tamperSimActive, setTamperSimActive] = useState(false);
  const [tamperedIp, setTamperedIp] = useState('8.8.8.8');
  const [loading, setLoading] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const canApprove = currentUser?.role === 'APPROVER' || currentUser?.role === 'ADMIN';

  const handleDecisionSubmit = async () => {
    if (!decisionModal || !decisionReason.trim()) return;
    setLoading(true);
    setActionError(null);
    setActionSuccess(null);

    try {
      let clientParams: ActionParameters | undefined = undefined;

      if (tamperSimActive) {
        clientParams = {
          ...decisionModal.req.parameters,
          target: tamperedIp,
        };
      }

      const res = await api.decideApproval(
        decisionModal.req.id,
        decisionModal.decision,
        decisionReason,
        clientParams
      );

      setActionSuccess(res.message);
      setDecisionModal(null);
      setDecisionReason('');
      setTamperSimActive(false);
      onRefresh();
      onAuditUpdated();
    } catch (err: any) {
      setActionError(err.message || 'Approval decision rejected.');
      onAuditUpdated();
    } finally {
      setLoading(false);
    }
  };

  const statusBadge = (status: string) => {
    switch (status) {
      case 'PENDING':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'APPROVED':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'REJECTED':
        return 'bg-red-950 text-red-300 border-red-800';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="space-y-5">
      {/* Overview & Security Architecture Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <h1 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <FileCheck2 className="w-4 h-4 text-slate-400" />
              <span>Remediation Authorization Queue</span>
            </h1>
            <p className="text-xs text-slate-400 max-w-3xl">
              Disruptive firewall and containment actions require verified human sign-off. Proposals are bound to an immutable SHA-256 parameter hash to prevent unauthorized payload manipulation.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs px-2.5 py-1 rounded border border-slate-800 bg-slate-950 font-mono text-slate-300">
              Active Role: <strong className="text-slate-100">{currentUser?.role || 'GUEST'}</strong>
            </span>
          </div>
        </div>

        {/* Segregation of Duties Notice */}
        {!canApprove && (
          <div className="mt-3.5 p-3 rounded bg-slate-950 border border-slate-800 text-slate-400 text-xs flex items-start gap-2">
            <Info className="w-4 h-4 text-slate-400 flex-shrink-0 mt-0.5" />
            <div>
              <span className="text-slate-200 font-medium">Role Restriction:</span> Logged in as <strong className="font-mono text-slate-300">ANALYST</strong>. Analysts have view-only access on remediation proposals. Authorization requires the <strong className="font-mono text-slate-300">APPROVER</strong> or <strong className="font-mono text-slate-300">ADMIN</strong> role.
            </div>
          </div>
        )}

        {actionSuccess && (
          <div className="mt-3 p-2.5 rounded bg-slate-950 border border-emerald-800 text-emerald-300 text-xs flex items-center gap-2 font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{actionSuccess}</span>
          </div>
        )}

        {actionError && (
          <div className="mt-3 p-2.5 rounded bg-slate-950 border border-red-800 text-red-300 text-xs flex items-center gap-2 font-mono">
            <AlertOctagon className="w-4 h-4 text-red-400" />
            <span>{actionError}</span>
          </div>
        )}
      </div>

      {/* Approvals List */}
      <div className="space-y-3">
        {approvals.length === 0 ? (
          <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-lg text-slate-400 text-xs">
            No remediation requests in queue.
          </div>
        ) : (
          approvals.map(req => {
            const isPending = req.status === 'PENDING';

            return (
              <div
                key={req.id}
                className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3"
              >
                {/* Header Row */}
                <div className="flex flex-wrap items-center justify-between gap-2.5">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${statusBadge(req.status)}`}>
                      {req.status}
                    </span>
                    <span className="text-slate-100 font-medium text-xs">
                      Action: <code className="text-slate-200 font-mono font-semibold">{req.actionType}</code>
                    </span>
                    <span className="text-slate-600 text-xs">|</span>
                    <span className="text-slate-400 text-xs font-mono">ID: {req.id}</span>
                  </div>

                  <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                    <span>Requested: {new Date(req.requestedAt).toLocaleTimeString()}</span>
                    {isPending && (
                      <span className="text-amber-400 ml-1">
                        (Expires: {new Date(req.expiresAt).toLocaleTimeString()})
                      </span>
                    )}
                  </div>
                </div>

                {/* Content Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800 space-y-1.5 font-mono">
                    <div className="text-slate-400 font-medium">Parameters:</div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-slate-500">Target:</span>
                      <span className="text-slate-200 font-bold">{req.parameters.target}</span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-slate-500">TTL:</span>
                      <span className="text-slate-300">{req.parameters.ttlMinutes}m</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800 space-y-1">
                    <div className="text-slate-400 font-medium">Context:</div>
                    <div className="text-slate-300 text-[11px] leading-relaxed">
                      {req.incidentSummary}
                    </div>
                    <div className="text-[10px] font-mono text-slate-400 pt-1">
                      {req.mitreTechnique}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800 space-y-1 font-mono">
                    <div className="text-slate-400 font-medium flex items-center gap-1">
                      <Hash className="w-3.5 h-3.5 text-slate-400" />
                      <span>SHA-256 Parameter Hash:</span>
                    </div>
                    <div className="p-1 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-300 break-all select-all">
                      {req.parameterHash}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      Cryptographically bound to prevent parameter alteration.
                    </div>
                  </div>
                </div>

                {/* Decision Row */}
                <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2.5">
                  <div className="text-xs text-slate-400">
                    {req.decidedBy && (
                      <span>
                        Decided by <strong className="text-slate-200 font-mono">{req.decidedBy}</strong> ({req.decidedRole}) at {new Date(req.decidedAt!).toLocaleTimeString()} — "{req.decisionReason}"
                      </span>
                    )}
                  </div>

                  {isPending && (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          setDecisionModal({ req, decision: 'REJECT' });
                          setDecisionReason('False positive indication; containment rejected.');
                          setTamperSimActive(false);
                        }}
                        disabled={!canApprove}
                        className="px-3 py-1.5 rounded text-xs font-medium border border-slate-700 bg-slate-950 hover:bg-slate-800 text-slate-300 disabled:opacity-40 transition"
                      >
                        Reject
                      </button>

                      <button
                        onClick={() => {
                          setDecisionModal({ req, decision: 'APPROVE' });
                          setDecisionReason('Confirmed malicious authentication assault; temporary block authorized.');
                          setTamperSimActive(false);
                        }}
                        disabled={!canApprove}
                        className="px-3.5 py-1.5 rounded text-xs font-semibold bg-slate-100 hover:bg-white text-slate-950 disabled:opacity-40 transition"
                      >
                        Authorize Action
                      </button>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Decision Modal */}
      {decisionModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-lg w-full p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="font-semibold text-slate-100 text-sm">
                Confirm {decisionModal.decision === 'APPROVE' ? 'Authorization' : 'Rejection'}
              </h3>
              <button
                onClick={() => setDecisionModal(null)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs space-y-1 font-mono">
              <div className="flex justify-between">
                <span className="text-slate-500">Action:</span>
                <span className="text-slate-200 font-semibold">{decisionModal.req.actionType}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Target Entity:</span>
                <span className="text-slate-200 font-semibold">{decisionModal.req.parameters.target}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Parameter Hash:</span>
                <span className="text-slate-400">{decisionModal.req.parameterHash.substring(0, 16)}...</span>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Mandatory Operational Justification:
              </label>
              <textarea
                value={decisionReason}
                onChange={e => setDecisionReason(e.target.value)}
                rows={3}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-700"
                placeholder="Document operational reason for audit trail..."
              />
            </div>

            {/* Parameter Tampering Security Test */}
            <div className="p-2.5 rounded bg-slate-950 border border-dashed border-slate-700 space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                  <Bug className="w-3.5 h-3.5 text-slate-400" />
                  <span>Test Parameter Tampering Defense</span>
                </div>
                <label className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={tamperSimActive}
                    onChange={e => setTamperSimActive(e.target.checked)}
                    className="rounded bg-slate-900 border-slate-700 text-slate-500"
                  />
                  <span>Simulate Attack</span>
                </label>
              </div>

              {tamperSimActive && (
                <div className="space-y-1.5 text-xs">
                  <p className="text-[11px] text-slate-400">
                    Simulates in-transit modification of target entity (e.g. changing IP to <code className="text-slate-300 font-mono">8.8.8.8</code>). The server recalculates SHA-256 and rejects the mismatch.
                  </p>
                  <div className="flex items-center gap-2 font-mono text-[11px]">
                    <span className="text-slate-500">Altered Target:</span>
                    <input
                      type="text"
                      value={tamperedIp}
                      onChange={e => setTamperedIp(e.target.value)}
                      className="bg-slate-900 border border-slate-700 px-2 py-0.5 rounded text-xs text-slate-200 font-mono"
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="pt-2 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDecisionModal(null)}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDecisionSubmit}
                disabled={loading || !decisionReason.trim()}
                className="px-4 py-1.5 rounded text-xs font-semibold bg-slate-100 hover:bg-white text-slate-950 transition disabled:opacity-50"
              >
                {loading ? 'Processing...' : `Confirm ${decisionModal.decision}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
