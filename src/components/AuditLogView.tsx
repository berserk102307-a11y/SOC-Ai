import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  RefreshCw,
  RotateCcw,
  Hash,
  Link as LinkIcon,
  Filter,
  Eye,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../services/api.ts';
import type { AuditEvent, ChainVerificationResult, AuditActor } from '../types/index.ts';

interface AuditLogViewProps {
  events: AuditEvent[];
  verification: ChainVerificationResult | null;
  isTampered: boolean;
  onRefresh: () => void;
}

export const AuditLogView: React.FC<AuditLogViewProps> = ({
  events,
  verification,
  isTampered,
  onRefresh,
}) => {
  const [selectedActor, setSelectedActor] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [inspectEvent, setInspectEvent] = useState<AuditEvent | null>(null);
  const [loading, setLoading] = useState(false);
  const [tamperLoading, setTamperLoading] = useState(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'danger'; message: string } | null>(null);

  const actorColors: Record<AuditActor, { bg: string; text: string; border: string }> = {
    SYSTEM: { bg: 'bg-slate-800', text: 'text-slate-300', border: 'border-slate-700' },
    MODEL: { bg: 'bg-emerald-950/60', text: 'text-emerald-300', border: 'border-emerald-800' },
    USER: { bg: 'bg-blue-950/60', text: 'text-blue-300', border: 'border-blue-800' },
    MONITOR: { bg: 'bg-amber-950/60', text: 'text-amber-300', border: 'border-amber-800' },
  };

  const filteredEvents = events.filter(e => {
    if (selectedActor !== 'ALL' && e.actor !== selectedActor) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const inId = e.actorId.toLowerCase().includes(q);
      const inType = e.eventType.toLowerCase().includes(q);
      const inPayload = JSON.stringify(e.payload).toLowerCase().includes(q);
      const inHash = e.hash.toLowerCase().includes(q);
      return inId || inType || inPayload || inHash;
    }
    return true;
  });

  const handleVerify = async () => {
    setLoading(true);
    try {
      await api.verifyAuditChain();
      onRefresh();
      setNotification({
        type: 'success',
        message: 'Cryptographic hash chain verification complete: All blocks validated from Genesis to Head.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSimulateTamper = async (index: number) => {
    setTamperLoading(true);
    try {
      await api.simulateTamper(index, 'targetUser', 'INJECTED_ATTACKER_ACCOUNT');
      onRefresh();
      setNotification({
        type: 'danger',
        message: `Tamper simulated at block #${index}: Record payload modified. Cryptographic chain integrity check actively flags failure.`,
      });
    } catch (err: any) {
      setNotification({ type: 'danger', message: err.message });
    } finally {
      setTamperLoading(false);
    }
  };

  const handleRestoreChain = async () => {
    setTamperLoading(true);
    try {
      await api.restoreAuditChain();
      onRefresh();
      setNotification({
        type: 'success',
        message: 'Audit chain restored to pristine cryptographic baseline. Verification status: 100% valid.',
      });
    } finally {
      setTamperLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Overview Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <h1 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <LinkIcon className="w-4 h-4 text-slate-400" />
              <span>Append-Only Cryptographic Audit Log</span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                SHA-256 Linked
              </span>
            </h1>
            <p className="text-xs text-slate-400 max-w-3xl">
              NIST SP 800-92 Specification: Every activity is appended with actor, event type, payload, and the SHA-256 hash of the preceding row. Update and delete statements are blocked.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleVerify}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-100 hover:bg-white text-slate-950 font-medium text-xs transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Verify Chain Integrity</span>
            </button>

            {!isTampered ? (
              <button
                onClick={() => handleSimulateTamper(1)}
                disabled={tamperLoading || events.length < 2}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-mono transition"
                title="Simulates an attacker altering a historical event in the database to test tamper detection"
              >
                <span>Test DB Tampering (Event #1)</span>
              </button>
            ) : (
              <button
                onClick={handleRestoreChain}
                disabled={tamperLoading}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-600 transition"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Restore Chain</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Integrity Status Card */}
        {verification && (
          <div
            className={`mt-3.5 p-3 rounded-lg border text-xs flex flex-wrap items-center justify-between gap-3 ${
              verification.valid
                ? 'bg-slate-950 border-slate-800 text-slate-300'
                : 'bg-red-950/60 border-red-800 text-red-200'
            }`}
          >
            <div className="flex items-center gap-2.5">
              {verification.valid ? (
                <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0" />
              )}
              <div>
                <div className="font-semibold text-xs">
                  {verification.valid
                    ? 'Cryptographic Hash Chain Valid: Intact'
                    : 'INTEGRITY ALERT: Tampered Block Detected'}
                </div>
                <div className="font-mono text-[11px] text-slate-400">{verification.message}</div>
                {verification.brokenIndex !== undefined && (
                  <div className="mt-0.5 font-mono text-[11px] text-amber-300">
                    Failed Block Index: #{verification.brokenIndex} | Expected: {verification.expectedHash?.substring(0, 16)}... | Actual: {verification.actualHash?.substring(0, 16)}...
                  </div>
                )}
              </div>
            </div>

            <div className="text-right font-mono text-[11px] text-slate-400">
              <div>Total Blocks: {verification.totalEntries}</div>
              <div>Checked: {new Date(verification.lastVerifiedAt).toLocaleTimeString()}</div>
            </div>
          </div>
        )}

        {notification && (
          <div
            className={`mt-2.5 p-2.5 rounded text-xs flex items-center justify-between font-mono ${
              notification.type === 'success'
                ? 'bg-slate-950 border border-slate-800 text-slate-300'
                : 'bg-red-950/50 border border-red-800 text-red-200'
            }`}
          >
            <span>{notification.message}</span>
            <button
              onClick={() => setNotification(null)}
              className="text-slate-400 hover:text-white font-bold ml-2"
            >
              ✕
            </button>
          </div>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900 p-3 rounded-lg border border-slate-800">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-400 font-medium mr-1 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Actor:
          </span>
          {['ALL', 'SYSTEM', 'MODEL', 'USER', 'MONITOR'].map(actor => (
            <button
              key={actor}
              onClick={() => setSelectedActor(actor)}
              className={`px-2 py-1 rounded text-xs font-mono transition ${
                selectedActor === actor
                  ? 'bg-slate-700 text-slate-100 font-medium'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {actor}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search payload, hash, actor, type..."
            className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-700 font-mono"
          />
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-2.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between text-xs">
          <div className="font-medium text-slate-300">
            Audit Ledger ({filteredEvents.length} of {events.length} records)
          </div>
          <span className="text-[11px] text-slate-500 font-mono">
            SHA256(index + timestamp + actor + actorId + eventType + payload + prevHash)
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
              <tr>
                <th className="py-2.5 px-3 w-16">#</th>
                <th className="py-2.5 px-3 w-32">Timestamp</th>
                <th className="py-2.5 px-3 w-28">Actor</th>
                <th className="py-2.5 px-3 w-52">Event Type</th>
                <th className="py-2.5 px-3">Payload Summary</th>
                <th className="py-2.5 px-3 w-48">Cryptographic Link</th>
                <th className="py-2.5 px-3 w-14 text-center">View</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredEvents.map(evt => {
                const isGenesis = evt.index === 0;
                const isBroken = verification?.brokenIndex === evt.index;
                const actorStyle = actorColors[evt.actor] || actorColors.SYSTEM;

                return (
                  <tr
                    key={evt.id}
                    className={`transition hover:bg-slate-800/40 ${
                      isBroken ? 'bg-red-950/50 border-l-4 border-red-500' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3 text-slate-300">
                      <div className="flex items-center gap-1.5">
                        <span className="font-semibold">#{evt.index}</span>
                        {isGenesis && (
                          <span className="text-[9px] px-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            GENESIS
                          </span>
                        )}
                        {isBroken && (
                          <span className="text-[9px] px-1 rounded bg-red-900 text-red-200 border border-red-700">
                            ALTERED
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      {new Date(evt.timestamp).toLocaleTimeString([], {
                        hour12: false,
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      })}
                    </td>

                    <td className="py-2.5 px-3">
                      <div className="space-y-0.5">
                        <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium border ${actorStyle.bg} ${actorStyle.text} ${actorStyle.border}`}>
                          {evt.actor}
                        </span>
                        <div className="text-[10px] text-slate-400 truncate max-w-[120px]" title={evt.actorId}>
                          {evt.actorId}
                        </div>
                      </div>
                    </td>

                    <td className="py-2.5 px-3 font-semibold text-slate-200">
                      {evt.eventType}
                    </td>

                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      <div className="truncate max-w-md">
                        {JSON.stringify(evt.payload)}
                      </div>
                    </td>

                    <td className="py-2.5 px-3 text-[10px] space-y-0.5 text-slate-400">
                      <div className="truncate">
                        <span className="text-slate-600">prev:</span> {evt.prevHash.substring(0, 14)}...
                      </div>
                      <div className="truncate font-medium text-slate-300">
                        <span className="text-slate-600 font-normal">hash:</span> {evt.hash.substring(0, 14)}...
                      </div>
                    </td>

                    <td className="py-2.5 px-3 text-center">
                      <button
                        onClick={() => setInspectEvent(evt)}
                        className="p-1 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 transition"
                        title="View Full Cryptographic Block Details"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspect Modal */}
      {inspectEvent && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-2xl w-full p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Hash className="w-4 h-4 text-slate-400" />
                <h3 className="font-semibold text-slate-100 text-sm">
                  Audit Entry #{inspectEvent.index} Details
                </h3>
              </div>
              <button
                onClick={() => setInspectEvent(null)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="grid grid-cols-2 gap-2 p-2.5 rounded bg-slate-950 border border-slate-800">
                <div>
                  <span className="text-slate-500 block text-[10px]">Actor &amp; Source:</span>
                  <span className="text-slate-200">{inspectEvent.actor} ({inspectEvent.actorId})</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Timestamp:</span>
                  <span className="text-slate-300">{inspectEvent.timestamp}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Event Type:</span>
                  <span className="text-slate-200 font-semibold">{inspectEvent.eventType}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Event ID:</span>
                  <span className="text-slate-400">{inspectEvent.id}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 block mb-1 text-[11px]">Previous Block Hash (prevHash):</span>
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-400 break-all select-all text-[11px]">
                  {inspectEvent.prevHash}
                </div>
              </div>

              <div>
                <span className="text-slate-300 block mb-1 text-[11px] font-semibold">Block Hash (hash):</span>
                <div className="p-2 rounded bg-slate-950 border border-slate-700 text-slate-200 break-all select-all font-semibold text-[11px]">
                  {inspectEvent.hash}
                </div>
              </div>

              <div>
                <span className="text-slate-400 block mb-1 text-[11px]">Payload:</span>
                <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-300 overflow-x-auto text-[11px] max-h-56">
                  {JSON.stringify(inspectEvent.payload, null, 2)}
                </pre>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setInspectEvent(null)}
                className="px-3.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
