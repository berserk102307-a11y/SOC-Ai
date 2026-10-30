import React, { useState } from 'react';
import {
  KeyRound,
  ShieldCheck,
  Plus,
  Trash2,
  Copy,
  Check,
  Info,
  Server,
  Lock,
} from 'lucide-react';
import { api } from '../services/api.ts';
import type { StoredApiKeyItem, UserProfile } from '../types/index.ts';

interface ApiKeyManagerProps {
  apiKeys: StoredApiKeyItem[];
  seedRawKey: string;
  currentUser: UserProfile | null;
  onRefresh: () => void;
  onAuditUpdated: () => void;
}

export const ApiKeyManager: React.FC<ApiKeyManagerProps> = ({
  apiKeys,
  seedRawKey,
  currentUser,
  onRefresh,
  onAuditUpdated,
}) => {
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [name, setName] = useState('');
  const [host, setHost] = useState('');
  const [createdKeyData, setCreatedKeyData] = useState<{ rawKey: string; record: StoredApiKeyItem } | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = currentUser?.role === 'ADMIN';

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !host.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const res = await api.createApiKey(name, host);
      setCreatedKeyData({ rawKey: res.rawKey, record: res.keyRecord });
      setName('');
      setHost('');
      onRefresh();
      onAuditUpdated();
    } catch (err: any) {
      setError(err.message || 'Failed to generate key.');
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (id: string) => {
    if (!window.confirm(`Revoke Sensor API Key ${id}? Any further telemetry from this sensor will be rejected with HTTP 401.`)) {
      return;
    }
    try {
      await api.revokeApiKey(id);
      onRefresh();
      onAuditUpdated();
    } catch (err: any) {
      alert(err.message || 'Failed to revoke key.');
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  return (
    <div className="space-y-5">
      {/* Header and Security Spec */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <h1 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-slate-400" />
              <span>Windows Monitor Sensor API Key Management</span>
            </h1>
            <p className="text-xs text-slate-400 max-w-3xl">
              Sensor Ingestion Authentication: Each host runs a native Windows monitor sending <code className="text-slate-300 font-mono">X-Monitor-API-Key</code>. The server persists only the cryptographic SHA-256 hash. Authentication is performed via <code className="text-slate-300 font-mono">timingSafeEqual</code> in constant time to thwart timing side-channel attacks.
            </p>
          </div>

          <button
            onClick={() => setShowCreateModal(true)}
            disabled={!isAdmin}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition ${
              isAdmin
                ? 'bg-slate-100 hover:bg-white text-slate-950 font-semibold'
                : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
            }`}
            title={!isAdmin ? 'ADMIN role required to issue keys' : 'Generate new sensor key'}
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Generate 32-Byte Key</span>
          </button>
        </div>

        {!isAdmin && (
          <div className="mt-3.5 p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-400 text-xs flex items-center gap-2">
            <Info className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
            <span>
              Role Notice: Only <strong className="font-mono text-slate-300">ADMIN</strong> users can generate or revoke Monitor API Keys. (Currently logged in as <strong className="font-mono text-slate-300">{currentUser?.role || 'ANALYST'}</strong>).
            </span>
          </div>
        )}

        {/* Quick Seed Key Copy for Lab Testing */}
        <div className="mt-3.5 p-2.5 rounded bg-slate-950 border border-slate-800 text-xs flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Default Active Sensor Key (WIN-DC-01):</span>
            <code className="text-slate-200 font-mono select-all font-medium">{seedRawKey}</code>
          </div>
          <button
            onClick={() => handleCopy(seedRawKey)}
            className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono border border-slate-700"
          >
            {copiedKey ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copiedKey ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* API Keys Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-2.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between text-xs">
          <div className="font-medium text-slate-300 flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-slate-400" />
            <span>Registered Sensor Keys ({apiKeys.length})</span>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">
            Storage format: SHA-256 Digest Only
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 text-[11px]">
              <tr>
                <th className="py-2.5 px-3">Host FQDN</th>
                <th className="py-2.5 px-3">Label</th>
                <th className="py-2.5 px-3">Prefix</th>
                <th className="py-2.5 px-3">Persisted SHA-256 Digest</th>
                <th className="py-2.5 px-3">Created</th>
                <th className="py-2.5 px-3">Last Ingest</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-[11px]">
              {apiKeys.map(k => (
                <tr key={k.id} className="hover:bg-slate-800/40 transition">
                  <td className="py-2.5 px-3 font-semibold text-slate-200 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-slate-500" />
                    <span>{k.host}</span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">{k.name}</td>
                  <td className="py-2.5 px-3 text-slate-200">{k.keyPrefix}</td>
                  <td className="py-2.5 px-3 text-slate-400">
                    <span className="p-1 rounded bg-slate-950 border border-slate-800 text-[10px]">
                      {k.keyHashPreview}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400">
                    {new Date(k.createdAt).toLocaleDateString()}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400">
                    {k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleTimeString() : 'Never'}
                  </td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                        k.revoked
                          ? 'bg-red-950 text-red-400 border-red-800'
                          : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                      }`}
                    >
                      {k.revoked ? 'REVOKED' : 'ACTIVE'}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-center">
                    {!k.revoked && (
                      <button
                        onClick={() => handleRevoke(k.id)}
                        disabled={!isAdmin}
                        className={`p-1 rounded transition ${
                          isAdmin
                            ? 'text-slate-400 hover:text-red-400 hover:bg-slate-800'
                            : 'text-slate-700 cursor-not-allowed'
                        }`}
                        title={!isAdmin ? 'ADMIN required' : 'Revoke Sensor Key'}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Key Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-md w-full p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-slate-400" />
                <span>Issue Sensor API Key</span>
              </h3>
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setCreatedKeyData(null);
                }}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            {error && (
              <div className="p-2.5 rounded bg-red-950/60 border border-red-800 text-red-200 text-xs">
                {error}
              </div>
            )}

            {!createdKeyData ? (
              <form onSubmit={handleCreate} className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Sensor Label:
                  </label>
                  <input
                    type="text"
                    value={name}
                    onChange={e => setName(e.target.value)}
                    required
                    placeholder="e.g. Windows DC Secondary VM-02"
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-slate-700"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Host FQDN:
                  </label>
                  <input
                    type="text"
                    value={host}
                    onChange={e => setHost(e.target.value)}
                    required
                    placeholder="e.g. WIN-DC-02.lab.local"
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono focus:outline-none focus:border-slate-700"
                  />
                </div>

                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400 space-y-1">
                  <span className="font-medium text-slate-300">Security Guarantee:</span>
                  <p>
                    A cryptographically random 32-byte key is generated. The server only persists the SHA-256 hash.
                  </p>
                </div>

                <div className="pt-2 flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-3.5 py-1.5 rounded bg-slate-100 hover:bg-white text-slate-950 font-semibold"
                  >
                    {loading ? 'Generating...' : 'Generate Key'}
                  </button>
                </div>
              </form>
            ) : (
              <div className="space-y-3 text-xs">
                <div className="p-2.5 rounded bg-slate-950 border border-slate-700 text-slate-300 space-y-1">
                  <div className="font-semibold flex items-center gap-1.5 text-slate-100">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    <span>Key Generated Successfully</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Store this key in your sensor configuration. The plaintext value cannot be recovered once closed.
                  </p>
                </div>

                <div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-slate-200 text-xs break-all select-all flex items-center justify-between">
                    <span>{createdKeyData.rawKey}</span>
                  </div>
                </div>

                <div className="pt-2 flex justify-end">
                  <button
                    onClick={() => {
                      setShowCreateModal(false);
                      setCreatedKeyData(null);
                    }}
                    className="px-3.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium"
                  >
                    Done
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
