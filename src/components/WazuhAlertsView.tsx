/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  Server,
  Search,
  Filter,
  Terminal,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Plus,
  RefreshCw,
  Clock,
  Shield,
  Layers,
} from 'lucide-react';
import type { WazuhAlert, WazuhStats, UserProfile } from '../types/index.ts';
import { api } from '../services/api.ts';

interface WazuhAlertsViewProps {
  user: UserProfile | null;
  onNavigateTab?: (tab: string) => void;
}

export const WazuhAlertsView: React.FC<WazuhAlertsViewProps> = ({ user, onNavigateTab }) => {
  const [alerts, setAlerts] = useState<WazuhAlert[]>([]);
  const [stats, setStats] = useState<WazuhStats | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [isLoading, setIsLoading] = useState(false);
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  // Manual Ingest Modal State
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [ruleIdInput, setRuleIdInput] = useState('5716');
  const [ruleLevelInput, setRuleLevelInput] = useState('10');
  const [ruleDescInput, setRuleDescInput] = useState('SSHD brute force trying to get access');
  const [agentNameInput, setAgentNameInput] = useState('SRV-UBUNTU-PROD');
  const [srcIpInput, setSrcIpInput] = useState('198.51.100.44');
  const [rawLogInput, setRawLogInput] = useState('sshd[5910]: Failed password for root from 198.51.100.44 port 48122 ssh2');

  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const [alertsRes, statsRes] = await Promise.all([
        api.getWazuhAlerts({
          limit: 100,
          severity: selectedSeverity === 'ALL' ? undefined : selectedSeverity,
          search: searchTerm,
        }),
        api.getWazuhStats(),
      ]);
      setAlerts(alertsRes.alerts);
      setStats(statsRes);
    } catch (err) {
      console.error('Failed to fetch Wazuh alerts:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [selectedSeverity]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchAlerts();
  };

  const handleManualIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.ingestWazuhAlert({
        rule: {
          id: Number(ruleIdInput) || 5716,
          level: Number(ruleLevelInput) || 10,
          description: ruleDescInput,
        },
        agent: {
          id: '002',
          name: agentNameInput,
        },
        data: {
          srcip: srcIpInput,
        },
        full_log: rawLogInput,
      });
      setShowIngestModal(false);
      fetchAlerts();
    } catch (err: any) {
      alert(`Ingestion failed: ${err.message}`);
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

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900/80 border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-white font-mono">
              WAZUH SIEM INGESTION &amp; LOG EXPLORER
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time syslog ingestion pipeline with rule-level normalization (0–15) to SOC severity tiers.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowIngestModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-medium bg-cyan-600 hover:bg-cyan-500 text-white transition"
          >
            <Plus className="w-3.5 h-3.5" />
            Ingest Custom Alert
          </button>
          <button
            onClick={fetchAlerts}
            className="p-1.5 rounded text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 transition"
            title="Refresh alerts"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Severity Breakdown Bar */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div
            onClick={() => setSelectedSeverity(selectedSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
            className={`p-3 rounded-lg border cursor-pointer transition ${
              selectedSeverity === 'CRITICAL'
                ? 'bg-rose-950/40 border-rose-500/60'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="text-[11px] font-mono text-slate-400">CRITICAL (L15)</div>
            <div className="text-xl font-bold font-mono text-rose-400">{stats.severityCounts.CRITICAL}</div>
          </div>

          <div
            onClick={() => setSelectedSeverity(selectedSeverity === 'HIGH' ? 'ALL' : 'HIGH')}
            className={`p-3 rounded-lg border cursor-pointer transition ${
              selectedSeverity === 'HIGH'
                ? 'bg-amber-950/40 border-amber-500/60'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="text-[11px] font-mono text-slate-400">HIGH (L12–L14)</div>
            <div className="text-xl font-bold font-mono text-amber-400">{stats.severityCounts.HIGH}</div>
          </div>

          <div
            onClick={() => setSelectedSeverity(selectedSeverity === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
            className={`p-3 rounded-lg border cursor-pointer transition ${
              selectedSeverity === 'MEDIUM'
                ? 'bg-yellow-950/40 border-yellow-500/60'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="text-[11px] font-mono text-slate-400">MEDIUM (L8–L11)</div>
            <div className="text-xl font-bold font-mono text-yellow-300">{stats.severityCounts.MEDIUM}</div>
          </div>

          <div
            onClick={() => setSelectedSeverity(selectedSeverity === 'LOW' ? 'ALL' : 'LOW')}
            className={`p-3 rounded-lg border cursor-pointer transition ${
              selectedSeverity === 'LOW'
                ? 'bg-slate-800/60 border-slate-600'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="text-[11px] font-mono text-slate-400">LOW (L0–L7)</div>
            <div className="text-xl font-bold font-mono text-slate-300">{stats.severityCounts.LOW}</div>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <form onSubmit={handleSearchSubmit} className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by rule ID, description, agent, or IP..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900/80 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 font-mono focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono font-medium text-slate-200 border border-slate-700 transition"
          >
            Filter
          </button>
        </div>
      </form>

      {/* Alerts Table */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 font-mono border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Rule ID &amp; Level</th>
                <th className="py-2.5 px-3">Description</th>
                <th className="py-2.5 px-3">Agent</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {alerts.length > 0 ? (
                alerts.map(alert => {
                  const isExpanded = expandedAlertId === alert.id;
                  return (
                    <React.Fragment key={alert.id}>
                      <tr className="hover:bg-slate-800/40 transition font-mono">
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(alert.severity)}`}>
                            {alert.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap text-slate-300">
                          <span>{alert.rule.id}</span>
                          <span className="text-slate-500 text-[10px] ml-1.5">(Level {alert.rule.level})</span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-200 max-w-md truncate font-sans text-xs">
                          {alert.rule.description}
                          {alert.rule.mitre?.technique && (
                            <span className="ml-2 font-mono text-[10px] text-cyan-400">
                              [{alert.rule.mitre.technique.join(', ')}]
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                          {alert.agent.name}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                          {alert.data?.srcip || '—'}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3 text-right whitespace-nowrap">
                          <button
                            onClick={() => setExpandedAlertId(isExpanded ? null : alert.id)}
                            className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-white transition"
                          >
                            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Raw Log Drawer */}
                      {isExpanded && (
                        <tr className="bg-slate-950/80 border-b border-slate-800/80">
                          <td colSpan={7} className="p-4 space-y-3 font-mono text-[11px]">
                            <div className="flex items-center justify-between text-slate-400">
                              <span className="font-semibold text-slate-300">RAW SYSLOG &amp; METADATA</span>
                              <span className="text-slate-500">Alert ID: {alert.id}</span>
                            </div>

                            <div className="p-3 rounded bg-slate-900 border border-slate-800 text-slate-300 whitespace-pre-wrap break-all">
                              {alert.full_log}
                            </div>

                            {alert.data && Object.keys(alert.data).length > 0 && (
                              <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800/80 text-slate-400 space-y-1">
                                <span className="text-[10px] text-slate-500 font-semibold block">PARSED ATTRIBUTES:</span>
                                {Object.entries(alert.data).map(([k, v]) => (
                                  <div key={k} className="flex gap-2">
                                    <span className="text-cyan-400">{k}:</span>
                                    <span className="text-slate-200">{String(v)}</span>
                                  </div>
                                ))}
                              </div>
                            )}

                            <div className="flex items-center justify-end gap-2 pt-1">
                              <button
                                onClick={() => {
                                  if (onNavigateTab) onNavigateTab('safety');
                                }}
                                className="px-2.5 py-1 rounded bg-cyan-700 hover:bg-cyan-600 text-white font-mono text-xs transition flex items-center gap-1"
                              >
                                <span>Test in Safety Gate</span>
                                <ExternalLink className="w-3 h-3" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-xs text-slate-500 font-mono">
                    No Wazuh alerts matching criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manual Ingest Modal */}
      {showIngestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl bg-slate-900 border border-slate-800 p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                INGEST CUSTOM WAZUH SYSLOG
              </h3>
              <button
                onClick={() => setShowIngestModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleManualIngest} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Rule ID:</label>
                  <input
                    type="number"
                    value={ruleIdInput}
                    onChange={e => setRuleIdInput(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Rule Level (0-15):</label>
                  <input
                    type="number"
                    min="0"
                    max="15"
                    value={ruleLevelInput}
                    onChange={e => setRuleLevelInput(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-mono mb-1">Rule Description:</label>
                <input
                  type="text"
                  value={ruleDescInput}
                  onChange={e => setRuleDescInput(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Target Agent:</label>
                  <input
                    type="text"
                    value={agentNameInput}
                    onChange={e => setAgentNameInput(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-mono mb-1">Source IP:</label>
                  <input
                    type="text"
                    value={srcIpInput}
                    onChange={e => setSrcIpInput(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-mono mb-1">Full Syslog Text:</label>
                <textarea
                  rows={3}
                  value={rawLogInput}
                  onChange={e => setRawLogInput(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-white font-mono text-[11px]"
                  required
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowIngestModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-mono font-medium transition"
                >
                  Ingest &amp; Normalize
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
