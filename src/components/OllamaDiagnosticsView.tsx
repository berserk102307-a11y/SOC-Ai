import React, { useState, useEffect, useCallback } from 'react';
import {
  Cpu,
  Terminal,
  Activity,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Play,
  Settings,
  Shield,
  Zap,
  Clock,
  Layers,
  Search,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  Trash2,
  Copy,
  Check,
} from 'lucide-react';
import { api } from '../services/api.ts';
import type {
  OllamaStatusResult,
  BackendCallRecord,
  BackendCallStats,
  AiLogAnalysisResult,
  UserProfile,
} from '../types/index.ts';

interface OllamaDiagnosticsViewProps {
  user: UserProfile | null;
  onNavigateTab?: (tab: string) => void;
}

export function OllamaDiagnosticsView({ user, onNavigateTab }: OllamaDiagnosticsViewProps) {
  // Service Status & Backend Calls
  const [status, setStatus] = useState<OllamaStatusResult | null>(null);
  const [calls, setCalls] = useState<BackendCallRecord[]>([]);
  const [stats, setStats] = useState<BackendCallStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [filterErrorsOnly, setFilterErrorsOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Selected Call or Manual Log Analysis
  const [selectedCallId, setSelectedCallId] = useState<string | null>(null);
  const [isAnalyzingCall, setIsAnalyzingCall] = useState<string | null>(null);
  const [activeAnalysis, setActiveAnalysis] = useState<AiLogAnalysisResult | null>(null);

  // Manual Log Input
  const [manualLogText, setManualLogText] = useState(
    'Mar 29 18:24:12 auth-gw sshd[19022]: Failed password for root from 198.51.100.22 port 48102 ssh2 - 6 consecutive failures'
  );
  const [isAnalyzingManual, setIsAnalyzingManual] = useState(false);

  // Configuration Modal State
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [customHost, setCustomHost] = useState('http://127.0.0.1:11434');
  const [selectedModel, setSelectedModel] = useState('llama3:latest');
  const [isSavingConfig, setIsSavingConfig] = useState(false);
  const [configMessage, setConfigMessage] = useState<string | null>(null);

  // Simulation State
  const [isSimulating, setIsSimulating] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [statusRes, callsRes] = await Promise.all([
        api.getOllamaStatus(),
        api.getBackendCalls({ limit: 50, errorsOnly: filterErrorsOnly }),
      ]);
      setStatus(statusRes);
      setCustomHost(statusRes.host);
      setSelectedModel(statusRes.activeModel);
      setCalls(callsRes.calls);
      setStats(callsRes.stats);
    } catch (err) {
      console.error('Failed to load Ollama diagnostics data:', err);
    } finally {
      setIsLoading(false);
    }
  }, [filterErrorsOnly]);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      api.getBackendCalls({ limit: 50, errorsOnly: filterErrorsOnly }).then((res) => {
        setCalls(res.calls);
        setStats(res.stats);
      }).catch(() => {});
    }, 6000);
    return () => clearInterval(interval);
  }, [loadData, filterErrorsOnly]);

  const handleAnalyzeCall = async (callId: string) => {
    setIsAnalyzingCall(callId);
    try {
      const res = await api.analyzeBackendCallWithOllama(callId);
      if (res.success && res.analysis) {
        setActiveAnalysis(res.analysis);
        setSelectedCallId(callId);
        // Refresh call list so the attached analysis badge shows up
        const callsRes = await api.getBackendCalls({ limit: 50, errorsOnly: filterErrorsOnly });
        setCalls(callsRes.calls);
        setStats(callsRes.stats);
      }
    } catch (err: any) {
      console.error('Call analysis failed:', err);
    } finally {
      setIsAnalyzingCall(null);
    }
  };

  const handleAnalyzeManualLog = async () => {
    if (!manualLogText.trim()) return;
    setIsAnalyzingManual(true);
    try {
      const res = await api.analyzeLogWithOllama({
        logText: manualLogText,
        context: 'Manual SOC Operator Log Verification',
      });
      if (res.success && res.analysis) {
        setActiveAnalysis(res.analysis);
      }
    } catch (err: any) {
      console.error('Manual log analysis failed:', err);
    } finally {
      setIsAnalyzingManual(false);
    }
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingConfig(true);
    setConfigMessage(null);
    try {
      const res = await api.configureOllama(customHost, selectedModel);
      setStatus(res);
      setConfigMessage(res.message);
      setTimeout(() => setShowConfigModal(false), 1200);
    } catch (err: any) {
      setConfigMessage(err.message || 'Configuration failed');
    } finally {
      setIsSavingConfig(false);
    }
  };

  const handleSimulateCall = async (
    scenario: 'BRUTE_FORCE' | 'RATE_LIMIT' | 'SERVER_500' | 'TAMPER_INJECTION'
  ) => {
    setIsSimulating(scenario);
    try {
      const res = await api.simulateBackendCall(scenario);
      if (res.success) {
        setActiveAnalysis(res.analysis);
        setSelectedCallId(res.callRecord.id);
        const callsRes = await api.getBackendCalls({ limit: 50, errorsOnly: filterErrorsOnly });
        setCalls(callsRes.calls);
        setStats(callsRes.stats);
      }
    } catch (err) {
      console.error('Simulation failed:', err);
    } finally {
      setIsSimulating(null);
    }
  };

  const handleClearCalls = async () => {
    if (!confirm('Clear recent tracked backend call history?')) return;
    try {
      await api.clearBackendCalls();
      setCalls([]);
      if (stats) {
        setStats({ ...stats, totalCallsTracked: 0, totalErrors: 0, errorRatePercent: 0 });
      }
    } catch (err) {
      console.error('Failed to clear calls:', err);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(text);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const filteredCalls = calls.filter((c) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.path.toLowerCase().includes(q) ||
      c.clientIp.toLowerCase().includes(q) ||
      c.method.toLowerCase().includes(q) ||
      (c.errorMessage && c.errorMessage.toLowerCase().includes(q)) ||
      (c.userEmail && c.userEmail.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      {/* Top Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="p-1.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              <Cpu className="h-5 w-5" />
            </span>
            <h1 className="text-xl font-bold text-slate-100 tracking-tight">
              Ollama AI Log &amp; Backend Diagnostic Console
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              Free Model AI
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Autonomous SIEM log error triage and backend API call security inspection powered by free open-source Ollama models with seamless fallback.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowConfigModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 transition-colors"
          >
            <Settings className="h-3.5 w-3.5 text-slate-400" />
            <span>Configure Ollama</span>
          </button>
          <button
            onClick={loadData}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600/80 hover:bg-indigo-600 text-white text-xs font-medium transition-colors shadow-sm disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh Telemetry</span>
          </button>
        </div>
      </div>

      {/* Ollama Engine Status Banner */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Connection State Card */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-mono">Engine Status</span>
            <span
              className={`h-2 w-2 rounded-full ${
                status?.connected ? 'bg-emerald-400 animate-pulse' : 'bg-cyan-400'
              }`}
            />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-lg font-bold text-slate-100">
              {status?.connected ? 'Ollama Live' : 'Standby / Fallback'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1 font-mono truncate">
            {status?.message || 'Connecting to Ollama host...'}
          </p>
        </div>

        {/* Active Free Model */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-mono">Active Model</span>
            <Terminal className="h-3.5 w-3.5 text-cyan-400" />
          </div>
          <div className="text-lg font-bold text-cyan-300 font-mono">
            {status?.activeModel || 'llama3:latest'}
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1 font-mono">
            <span>Host: {status?.host ? status.host.replace('http://', '') : '127.0.0.1:11434'}</span>
            <span>{status?.latencyMs || 0}ms</span>
          </div>
        </div>

        {/* Backend Calls Tracked */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-mono">Backend Calls</span>
            <Activity className="h-3.5 w-3.5 text-emerald-400" />
          </div>
          <div className="text-lg font-bold text-emerald-300 font-mono">
            {stats?.totalCallsTracked || calls.length}
          </div>
          <p className="text-[11px] text-slate-400 mt-1 font-mono">
            In-memory ring buffer (last 100 requests)
          </p>
        </div>

        {/* Errors & Anomalies Caught */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-mono">Error Rate</span>
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-lg font-bold text-amber-400 font-mono">
              {stats?.totalErrors || 0} errors
            </span>
            <span className="text-xs font-mono text-slate-400">
              ({stats?.errorRatePercent || 0}%)
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1 font-mono">
            {stats?.analyzedByAi || 0} diagnosed with AI
          </p>
        </div>
      </div>

      {/* Quick Setup Note for Ollama Local Run */}
      {!status?.connected && (
        <div className="p-3.5 rounded-xl border border-cyan-900/40 bg-cyan-950/20 text-xs text-cyan-300 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center gap-2.5">
            <Cpu className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5 sm:mt-0" />
            <div>
              <span className="font-semibold text-cyan-200">Local Ollama Integration Ready:</span>{' '}
              Ollama is listening on <code className="bg-slate-900 px-1 py-0.5 rounded text-cyan-300 font-mono">{status?.host || 'http://127.0.0.1:11434'}</code>. You can run any free model locally or connect a remote Ollama server.
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => handleCopy('ollama run llama3')}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900/80 hover:bg-slate-900 border border-cyan-800/60 font-mono text-[11px] text-cyan-300 transition-colors"
            >
              {copiedCmd === 'ollama run llama3' ? (
                <>
                  <Check className="h-3 w-3 text-emerald-400" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-3 w-3 text-cyan-400" />
                  <span>ollama run llama3</span>
                </>
              )}
            </button>
            <button
              onClick={() => setShowConfigModal(true)}
              className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-medium text-[11px] transition-colors"
            >
              Change URL / Model
            </button>
          </div>
        </div>
      )}

      {/* Main Grid: Left is Backend Calls / Tests, Right is AI Verdict & Manual Tester */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Live Backend Calls & Errors */}
        <div className="lg:col-span-7 space-y-4">
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/70">
            {/* Table Header Controls */}
            <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-indigo-400" />
                <h2 className="text-sm font-semibold text-slate-200">
                  Backend API Calls &amp; Error Stream
                </h2>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setFilterErrorsOnly(!filterErrorsOnly)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                    filterErrorsOnly
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-semibold'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {filterErrorsOnly ? 'Errors Only (Active)' : 'Show Errors Only'}
                </button>
                <button
                  onClick={handleClearCalls}
                  title="Clear Log History"
                  className="p-1.5 rounded hover:bg-slate-800 text-slate-500 hover:text-rose-400 transition-colors"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {/* Quick Simulate Attack Probes */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 mb-4">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
                <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
                  <Zap className="h-3.5 w-3.5 text-amber-400" />
                  Simulate Backend Call / Error for Ollama:
                </span>
                <span className="text-[10px] text-slate-500">Injects &amp; tests live</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <button
                  onClick={() => handleSimulateCall('BRUTE_FORCE')}
                  disabled={isSimulating !== null}
                  className="px-2 py-1.5 rounded bg-slate-900 hover:bg-slate-850 border border-rose-900/40 text-rose-300 hover:text-rose-200 text-[11px] font-mono text-left transition-colors truncate disabled:opacity-50"
                >
                  {isSimulating === 'BRUTE_FORCE' ? 'Testing...' : '⚡ 401 Spray Probe'}
                </button>
                <button
                  onClick={() => handleSimulateCall('RATE_LIMIT')}
                  disabled={isSimulating !== null}
                  className="px-2 py-1.5 rounded bg-slate-900 hover:bg-slate-850 border border-amber-900/40 text-amber-300 hover:text-amber-200 text-[11px] font-mono text-left transition-colors truncate disabled:opacity-50"
                >
                  {isSimulating === 'RATE_LIMIT' ? 'Testing...' : '⚡ 429 Lockout'}
                </button>
                <button
                  onClick={() => handleSimulateCall('TAMPER_INJECTION')}
                  disabled={isSimulating !== null}
                  className="px-2 py-1.5 rounded bg-slate-900 hover:bg-slate-850 border border-purple-900/40 text-purple-300 hover:text-purple-200 text-[11px] font-mono text-left transition-colors truncate disabled:opacity-50"
                >
                  {isSimulating === 'TAMPER_INJECTION' ? 'Testing...' : '⚡ Hash Tamper'}
                </button>
                <button
                  onClick={() => handleSimulateCall('SERVER_500')}
                  disabled={isSimulating !== null}
                  className="px-2 py-1.5 rounded bg-slate-900 hover:bg-slate-850 border border-slate-700 text-slate-300 hover:text-slate-100 text-[11px] font-mono text-left transition-colors truncate disabled:opacity-50"
                >
                  {isSimulating === 'SERVER_500' ? 'Testing...' : '⚡ 500 Exception'}
                </button>
              </div>
            </div>

            {/* Search Filter */}
            <div className="relative mb-3">
              <Search className="h-3.5 w-3.5 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search by path, status, IP, error message..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-indigo-500"
              />
            </div>

            {/* Calls List */}
            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {filteredCalls.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500 font-mono">
                  No backend calls match criteria.
                </div>
              ) : (
                filteredCalls.map((call) => {
                  const isSelected = selectedCallId === call.id;
                  const isAnalyzing = isAnalyzingCall === call.id;
                  return (
                    <div
                      key={call.id}
                      onClick={() => setSelectedCallId(isSelected ? null : call.id)}
                      className={`p-3 rounded-lg border text-xs font-mono transition-all cursor-pointer ${
                        isSelected
                          ? 'border-indigo-500/80 bg-indigo-950/20'
                          : call.hasError
                          ? 'border-rose-900/40 bg-rose-950/10 hover:border-rose-800/60'
                          : 'border-slate-800/80 bg-slate-950/40 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 truncate">
                          {/* Status Badge */}
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              call.statusCode >= 500
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                : call.statusCode === 429
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                : call.statusCode >= 400
                                ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            }`}
                          >
                            {call.statusCode}
                          </span>

                          {/* Method Badge */}
                          <span className="text-[10px] font-semibold text-slate-400">
                            {call.method}
                          </span>

                          {/* Path */}
                          <span className="text-slate-200 font-medium truncate">
                            {call.path}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          {call.aiAnalysis && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                              AI: {call.aiAnalysis.verdict}
                            </span>
                          )}
                          <span className="text-[10px] text-slate-500">
                            {call.durationMs}ms
                          </span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleAnalyzeCall(call.id);
                            }}
                            disabled={isAnalyzing}
                            className="px-2 py-0.5 rounded bg-indigo-600/90 hover:bg-indigo-600 text-white text-[10px] transition-colors flex items-center gap-1 disabled:opacity-50"
                          >
                            <Cpu className={`h-2.5 w-2.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
                            <span>{isAnalyzing ? 'Analyzing...' : 'Diagnose'}</span>
                          </button>
                        </div>
                      </div>

                      {/* Details row */}
                      <div className="flex items-center justify-between text-[10px] text-slate-400 mt-1.5 pt-1.5 border-t border-slate-800/40">
                        <div className="flex items-center gap-3">
                          <span>IP: <strong className="text-slate-300">{call.clientIp}</strong></span>
                          {call.userEmail && <span>User: {call.userEmail}</span>}
                        </div>
                        <span className="text-slate-500">
                          {new Date(call.timestamp).toLocaleTimeString()}
                        </span>
                      </div>

                      {/* If Error or Expanded */}
                      {call.errorMessage && (
                        <div className="mt-2 p-1.5 rounded bg-rose-950/30 border border-rose-900/30 text-[10px] text-rose-300">
                          ⚠️ {call.errorMessage}
                        </div>
                      )}

                      {/* Expanded View */}
                      {isSelected && (
                        <div className="mt-2 pt-2 border-t border-slate-800 space-y-2 text-[10px]">
                          <div>
                            <span className="text-slate-500">Payload Snippet:</span>
                            <pre className="mt-1 p-2 rounded bg-slate-900 text-slate-300 overflow-x-auto">
                              {call.requestSnippet || '{}'}
                            </pre>
                          </div>
                          {call.aiAnalysis && (
                            <div className="p-2 rounded bg-indigo-950/30 border border-indigo-900/40 space-y-1">
                              <div className="flex items-center justify-between font-semibold text-indigo-300">
                                <span>Ollama Decision: {call.aiAnalysis.autonomousDecision}</span>
                                <span>Confidence: {Math.round(call.aiAnalysis.confidence * 100)}%</span>
                              </div>
                              <p className="text-slate-300">{call.aiAnalysis.explanation}</p>
                              <p className="text-cyan-300">Remediation: {call.aiAnalysis.mitigation}</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Right Column: AI Analysis Result & Manual Log Tester */}
        <div className="lg:col-span-5 space-y-6">
          {/* Active AI Diagnostic Verdict Card */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/70">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-slate-200">
                  AI SOC Error &amp; Log Verdict
                </h3>
              </div>
              {activeAnalysis && (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  {activeAnalysis.modelUsed}
                </span>
              )}
            </div>

            {activeAnalysis ? (
              <div className="space-y-3.5 text-xs">
                {/* Target & Classification Banner */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500 font-mono mb-1 uppercase tracking-wider">
                    {activeAnalysis.targetType} Target
                  </div>
                  <div className="font-semibold text-slate-200 mb-2 truncate font-mono">
                    {activeAnalysis.targetSummary}
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono ${
                        activeAnalysis.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          : activeAnalysis.severity === 'HIGH'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      }`}
                    >
                      {activeAnalysis.severity} SEVERITY
                    </span>

                    <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                      {activeAnalysis.classification}
                    </span>

                    <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300">
                      {Math.round(activeAnalysis.confidence * 100)}% Confidence
                    </span>
                  </div>
                </div>

                {/* Autonomous Decision & Tier */}
                <div className="p-3 rounded-lg bg-indigo-950/20 border border-indigo-900/40">
                  <div className="flex items-center justify-between text-xs font-mono mb-1">
                    <span className="text-indigo-400 font-semibold">Autonomous Decision:</span>
                    <span className="text-cyan-300 font-bold">{activeAnalysis.autonomousDecision}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono">
                    Safety Gate Tier: <strong className="text-slate-200">{activeAnalysis.safetyTier}</strong>
                  </div>
                  {activeAnalysis.mitreTechnique !== 'N/A' && (
                    <div className="text-[11px] text-amber-300/90 font-mono mt-1">
                      MITRE: {activeAnalysis.mitreTechnique}
                    </div>
                  )}
                </div>

                {/* Root Cause & Narrative */}
                <div className="space-y-1.5">
                  <h4 className="text-[11px] font-semibold text-slate-300 font-mono">
                    Root Cause Diagnosis
                  </h4>
                  <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    {activeAnalysis.rootCause}
                  </p>
                </div>

                <div className="space-y-1.5">
                  <h4 className="text-[11px] font-semibold text-slate-300 font-mono">
                    Threat &amp; Impact Narrative
                  </h4>
                  <p className="text-xs text-slate-400 leading-relaxed bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    {activeAnalysis.threatDescription}
                  </p>
                </div>

                {/* Recommended Remediation Action */}
                <div className="space-y-1.5">
                  <h4 className="text-[11px] font-semibold text-emerald-400 font-mono flex items-center justify-between">
                    <span>Remediation Advice</span>
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                  </h4>
                  <p className="text-xs text-emerald-200/90 bg-emerald-950/20 p-2.5 rounded-lg border border-emerald-900/40">
                    {activeAnalysis.recommendedRemediation}
                  </p>
                </div>

                {/* Remediation Commands */}
                {activeAnalysis.remediationCommands && activeAnalysis.remediationCommands.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span>Mitigation Script:</span>
                    </div>
                    {activeAnalysis.remediationCommands.map((cmd, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between gap-2 p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300"
                      >
                        <code className="truncate">{cmd}</code>
                        <button
                          onClick={() => handleCopy(cmd)}
                          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100"
                        >
                          {copiedCmd === cmd ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="p-8 text-center text-xs text-slate-500 font-mono space-y-2">
                <Cpu className="h-8 w-8 text-slate-600 mx-auto" />
                <p>Select any backend call from the left or test a log below to trigger Ollama AI diagnosis.</p>
              </div>
            )}
          </div>

          {/* Manual Log & Traceback Tester */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/70 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-indigo-400" />
                <h3 className="text-sm font-semibold text-slate-200">
                  Interactive SIEM Log &amp; Trace Tester
                </h3>
              </div>
              <span className="text-[10px] text-slate-500 font-mono">
                Ollama Input Sandbox
              </span>
            </div>

            <p className="text-xs text-slate-400">
              Input custom syslog, Wazuh alert JSON, or backend error stack to inspect Ollama's classification and autonomous security actions.
            </p>

            <textarea
              rows={3}
              value={manualLogText}
              onChange={(e) => setManualLogText(e.target.value)}
              placeholder="Paste raw log event, error call stack, or JSON alert..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 font-mono placeholder-slate-600 focus:outline-none focus:border-indigo-500"
            />

            <div className="flex items-center justify-between">
              <button
                type="button"
                onClick={() =>
                  setManualLogText(
                    `{"timestamp":"${new Date().toISOString()}","rule":{"id":5710,"description":"sshd: Multiple authentication failures","level":10},"agent":{"name":"auth-node-01","ip":"10.0.4.15"},"data":{"srcip":"198.51.100.89","dstuser":"root"}}`
                  )
                }
                className="text-[11px] text-indigo-400 hover:text-indigo-300 font-mono underline"
              >
                Insert Wazuh Sample
              </button>

              <button
                onClick={handleAnalyzeManualLog}
                disabled={isAnalyzingManual || !manualLogText.trim()}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors disabled:opacity-50"
              >
                <Play className={`h-3 w-3 ${isAnalyzingManual ? 'animate-spin' : ''}`} />
                <span>{isAnalyzingManual ? 'Analyzing Log...' : 'Run Ollama Diagnosis'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-md p-6 rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Settings className="h-5 w-5 text-indigo-400" />
                <h3 className="text-base font-bold text-slate-100">
                  Configure Ollama Service
                </h3>
              </div>
              <button
                onClick={() => setShowConfigModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Set the host endpoint and the free model name. If you are running Ollama on your local machine or a private cloud instance, specify the URL here.
            </p>

            <form onSubmit={handleSaveConfig} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Ollama Host URL
                </label>
                <input
                  type="text"
                  value={customHost}
                  onChange={(e) => setCustomHost(e.target.value)}
                  placeholder="http://127.0.0.1:11434"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                />
                <span className="text-[10px] text-slate-500">
                  Default local daemon: http://127.0.0.1:11434
                </span>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Selected Free Model
                </label>
                <select
                  value={selectedModel}
                  onChange={(e) => setSelectedModel(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="llama3:latest">llama3:latest (Meta Llama 3 - Recommended)</option>
                  <option value="mistral:latest">mistral:latest (Mistral 7B)</option>
                  <option value="deepseek-r1:latest">deepseek-r1:latest (DeepSeek Reasoning)</option>
                  <option value="phi3:latest">phi3:latest (Microsoft Phi-3 Mini)</option>
                  <option value="qwen2.5:latest">qwen2.5:latest (Qwen 2.5 Security)</option>
                  <option value="gemma2:latest">gemma2:latest (Google Gemma 2)</option>
                </select>
              </div>

              {configMessage && (
                <div className="p-2 rounded bg-indigo-950/40 border border-indigo-900/40 text-xs font-mono text-indigo-300">
                  {configMessage}
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowConfigModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 font-mono transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSavingConfig}
                  className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold font-mono transition-colors disabled:opacity-50"
                >
                  {isSavingConfig ? 'Testing & Saving...' : 'Save & Ping Host'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
