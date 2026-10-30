import React, { useState, useEffect } from 'react';
import {
  FlaskConical,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Shield,
  HelpCircle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { api } from '../services/api.ts';
import type { SecuritySuiteReport } from '../types/index.ts';

interface SecurityTestMatrixProps {
  onAuditUpdated: () => void;
}

export const SecurityTestMatrix: React.FC<SecurityTestMatrixProps> = ({ onAuditUpdated }) => {
  const [report, setReport] = useState<SecuritySuiteReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'TESTS' | 'VIVA'>('TESTS');
  const [expandedViva, setExpandedViva] = useState<number | null>(0);

  const runTests = async () => {
    setLoading(true);
    try {
      const data = await api.getSecurityTestMatrix();
      setReport(data);
      onAuditUpdated();
    } catch (err: any) {
      console.error('Failed to run test suite:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runTests();
  }, []);

  const vivaQuestions = [
    {
      q: 'Why does the LLM not decide severity, technique or approval in AI-SOC?',
      a: 'A small local model (3B) is non-deterministic and prone to hallucinations and unsupported claims. Moving baseline severity and ATT&CK technique to deterministic detection rules, and remediation approval to a deterministic policy engine ensures strict guardrails. The LLM acts solely as an advisor providing grounded summaries and findings, while humans retain final sign-off on disruptive actions.',
    },
    {
      q: 'What stops a forged alert from causing an unauthorized network block?',
      a: 'Ingestion requires an authenticated 32-byte API key sent via the X-Monitor-API-Key header, verified in constant time against a stored SHA-256 hash. Alerts without a valid key return HTTP 401 and trigger a security audit event. Furthermore, no action executes automatically—disruptive firewall blocks require explicit approver sign-off with cryptographic parameter hash validation.',
    },
    {
      q: 'How does the append-only cryptographic hash chain detect tampering?',
      a: 'Every audit entry stores the SHA-256 hash of the preceding entry (prevHash) and computes its own hash as SHA256(index + timestamp + actor + actorId + eventType + canonicalJson(payload) + prevHash). If an attacker or compromised database administrator modifies or deletes a historical row, the mathematical digest breaks at that exact index, causing immediate verification failure.',
    },
    {
      q: 'How does the system prevent parameter tampering between policy proposal and approver execution?',
      a: 'When an approval request is generated, a cryptographic parameter hash (SHA-256 of the canonical parameters like target IP and TTL) is committed. When the approver submits their authorization, the server re-computes the hash of the action payload and compares it in constant time. If someone maliciously alters the target IP in-transit (e.g. to Google DNS 8.8.8.8), the server rejects the request with a hash mismatch error.',
    },
    {
      q: 'How does the platform defend against credential brute-forcing against SOC analysts?',
      a: 'The server employs PBKDF2 password hashing (10,000 rounds with 16-byte random salts) and an active IP-based rate limiter. After 5 consecutive failed attempts within a 60-second window, the client IP is locked out with a cooldown period, and an AUTH_RATE_LIMIT_TRIGGERED audit event is committed.',
    },
  ];

  return (
    <div className="space-y-5">
      {/* Header and Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <h1 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <FlaskConical className="w-4 h-4 text-slate-400" />
              <span>Platform Security Verification Suite</span>
            </h1>
            <p className="text-xs text-slate-400 max-w-3xl">
              Automated validation suite certifying platform security controls: constant-time key validation, RBAC segregation, parameter tampering defense, and rate limiting.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex rounded bg-slate-950 p-0.5 border border-slate-800 text-xs">
              <button
                onClick={() => setActiveTab('TESTS')}
                className={`px-2.5 py-1 rounded text-xs transition ${
                  activeTab === 'TESTS' ? 'bg-slate-700 text-slate-100 font-medium' : 'text-slate-400 hover:text-white'
                }`}
              >
                Test Matrix
              </button>
              <button
                onClick={() => setActiveTab('VIVA')}
                className={`px-2.5 py-1 rounded text-xs transition ${
                  activeTab === 'VIVA' ? 'bg-slate-700 text-slate-100 font-medium' : 'text-slate-400 hover:text-white'
                }`}
              >
                Defense Questions
              </button>
            </div>

            <button
              onClick={runTests}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-100 hover:bg-white text-slate-950 font-semibold text-xs disabled:opacity-50 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>{loading ? 'Running...' : 'Run All Tests'}</span>
            </button>
          </div>
        </div>

        {/* Scorecard Overview */}
        {report && (
          <div className="mt-3.5 grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Total Test Cases:</span>
              <span className="text-slate-200 font-bold text-sm">{report.totalTests}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Passed Checks:</span>
              <span className="text-emerald-400 font-bold text-sm">{report.passedCount}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Failed Checks:</span>
              <span className={`font-bold text-sm ${report.failedCount > 0 ? 'text-red-400' : 'text-slate-400'}`}>
                {report.failedCount}
              </span>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Success Rate:</span>
              <span className="text-slate-200 font-bold text-sm">{report.successRate}%</span>
            </div>
          </div>
        )}
      </div>

      {activeTab === 'TESTS' ? (
        /* Test Suite Results List */
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-4 py-2.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between text-xs">
            <div className="font-medium text-slate-300 flex items-center gap-2">
              <Shield className="w-3.5 h-3.5 text-slate-400" />
              <span>Automated Security Verification Results</span>
            </div>
            <span className="text-[11px] text-slate-500 font-mono">
              Executed: {report ? new Date(report.timestamp).toLocaleTimeString() : 'Pending'}
            </span>
          </div>

          <div className="divide-y divide-slate-800/70">
            {report?.results.map(test => {
              const isPass = test.status === 'PASS';

              return (
                <div key={test.id} className="p-3.5 space-y-2 hover:bg-slate-850/40 transition">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 font-semibold">
                        {test.id}
                      </span>
                      <span className="text-xs font-semibold text-slate-200">{test.name}</span>
                    </div>

                    <div className="flex items-center gap-2.5">
                      <span className="text-[11px] font-mono text-slate-500">{test.durationMs}ms</span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-medium flex items-center gap-1 border ${
                          isPass
                            ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                            : 'bg-red-950 text-red-300 border-red-800'
                        }`}
                      >
                        {isPass ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <XCircle className="w-3 h-3 text-red-400" />}
                        <span>{test.status}</span>
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 space-y-0.5">
                      <span className="text-slate-500 text-[10px] block">Expected Security Assertion:</span>
                      <span className="text-slate-300 text-[11px]">{test.expected}</span>
                    </div>

                    <div className="p-2 rounded bg-slate-950 border border-slate-800 space-y-0.5">
                      <span className="text-slate-500 text-[10px] block">Actual Result Received:</span>
                      <span className={`text-[11px] ${isPass ? 'text-emerald-300' : 'text-red-300'}`}>
                        {test.actual}
                      </span>
                    </div>
                  </div>

                  <p className="text-[11px] text-slate-400">
                    <strong className="text-slate-300 font-medium">Security Impact:</strong> {test.details}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        /* Viva and Defense Sheet */
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3">
          <div className="pb-2.5 border-b border-slate-800">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-slate-400" />
              <span>SOC Architecture &amp; Security Defense Questions</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Key architectural defenses: why a local 3B model, why the LLM does not decide severity/action, prompt injection defenses, and what stops forged alerts.
            </p>
          </div>

          <div className="space-y-2">
            {vivaQuestions.map((item, idx) => {
              const isOpen = expandedViva === idx;
              return (
                <div key={idx} className="border border-slate-800 rounded bg-slate-950/70 overflow-hidden">
                  <button
                    onClick={() => setExpandedViva(isOpen ? null : idx)}
                    className="w-full p-3 text-left text-xs font-medium text-slate-200 hover:text-white flex items-center justify-between gap-3 transition"
                  >
                    <span className="text-slate-200">{item.q}</span>
                    {isOpen ? <ChevronUp className="w-3.5 h-3.5 flex-shrink-0 text-slate-400" /> : <ChevronDown className="w-3.5 h-3.5 flex-shrink-0 text-slate-400" />}
                  </button>
                  {isOpen && (
                    <div className="px-3 pb-3 text-xs text-slate-300 leading-relaxed border-t border-slate-800 pt-2">
                      {item.a}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
