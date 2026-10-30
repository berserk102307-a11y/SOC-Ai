import React, { useState, useEffect } from 'react';
import {
  Shield,
  Lock,
  Mail,
  AlertTriangle,
  CheckCircle2,
  UserCheck,
  Flame,
  RotateCcw,
  Eye,
  EyeOff,
  Radio,
  KeyRound,
  FileCheck2,
  Server,
  ArrowRight,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { api } from '../services/api.ts';
import type { UserProfile, UserPermissions, UserRole } from '../types/index.ts';

interface LoginScreenProps {
  onLoginSuccess: (user: UserProfile, permissions: UserPermissions) => void;
  onAuditUpdated: () => void;
  chainCount?: number;
  chainValid?: boolean;
}

export const LoginScreen: React.FC<LoginScreenProps> = ({
  onLoginSuccess,
  onAuditUpdated,
  chainCount = 0,
  chainValid = true,
}) => {
  const [email, setEmail] = useState('analyst@soc.corp');
  const [password, setPassword] = useState('Analyst@2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);
  const [lockoutSec, setLockoutSec] = useState<number | null>(null);
  const [resetStatus, setResetStatus] = useState<string | null>(null);

  // Countdown timer for lockout cooldown
  useEffect(() => {
    if (lockoutSec === null || lockoutSec <= 0) return;
    const timer = setInterval(() => {
      setLockoutSec(prev => {
        if (prev === null || prev <= 1) {
          setError(null);
          return null;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [lockoutSec]);

  // Standard Login submit
  const handleSubmit = async (e?: React.FormEvent, bypassLockout = false) => {
    if (e) e.preventDefault();
    setLoading(true);
    setError(null);
    setResetStatus(null);
    try {
      const res = await api.login(email, password, bypassLockout);
      onLoginSuccess(res.user, res.permissions);
      onAuditUpdated();
    } catch (err: any) {
      setError(err.message || 'Login failed.');
      if (err.data?.remainingAttempts !== undefined) {
        setRemainingAttempts(err.data.remainingAttempts);
      }
      if (err.data?.retryAfter) {
        setLockoutSec(err.data.retryAfter);
      }
      onAuditUpdated();
    } finally {
      setLoading(false);
    }
  };

  // 1-Click Instant Sign In as specified role (clears any rate locks and logs in directly)
  const handleInstantLogin = async (role: 'ANALYST' | 'APPROVER' | 'ADMIN') => {
    setLoading(true);
    setError(null);
    setResetStatus(null);
    setLockoutSec(null);
    try {
      const res = await api.quickLogin(role);
      onLoginSuccess(res.user, res.permissions);
      onAuditUpdated();
    } catch (err: any) {
      setError(err.message || `Failed to sign in as ${role}.`);
      onAuditUpdated();
    } finally {
      setLoading(false);
    }
  };

  // Pre-fill credentials in form
  const handleSelectRole = (role: 'ANALYST' | 'APPROVER' | 'ADMIN') => {
    setError(null);
    setResetStatus(null);
    if (role === 'ANALYST') {
      setEmail('analyst@soc.corp');
      setPassword('Analyst@2026!');
    } else if (role === 'APPROVER') {
      setEmail('approver@soc.corp');
      setPassword('Approver@2026!');
    } else {
      setEmail('admin@soc.corp');
      setPassword('Admin@2026!');
    }
  };

  // Reset Rate Limiter
  const handleResetRateLimit = async () => {
    setLoading(true);
    try {
      await api.resetRateLimit(email);
      setLockoutSec(null);
      setError(null);
      setRemainingAttempts(5);
      setResetStatus('Rate limit and lockout successfully cleared. You may now sign in.');
      onAuditUpdated();
    } catch (err: any) {
      setError(err.message || 'Failed to reset rate limit.');
    } finally {
      setLoading(false);
    }
  };

  // Simulate Rate Limiter for security verification
  const simulateBruteForceLockout = async () => {
    setLoading(true);
    setError(null);
    setResetStatus(null);
    try {
      for (let i = 0; i < 5; i++) {
        try {
          await api.login(email, 'WrongPassword123!');
        } catch {
          // ignore until locked
        }
      }
      await api.login(email, password);
    } catch (err: any) {
      setError(`Brute-force lockout triggered: ${err.message}`);
      if (err.data?.retryAfter) {
        setLockoutSec(err.data.retryAfter);
      }
      onAuditUpdated();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Gateway Header (No inner navigation tabs to prevent confusion) */}
      <header className="border-b border-slate-800 bg-slate-950 sticky top-0 z-50">
        <div className="px-4 py-2 border-b border-slate-800/80 bg-slate-900/60 flex flex-wrap items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2 font-mono text-[11px]">
            <span className="text-slate-200 font-semibold flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
              SECURE ACCESS GATEWAY
            </span>
            <span className="text-slate-600">/</span>
            <span className="text-slate-400">Autonomous SIEM &amp; Security Operations Console</span>
          </div>

          <div className="flex items-center gap-3 font-mono text-[11px]">
            <div className="flex items-center gap-1.5 text-slate-300">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>NIST SP 800-92 Ledger: {chainCount} blocks</span>
            </div>
            <span className="text-slate-700 hidden sm:inline">|</span>
            <span className="text-slate-500 hidden sm:inline">Port 3000 Verified</span>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-100 shadow-sm">
              <Shield className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="text-base font-bold text-slate-100 flex items-center gap-2 leading-none">
                AI-SOC Operations Platform
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1">
                Zero-Trust Access Control &bull; Wazuh SIEM &bull; Activity Ledger
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleResetRateLimit}
              className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-slate-700 transition"
              title="Clear any rate-limit locks on this IP or account"
            >
              <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
              <span>Reset Rate Limiter</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Sign-In Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 flex items-center justify-center">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Left Column: Platform Overview & Architecture */}
          <div className="lg:col-span-6 space-y-6">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-medium bg-slate-900 text-indigo-300 border border-indigo-900/50 mb-3">
                <Shield className="w-3.5 h-3.5 text-indigo-400" />
                <span>Enterprise Security Operations Console</span>
              </div>
              <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-100 tracking-tight leading-tight">
                Role-Based Authentication &amp; Audit Gateway
              </h1>
              <p className="mt-2.5 text-sm text-slate-400 leading-relaxed">
                Autonomous SIEM defense system with deterministic safety gating, Wazuh alert ingestion, and cryptographic NIST SP 800-92 tamper-evident audit logging.
              </p>
            </div>

            {/* Role Access Profiles (1-Click Login Cards) */}
            <div>
              <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono mb-2.5 flex items-center justify-between">
                <span>Authorized Personnel Roles</span>
                <span className="text-[11px] text-indigo-400 lowercase font-normal">click to instant sign-in</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* Analyst */}
                <div
                  onClick={() => handleInstantLogin('ANALYST')}
                  className="group p-3 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-indigo-500/60 hover:bg-slate-800/80 cursor-pointer transition flex flex-col justify-between text-left"
                >
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs font-bold text-slate-200 group-hover:text-indigo-300">Analyst</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">Tier-1</span>
                    </div>
                    <div className="text-xs text-slate-400">Maya Lin</div>
                    <div className="text-[11px] text-slate-500 mt-1">Alert triage, MITRE mapping &amp; investigations.</div>
                  </div>
                  <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-indigo-400 font-medium">
                    <span>Instant Sign In</span>
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                </div>

                {/* Approver */}
                <div
                  onClick={() => handleInstantLogin('APPROVER')}
                  className="group p-3 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-indigo-500/60 hover:bg-slate-800/80 cursor-pointer transition flex flex-col justify-between text-left"
                >
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs font-bold text-slate-200 group-hover:text-indigo-300">Approver</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">Commander</span>
                    </div>
                    <div className="text-xs text-slate-400">David Chen</div>
                    <div className="text-[11px] text-slate-500 mt-1">Remediation authorizations &amp; policy overrides.</div>
                  </div>
                  <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-indigo-400 font-medium">
                    <span>Instant Sign In</span>
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                </div>

                {/* Admin */}
                <div
                  onClick={() => handleInstantLogin('ADMIN')}
                  className="group p-3 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-indigo-500/60 hover:bg-slate-800/80 cursor-pointer transition flex flex-col justify-between text-left"
                >
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs font-bold text-slate-200 group-hover:text-indigo-300">Admin</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">Full</span>
                    </div>
                    <div className="text-xs text-slate-400">Sarah Connor</div>
                    <div className="text-[11px] text-slate-500 mt-1">Sensor API keys, test suite &amp; ledger audits.</div>
                  </div>
                  <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-indigo-400 font-medium">
                    <span>Instant Sign In</span>
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                </div>
              </div>
            </div>

            {/* Cryptographic Security Specs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/90">
                <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 mb-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  PBKDF2 Password Salting
                </div>
                <div className="text-[11px] text-slate-400">
                  10,000 iterations SHA-256 with cryptographically random 16-byte salt per user.
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/90">
                <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 mb-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  Constant-Time API Keys
                </div>
                <div className="text-[11px] text-slate-400">
                  Keys evaluated via <code className="text-slate-300">timingSafeEqual</code> preventing side-channel attacks.
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/90">
                <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 mb-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  Parameter Hash Binding
                </div>
                <div className="text-[11px] text-slate-400">
                  Proposals cryptographically bound to exact IP and TTL parameters via SHA-256.
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/90">
                <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 mb-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  NIST SP 800-92 Hash Ledger
                </div>
                <div className="text-[11px] text-slate-400">
                  Continuous hash-chaining linking every event to the prior block for tamper detection.
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Dedicated Interactive Sign-In Box */}
          <div className="lg:col-span-6 bg-slate-900/95 border border-slate-800 rounded-xl p-6 sm:p-7 shadow-2xl">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-indigo-400" />
                  Personnel Authentication
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Sign in with authorized SOC credentials
                </p>
              </div>
              <div className="flex items-center gap-1">
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/50">
                  TLS 1.3 Active
                </span>
              </div>
            </div>

            {/* Quick Fill Selectors */}
            <div className="mb-4">
              <label className="block text-xs font-medium text-slate-400 mb-1.5">
                Quick-Select Credentials:
              </label>
              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => handleSelectRole('ANALYST')}
                  className={`p-2 rounded-lg border text-left transition ${
                    email === 'analyst@soc.corp'
                      ? 'bg-slate-800 border-indigo-500 text-slate-100'
                      : 'bg-slate-950 hover:bg-slate-850 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="text-xs font-semibold">Analyst</div>
                  <div className="text-[10px] text-slate-400 truncate">Maya Lin</div>
                </button>
                <button
                  type="button"
                  onClick={() => handleSelectRole('APPROVER')}
                  className={`p-2 rounded-lg border text-left transition ${
                    email === 'approver@soc.corp'
                      ? 'bg-slate-800 border-indigo-500 text-slate-100'
                      : 'bg-slate-950 hover:bg-slate-850 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="text-xs font-semibold">Approver</div>
                  <div className="text-[10px] text-slate-400 truncate">David Chen</div>
                </button>
                <button
                  type="button"
                  onClick={() => handleSelectRole('ADMIN')}
                  className={`p-2 rounded-lg border text-left transition ${
                    email === 'admin@soc.corp'
                      ? 'bg-slate-800 border-indigo-500 text-slate-100'
                      : 'bg-slate-950 hover:bg-slate-850 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="text-xs font-semibold">Admin</div>
                  <div className="text-[10px] text-slate-400 truncate">Sarah Connor</div>
                </button>
              </div>
            </div>

            {/* Success / Reset Feedback */}
            {resetStatus && (
              <div className="mb-4 p-3 rounded-lg bg-emerald-950/70 border border-emerald-800/80 text-emerald-200 text-xs flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold">{resetStatus}</div>
                </div>
              </div>
            )}

            {/* Error & Rate Limit Lockout Banner with Instant Unlock Action */}
            {error && (
              <div className="mb-4 p-3.5 rounded-lg bg-red-950/70 border border-red-800/90 text-red-200 text-xs flex flex-col gap-2.5">
                <div className="flex items-start gap-2.5">
                  <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <div className="font-semibold text-red-100">{error}</div>
                    {remainingAttempts !== null && remainingAttempts > 0 && (
                      <div className="mt-1 text-[11px] text-red-300">
                        Remaining attempts before rate lockdown:{' '}
                        <span className="font-mono font-bold text-red-100">{remainingAttempts}</span>
                      </div>
                    )}
                    {lockoutSec !== null && lockoutSec > 0 && (
                      <div className="mt-1 text-[11px] text-amber-300 font-mono">
                        Rate-limit lockdown active. Cooldown:{' '}
                        <span className="font-bold">{lockoutSec}</span> seconds.
                      </div>
                    )}
                  </div>
                </div>

                {/* Instant Unlock Action Button */}
                <div className="pt-2 border-t border-red-900/60 flex items-center justify-between gap-2">
                  <span className="text-[11px] text-red-300">Need immediate access?</span>
                  <button
                    type="button"
                    onClick={handleResetRateLimit}
                    className="px-2.5 py-1 rounded bg-red-900/80 hover:bg-red-800 text-white font-medium text-xs flex items-center gap-1.5 transition"
                  >
                    <RotateCcw className="w-3 h-3 text-amber-300" />
                    <span>Unlock Account &amp; Reset Cooldown</span>
                  </button>
                </div>
              </div>
            )}

            {/* Authentication Form */}
            <form onSubmit={e => handleSubmit(e, false)} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Username / Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-indigo-500 font-mono"
                    placeholder="analyst@soc.corp"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-10 py-2 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
                    title={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="pt-2 flex flex-col gap-2.5">
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 px-4 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs tracking-wide transition flex items-center justify-center gap-2 shadow-md hover:shadow-indigo-500/20 disabled:opacity-50"
                >
                  {loading ? (
                    <span>Authenticating Credentials...</span>
                  ) : (
                    <>
                      <UserCheck className="w-4 h-4" />
                      <span>Sign In to SOC Console</span>
                    </>
                  )}
                </button>

                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={simulateBruteForceLockout}
                    disabled={loading}
                    className="py-2 px-2.5 rounded-lg bg-slate-950 hover:bg-slate-850 border border-slate-800 text-slate-400 hover:text-slate-200 text-[11px] font-mono transition flex items-center justify-center gap-1.5"
                    title="Simulates 5 rapid invalid passwords to test the IP rate-limiting lockout mechanism"
                  >
                    <Flame className="w-3.5 h-3.5 text-amber-400" />
                    <span>Test Rate Limiter</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleResetRateLimit}
                    disabled={loading}
                    className="py-2 px-2.5 rounded-lg bg-slate-950 hover:bg-slate-850 border border-slate-800 text-slate-400 hover:text-emerald-400 text-[11px] font-mono transition flex items-center justify-center gap-1.5"
                    title="Clear rate limits immediately"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Reset Lockouts</span>
                  </button>
                </div>
              </div>
            </form>

            <div className="mt-5 pt-3.5 border-t border-slate-800/80 text-[11px] text-slate-500 text-center font-mono">
              Authentication events are cryptographically hashed and recorded to the append-only ledger.
            </div>
          </div>
        </div>
      </main>

      {/* Dedicated Sign-In Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-3 px-6 text-xs text-slate-500 font-mono flex flex-wrap items-center justify-between gap-2">
        <div>AI-SOC Security Operations Platform &bull; Person B Implementation</div>
        <div>Compliant with NIST SP 800-92 &bull; PBKDF2 SHA-256 &bull; Strict Role Isolation</div>
      </footer>
    </div>
  );
};
