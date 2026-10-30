import React from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  LogOut,
  FileCheck2,
  Lock,
  KeyRound,
  FlaskConical,
  FileText,
  LayoutDashboard,
  Server,
  Sliders,
  Cpu,
} from 'lucide-react';
import type { UserProfile, UserRole } from '../types/index.ts';

interface NavbarProps {
  user: UserProfile | null;
  activeTab: string;
  onTabChange: (tab: string) => void;
  onLogout: () => void;
  onSwitchRole: (role: UserRole) => void;
  chainValid: boolean;
  chainCount: number;
  pendingApprovalsCount?: number;
  totalAlertsCount?: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  user,
  activeTab,
  onTabChange,
  onLogout,
  onSwitchRole,
  chainValid,
  chainCount,
  pendingApprovalsCount = 0,
  totalAlertsCount = 0,
}) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'ollama', label: 'Ollama AI Diagnostics', icon: Cpu, badge: 'Free AI' },
    { id: 'wazuh', label: 'Wazuh SIEM Ingestion', icon: Server, badge: totalAlertsCount > 0 ? totalAlertsCount : undefined },
    { id: 'safety', label: 'Safety Gate & Policy', icon: Sliders },
    { id: 'approvals', label: 'Remediation Approvals', icon: FileCheck2, badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : undefined },
    { id: 'investigations', label: 'Incident Triage', icon: FileText },
    { id: 'audit', label: 'Audit Ledger', icon: Lock, badge: chainCount },
    { id: 'apikeys', label: 'Sensor API Keys', icon: KeyRound },
    { id: 'matrix', label: 'Security Test Suite', icon: FlaskConical },
  ];

  return (
    <header className="border-b border-slate-800 bg-slate-950 sticky top-0 z-50">
      {/* Top Status Bar */}
      <div className="px-4 py-1.5 border-b border-slate-800/80 bg-slate-900/60 flex flex-wrap items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2.5 font-mono text-[11px]">
          <span className="text-slate-300 font-semibold">SOC PORTAL</span>
          <span className="text-slate-600">/</span>
          <span className="text-slate-400">Authentication &amp; Activity Logging Subsystem</span>
          <span className="text-slate-600 hidden sm:inline">/</span>
          <span className="hidden sm:inline text-slate-500">NIST SP 800-92 Compliance</span>
        </div>

        {/* Audit Chain Integrity Status */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => onTabChange('audit')}
            className={`flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono border transition ${
              chainValid
                ? 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700'
                : 'bg-red-950 text-red-300 border-red-800 hover:bg-red-900'
            }`}
            title="Inspect cryptographic hash chain integrity"
          >
            {chainValid ? (
              <>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Audit Chain: Valid ({chainCount} blocks)</span>
              </>
            ) : (
              <>
                <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                <span className="font-semibold text-red-200">Integrity Breach Detected</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Main Bar */}
      <div className="max-w-7xl mx-auto px-4 py-2.5 flex flex-wrap items-center justify-between gap-3">
        {/* Brand */}
        <div className="flex items-center gap-2.5">
          <div className="h-8 w-8 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-200">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="text-sm font-semibold text-slate-100 flex items-center gap-2 leading-none">
              Security Operations Center
            </div>
            <div className="text-[11px] text-slate-400 font-mono mt-0.5">
              Access Control &amp; Activity Ledger
            </div>
          </div>
        </div>

        {/* User Controls */}
        {user && (
          <div className="flex items-center gap-2.5">
            {/* Role Switcher */}
            <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-0.5 rounded text-xs">
              <span className="text-slate-500 px-1.5 font-mono text-[11px] hidden md:inline">Role:</span>
              <button
                onClick={() => onSwitchRole('ANALYST')}
                className={`px-2 py-0.5 rounded text-xs font-medium transition ${
                  user.role === 'ANALYST'
                    ? 'bg-slate-700 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Switch to Analyst"
              >
                Analyst
              </button>
              <button
                onClick={() => onSwitchRole('APPROVER')}
                className={`px-2 py-0.5 rounded text-xs font-medium transition ${
                  user.role === 'APPROVER'
                    ? 'bg-slate-700 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Switch to Approver"
              >
                Approver
              </button>
              <button
                onClick={() => onSwitchRole('ADMIN')}
                className={`px-2 py-0.5 rounded text-xs font-medium transition ${
                  user.role === 'ADMIN'
                    ? 'bg-slate-700 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Switch to Admin"
              >
                Admin
              </button>
            </div>

            {/* Profile Info */}
            <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs">
              <UserCheck className="w-3.5 h-3.5 text-slate-400" />
              <div>
                <span className="font-medium text-slate-200">{user.name}</span>
                <span className="text-slate-500 font-mono text-[10px] ml-1.5">({user.role})</span>
              </div>
            </div>

            {/* Logout */}
            <button
              onClick={onLogout}
              className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-red-400 transition"
              title="Sign Out"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Tabs Row */}
      <div className="max-w-7xl mx-auto px-4 flex space-x-1 overflow-x-auto scrollbar-none border-t border-slate-800/80">
        {navItems.map(item => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition whitespace-nowrap ${
                isActive
                  ? 'border-slate-300 text-slate-100 bg-slate-900/60'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Icon className="w-3.5 h-3.5 text-slate-400" />
              <span>{item.label}</span>
              {item.badge !== undefined && (
                <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </header>
  );
};
