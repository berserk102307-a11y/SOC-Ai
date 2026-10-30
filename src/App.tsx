/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api, getStoredToken } from './services/api.ts';
import { Navbar } from './components/Navbar.tsx';
import { LoginScreen } from './components/LoginScreen.tsx';
import { DashboardOverview } from './components/DashboardOverview.tsx';
import { WazuhAlertsView } from './components/WazuhAlertsView.tsx';
import { SafetyGateSimulator } from './components/SafetyGateSimulator.tsx';
import { AuditLogView } from './components/AuditLogView.tsx';
import { ApprovalInbox } from './components/ApprovalInbox.tsx';
import { InvestigationTriageView } from './components/InvestigationTriageView.tsx';
import { ApiKeyManager } from './components/ApiKeyManager.tsx';
import { SecurityTestMatrix } from './components/SecurityTestMatrix.tsx';
import { OllamaDiagnosticsView } from './components/OllamaDiagnosticsView.tsx';
import type {
  UserProfile,
  UserPermissions,
  AuditEvent,
  ChainVerificationResult,
  StoredApiKeyItem,
  ApprovalRequest,
  IncidentFixture,
  UserRole,
  DashboardOverviewData,
  ScenarioDefinition,
} from './types/index.ts';

export default function App() {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [permissions, setPermissions] = useState<UserPermissions | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);

  // Active Tab - default to Dashboard for fast operational overview
  const [activeTab, setActiveTab] = useState<string>('dashboard');

  // Shared Data Stores
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [chainVerification, setChainVerification] = useState<ChainVerificationResult | null>(null);
  const [isTampered, setIsTampered] = useState(false);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [incidents, setIncidents] = useState<IncidentFixture[]>([]);
  const [apiKeys, setApiKeys] = useState<StoredApiKeyItem[]>([]);
  const [seedRawKey, setSeedRawKey] = useState<string>('');

  // Dashboard & Scenarios Stores
  const [dashboardOverview, setDashboardOverview] = useState<DashboardOverviewData | null>(null);
  const [scenarios, setScenarios] = useState<ScenarioDefinition[]>([]);

  // Fetch initial audit status & data
  const loadAuditData = useCallback(async () => {
    try {
      const data = await api.getAuditLog();
      setAuditEvents(data.events);
      setChainVerification(data.integrity);
      setIsTampered(data.isTampered);
    } catch (err) {
      console.error('Failed to load audit data:', err);
    }
  }, []);

  const loadAllSocData = useCallback(async () => {
    try {
      const [auditData, approvalsData, incidentsData, keysData, overviewData, scenariosData] =
        await Promise.all([
          api.getAuditLog(),
          api.getApprovals(),
          api.getIncidents(),
          api.getApiKeys(),
          api.getDashboardOverview(),
          api.getScenarios(),
        ]);

      setAuditEvents(auditData.events);
      setChainVerification(auditData.integrity);
      setIsTampered(auditData.isTampered);
      setApprovals(approvalsData.approvals);
      setIncidents(incidentsData.incidents);
      setApiKeys(keysData.keys);
      setSeedRawKey(keysData.seedRawKey);
      setDashboardOverview(overviewData);
      setScenarios(scenariosData.scenarios);
    } catch (err) {
      console.error('Failed to load SOC data:', err);
    }
  }, []);

  // Check existing session at startup
  useEffect(() => {
    const initAuth = async () => {
      try {
        if (getStoredToken()) {
          const res = await api.getMe();
          if (res.authenticated && res.user && res.permissions) {
            setUser(res.user);
            setPermissions(res.permissions);
          }
        }
      } catch (err) {
        console.warn('Initial session check failed:', err);
      } finally {
        setIsInitializing(false);
        loadAllSocData();
      }
    };
    initAuth();
  }, [loadAllSocData]);

  const handleLoginSuccess = (loggedInUser: UserProfile, perms: UserPermissions) => {
    setUser(loggedInUser);
    setPermissions(perms);
    setActiveTab('dashboard');
    loadAllSocData();
  };

  const handleLogout = async () => {
    await api.logout();
    setUser(null);
    setPermissions(null);
    setActiveTab('dashboard');
    loadAuditData();
  };

  const handleSwitchRole = async (role: UserRole) => {
    try {
      const res = await api.switchRole(role);
      setUser(res.user);
      setPermissions(res.permissions);
      loadAllSocData();
    } catch (err) {
      console.error('Failed to switch role:', err);
    }
  };

  if (isInitializing) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400 font-mono text-xs">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-slate-400 animate-pulse"></span>
          <span>Loading security operations console...</span>
        </div>
      </div>
    );
  }

  // If not authenticated, render the dedicated Login Screen page directly
  if (!user) {
    return (
      <LoginScreen
        onLoginSuccess={handleLoginSuccess}
        onAuditUpdated={loadAuditData}
        chainCount={auditEvents.length}
        chainValid={chainVerification?.valid ?? true}
      />
    );
  }

  const pendingApprovalsCount = approvals.filter(a => a.status === 'PENDING').length;
  const totalAlertsCount = dashboardOverview?.wazuhStats.totalAlerts ?? 0;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Navigation Bar */}
      <Navbar
        user={user}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onLogout={handleLogout}
        onSwitchRole={handleSwitchRole}
        chainValid={chainVerification?.valid ?? true}
        chainCount={auditEvents.length}
        pendingApprovalsCount={pendingApprovalsCount}
        totalAlertsCount={totalAlertsCount}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6">
        <div>
          {activeTab === 'dashboard' && (
              <DashboardOverview
                overviewData={dashboardOverview}
                scenarios={scenarios}
                user={user}
                permissions={permissions}
                onNavigateTab={setActiveTab}
                onRefreshData={loadAllSocData}
              />
            )}

            {activeTab === 'ollama' && (
              <OllamaDiagnosticsView
                user={user}
                onNavigateTab={setActiveTab}
              />
            )}

            {activeTab === 'wazuh' && (
              <WazuhAlertsView
                user={user}
                onNavigateTab={setActiveTab}
              />
            )}

            {activeTab === 'safety' && (
              <SafetyGateSimulator
                user={user}
                onRefreshApprovals={loadAllSocData}
                onNavigateTab={setActiveTab}
              />
            )}

            {activeTab === 'audit' && (
              <AuditLogView
                events={auditEvents}
                verification={chainVerification}
                isTampered={isTampered}
                onRefresh={loadAllSocData}
              />
            )}

            {activeTab === 'approvals' && (
              <ApprovalInbox
                approvals={approvals}
                currentUser={user}
                onRefresh={loadAllSocData}
                onAuditUpdated={loadAuditData}
              />
            )}

            {activeTab === 'investigations' && (
              <InvestigationTriageView
                incidents={incidents}
                currentUser={user}
                onRefresh={loadAllSocData}
                onAuditUpdated={loadAuditData}
              />
            )}

            {activeTab === 'apikeys' && (
              <ApiKeyManager
                apiKeys={apiKeys}
                seedRawKey={seedRawKey}
                currentUser={user}
                onRefresh={loadAllSocData}
                onAuditUpdated={loadAuditData}
              />
            )}

            {activeTab === 'matrix' && (
              <SecurityTestMatrix onAuditUpdated={loadAuditData} />
            )}
          </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-3 px-6 text-xs text-slate-500 font-mono flex flex-wrap items-center justify-between gap-2">
        <div>
          Autonomous SOC Operations &amp; SIEM Defense Platform
        </div>
        <div>
          Wazuh Ingestion • Deterministic Policies P001–P005 • NIST SP 800-92 Hash Ledger
        </div>
      </footer>
    </div>
  );
}
