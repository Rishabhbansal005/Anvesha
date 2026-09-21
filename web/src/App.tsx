import React, { useState, useEffect } from 'react';
import { ThemeProvider } from './context/ThemeContext';
import { TopBar } from './components/layout/TopBar';
import { CommandPalette } from './components/common/CommandPalette';
import { DashboardPage } from './pages/DashboardPage';
import { InvestigationWorkspace } from './pages/InvestigationWorkspace';
import { CasesPage } from './pages/CasesPage';
import { AlertsPage } from './pages/AlertsPage';
import { IntelligencePage } from './pages/IntelligencePage';
import { NavTab, API_BASE_URL } from './constants';
import { CampaignInvestigationPage } from './pages/CampaignInvestigationPage';
import { ErrorBoundary } from './components/common/ErrorBoundary';

export function AppContent() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  
  // Real Supabase stats state (Starts at clean zero)
  const [stats, setStats] = useState({
    total_investigations: 0,
    critical_threats: 0,
    unreviewed_alerts_count: 0,
    active_campaigns_count: 0,
    urgent_actions_required: [],
    recent_activity: [],
    has_records: false
  });
  const [supabaseConnected, setSupabaseConnected] = useState(false);

  // Poll real Supabase health & stats
  const fetchStats = async () => {
    try {
      const healthRes = await fetch(`${API_BASE_URL}/health`);
      if (healthRes.ok) {
        const healthData = await healthRes.json();
        setSupabaseConnected(healthData.supabase_connected || false);
        
        const statsRes = await fetch(`${API_BASE_URL}/stats/overview`);
        if (statsRes.ok) {
          const data = await statsRes.json();
          setStats(data);
        }
      } else {
        setSupabaseConnected(false);
      }
    } catch (err) {
      setSupabaseConnected(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 12000);
    return () => clearInterval(interval);
  }, []);

  const handleSelectCase = (caseId: string) => {
    setSelectedCaseId(caseId);
    setCurrentTab('workspace');
  };

  return (
    <div className="flex flex-col min-h-screen w-screen bg-[#080C12] text-[#E8EDF3] transition-colors font-sans antialiased">
      {/* Sleek Top Command Bar (Replaces old heavy sidebar) */}
      <TopBar
        currentTab={currentTab}
        onSelectTab={(tab) => {
          setCurrentTab(tab);
          if (tab !== 'workspace') setSelectedCaseId(null);
        }}
        onOpenCommandPalette={() => setCommandPaletteOpen(true)}
        supabaseConnected={supabaseConnected}
        unreviewedAlertsCount={stats.unreviewed_alerts_count}
      />

      {/* Global Search / Command Palette Overlay (âŒ˜K) */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        onSelectCase={handleSelectCase}
      />

      {/* Main Viewport Content */}
      <div className="flex-1 overflow-y-auto">
        {currentTab === 'dashboard' && (
          <DashboardPage
            stats={stats}
            onNavigate={(tab) => setCurrentTab(tab)}
            onSelectCase={handleSelectCase}
          />
        )}

        {currentTab === 'workspace' && (
          <InvestigationWorkspace
            activeCaseId={selectedCaseId}
            onClearActiveCase={() => setSelectedCaseId(null)}
          />
        )}

        {currentTab === 'investigations' && (
          <CasesPage
            onSelectCase={handleSelectCase}
            onStartNewInvestigation={() => {
              setSelectedCaseId(null);
              setCurrentTab('workspace');
            }}
          />
        )}

        {currentTab === 'alerts' && <AlertsPage />}

        {currentTab === 'intelligence' && <IntelligencePage />}

        {currentTab === 'campaigns' && <CampaignInvestigationPage />}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <ErrorBoundary fallbackTitle="Application Shell Interrupted">
        <AppContent />
      </ErrorBoundary>
    </ThemeProvider>
  );
}

