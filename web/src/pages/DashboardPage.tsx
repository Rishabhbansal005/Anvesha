import React from 'react';
import { 
  ShieldAlert, 
  MailSearch, 
  Layers, 
  Clock, 
  ArrowRight, 
  CheckCircle2, 
  AlertTriangle,
  FileCheck2,
  FolderPlus
} from 'lucide-react';
import { EmptyState } from '../components/common/EmptyState';
import { RiskBadge } from '../components/common/RiskBadge';
import { NavTab } from '../constants';
import { NetworkTelemetryTester } from '../components/network/NetworkTelemetryTester';
import { Radio } from 'lucide-react';

interface DashboardPageProps {
  stats: {
    total_investigations: number;
    critical_threats: number;
    unreviewed_alerts_count: number;
    active_campaigns_count: number;
    urgent_actions_required: any[];
    recent_activity: any[];
    has_records: boolean;
  };
  onNavigate: (tab: NavTab) => void;
  onSelectCase: (caseId: string) => void;
}

const getGreeting = (): string => {
  const hour = new Date().getHours();
  if (hour >= 5 && hour < 12) return 'Good morning';
  if (hour >= 12 && hour < 17) return 'Good afternoon';
  if (hour >= 17 && hour < 21) return 'Good evening';
  return 'Good night';
};

export const DashboardPage: React.FC<DashboardPageProps> = ({
  stats,
  onNavigate,
  onSelectCase
}) => {
  const scrollToEngine5 = () => {
    const el = document.getElementById('engine-5-simulator');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto py-4">
      {/* Command Center Header */}
      <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-4 border-b border-[#25313E]/60 pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#E8EDF3] font-sans">
            {getGreeting()}, Analyst.
          </h1>
          <p className="text-xs text-[#8996A6] mt-1 font-mono">
            Here's what requires your attention in the active workspace.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={scrollToEngine5}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-md bg-[#151D27] hover:bg-[#1E293B] text-[#5B8DEF] border border-[#5B8DEF]/30 hover:border-[#5B8DEF] text-xs font-semibold tracking-wide transition-all cursor-pointer"
          >
            <Radio size={14} className="animate-pulse" />
            Test Engine 5 (Network)
          </button>

          <button
            onClick={() => onNavigate('workspace')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-[#5B8DEF] hover:bg-[#4a7de0] text-white text-xs font-semibold tracking-wide transition-all shadow-subtle cursor-pointer self-start sm:self-auto"
          >
            <MailSearch size={15} />
            Start Investigation
          </button>
        </div>
      </div>

      {/* Case 1: When Supabase has ZERO records (Standard Empty Product State) */}
      {!stats.has_records && (
        <div className="space-y-6">
          <EmptyState
            icon={FolderPlus}
            title="No investigations yet"
            description="Your forensic workspace is ready. Upload a suspicious email or paste RFC-822 headers to begin your first investigation."
            actionLabel="Start First Investigation"
            onAction={() => onNavigate('workspace')}
          />

          {/* Calm Status Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-4 border-t border-[#25313E]/40 text-xs text-[#8996A6]">
            <div className="p-4 rounded-lg bg-[#0F151D] border border-[#25313E]">
              <span className="text-[11px] font-mono text-[#8996A6] uppercase block mb-1">Active Alerts</span>
              <span className="text-sm font-semibold text-[#E8EDF3]">No active alerts</span>
              <p className="text-[11px] text-[#8996A6] mt-1">High-priority findings will appear here upon ingestion.</p>
            </div>

            <div className="p-4 rounded-lg bg-[#0F151D] border border-[#25313E]">
              <span className="text-[11px] font-mono text-[#8996A6] uppercase block mb-1">Campaign Tracking</span>
              <span className="text-sm font-semibold text-[#E8EDF3]">No campaigns detected</span>
              <p className="text-[11px] text-[#8996A6] mt-1">Relationships emerge when cases share observable infrastructure.</p>
            </div>

            <div className="p-4 rounded-lg bg-[#0F151D] border border-[#25313E]">
              <span className="text-[11px] font-mono text-[#8996A6] uppercase block mb-1">Evidence Ledger</span>
              <span className="text-sm font-semibold text-[#E8EDF3]">Cryptographic Chain Ready</span>
              <p className="text-[11px] text-[#8996A6] mt-1">SHA-256 sequencing initialized for incoming RFC-822 messages.</p>
            </div>
          </div>
        </div>
      )}

      {/* Case 2: When Real Records Exist in Supabase */}
      {stats.has_records && (
        <div className="space-y-6">
          {/* Priority Attention Section */}
          <div className="space-y-3">
            <h2 className="text-xs font-mono font-bold tracking-wider uppercase text-[#8996A6]">
              URGENT ATTENTION REQUIRED ({stats.urgent_actions_required.length})
            </h2>

            {stats.urgent_actions_required.length === 0 ? (
              <div className="p-4 rounded-lg bg-[#0F151D] border border-[#25313E] text-xs text-[#8996A6]">
                All active investigations are triaged. No critical pending threats.
              </div>
            ) : (
              <div className="space-y-2">
                {stats.urgent_actions_required.map((item) => (
                  <div
                    key={item.id}
                    onClick={() => {
                      onSelectCase(item.case_number);
                      onNavigate('workspace');
                    }}
                    className="p-4 rounded-lg bg-[#0F151D] border border-[#25313E] hover:border-[#5B8DEF]/60 transition-all cursor-pointer flex items-center justify-between gap-4"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-[#5B8DEF]">{item.case_number}</span>
                        <span className="text-[#8996A6]">·</span>
                        <span className="text-xs font-bold text-[#E8EDF3]">{item.title}</span>
                      </div>
                      <span className="text-[11px] font-mono text-[#8996A6] mt-1 block">Status: {item.status}</span>
                    </div>

                    <div className="flex items-center gap-3">
                      <RiskBadge score={item.risk_score} level={item.risk_level} size="sm" />
                      <ArrowRight size={14} className="text-[#8996A6]" />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Recent Activity Timeline */}
          {stats.recent_activity.length > 0 && (
            <div className="space-y-3 pt-4 border-t border-[#25313E]/60">
              <h2 className="text-xs font-mono font-bold tracking-wider uppercase text-[#8996A6]">
                RECENT INVESTIGATION ACTIVITY
              </h2>
              <div className="rounded-lg bg-[#0F151D] border border-[#25313E] divide-y divide-[#25313E]/60 overflow-hidden text-xs">
                {stats.recent_activity.map((act, idx) => (
                  <div key={idx} className="p-3 flex items-center justify-between">
                    <span className="text-[#E8EDF3]">{act.description}</span>
                    <span className="text-[11px] font-mono text-[#8996A6]">{act.timestamp}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Dedicated Engine 5 Interactive Telemetry Section */}
      <div id="engine-5-simulator" className="pt-4 border-t border-[#25313E]/60">
        <NetworkTelemetryTester />
      </div>
    </div>
  );
};
