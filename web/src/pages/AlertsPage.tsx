import React, { useState, useEffect } from 'react';
import { Bell, CheckCircle2, ShieldAlert } from 'lucide-react';
import { EmptyState } from '../components/common/EmptyState';
import { RiskBadge } from '../components/common/RiskBadge';
import { API_BASE_URL } from '../constants';

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE_URL}/alerts`)
      .then(res => res.json())
      .then(data => setAlerts(data.items || []))
      .catch(e => setAlerts([]))
      .finally(() => setLoading(false));
  }, []);

  const handleTriage = async (alertId: string, action: 'REVIEW' | 'ESCALATE') => {
    try {
      await fetch(`${API_BASE_URL}/alerts/${alertId}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, note: `Triaged via ANVESH workstation` })
      });
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, is_reviewed: true, is_escalated: action === 'ESCALATE' } : a));
    } catch (e) {
      console.warn("Triage failed:", e);
    }
  };

  if (loading) {
    return (
      <div className="py-16 text-center text-xs font-mono text-[#8996A6]">
        Checking alert stream in Supabase...
      </div>
    );
  }

  if (alerts.length === 0) {
    return (
      <div className="py-8 max-w-4xl mx-auto">
        <EmptyState
          icon={Bell}
          title="No active alerts"
          description="New high-priority findings and anomalies will appear here when emails exceed risk thresholds."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto py-4">
      <div className="border-b border-[#25313E]/60 pb-4">
        <h2 className="text-xl font-bold tracking-tight text-[#E8EDF3] font-mono">
          REAL-TIME ALERT TRIAGE
        </h2>
        <p className="text-xs text-[#8996A6] mt-1">
          Active alerts requiring investigator triage. Shared directly with mobile on-call companion.
        </p>
      </div>

      <div className="space-y-3">
        {alerts.map((a, idx) => (
          <div
            key={a.id || a.case_id || `alert-${idx}`}
            className="p-4 rounded-lg bg-[#0F151D] border border-[#25313E] flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs"
          >
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-[#E8EDF3]">{a.title}</span>
                {a.is_escalated && (
                  <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-[#EF6262]/20 text-[#EF6262] border border-[#EF6262]/40">
                    ESCALATED
                  </span>
                )}
              </div>
              <p className="text-[#8996A6] mt-1">{a.summary}</p>
            </div>

            <div className="flex items-center gap-3 flex-shrink-0">
              <RiskBadge score={a.risk_score} level={a.risk_level} size="sm" />
              <div className="flex gap-2">
                {!a.is_reviewed && (
                  <button
                    onClick={() => handleTriage(a.id, 'REVIEW')}
                    className="px-2.5 py-1 rounded bg-[#151D27] hover:bg-[#25313E] text-[#E8EDF3] font-medium cursor-pointer"
                  >
                    Acknowledge
                  </button>
                )}
                {!a.is_escalated && (
                  <button
                    onClick={() => handleTriage(a.id, 'ESCALATE')}
                    className="px-2.5 py-1 rounded bg-[#EF6262]/20 hover:bg-[#EF6262]/30 text-[#EF6262] border border-[#EF6262]/40 font-medium cursor-pointer"
                  >
                    Escalate
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
