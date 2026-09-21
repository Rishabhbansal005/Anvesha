import React, { useState, useEffect } from 'react';
import { Layers, Network, ChevronRight, ShieldAlert, ArrowUpRight } from 'lucide-react';
import { CampaignItem } from '../types';
import { API_BASE_URL } from '../constants';
import { IOCChip } from '../components/common/IOCChip';

export const CampaignsPage: React.FC = () => {
  const [campaigns, setCampaigns] = useState<CampaignItem[]>([]);

  useEffect(() => {
    fetch(`${API_BASE_URL}/campaigns`)
      .then(res => res.json())
      .then(data => setCampaigns(data.items || []))
      .catch(e => console.warn(e));
  }, []);

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
        <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100 font-mono">
          THREAT CAMPAIGN CORRELATION
        </h2>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
          Correlated attack campaigns identified through shared infrastructure, sender anomalies, and similarity heuristics.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {campaigns.map((c) => (
          <div key={c.id} className="p-5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111C32] space-y-4 shadow-sm">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-blue-950/40 text-blue-400 border border-blue-800/60 font-semibold">
                  {c.threat_cluster || 'Cluster Alpha'}
                </span>
                <h3 className="text-base font-bold font-mono text-slate-900 dark:text-slate-100 mt-2">
                  {c.name}
                </h3>
              </div>
              <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-red-950 text-red-400 border border-red-800">
                {c.severity}
              </span>
            </div>

            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              {c.description}
            </p>

            <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block uppercase">
                Correlated Cases:
              </span>
              <div className="flex flex-wrap gap-1.5 font-mono text-xs">
                {c.associated_cases.map(caseNum => (
                  <span key={caseNum} className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-blue-500 font-bold">
                    {caseNum}
                  </span>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-[11px] font-mono text-slate-400 block uppercase">
                Shared Indicators of Compromise:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {c.shared_iocs.map(ioc => (
                  <span key={ioc} className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 font-mono text-xs border border-slate-800">
                    {ioc}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
