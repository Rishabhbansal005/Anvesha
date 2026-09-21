import React, { useState, useEffect } from 'react';
import { 
  FolderPlus, 
  Search, 
  Trash2, 
  Filter, 
  ChevronRight, 
  AlertTriangle,
  Calendar,
  ShieldAlert
} from 'lucide-react';
import { EmptyState } from '../components/common/EmptyState';
import { RiskBadge } from '../components/common/RiskBadge';
import { API_BASE_URL } from '../constants';

interface CasesPageProps {
  onSelectCase: (caseId: string) => void;
  onStartNewInvestigation: () => void;
}

export const CasesPage: React.FC<CasesPageProps> = ({
  onSelectCase,
  onStartNewInvestigation
}) => {
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [caseToDelete, setCaseToDelete] = useState<any | null>(null);
  const [deleting, setDeleting] = useState(false);

  const fetchCases = () => {
    setLoading(true);
    setError(null);
    let url = `${API_BASE_URL}/cases?limit=100`;
    if (riskFilter !== 'ALL') url += `&risk_level=${riskFilter}`;
    if (statusFilter !== 'ALL') url += `&status=${statusFilter}`;
    if (decisionFilter !== 'ALL') url += `&decision=${decisionFilter}`;
    if (searchTerm.trim()) url += `&q=${encodeURIComponent(searchTerm.trim())}`;

    fetch(url)
      .then(async (res) => {
        if (!res.ok) throw new Error('Failed to retrieve cases from Supabase ledger');
        return res.json();
      })
      .then((data) => {
        setCases(data.items || []);
      })
      .catch((err) => {
        setError(err.message || 'Error connecting to database');
        setCases([]);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchCases();
  }, [riskFilter, statusFilter, decisionFilter]);

  // Handle Search on Enter or debounce
  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchCases();
  };

  // Safe Case Deletion with cascade
  const handleConfirmDelete = async () => {
    if (!caseToDelete) return;
    setDeleting(true);
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${caseToDelete.id || caseToDelete.case_number}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        setCases((prev) => prev.filter((c) => c.case_number !== caseToDelete.case_number && c.id !== caseToDelete.id));
        setCaseToDelete(null);
      } else {
        alert('Failed to delete investigation from database.');
      }
    } catch (err) {
      console.error('Delete case error:', err);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto py-4">
      {/* Header */}
      <div className="border-b border-[#25313E]/60 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-[#E8EDF3] font-mono">
            INVESTIGATIONS & CASES
          </h2>
          <p className="text-xs text-[#8996A6] mt-0.5">
            Real threat investigations recorded in immutable database ledger.
          </p>
        </div>
        <button
          onClick={onStartNewInvestigation}
          className="px-3 py-1.5 rounded-md bg-[#5B8DEF] hover:bg-[#4a7de0] text-white text-xs font-semibold font-mono transition-colors cursor-pointer self-start sm:self-auto flex items-center gap-1.5"
        >
          <FolderPlus size={14} />
          <span>New Investigation</span>
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-[#0F151D] border border-[#25313E] rounded-lg p-3 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex gap-2">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8996A6]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by case number, subject, sender, or origin IP..."
              className="w-full bg-[#080C12] border border-[#25313E] rounded-md pl-9 pr-3 py-1.5 text-xs text-[#E8EDF3] placeholder-[#8996A6] focus:outline-none focus:border-[#5B8DEF] font-mono"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 rounded-md bg-[#1D2633] hover:bg-[#25313E] text-xs font-mono text-[#E8EDF3] transition-colors cursor-pointer"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-4 text-xs font-mono pt-1 border-t border-[#25313E]/40">
          {/* Risk Filters */}
          <div className="flex items-center gap-1.5">
            <span className="text-[#8996A6] text-[11px]">Risk:</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setRiskFilter(lvl)}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  riskFilter === lvl
                    ? 'bg-[#5B8DEF] text-white'
                    : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#1D2633]'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          {/* Status Filters */}
          <div className="flex items-center gap-1.5">
            <span className="text-[#8996A6] text-[11px]">Status:</span>
            {['ALL', 'NEW', 'TRIAGED', 'INVESTIGATING', 'ESCALATED', 'RESOLVED', 'CLOSED'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  statusFilter === st
                    ? 'bg-[#5B8DEF] text-white'
                    : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#1D2633]'
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Decision Filters */}
          <div className="flex items-center gap-1.5">
            <span className="text-[#8996A6] text-[11px]">Decision:</span>
            {[
              { id: 'ALL', label: 'ALL' },
              { id: 'CONFIRMED_THREAT', label: 'THREAT' },
              { id: 'BENIGN_FALSE_POSITIVE', label: 'BENIGN' },
              { id: 'NEEDS_MORE_EVIDENCE', label: 'MORE INFO' },
              { id: 'PENDING', label: 'PENDING' }
            ].map((dec) => (
              <button
                key={dec.id}
                onClick={() => setDecisionFilter(dec.id)}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  decisionFilter === dec.id
                    ? 'bg-[#30D158] text-black font-bold'
                    : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#1D2633]'
                }`}
              >
                {dec.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <div className="py-16 text-center text-xs font-mono text-[#8996A6]">
          Loading investigations from Supabase...
        </div>
      ) : error ? (
        <div className="p-4 rounded-lg bg-[#FF453A]/10 border border-[#FF453A]/30 text-xs font-mono text-[#FF453A] flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={fetchCases}
            className="px-2.5 py-1 rounded bg-[#FF453A]/20 hover:bg-[#FF453A]/30 text-white cursor-pointer"
          >
            Retry
          </button>
        </div>
      ) : cases.length === 0 ? (
        <div className="py-8 max-w-4xl mx-auto">
          <EmptyState
            icon={FolderPlus}
            title="No investigations yet"
            description="Your forensic workspace is ready. Upload a suspicious email or paste RFC-822 headers to begin."
            actionLabel="Start Investigation"
            onAction={onStartNewInvestigation}
          />
        </div>
      ) : (
        <div className="rounded-lg border border-[#25313E] bg-[#0F151D] divide-y divide-[#25313E]/60 overflow-hidden text-xs">
          {cases.map((c) => (
            <div
              key={c.id || c.case_number}
              className="p-4 flex items-center justify-between hover:bg-[#151D27] transition-colors group"
            >
              <div 
                onClick={() => onSelectCase(c.case_number || c.id)}
                className="space-y-1 flex-1 cursor-pointer pr-4"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-[#5B8DEF]">{c.case_number}</span>
                  <span className="text-[#8996A6]">·</span>
                  <span className="font-semibold text-[#E8EDF3] truncate max-w-lg">{c.title}</span>
                </div>
                <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-[#8996A6]">
                  <span>Threat: {c.threat_type || 'BEC'}</span>
                  <span>·</span>
                  <span>Origin: {c.probable_origin_ip || 'Not established'}</span>
                  <span>·</span>
                  <span className="uppercase font-bold text-[#5B8DEF]">{c.status}</span>
                  {c.assigned_to && (
                    <>
                      <span>·</span>
                      <span className="text-[#8996A6]">Assignee: <strong className="text-[#E8EDF3]">{String(c.assigned_to)}</strong></span>
                    </>
                  )}
                  {c.analyst_decision && (
                    <>
                      <span>·</span>
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                        c.analyst_decision === 'CONFIRMED_THREAT' ? 'bg-[#FF453A]/20 text-[#FF453A] border border-[#FF453A]/40' :
                        c.analyst_decision === 'BENIGN_FALSE_POSITIVE' ? 'bg-[#30D158]/20 text-[#30D158] border border-[#30D158]/40' :
                        c.analyst_decision === 'NEEDS_MORE_EVIDENCE' ? 'bg-[#FF9F0A]/20 text-[#FF9F0A] border border-[#FF9F0A]/40' : 'bg-[#1D2633] text-[#8996A6]'
                      }`}>
                        {c.analyst_decision.replace(/_/g, ' ')}
                      </span>
                    </>
                  )}
                  {c.created_at && (
                    <>
                      <span>·</span>
                      <span>{new Date(c.created_at).toLocaleDateString()}</span>
                    </>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-4">
                <RiskBadge score={c.risk_score || 0} level={c.risk_level} size="sm" />
                
                {/* Safe Delete Action */}
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setCaseToDelete(c);
                  }}
                  title="Delete case"
                  className="p-1.5 rounded text-[#8996A6] hover:text-[#FF453A] hover:bg-[#1D2633] transition-colors opacity-60 group-hover:opacity-100 cursor-pointer"
                >
                  <Trash2 size={14} />
                </button>

                <div 
                  onClick={() => onSelectCase(c.case_number || c.id)}
                  className="cursor-pointer"
                >
                  <ChevronRight size={15} className="text-[#8996A6]" />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {caseToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
          <div className="bg-[#0F151D] border border-[#25313E] rounded-xl max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3 text-[#FF453A]">
              <AlertTriangle size={20} />
              <h3 className="text-sm font-bold font-mono uppercase tracking-wide">
                Confirm Case Deletion
              </h3>
            </div>
            <p className="text-xs text-[#8996A6] leading-relaxed">
              Are you sure you want to permanently delete investigation <strong className="text-[#E8EDF3] font-mono">{caseToDelete.case_number}</strong>? 
              This will cascade-delete all linked cryptographic evidence, headers, and observable records from Supabase.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setCaseToDelete(null)}
                disabled={deleting}
                className="px-3 py-1.5 rounded-md border border-[#25313E] bg-[#151D27] text-xs font-mono text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                disabled={deleting}
                className="px-3 py-1.5 rounded-md bg-[#FF453A] hover:bg-[#d63a30] text-xs font-mono text-white font-semibold cursor-pointer"
              >
                {deleting ? 'Deleting...' : 'Delete Case'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
