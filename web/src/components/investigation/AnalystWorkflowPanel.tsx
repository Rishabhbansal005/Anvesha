import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  UserCheck, 
  ArrowRight, 
  Lock, 
  Unlock, 
  Send, 
  CheckCircle2, 
  XCircle, 
  HelpCircle, 
  Clock, 
  FileText, 
  Activity, 
  ChevronRight,
  RotateCcw,
  User,
  AlertOctagon,
  CornerDownRight,
  Compass
} from 'lucide-react';
import { API_BASE_URL, getAuthHeaders, DEFAULT_ANALYST } from '../../constants';
import { CaseItem, CaseNoteItem, CaseActivityItem, CaseStatus, AnalystDecisionType } from '../../types';

interface AnalystWorkflowPanelProps {
  caseData: CaseItem;
  onCaseUpdated: () => void;
}

export const AnalystWorkflowPanel: React.FC<AnalystWorkflowPanelProps> = ({
  caseData,
  onCaseUpdated
}) => {
  const caseId = caseData.case_number || String(caseData.id);
  const isClosed = caseData.status === 'CLOSED';

  // State
  const [notes, setNotes] = useState<CaseNoteItem[]>([]);
  const [activities, setActivities] = useState<CaseActivityItem[]>([]);
  const [loadingNotes, setLoadingNotes] = useState(false);
  const [loadingActivity, setLoadingActivity] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Active Analyst Configuration
  const [currentAnalystId, setCurrentAnalystId] = useState<string>(() => {
    return localStorage.getItem('anvesh_analyst_id') || DEFAULT_ANALYST.id;
  });

  // Note Form
  const [noteContent, setNoteContent] = useState('');

  // Decision Form
  const [decision, setDecision] = useState<AnalystDecisionType>(
    (caseData.analyst_decision as AnalystDecisionType) || 'PENDING'
  );
  const [decisionReason, setDecisionReason] = useState(caseData.analyst_decision_reason || '');

  // Modals
  const [escalateModalOpen, setEscalateModalOpen] = useState(false);
  const [escalationReason, setEscationReason] = useState('');

  const [resolveModalOpen, setResolveModalOpen] = useState(false);
  const [resolveDecision, setResolveDecision] = useState<'CONFIRMED_THREAT' | 'BENIGN_FALSE_POSITIVE'>('CONFIRMED_THREAT');
  const [resolveReason, setResolveReason] = useState('');

  // Assignee input
  const [assigneeInput, setAssigneeInput] = useState(String(caseData.assigned_to || ''));
  const [showReassignInput, setShowReassignInput] = useState(false);

  // Sync decision if caseData changes
  useEffect(() => {
    if (caseData.analyst_decision) {
      setDecision(caseData.analyst_decision as AnalystDecisionType);
    }
    if (caseData.analyst_decision_reason) {
      setDecisionReason(caseData.analyst_decision_reason);
    }
    setAssigneeInput(String(caseData.assigned_to || ''));
  }, [caseData]);

  // Fetch Notes & Activities
  const fetchNotesAndActivity = async () => {
    setLoadingNotes(true);
    setLoadingActivity(true);
    try {
      const [notesRes, actRes] = await Promise.all([
        fetch(`${API_BASE_URL}/cases/${caseId}/notes`, {
          headers: getAuthHeaders(currentAnalystId)
        }),
        fetch(`${API_BASE_URL}/cases/${caseId}/activity`, {
          headers: getAuthHeaders(currentAnalystId)
        })
      ]);

      if (notesRes.ok) {
        const notesData = await notesRes.json();
        const parsedNotes = Array.isArray(notesData)
          ? notesData
          : (Array.isArray(notesData?.notes)
              ? notesData.notes
              : (Array.isArray(notesData?.items) ? notesData.items : []));
        setNotes(parsedNotes);
      }
      if (actRes.ok) {
        const actData = await actRes.json();
        const parsedActs = Array.isArray(actData)
          ? actData
          : (Array.isArray(actData?.activities)
              ? actData.activities
              : (Array.isArray(actData?.items) ? actData.items : []));
        setActivities(parsedActs);
      }
    } catch (err) {
      console.warn('Error fetching notes or activity:', err);
    } finally {
      setLoadingNotes(false);
      setLoadingActivity(false);
    }
  };

  useEffect(() => {
    fetchNotesAndActivity();
  }, [caseId]);

  const handleAnalystIdChange = (newId: string) => {
    const trimmed = newId.trim();
    if (!trimmed) return;
    setCurrentAnalystId(trimmed);
    localStorage.setItem('anvesh_analyst_id', trimmed);
  };

  const clearNotifications = () => {
    setActionError(null);
    setActionSuccess(null);
  };

  // Status Transition
  const handleTransition = async (targetStatus: CaseStatus, note?: string) => {
    clearNotifications();
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${caseId}/status`, {
        method: 'PATCH',
        headers: getAuthHeaders(currentAnalystId),
        body: JSON.stringify({
          status: targetStatus,
          note: note || `Status transitioned to ${targetStatus} via Analyst Workspace`
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Transition to ${targetStatus} rejected.`);
      }

      setActionSuccess(`Case successfully updated to ${targetStatus}`);
      onCaseUpdated();
      fetchNotesAndActivity();
    } catch (err: any) {
      setActionError(err.message || 'Status transition failed.');
    } finally {
      setSubmitting(false);
    }
  };

  // Assignment
  const handleAssign = async (analystToAssign: string) => {
    clearNotifications();
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${caseId}/assignment`, {
        method: 'PATCH',
        headers: getAuthHeaders(currentAnalystId),
        body: JSON.stringify({
          assigned_to: analystToAssign.trim()
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Assignment update rejected.');
      }

      setActionSuccess(`Case assigned to ${analystToAssign}`);
      setShowReassignInput(false);
      onCaseUpdated();
      fetchNotesAndActivity();
    } catch (err: any) {
      setActionError(err.message || 'Assignment failed.');
    } finally {
      setSubmitting(false);
    }
  };

  // Record Decision
  const handleSaveDecision = async () => {
    if (!decisionReason.trim()) {
      setActionError('Analyst decision justification is required.');
      return;
    }
    if (decision === 'PENDING') {
      setActionError('Please select a definitive decision (Confirmed Threat, Benign, or Needs More Evidence).');
      return;
    }

    clearNotifications();
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${caseId}/decision`, {
        method: 'POST',
        headers: getAuthHeaders(currentAnalystId),
        body: JSON.stringify({
          decision,
          reason: decisionReason.trim()
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Failed to record analyst decision.');
      }

      setActionSuccess('Analyst decision recorded successfully. System assessment remains untouched.');
      onCaseUpdated();
      fetchNotesAndActivity();
    } catch (err: any) {
      setActionError(err.message || 'Decision submission failed.');
    } finally {
      setSubmitting(false);
    }
  };

  // Add Note
  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteContent.trim()) return;

    clearNotifications();
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${caseId}/notes`, {
        method: 'POST',
        headers: getAuthHeaders(currentAnalystId),
        body: JSON.stringify({
          content: noteContent.trim()
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Failed to add investigation note.');
      }

      setNoteContent('');
      setActionSuccess('Investigation note recorded in append-only ledger.');
      fetchNotesAndActivity();
    } catch (err: any) {
      setActionError(err.message || 'Note submission failed.');
    } finally {
      setSubmitting(false);
    }
  };

  // Escalate
  const handleEscalateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!escalationReason.trim()) {
      setActionError('Escalation reason is required.');
      return;
    }

    clearNotifications();
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${caseId}/escalate`, {
        method: 'POST',
        headers: getAuthHeaders(currentAnalystId),
        body: JSON.stringify({
          escalation_reason: escalationReason.trim()
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Escalation failed.');
      }

      setEscalateModalOpen(false);
      setEscationReason('');
      setActionSuccess('Case escalated successfully.');
      onCaseUpdated();
      fetchNotesAndActivity();
    } catch (err: any) {
      setActionError(err.message || 'Escalation failed.');
    } finally {
      setSubmitting(false);
    }
  };

  // Resolve
  const handleResolveSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resolveReason.trim()) {
      setActionError('Resolution summary notes are required.');
      return;
    }

    clearNotifications();
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${caseId}/resolve`, {
        method: 'POST',
        headers: getAuthHeaders(currentAnalystId),
        body: JSON.stringify({
          decision: resolveDecision,
          resolution_notes: resolveReason.trim()
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Resolution failed.');
      }

      setResolveModalOpen(false);
      setResolveReason('');
      setActionSuccess('Case resolved successfully.');
      onCaseUpdated();
      fetchNotesAndActivity();
    } catch (err: any) {
      setActionError(err.message || 'Resolution failed.');
    } finally {
      setSubmitting(false);
    }
  };

  // Status Badge Helper
  const getStatusBadge = (status: CaseStatus) => {
    switch (status) {
      case 'NEW':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#5B8DEF]/15 text-[#5B8DEF] border border-[#5B8DEF]/30">NEW</span>;
      case 'TRIAGED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#8E44AD]/15 text-[#AF7AC5] border border-[#8E44AD]/30">TRIAGED</span>;
      case 'INVESTIGATING':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#2980B9]/15 text-[#5DADE2] border border-[#2980B9]/30">INVESTIGATING</span>;
      case 'ESCALATED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#E74C3C]/15 text-[#EC7063] border border-[#E74C3C]/30 animate-pulse">ESCALATED</span>;
      case 'RESOLVED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#27AE60]/15 text-[#58D68D] border border-[#27AE60]/30">RESOLVED</span>;
      case 'CLOSED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#7F8C8D]/15 text-[#BDC3C7] border border-[#7F8C8D]/30">CLOSED</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#1D2633] text-[#8996A6]">{status}</span>;
    }
  };

  // Decision Badge Helper
  const getDecisionBadge = (dec?: string | null) => {
    if (!dec || dec === 'PENDING') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#1D2633] text-[#8996A6] border border-[#25313E]">PENDING REVIEW</span>;
    }
    if (dec === 'CONFIRMED_THREAT') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#FF453A]/20 text-[#FF453A] border border-[#FF453A]/40">CONFIRMED THREAT</span>;
    }
    if (dec === 'BENIGN_FALSE_POSITIVE') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#30D158]/20 text-[#30D158] border border-[#30D158]/40">BENIGN / FALSE POSITIVE</span>;
    }
    if (dec === 'NEEDS_MORE_EVIDENCE') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#FF9F0A]/20 text-[#FF9F0A] border border-[#FF9F0A]/40">NEEDS MORE EVIDENCE</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#1D2633] text-[#8996A6]">{dec}</span>;
  };

  return (
    <div className="space-y-6">
      {/* 1. Attribution Boundary Safeguard Notice */}
      <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-3.5 flex items-start gap-3 shadow-sm">
        <Compass size={18} className="text-[#FF9F0A] flex-shrink-0 mt-0.5" />
        <div className="space-y-0.5 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="font-bold text-[#E8EDF3]">ATTRIBUTION BOUNDARY SAFEGUARD:</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-[#FF453A]/20 text-[#FF453A] border border-[#FF453A]/40">
              ACTOR IDENTITY: NOT ESTABLISHED
            </span>
          </div>
          <p className="text-[#8996A6] text-[11px] leading-relaxed">
            All escalation, triage, and resolution decisions operate strictly on observable infrastructure, SPF/DKIM authentication telemetry, and content patterns. Individual physical actor identity cannot be established.
          </p>
        </div>
      </div>

      {/* Notifications */}
      {actionError && (
        <div className="p-3 rounded-lg bg-[#FF453A]/10 border border-[#FF453A]/30 text-xs font-mono text-[#FF453A] flex items-center justify-between">
          <span>{actionError}</span>
          <button onClick={() => setActionError(null)} className="text-xs hover:underline cursor-pointer">Dismiss</button>
        </div>
      )}
      {actionSuccess && (
        <div className="p-3 rounded-lg bg-[#30D158]/10 border border-[#30D158]/30 text-xs font-mono text-[#30D158] flex items-center justify-between">
          <span>{actionSuccess}</span>
          <button onClick={() => setActionSuccess(null)} className="text-xs hover:underline cursor-pointer">Dismiss</button>
        </div>
      )}

      {/* 2. Top Control Bar: Lifecycle Status & Quick Actions */}
      <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-4 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-[#25313E]/60 pb-3">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 font-mono">
              <span className="text-xs uppercase text-[#8996A6]">Current Status:</span>
              {getStatusBadge(caseData.status)}
            </div>
            {isClosed && (
              <span className="inline-flex items-center gap-1 text-[11px] font-mono text-[#8996A6] bg-[#080C12] px-2 py-0.5 rounded border border-[#25313E]">
                <Lock size={12} className="text-[#8996A6]" />
                <span>Case Locked</span>
              </span>
            )}
          </div>

          {/* Active Analyst Switcher */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <User size={13} className="text-[#5B8DEF]" />
            <span className="text-[#8996A6]">Session Analyst:</span>
            <input 
              type="text"
              value={currentAnalystId}
              onChange={(e) => handleAnalystIdChange(e.target.value)}
              className="px-2 py-0.5 rounded bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#5B8DEF] focus:outline-none focus:border-[#5B8DEF] w-36"
              title="Authenticated Analyst ID sent in X-Analyst-ID header"
            />
          </div>
        </div>

        {/* Quick Transition Buttons */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-xs font-mono text-[#8996A6] mr-1">Lifecycle Actions:</span>

          {caseData.status === 'NEW' && (
            <button
              onClick={() => handleTransition('TRIAGED')}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-[#8E44AD]/20 hover:bg-[#8E44AD]/30 border border-[#8E44AD]/40 text-xs font-mono font-semibold text-[#AF7AC5] transition-colors cursor-pointer disabled:opacity-50"
            >
              Mark Triaged
            </button>
          )}

          {(caseData.status === 'NEW' || caseData.status === 'TRIAGED') && (
            <button
              onClick={() => handleTransition('INVESTIGATING')}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-[#2980B9]/20 hover:bg-[#2980B9]/30 border border-[#2980B9]/40 text-xs font-mono font-semibold text-[#5DADE2] transition-colors cursor-pointer disabled:opacity-50"
            >
              Start Investigation
            </button>
          )}

          {caseData.status !== 'ESCALATED' && caseData.status !== 'CLOSED' && caseData.status !== 'RESOLVED' && (
            <button
              onClick={() => setEscalateModalOpen(true)}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-[#E74C3C]/20 hover:bg-[#E74C3C]/30 border border-[#E74C3C]/40 text-xs font-mono font-semibold text-[#EC7063] transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
            >
              <AlertTriangle size={13} />
              <span>Escalate Case</span>
            </button>
          )}

          {caseData.status === 'ESCALATED' && (
            <button
              onClick={() => handleTransition('INVESTIGATING', 'De-escalated back to active investigation')}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-[#2980B9]/20 hover:bg-[#2980B9]/30 border border-[#2980B9]/40 text-xs font-mono font-semibold text-[#5DADE2] transition-colors cursor-pointer disabled:opacity-50"
            >
              De-escalate to Investigating
            </button>
          )}

          {caseData.status !== 'RESOLVED' && caseData.status !== 'CLOSED' && (
            <button
              onClick={() => setResolveModalOpen(true)}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-[#27AE60]/20 hover:bg-[#27AE60]/30 border border-[#27AE60]/40 text-xs font-mono font-semibold text-[#58D68D] transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
            >
              <CheckCircle2 size={13} />
              <span>Resolve Case</span>
            </button>
          )}

          {caseData.status === 'RESOLVED' && (
            <>
              <button
                onClick={() => handleTransition('CLOSED', 'Case formally closed after resolution')}
                disabled={submitting}
                className="px-3 py-1.5 rounded bg-[#7F8C8D]/20 hover:bg-[#7F8C8D]/30 border border-[#7F8C8D]/40 text-xs font-mono font-semibold text-[#BDC3C7] transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
              >
                <Lock size={13} />
                <span>Close Case (Lock)</span>
              </button>
              <button
                onClick={() => handleTransition('INVESTIGATING', 'Reopened for additional investigation')}
                disabled={submitting}
                className="px-3 py-1.5 rounded bg-[#1D2633] hover:bg-[#25313E] border border-[#25313E] text-xs font-mono text-[#8996A6] transition-colors cursor-pointer disabled:opacity-50"
              >
                Reopen Case
              </button>
            </>
          )}

          {caseData.status === 'CLOSED' && (
            <button
              onClick={() => handleTransition('INVESTIGATING', 'Reopened from closed state for follow-up')}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-[#5B8DEF]/20 hover:bg-[#5B8DEF]/30 border border-[#5B8DEF]/40 text-xs font-mono font-semibold text-[#5B8DEF] transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
            >
              <Unlock size={13} />
              <span>Reopen Case for Investigation</span>
            </button>
          )}
        </div>

        {/* Assignee Bar */}
        <div className="pt-2 border-t border-[#25313E]/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#8996A6]">Assignee:</span>
            <span className="font-bold text-[#E8EDF3]">
              {caseData.assigned_to ? String(caseData.assigned_to) : 'Unassigned'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {!showReassignInput ? (
              <>
                {caseData.assigned_to !== currentAnalystId && (
                  <button
                    onClick={() => handleAssign(currentAnalystId)}
                    disabled={submitting || isClosed}
                    className="px-2.5 py-1 rounded bg-[#1D2633] hover:bg-[#25313E] text-xs text-[#5B8DEF] transition-colors cursor-pointer disabled:opacity-50"
                  >
                    Assign to Me ({currentAnalystId})
                  </button>
                )}
                <button
                  onClick={() => setShowReassignInput(true)}
                  disabled={submitting || isClosed}
                  className="px-2.5 py-1 rounded bg-[#151D27] hover:bg-[#25313E] text-xs text-[#8996A6] transition-colors cursor-pointer disabled:opacity-50"
                >
                  Change Assignee
                </button>
              </>
            ) : (
              <div className="flex items-center gap-1.5">
                <input
                  type="text"
                  placeholder="analyst_usr_xxx"
                  value={assigneeInput}
                  onChange={(e) => setAssigneeInput(e.target.value)}
                  className="px-2 py-1 rounded bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#E8EDF3] focus:outline-none focus:border-[#5B8DEF] w-36"
                />
                <button
                  onClick={() => handleAssign(assigneeInput)}
                  disabled={submitting || !assigneeInput.trim()}
                  className="px-2.5 py-1 rounded bg-[#5B8DEF] text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
                >
                  Save
                </button>
                <button
                  onClick={() => setShowReassignInput(false)}
                  className="px-2 py-1 text-xs text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 3. Side-by-Side: System Assessment vs Analyst Decision */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Left Card: System Assessment (Immutable) */}
        <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
            <div className="flex items-center gap-2">
              <ShieldCheck size={16} className="text-[#5B8DEF]" />
              <h3 className="text-xs font-bold font-mono uppercase text-[#E8EDF3] tracking-wide">
                System Forensic Assessment
              </h3>
            </div>
            <span className="inline-flex items-center gap-1 text-[10px] font-mono text-[#8996A6] bg-[#080C12] px-2 py-0.5 rounded border border-[#25313E]">
              <Lock size={10} />
              <span>Immutable</span>
            </span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 rounded bg-[#080C12] border border-[#25313E]/60 flex items-center justify-between">
              <span className="text-[#8996A6]">Automated Risk Score:</span>
              <span className={`font-bold text-sm ${
                caseData.risk_level === 'CRITICAL' ? 'text-[#FF453A]' :
                caseData.risk_level === 'HIGH' ? 'text-[#FF9F0A]' :
                caseData.risk_level === 'MEDIUM' ? 'text-[#FFD60A]' : 'text-[#30D158]'
              }`}>
                {caseData.risk_score}/100 · {caseData.risk_level}
              </span>
            </div>

            <div className="p-3 rounded bg-[#080C12] border border-[#25313E]/60 flex items-center justify-between">
              <span className="text-[#8996A6]">Threat Classification:</span>
              <span className="font-bold text-[#E8EDF3]">{caseData.threat_type || 'BEC'}</span>
            </div>

            <div className="p-3 rounded bg-[#080C12] border border-[#25313E]/60 flex items-center justify-between">
              <span className="text-[#8996A6]">Origin Confidence:</span>
              <span className="font-bold text-[#E8EDF3]">{caseData.origin_confidence || 'HIGH'}</span>
            </div>

            <div className="p-3 rounded bg-[#080C12] border border-[#25313E]/60 flex items-center justify-between">
              <span className="text-[#8996A6]">Probable Origin IP:</span>
              <span className="font-bold text-[#5B8DEF]">{caseData.probable_origin_ip || 'Not Established'}</span>
            </div>
          </div>

          <p className="text-[11px] font-mono text-[#8996A6] bg-[#151D27]/60 p-2.5 rounded border border-[#25313E]/40 leading-relaxed">
            Note: System scores reflect raw sensor ML & forensic model outputs. These metrics remain untouched regardless of analyst triage or dispute.
          </p>
        </div>

        {/* Right Card: Analyst Decision (Human Adjudication) */}
        <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
            <div className="flex items-center gap-2">
              <UserCheck size={16} className="text-[#30D158]" />
              <h3 className="text-xs font-bold font-mono uppercase text-[#E8EDF3] tracking-wide">
                Analyst Adjudication
              </h3>
            </div>
            {getDecisionBadge(caseData.analyst_decision)}
          </div>

          {caseData.analyst_decision_by && (
            <div className="text-[11px] font-mono text-[#8996A6] bg-[#080C12] p-2 rounded border border-[#25313E]/40 flex items-center justify-between">
              <span>Recorded by: <strong className="text-[#E8EDF3]">{caseData.analyst_decision_by}</strong></span>
              {caseData.analyst_decision_at && (
                <span>{new Date(caseData.analyst_decision_at).toLocaleString()}</span>
              )}
            </div>
          )}

          <div className="space-y-3 font-mono text-xs">
            <label className="block text-[11px] uppercase text-[#8996A6]">Select Formal Decision:</label>
            <div className="space-y-2">
              <label className={`flex items-center gap-2.5 p-2.5 rounded border cursor-pointer transition-colors ${
                decision === 'CONFIRMED_THREAT' 
                  ? 'bg-[#FF453A]/10 border-[#FF453A]/40 text-[#FF453A]' 
                  : 'bg-[#080C12] border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3]'
              }`}>
                <input
                  type="radio"
                  name="analyst_decision"
                  value="CONFIRMED_THREAT"
                  checked={decision === 'CONFIRMED_THREAT'}
                  disabled={isClosed}
                  onChange={() => setDecision('CONFIRMED_THREAT')}
                  className="accent-[#FF453A]"
                />
                <span className="font-semibold text-xs">Confirmed Threat</span>
                <span className="text-[10px] opacity-70 ml-auto">Malicious intent verified</span>
              </label>

              <label className={`flex items-center gap-2.5 p-2.5 rounded border cursor-pointer transition-colors ${
                decision === 'BENIGN_FALSE_POSITIVE' 
                  ? 'bg-[#30D158]/10 border-[#30D158]/40 text-[#30D158]' 
                  : 'bg-[#080C12] border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3]'
              }`}>
                <input
                  type="radio"
                  name="analyst_decision"
                  value="BENIGN_FALSE_POSITIVE"
                  checked={decision === 'BENIGN_FALSE_POSITIVE'}
                  disabled={isClosed}
                  onChange={() => setDecision('BENIGN_FALSE_POSITIVE')}
                  className="accent-[#30D158]"
                />
                <span className="font-semibold text-xs">Benign / False Positive</span>
                <span className="text-[10px] opacity-70 ml-auto">Legitimate email communication</span>
              </label>

              <label className={`flex items-center gap-2.5 p-2.5 rounded border cursor-pointer transition-colors ${
                decision === 'NEEDS_MORE_EVIDENCE' 
                  ? 'bg-[#FF9F0A]/10 border-[#FF9F0A]/40 text-[#FF9F0A]' 
                  : 'bg-[#080C12] border-[#25313E] text-[#8996A6] hover:text-[#E8EDF3]'
              }`}>
                <input
                  type="radio"
                  name="analyst_decision"
                  value="NEEDS_MORE_EVIDENCE"
                  checked={decision === 'NEEDS_MORE_EVIDENCE'}
                  disabled={isClosed}
                  onChange={() => setDecision('NEEDS_MORE_EVIDENCE')}
                  className="accent-[#FF9F0A]"
                />
                <span className="font-semibold text-xs">Needs More Evidence</span>
                <span className="text-[10px] opacity-70 ml-auto">Awaiting gateway logs or IOCs</span>
              </label>
            </div>

            <div className="space-y-1.5 pt-1">
              <label className="block text-[11px] uppercase text-[#8996A6]">Decision Justification (Mandatory):</label>
              <textarea
                rows={3}
                value={decisionReason}
                disabled={isClosed}
                onChange={(e) => setDecisionReason(e.target.value)}
                placeholder="Explain the forensic rationale behind this decision..."
                className="w-full rounded bg-[#080C12] border border-[#25313E] p-2 text-xs font-mono text-[#E8EDF3] placeholder-[#8996A6]/60 focus:outline-none focus:border-[#30D158]"
              />
            </div>

            <button
              onClick={handleSaveDecision}
              disabled={submitting || isClosed || !decisionReason.trim() || decision === 'PENDING'}
              className="w-full py-2 rounded bg-[#30D158]/20 hover:bg-[#30D158]/30 border border-[#30D158]/40 text-[#30D158] font-bold text-xs transition-colors cursor-pointer disabled:opacity-40"
            >
              Save Analyst Adjudication
            </button>
          </div>
        </div>
      </div>

      {/* 4. Append-Only Investigation Notes */}
      <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
          <div className="flex items-center gap-2">
            <FileText size={16} className="text-[#5B8DEF]" />
            <h3 className="text-xs font-bold font-mono uppercase text-[#E8EDF3] tracking-wide">
              Append-Only Forensic Notes
            </h3>
          </div>
          <span className="text-[10px] font-mono text-[#8996A6]">
            {Array.isArray(notes) ? notes.length : 0} notes recorded
          </span>
        </div>

        {/* Note Input */}
        {!isClosed ? (
          <form onSubmit={handleAddNote} className="space-y-2">
            <textarea
              rows={2}
              value={noteContent}
              onChange={(e) => setNoteContent(e.target.value)}
              placeholder="Record forensic observation, hypothesis, or interview finding (append-only)..."
              className="w-full rounded bg-[#080C12] border border-[#25313E] p-2.5 text-xs font-mono text-[#E8EDF3] placeholder-[#8996A6]/60 focus:outline-none focus:border-[#5B8DEF]"
            />
            <div className="flex justify-between items-center">
              <span className="text-[10px] font-mono text-[#8996A6]">
                Author will be saved as: <strong className="text-[#5B8DEF]">{currentAnalystId}</strong>
              </span>
              <button
                type="submit"
                disabled={submitting || !noteContent.trim()}
                className="px-4 py-1.5 rounded bg-[#5B8DEF] hover:bg-[#4a7de0] text-white text-xs font-mono font-semibold transition-colors cursor-pointer disabled:opacity-40 flex items-center gap-1.5"
              >
                <Send size={12} />
                <span>Add Note</span>
              </button>
            </div>
          </form>
        ) : (
          <div className="p-3 rounded bg-[#080C12] border border-[#25313E] text-xs font-mono text-[#8996A6] flex items-center gap-2">
            <Lock size={13} />
            <span>Case is closed. Reopen the case to record additional notes.</span>
          </div>
        )}

        {/* Notes Feed */}
        <div className="space-y-2.5 pt-2">
          {loadingNotes ? (
            <div className="py-6 text-center text-xs font-mono text-[#8996A6]">Loading notes ledger...</div>
          ) : (!Array.isArray(notes) || notes.length === 0) ? (
            <div className="p-4 rounded bg-[#080C12] border border-[#25313E]/60 text-center text-xs font-mono text-[#8996A6]">
              No forensic notes logged for this case yet.
            </div>
          ) : (
            notes.map((n) => (
              <div key={n.id} className="p-3 rounded bg-[#080C12] border border-[#25313E]/60 space-y-1.5 text-xs font-mono">
                <div className="flex items-center justify-between text-[11px] text-[#8996A6] border-b border-[#25313E]/40 pb-1">
                  <div className="flex items-center gap-2">
                    <User size={12} className="text-[#5B8DEF]" />
                    <span className="font-bold text-[#E8EDF3]">{n.author_id}</span>
                    {n.author_email && <span className="text-[#8996A6]">({n.author_email})</span>}
                  </div>
                  <span>{new Date(n.created_at).toLocaleString()}</span>
                </div>
                <p className="text-[#E8EDF3] leading-relaxed whitespace-pre-wrap">{n.content}</p>
              </div>
            ))
          )}
        </div>
      </div>

      {/* 5. Unified Activity Timeline */}
      <div className="rounded-lg border border-[#25313E] bg-[#0F151D] p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-[#25313E]/60 pb-3">
          <div className="flex items-center gap-2">
            <Activity size={16} className="text-[#5B8DEF]" />
            <h3 className="text-xs font-bold font-mono uppercase text-[#E8EDF3] tracking-wide">
              Unified Activity Timeline
            </h3>
          </div>
          <span className="text-[10px] font-mono text-[#8996A6]">
            {Array.isArray(activities) ? activities.length : 0} events logged
          </span>
        </div>

        <div className="space-y-2 pt-1 font-mono text-xs">
          {loadingActivity ? (
            <div className="py-6 text-center text-[#8996A6]">Loading timeline events...</div>
          ) : (!Array.isArray(activities) || activities.length === 0) ? (
            <div className="p-4 rounded bg-[#080C12] border border-[#25313E]/60 text-center text-[#8996A6]">
              No activity logged yet.
            </div>
          ) : (
            activities.map((act) => {
              const isSystem = act.actor_id === 'SYSTEM' || act.event_type === 'SYSTEM_ALERT';
              return (
                <div key={act.id} className="p-3 rounded bg-[#080C12] border border-[#25313E]/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                        isSystem 
                          ? 'bg-[#5B8DEF]/20 text-[#5B8DEF] border border-[#5B8DEF]/30' 
                          : 'bg-[#30D158]/20 text-[#30D158] border border-[#30D158]/30'
                      }`}>
                        {isSystem ? 'SYSTEM' : 'ANALYST'}
                      </span>
                      <span className="font-bold text-[#E8EDF3] text-xs">{act.event_type}</span>
                      <span className="text-[#8996A6] text-[11px]">by {act.actor_id}</span>
                    </div>
                    <p className="text-[#8996A6] text-xs">{act.description}</p>
                  </div>
                  <span className="text-[10px] text-[#8996A6] flex-shrink-0 self-start sm:self-center">
                    {new Date(act.created_at).toLocaleString()}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* MODAL 1: Escalate Case */}
      {escalateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
          <div className="w-full max-w-md rounded-lg border border-[#E74C3C]/50 bg-[#0F151D] p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-[#25313E] pb-3">
              <div className="flex items-center gap-2 text-[#EC7063]">
                <AlertTriangle size={18} />
                <h3 className="text-sm font-bold font-mono uppercase">Escalate Investigation</h3>
              </div>
              <button 
                onClick={() => setEscalateModalOpen(false)}
                className="text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleEscalateSubmit} className="space-y-4 font-mono text-xs">
              <p className="text-[#8996A6] leading-relaxed">
                Escalation triggers immediate on-call notifications and raises case priority. State will transition to <strong className="text-[#EC7063]">ESCALATED</strong>.
              </p>

              <div className="space-y-1.5">
                <label className="block text-[11px] uppercase text-[#8996A6]">
                  Escalation Reason (Mandatory):
                </label>
                <textarea
                  rows={4}
                  value={escalationReason}
                  onChange={(e) => setEscationReason(e.target.value)}
                  placeholder="e.g. VIP targeted, active C2 beaconing observed, credentials verified compromised..."
                  className="w-full rounded bg-[#080C12] border border-[#25313E] p-2 text-xs text-[#E8EDF3] placeholder-[#8996A6]/60 focus:outline-none focus:border-[#EC7063]"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEscalateModalOpen(false)}
                  className="px-3 py-1.5 rounded bg-[#1D2633] text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !escalationReason.trim()}
                  className="px-4 py-1.5 rounded bg-[#E74C3C] hover:bg-[#c0392b] text-white font-bold cursor-pointer disabled:opacity-50"
                >
                  Confirm Escalation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: Resolve Case */}
      {resolveModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
          <div className="w-full max-w-md rounded-lg border border-[#27AE60]/50 bg-[#0F151D] p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-[#25313E] pb-3">
              <div className="flex items-center gap-2 text-[#58D68D]">
                <CheckCircle2 size={18} />
                <h3 className="text-sm font-bold font-mono uppercase">Resolve Investigation</h3>
              </div>
              <button 
                onClick={() => setResolveModalOpen(false)}
                className="text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleResolveSubmit} className="space-y-4 font-mono text-xs">
              <div className="space-y-2">
                <label className="block text-[11px] uppercase text-[#8996A6]">
                  Resolution Disposition:
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setResolveDecision('CONFIRMED_THREAT')}
                    className={`p-2.5 rounded border text-center font-bold text-xs cursor-pointer transition-colors ${
                      resolveDecision === 'CONFIRMED_THREAT'
                        ? 'bg-[#FF453A]/20 border-[#FF453A]/50 text-[#FF453A]'
                        : 'bg-[#080C12] border-[#25313E] text-[#8996A6]'
                    }`}
                  >
                    Confirmed Threat
                  </button>
                  <button
                    type="button"
                    onClick={() => setResolveDecision('BENIGN_FALSE_POSITIVE')}
                    className={`p-2.5 rounded border text-center font-bold text-xs cursor-pointer transition-colors ${
                      resolveDecision === 'BENIGN_FALSE_POSITIVE'
                        ? 'bg-[#30D158]/20 border-[#30D158]/50 text-[#30D158]'
                        : 'bg-[#080C12] border-[#25313E] text-[#8996A6]'
                    }`}
                  >
                    Benign / FP
                  </button>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="block text-[11px] uppercase text-[#8996A6]">
                  Resolution Notes (Mandatory):
                </label>
                <textarea
                  rows={4}
                  value={resolveReason}
                  onChange={(e) => setResolveReason(e.target.value)}
                  placeholder="Summarize forensic findings, mitigations applied, and closing recommendations..."
                  className="w-full rounded bg-[#080C12] border border-[#25313E] p-2 text-xs text-[#E8EDF3] placeholder-[#8996A6]/60 focus:outline-none focus:border-[#27AE60]"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setResolveModalOpen(false)}
                  className="px-3 py-1.5 rounded bg-[#1D2633] text-[#8996A6] hover:text-[#E8EDF3] cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !resolveReason.trim()}
                  className="px-4 py-1.5 rounded bg-[#27AE60] hover:bg-[#229954] text-white font-bold cursor-pointer disabled:opacity-50"
                >
                  Confirm Resolution
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
