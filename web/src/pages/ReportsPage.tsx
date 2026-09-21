import React from 'react';
import { FileText, Download, Printer, Shield, CheckCircle } from 'lucide-react';
import { BRAND } from '../constants';

export const ReportsPage: React.FC = () => {
  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100 font-mono">
            FORENSIC INCIDENT REPORTS
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Export formal incident analysis reports for legal disclosure, CERT-In advisory, or enterprise SOC response.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold font-mono flex items-center gap-1.5 border border-slate-700 transition-colors cursor-pointer">
            <Printer size={14} />
            Print Report
          </button>
          <button className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold font-mono flex items-center gap-1.5 transition-colors cursor-pointer">
            <Download size={14} />
            Export Signed PDF
          </button>
        </div>
      </div>

      {/* Forensic Report Document Preview */}
      <div className="p-8 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111C32] shadow-sm space-y-6 text-slate-800 dark:text-slate-200 font-sans">
        {/* Document Header */}
        <div className="border-b border-slate-200 dark:border-slate-800 pb-4 flex justify-between items-start">
          <div>
            <span className="text-xs font-mono uppercase text-blue-500 font-bold block">
              OFFICIAL CYBERSECURITY FORENSIC INCIDENT DOSSIER
            </span>
            <h1 className="text-xl font-bold font-mono text-slate-900 dark:text-slate-50 mt-1">
              INCIDENT #CASE-1042 — FORENSIC REPORT
            </h1>
            <span className="text-xs text-slate-500">
              Investigator Platform: {BRAND.NAME} ({BRAND.PROBLEM_STATEMENT})
            </span>
          </div>
          <div className="text-right font-mono text-xs text-slate-400">
            <div>DATE: 2026-09-03</div>
            <div>STATUS: TIER 2 ESCALATED</div>
          </div>
        </div>

        {/* Section 1: Executive Summary */}
        <div className="space-y-2">
          <h2 className="text-xs font-mono font-bold uppercase text-slate-500 dark:text-slate-400 tracking-wider">
            1. EXECUTIVE THREAT ASSESSMENT
          </h2>
          <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-300">
            On 2026-09-03 at 18:45 UTC, an anomalous email purporting to originate from corporate executive leadership was quarantined. Automated analysis by {BRAND.NAME} identified a <strong>94/100 (CRITICAL RISK)</strong> Business Email Compromise attack utilizing executive display impersonation coupled with cryptographic SPF/DKIM validation failures.
          </p>
        </div>

        {/* Section 2: Technical Observations Table */}
        <div className="space-y-2">
          <h2 className="text-xs font-mono font-bold uppercase text-slate-500 dark:text-slate-400 tracking-wider">
            2. RECONSTRUCTED INFRASTRUCTURE & AUTHENTICATION
          </h2>
          <div className="border border-slate-200 dark:border-slate-800 rounded text-xs font-mono overflow-hidden">
            <div className="grid grid-cols-2 p-2 bg-slate-50 dark:bg-slate-900/60 border-b border-slate-200 dark:border-slate-800">
              <span className="text-slate-400">Probable Origin Public IP:</span>
              <span className="font-bold text-red-400">185.220.101.42</span>
            </div>
            <div className="grid grid-cols-2 p-2 border-b border-slate-200 dark:border-slate-800">
              <span className="text-slate-400">Origin Confidence:</span>
              <span className="text-amber-400">MEDIUM (Observed client-relay transition)</span>
            </div>
            <div className="grid grid-cols-2 p-2 bg-slate-50 dark:bg-slate-900/60 border-b border-slate-200 dark:border-slate-800">
              <span className="text-slate-400">Approximate IP Location:</span>
              <span>Amsterdam, Netherlands (AS208323)</span>
            </div>
            <div className="grid grid-cols-2 p-2">
              <span className="text-slate-400">SPF / DKIM / DMARC:</span>
              <span className="text-red-400 font-bold">FAIL / FAIL / FAIL</span>
            </div>
          </div>
        </div>

        {/* Mandatory AI Verification Disclaimer */}
        <div className="p-3 rounded bg-amber-950/20 border border-amber-800/40 text-[11px] font-mono text-amber-300 italic">
          ⚠️ AI-generated forensic draft — analyst verification required before official submission to legal or regulatory authorities.
        </div>
      </div>
    </div>
  );
};
