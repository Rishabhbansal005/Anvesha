import React from 'react';
import { Target, HelpCircle } from 'lucide-react';
import { OriginConfidence } from '../../types';

interface ConfidencePillProps {
  confidence: OriginConfidence | string;
  size?: 'sm' | 'md';
}

export const ConfidencePill: React.FC<ConfidencePillProps> = ({ confidence, size = 'md' }) => {
  const normalized = (confidence || 'LOW').toUpperCase();

  const styles: Record<string, string> = {
    HIGH: 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60',
    MEDIUM: 'bg-amber-950/40 text-amber-300 border-amber-800/60',
    LOW: 'bg-slate-800 text-slate-300 border-slate-700',
    UNRELIABLE: 'bg-red-950/40 text-red-300 border-red-800/60'
  };

  const currentStyle = styles[normalized] || styles.LOW;
  const padding = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border font-mono tracking-tight ${padding} ${currentStyle}`}
      title={`Confidence Level: ${normalized}. Indicates evidentiary reliability of the observed hop sequence.`}
    >
      <Target size={size === 'sm' ? 12 : 13} className="text-current opacity-80" />
      <span className="font-sans text-[11px] text-slate-400 font-normal">Confidence:</span>
      <span className="font-bold">{normalized}</span>
    </span>
  );
};
