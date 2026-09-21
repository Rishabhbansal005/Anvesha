import React, { useState } from 'react';
import { Copy, Check, ExternalLink } from 'lucide-react';

interface IOCChipProps {
  type: 'IP' | 'DOMAIN' | 'URL' | 'HASH';
  value: string;
  isMalicious?: boolean;
}

export const IOCChip: React.FC<IOCChipProps> = ({ type, value, isMalicious = false }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const typeStyles = {
    IP: 'bg-blue-950/40 text-blue-300 border-blue-800/60',
    DOMAIN: 'bg-purple-950/40 text-purple-300 border-purple-800/60',
    URL: 'bg-amber-950/40 text-amber-300 border-amber-800/60',
    HASH: 'bg-slate-800 text-slate-300 border-slate-700'
  };

  return (
    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border font-mono text-xs ${typeStyles[type]}`}>
      <span className="text-[10px] font-bold opacity-75 uppercase">{type}</span>
      <span className="font-semibold tracking-tight text-slate-100">{value}</span>
      <button
        onClick={handleCopy}
        title="Copy to clipboard"
        className="p-0.5 rounded hover:bg-white/10 text-slate-400 hover:text-white transition-colors cursor-pointer"
      >
        {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
      </button>
    </div>
  );
};
