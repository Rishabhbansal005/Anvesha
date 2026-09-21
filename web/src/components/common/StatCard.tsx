import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtext?: string;
  icon: LucideIcon;
  variant?: 'neutral' | 'critical' | 'warning' | 'success';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtext,
  icon: Icon,
  variant = 'neutral'
}) => {
  const borderStyles = {
    neutral: 'border-slate-800 dark:border-slate-800 hover:border-slate-700',
    critical: 'border-red-900/40 hover:border-red-800/60 bg-gradient-to-br from-red-950/10 to-transparent',
    warning: 'border-amber-900/40 hover:border-amber-800/60 bg-gradient-to-br from-amber-950/10 to-transparent',
    success: 'border-emerald-900/40 hover:border-emerald-800/60 bg-gradient-to-br from-emerald-950/10 to-transparent'
  };

  const iconColors = {
    neutral: 'text-blue-400 bg-blue-950/40 border-blue-800/50',
    critical: 'text-red-400 bg-red-950/50 border-red-800/60',
    warning: 'text-amber-400 bg-amber-950/50 border-amber-800/60',
    success: 'text-emerald-400 bg-emerald-950/50 border-emerald-800/60'
  };

  return (
    <div className={`p-4 rounded-lg bg-white dark:bg-[#111C32] border transition-all duration-150 shadow-sm ${borderStyles[variant]}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
          {title}
        </span>
        <div className={`w-8 h-8 rounded-md flex items-center justify-center border ${iconColors[variant]}`}>
          <Icon size={16} />
        </div>
      </div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-2xl font-bold font-mono tracking-tight text-slate-900 dark:text-slate-50">
          {value}
        </span>
        {subtext && (
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {subtext}
          </span>
        )}
      </div>
    </div>
  );
};
