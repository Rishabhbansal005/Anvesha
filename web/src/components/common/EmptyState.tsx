import React from 'react';
import { LucideIcon } from 'lucide-react';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon,
  title,
  description,
  actionLabel,
  onAction
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-xl border border-dashed border-[#25313E] dark:border-[#25313E] light:border-[#D5DDE6] bg-[#0F151D]/40 dark:bg-[#0F151D]/40 light:bg-[#FFFFFF] max-w-lg mx-auto my-8 transition-all">
      <div className="w-11 h-11 rounded-full bg-[#151D27] dark:bg-[#151D27] light:bg-[#EEF2F6] border border-[#25313E] dark:border-[#25313E] light:border-[#D5DDE6] flex items-center justify-center text-[#8996A6] mb-4">
        <Icon size={20} className="text-[#5B8DEF]" />
      </div>
      <h3 className="text-sm font-semibold tracking-tight text-[#E8EDF3] dark:text-[#E8EDF3] light:text-[#17212B] uppercase font-mono">
        {title}
      </h3>
      <p className="text-xs text-[#8996A6] dark:text-[#8996A6] light:text-[#5F6B78] mt-1.5 max-w-sm leading-relaxed">
        {description}
      </p>
      {actionLabel && onAction && (
        <button
          onClick={onAction}
          className="mt-5 px-4 py-2 rounded-md bg-[#5B8DEF] hover:bg-[#4a7de0] text-white text-xs font-semibold tracking-wide transition-all shadow-subtle cursor-pointer"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
};
