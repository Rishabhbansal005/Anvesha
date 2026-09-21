import React from 'react';
import { Search, Sun, Moon } from 'lucide-react';
import { NavTab } from '../../constants';
import { useTheme } from '../../context/ThemeContext';

interface TopBarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  onOpenCommandPalette: () => void;
  supabaseConnected: boolean;
  unreviewedAlertsCount: number;
}

export const TopBar: React.FC<TopBarProps> = ({
  currentTab, onSelectTab, onOpenCommandPalette, supabaseConnected, unreviewedAlertsCount
}) => {
  const { theme, toggleTheme } = useTheme();

  const navBtn = (tab: NavTab, label: string, badge?: number) => (
    <button
      key={tab}
      onClick={() => onSelectTab(tab)}
      className={`px-3 py-1 rounded-md text-xs font-medium transition-all cursor-pointer flex items-center gap-1.5 ${
        currentTab === tab
          ? 'bg-[#5B8DEF] text-white shadow-sm'
          : 'text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#25313E]/50'
      }`}
    >
      <span>{label}</span>
      {badge !== undefined && badge > 0 && (
        <span className="w-4 h-4 rounded-full bg-[#EF6262] text-white text-[10px] font-bold flex items-center justify-center font-mono">
          {badge}
        </span>
      )}
    </button>
  );

  return (
    <header className="h-14 border-b border-[#25313E] bg-[#0F151D]/90 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-30 transition-all select-none">
      {/* Brand + Nav */}
      <div className="flex items-center gap-5">
        <div onClick={() => onSelectTab('dashboard')} className="flex items-center cursor-pointer group">
          <img
            src="/brand/anvesh-logo-transparent.png"
            alt="ANVESH"
            className="h-[42px] w-auto object-contain group-hover:opacity-95 transition-opacity drop-shadow-[0_2px_10px_rgba(30,130,250,0.15)]"
            draggable={false}
          />
        </div>

        <nav className="hidden md:flex items-center gap-1 bg-[#151D27] p-1 rounded-lg border border-[#25313E]">
          {navBtn('dashboard', 'Overview')}
          {navBtn('workspace', 'Investigation Workspace')}
          {navBtn('investigations', 'Cases')}
          {navBtn('alerts', 'Alerts', unreviewedAlertsCount)}
          {navBtn('intelligence', 'Intelligence')}
          {navBtn('campaigns', 'Campaigns')}
        </nav>
      </div>

      {/* Center: Search */}
      <div className="flex-1 max-w-md mx-6 hidden lg:block">
        <button onClick={onOpenCommandPalette}
          className="w-full flex items-center justify-between px-3 py-1.5 rounded-md bg-[#151D27] border border-[#25313E] text-xs text-[#8996A6] hover:border-[#5B8DEF]/40 transition-colors cursor-pointer">
          <div className="flex items-center gap-2">
            <Search size={14} />
            <span>Search emails, IPs, domains, cases...</span>
          </div>
          <kbd className="px-1.5 py-0.5 rounded bg-[#25313E] text-[10px] font-mono text-[#8996A6]">Ctrl K</kbd>
        </button>
      </div>

      {/* Right */}
      <div className="flex items-center gap-3">
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-xs font-mono transition-colors ${
          supabaseConnected ? 'bg-[#35C98A]/10 text-[#35C98A] border-[#35C98A]/30' : 'bg-[#F2B84B]/10 text-[#F2B84B] border-[#F2B84B]/30'
        }`} title={supabaseConnected ? 'Live connection active' : 'Connecting...'}>
          <span className={`w-1.5 h-1.5 rounded-full ${supabaseConnected ? 'bg-[#35C98A] animate-pulse' : 'bg-[#F2B84B]'}`} />
          <span className="hidden sm:inline">{supabaseConnected ? 'SUPABASE LIVE' : 'SYNCING'}</span>
        </div>

        <button onClick={toggleTheme} aria-label="Toggle Theme"
          className="p-2 rounded-md hover:bg-[#151D27] text-[#8996A6] hover:text-[#E8EDF3] border border-[#25313E] transition-colors cursor-pointer"
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}>
          {theme === 'dark' ? <Sun size={15} className="text-[#F2B84B]" /> : <Moon size={15} />}
        </button>

        <div className="flex items-center gap-2 pl-2 border-l border-[#25313E]">
          <div className="w-7 h-7 rounded-full bg-[#151D27] border border-[#25313E] flex items-center justify-center text-xs font-mono font-bold text-[#5B8DEF]">
            AN
          </div>
        </div>
      </div>
    </header>
  );
};
