import React, { useState, useEffect, useRef } from 'react';
import { Search, X, Briefcase, Network, ArrowRight } from 'lucide-react';
import { API_BASE_URL } from '../../constants';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectCase: (caseId: string) => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({ isOpen, onClose, onSelectCase }) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery('');
      setResults([]);
    }
  }, [isOpen]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const handleSearch = async (val: string) => {
    setQuery(val);
    if (!val.trim()) {
      setResults([]);
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/intelligence/search?q=${encodeURIComponent(val)}`);
      if (res.ok) {
        const data = await res.json();
        setResults(data.results || []);
      }
    } catch (e) {
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 bg-black/60 backdrop-blur-sm p-4 animate-fade-in">
      <div 
        className="w-full max-w-xl rounded-xl border border-[#25313E] bg-[#0F151D] text-[#E8EDF3] shadow-elevated overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Header */}
        <div className="flex items-center px-4 py-3 border-b border-[#25313E] gap-3">
          <Search size={18} className="text-[#8996A6]" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => handleSearch(e.target.value)}
            placeholder="Search emails, IPs, domains, cases..."
            className="flex-1 bg-transparent text-sm text-[#E8EDF3] placeholder-[#8996A6] focus:outline-none font-sans"
          />
          <button 
            onClick={onClose}
            className="p-1 rounded text-[#8996A6] hover:text-[#E8EDF3] hover:bg-[#151D27] cursor-pointer"
          >
            <X size={16} />
          </button>
        </div>

        {/* Results Stream */}
        <div className="max-h-80 overflow-y-auto p-2 divide-y divide-[#25313E]/40 text-xs">
          {loading && (
            <div className="py-8 text-center text-[#8996A6] font-mono">
              Querying live Supabase records...
            </div>
          )}

          {!loading && query && results.length === 0 && (
            <div className="py-8 text-center text-[#8996A6]">
              No matching investigations or indicators.
            </div>
          )}

          {!loading && !query && (
            <div className="py-6 text-center text-[#8996A6] text-xs font-mono">
              Type to search investigations, indicators, or cases in Supabase.
            </div>
          )}

          {!loading && results.map((item, idx) => (
            <div
              key={idx}
              onClick={() => {
                if (item.type === 'CASE') {
                  onSelectCase(item.id);
                  onClose();
                }
              }}
              className="p-3 flex items-center justify-between hover:bg-[#151D27] rounded-md cursor-pointer transition-colors"
            >
              <div className="flex items-center gap-2.5">
                {item.type === 'CASE' ? (
                  <Briefcase size={15} className="text-[#5B8DEF]" />
                ) : (
                  <Network size={15} className="text-[#8B7CF6]" />
                )}
                <div>
                  <span className="font-semibold text-[#E8EDF3] block">{item.title}</span>
                  <span className="text-[11px] text-[#8996A6]">{item.subtitle}</span>
                </div>
              </div>
              <ArrowRight size={14} className="text-[#8996A6]" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
