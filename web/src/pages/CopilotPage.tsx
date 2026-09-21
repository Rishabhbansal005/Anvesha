import React, { useState } from 'react';
import { Bot, Send, ShieldAlert, Sparkles, Terminal, ArrowRight } from 'lucide-react';
import { BRAND } from '../constants';

export const CopilotPage: React.FC = () => {
  const [messages, setMessages] = useState([
    {
      sender: 'copilot',
      text: `Greetings Analyst. I am the ${BRAND.NAME} Forensic Copilot. I operate strictly on structured evidence compiled by the deterministic forensic engine. How can I assist with Case CASE-1042 or active campaigns?`
    }
  ]);
  const [input, setInput] = useState('');

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userText = input;
    setMessages(prev => [...prev, { sender: 'user', text: userText }]);
    setInput('');

    setTimeout(() => {
      setMessages(prev => [
        ...prev,
        {
          sender: 'copilot',
          text: `[AI-generated draft — analyst verification required]: Regarding your query on "${userText}" — Case CASE-1042 presents high confidence BEC indicators. The sender address claims CEO identity, but the RFC-822 Received header chain isolates the earliest unauthenticated hop at 185.220.101.42 (Tor/Bulletproof hosting in Netherlands). SPF and DKIM both failed. Recommended next step: Query domain registrar records for lookalike homoglyphs registered within the last 72 hours.`
        }
      ]);
    }, 700);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
        <div className="flex items-center gap-2">
          <Bot size={20} className="text-blue-500" />
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100 font-mono">
            AI INVESTIGATION COPILOT
          </h2>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
          Operates strictly on structured forensic evidence output. Never overrides deterministic forensic parser results.
        </p>
      </div>

      {/* Chat Container */}
      <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-[#111C32] flex flex-col h-[520px] shadow-sm">
        {/* Messages */}
        <div className="flex-1 p-4 overflow-y-auto space-y-4 text-xs font-sans">
          {messages.map((m, idx) => (
            <div
              key={idx}
              className={`flex gap-3 max-w-2xl ${
                m.sender === 'user' ? 'ml-auto flex-row-reverse' : ''
              }`}
            >
              <div
                className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 text-xs font-bold ${
                  m.sender === 'user'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-blue-400 border border-slate-700'
                }`}
              >
                {m.sender === 'user' ? 'U' : <Bot size={15} />}
              </div>
              <div
                className={`p-3.5 rounded-lg leading-relaxed ${
                  m.sender === 'user'
                    ? 'bg-blue-600 text-white font-medium'
                    : 'bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200'
                }`}
              >
                {m.text}
              </div>
            </div>
          ))}
        </div>

        {/* Input */}
        <form onSubmit={handleSend} className="p-3 border-t border-slate-200 dark:border-slate-800 flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask Copilot about evidence, indicators, or case relationships..."
            className="flex-1 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md px-3 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
          <button
            type="submit"
            className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Send size={13} />
            Ask
          </button>
        </form>
      </div>
    </div>
  );
};
