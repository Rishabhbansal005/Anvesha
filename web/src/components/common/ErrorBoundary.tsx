import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[ANVESH UI ErrorBoundary caught error]:', error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="rounded-lg border border-[#FF453A]/40 bg-[#0F151D] p-6 space-y-4 font-mono">
          <div className="flex items-center gap-3 text-[#FF453A]">
            <AlertOctagon size={22} className="shrink-0" />
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-[#FF453A]">
                {this.props.fallbackTitle || 'Component Rendering Interrupted'}
              </h3>
              <p className="text-xs text-[#8996A6] mt-0.5">
                A localized runtime error was caught and isolated to keep the workspace operational.
              </p>
            </div>
          </div>

          <div className="rounded bg-[#080C12] border border-[#25313E] p-3 text-xs text-[#EC7063] break-all leading-relaxed">
            {this.state.error?.message || 'Unknown runtime error'}
          </div>

          <div className="flex items-center gap-3 pt-1">
            <button
              onClick={this.handleReset}
              className="px-3.5 py-1.5 rounded bg-[#5B8DEF]/20 hover:bg-[#5B8DEF]/30 border border-[#5B8DEF]/40 text-[#5B8DEF] text-xs font-bold transition-colors cursor-pointer flex items-center gap-1.5"
            >
              <RotateCcw size={13} />
              <span>Retry Rendering</span>
            </button>
            <button
              onClick={() => window.location.reload()}
              className="px-3.5 py-1.5 rounded bg-[#1D2633] hover:bg-[#25313E] text-[#8996A6] hover:text-[#E8EDF3] text-xs transition-colors cursor-pointer"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
