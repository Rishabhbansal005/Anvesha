import React from 'react';
import { ShieldAlert, AlertTriangle, AlertCircle, CheckCircle2, Info } from 'lucide-react';
import { RISK_LEVELS } from '../../constants';
import type { RiskLevel } from '../../types';

interface RiskBadgeProps {
  score: number;
  level?: RiskLevel;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  score,
  level,
  size = 'md',
  showIcon = true
}) => {
  // Derive level if not provided
  let derivedLevel: RiskLevel = 'INFORMATIONAL';
  if (score >= 85) derivedLevel = 'CRITICAL';
  else if (score >= 70) derivedLevel = 'HIGH';
  else if (score >= 40) derivedLevel = 'MEDIUM';
  else if (score >= 15) derivedLevel = 'LOW';

  const finalLevel = level || derivedLevel;
  const config = RISK_LEVELS[finalLevel] || RISK_LEVELS.INFORMATIONAL;

  const iconMap = {
    CRITICAL: ShieldAlert,
    HIGH: AlertTriangle,
    MEDIUM: AlertCircle,
    LOW: CheckCircle2,
    INFORMATIONAL: Info,
  };

  const IconComponent = iconMap[finalLevel] || Info;

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs font-medium px-2.5 py-1 gap-1.5',
    lg: 'text-sm font-semibold px-3.5 py-1.5 gap-2'
  };

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16
  };

  return (
    <span
      className={`inline-flex items-center rounded-md border tracking-wide font-mono transition-colors ${config.bgDark} dark:${config.bgDark} ${sizeClasses[size]}`}
      title={`Risk Score: ${score}/100 - ${config.label}`}
      role="status"
      aria-label={`Risk Level: ${score} out of 100, ${config.label}`}
    >
      {showIcon && <IconComponent size={iconSizes[size]} className="flex-shrink-0" />}
      <span className="font-bold">{score}/100</span>
      <span className="opacity-40">·</span>
      <span className="uppercase tracking-wider font-sans font-semibold">{config.label}</span>
    </span>
  );
};
