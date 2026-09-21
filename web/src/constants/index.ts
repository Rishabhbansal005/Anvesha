export const BRAND = {
  NAME: "ANVESH",
  HINDI_NAME: "अन्वेषण",
  SUBTITLE: "Email Threat Detection & Forensic Intelligence",
  PROBLEM_STATEMENT: "SIH26106",
  VERSION: "2.0.0-workspace"
};

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

export type NavTab = 'dashboard' | 'workspace' | 'investigations' | 'alerts' | 'intelligence' | 'campaigns';

export const RISK_LEVELS = {
  CRITICAL: { label: 'CRITICAL', min: 85, color: '#EF6262', bgDark: 'bg-[#EF6262]/15 text-[#EF6262] border-[#EF6262]/30' },
  HIGH: { label: 'HIGH', min: 70, color: '#F2B84B', bgDark: 'bg-[#F2B84B]/15 text-[#F2B84B] border-[#F2B84B]/30' },
  MEDIUM: { label: 'MEDIUM', min: 40, color: '#F2B84B', bgDark: 'bg-[#F2B84B]/15 text-[#F2B84B] border-[#F2B84B]/30' },
  LOW: { label: 'LOW', min: 15, color: '#35C98A', bgDark: 'bg-[#35C98A]/15 text-[#35C98A] border-[#35C98A]/30' },
  INFORMATIONAL: { label: 'INFO', min: 0, color: '#5B8DEF', bgDark: 'bg-[#5B8DEF]/15 text-[#5B8DEF] border-[#5B8DEF]/30' }
};

export const FORENSIC_TERMS = {
  ORIGIN: "Probable Origin",
  CONFIDENCE: "Origin Confidence",
  INFRASTRUCTURE: "Observed Infrastructure",
  LOCATION: "Approximate IP-associated Location"
};

export const DEFAULT_ANALYST = {
  id: "analyst_usr_902",
  email: "analyst@anvesh.gov.in",
  name: "SOC Senior Analyst"
};

export const getAuthHeaders = (analystId?: string) => {
  const activeId = analystId || (typeof window !== 'undefined' ? localStorage.getItem('anvesh_analyst_id') : null) || DEFAULT_ANALYST.id;
  return {
    'Content-Type': 'application/json',
    'X-Analyst-ID': activeId
  };
};


