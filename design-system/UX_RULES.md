# PROJECT_NAME Design System — Forensic UX & Integrity Rules

> **Forensic Ethics, Neutrality, and UI Integrity**

---

## 1. Forensic Language Guardrails

Cyber investigations require strict adherence to objective evidentiary language. The UI must maintain evidentiary neutrality:

| ❌ PROHIBITED PHRASING | ✅ MANDATORY FORENSIC REPLACEMENT |
| :--- | :--- |
| "Attacker Location" | **"Approximate IP-associated Location"** |
| "Attacker Identity" | **"Sender Claims / Account Attribution Under Investigation"** |
| "Origin IP" (unqualified) | **"Probable Origin IP"** with explicit **"Origin Confidence"** |
| "Attacker Server" | **"Observed Infrastructure"** or **"Relay Node"** |
| "Guaranteed Phishing" | **"High-Confidence Phishing Indicators Observed"** |
| "Fake Email" | **"Authentication Failure (SPF/DKIM/DMARC Mismatch)"** |

---

## 2. Evidence Presentation Rules

1. **Off-Chain Immutable Chain**:
   - Every parsed email is hashed with SHA-256 upon ingestion.
   - Display the SHA-256 fingerprint alongside an "Evidence Verified" or "Ledger Sequenced" stamp.
2. **AI Copilot Boundaries**:
   - AI outputs must NEVER alter the underlying deterministic forensic results.
   - Every AI-generated summary, suggestion, or draft report must be explicitly captioned:  
     > *"AI-generated forensic draft — analyst verification required before official submission."*
3. **Graceful Fallback on External Enrichment**:
   - If GeoIP, VirusTotal, or AbuseIPDB is unavailable or rate-limited, NEVER crash or show an empty red alert.
   - Render: *"Enrichment Pending / Service Unavailable (Local Analysis Preserved)"*.
4. **Simulation Badge**:
   - In dev/demo modes, clearly display a discreet badge: `[DEMO DATA - SIMULATED]` on mocked entities, so judges and developers know exactly what is real vs. simulated.
