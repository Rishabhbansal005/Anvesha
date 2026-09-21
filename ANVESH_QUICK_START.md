# ANVESH — Quick Start Card (1-Page Operator Reference)
**AI-Powered Email Threat Detection, GeoLocation & Cyber Forensic Intelligence Platform**  
**Problem Statement:** `SIH26106` | **System Version:** `2.0.0-workspace`

---

## 3-Terminal Local Startup Procedure

### Terminal 1: Backend Engine (FastAPI)
```powershell
cd "c:\Users\Rishabh Bansal\OneDrive\Desktop\Razorpay Buildathon\SIH2026\backend"
& "C:\Program Files\Python312\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- **Backend Base:** `http://localhost:8000`
- **Swagger Docs:** `http://localhost:8000/docs`
- **Health Verification:** `http://localhost:8000/api/v1/health`

### Terminal 2: Web Dashboard (React 19 + Vite)
```powershell
cd "c:\Users\Rishabh Bansal\OneDrive\Desktop\Razorpay Buildathon\SIH2026\web"
npm run dev
```
- **Web App URL:** `http://localhost:5173/`

### Terminal 3: Mobile Incident Response App (Expo SDK 52)
```powershell
cd "c:\Users\Rishabh Bansal\OneDrive\Desktop\Razorpay Buildathon\SIH2026\mobile"
npx expo start
```
- **Physical Phone (Expo Go):** Scan the terminal QR code from the Expo Go app.
- **Android Emulator:** Press `a` in the terminal.
- **Web Preview:** Press `w` in the terminal.

---

## 10-Step Live Demo Execution

| Step | Action | What to Show / Emphasize |
| :---: | :--- | :--- |
| **1** | Open `http://localhost:5173/` | Point out the official ANVESH brand mark and `• SUPABASE LIVE` status badge. |
| **2** | Click **Start Investigation** | Opens the forensic ingestion workspace. |
| **3** | Upload `scenario_01_classic_phishing.eml` | Shows instant RFC-822 parsing, SHA-256 fingerprint, and **CRITICAL** threat score. |
| **4** | Upload `scenario_02_bec_payment_change.eml` | Demonstrates Model 2 detecting urgent financial rerouting and social engineering language. |
| **5** | Upload `scenario_03_lookalike_impersonation.eml` | Highlights Model 3B identifying homoglyph / typosquatted domain deception. |
| **6** | Upload `scenario_04_authenticated_bec.eml` | **Key Forensic Gap:** Show `SPF/DKIM/DMARC PASS`, but high behavioral risk and non-attribution boundary. |
| **7** | Click **Campaigns Tab** | Demonstrates multi-email correlation graph linking shared relay infrastructure. |
| **8** | Click **Cases Tab** → Select Case | Shows case state machine (`OPEN` → `UNDER_REVIEW` → `RESOLVED`) and analyst decision recording. |
| **9** | Click **Export Forensic Dossier (PDF)** | Generates and downloads the court-ready, cryptographically sealed forensic PDF report. |
| **10** | Open Mobile Companion App | Demonstrates real-time case synchronization, alerts triage, and incident response on mobile. |

---

## Quick Network & Mobile Reference

- **Operator PC LAN IP:** `192.168.1.5`
- **Mobile Backend Endpoint:** `http://192.168.1.5:8000/api/v1`
- **Allow Port in Windows Firewall:**
  ```powershell
  New-NetFirewallRule -DisplayName "ANVESH Backend 8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
  ```
- **Demo Fixtures Directory:** `backend/tests/fixtures/sih_demo/`

---

## Safe Shutdown
Press `CTRL + C` in each terminal window (Web, Mobile, then Backend).
