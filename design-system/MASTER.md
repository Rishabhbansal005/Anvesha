# ANVESH Design System Master Specification

> **Product**: ANVESH (अन्वेष)  
> **Subtitle**: Email Threat Detection & Forensic Intelligence  
> **Problem Statement**: SIH26106 (Smart India Hackathon 2026)  
> **Design Philosophy**: Apple-inspired clarity, restrained depth, digital forensic workstation (Density 8/10)  
> **Primary Rule**: **ZERO FAKE PRODUCTION DATA** (Empty database is an intentional, valid product state)

---

## 1. Brand Identity & Forensic Workspace

- **Name**: **ANVESH** (अन्वेष)
- **Meaning**: Investigation / खोज / Forensic intelligence.
- **Visual Stance**: High-precision forensic workstation for cybersecurity analysts. Never looks like a generic corporate admin dashboard or a gaming interface.

---

## 2. Color Tokens

### Dark Mode (Primary SOC Environment)
| Token | Hex | Role |
|---|---|---|
| Canvas Background | `#080C12` | Deepest canvas layer |
| Surface | `#0F151D` | Standard card and container surface |
| Elevated | `#151D27` | Floating panels, modals, dropdowns |
| Subtle Border | `#25313E` | Component and divider borders |
| Text Primary | `#E8EDF3` | Headings and primary forensic metrics |
| Text Secondary | `#8996A6` | Labels, captions, secondary context |
| Brand Accent | `#5B8DEF` | Brand elements, active states |
| Investigation Accent | `#8B7CF6` | Correlation links, IOC clusters |
| Verified (Clean) | `#35C98A` | Cryptographic pass (SPF/DKIM), low risk |
| Suspicious (Medium) | `#F2B84B` | Anomaly warning, unverified relay |
| Critical (Threat) | `#EF6262` | BEC, spoofing, high-risk flags |

### Light Mode (Auditing & Legal Reporting)
| Token | Hex | Role |
|---|---|---|
| Canvas Background | `#F4F7FA` | Clean neutral canvas |
| Surface | `#FFFFFF` | White container background |
| Secondary | `#EEF2F6` | Muted background sections |
| Subtle Border | `#D5DDE6` | Structural borders |
| Text Primary | `#17212B` | High contrast primary text |
| Text Secondary | `#5F6B78` | Readable secondary metadata |
| Brand Accent | `#315EAA` | Deep brand blue |
| Investigation Accent| `#6657C7` | Muted purple |
| Verified | `#167A59` | Forest green |
| Suspicious | `#9A6500` | Deep amber |
| Critical | `#C53D3D` | Deep crimson |

---

## 3. Typography & Numerical Precision

- **UI Font**: `Inter`, `-apple-system`, `sans-serif`
- **Technical Values Font**: `IBM Plex Mono` / `JetBrains Mono`
  - Applied to: IP addresses, domain names, SHA-256 hashes, Message-IDs, RFC-822 headers, timestamps, case numbers.
- **Rule**: Numerical threat metrics must NEVER use color alone. Always provide score + explicit category badge (`92/100 · CRITICAL`).

---

## 4. Navigation Architecture

- **Top Command Bar**: Sleek 56px header housing brand identity, view switcher (`Overview`, `Investigation Workspace`, `Cases`, `Alerts`, `Intelligence`), global search palette trigger (`⌘K`), and live Supabase status dot.
- **Investigation Workspace (3-Pane Architecture)**:
  - **Pane 1 (Left)**: Contextual investigation tree (`Overview`, `Timeline`, `Headers`, `Authentication`, `SMTP Route`, `Evidence`, `Report`).
  - **Pane 2 (Center)**: Primary evidence canvas following **CONCLUSION → REASON → EVIDENCE → RAW DATA**.
  - **Pane 3 (Right)**: Collapsible **Evidence Inspector** for on-demand drilldown into selected indicators.

---

## 5. Zero-Fake-Data & Empty State Policy

1. **Empty Supabase Database is Valid**:
   - 0 investigations → Clean, intentional prompt: *"No investigations yet. Upload a suspicious email to begin your first forensic investigation."* `[ Start Investigation ]`.
   - 0 alerts → *"No active alerts. New high-priority findings will appear here."*
   - 0 campaigns → *"No campaigns detected."*
2. **No Mock Data in Production**:
   - Production React components and FastAPI endpoints MUST NOT contain hardcoded arrays.
   - Demo data is strictly isolated to `scripts/seed_demo_data.py` and requires explicit execution.
