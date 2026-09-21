# PROJECT_NAME Design System — Component Specifications

> **Shared Component Architecture across Web & Mobile**

---

## 1. RiskBadge Component

Used everywhere risk is displayed. Must **never** rely on color alone.

### Props & Visual Structure:
- `score: number` (0 to 100)
- `level?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL'` (auto-derived if omitted)
- `showIcon?: boolean` (defaults to `true`)
- `size?: 'sm' | 'md' | 'lg'`

### Output Format:
- `[🔴 94/100 · CRITICAL]` (Red background pill, ShieldAlert icon)
- `[🟠 78/100 · HIGH]` (Orange background pill, AlertTriangle icon)
- `[🟡 54/100 · MEDIUM]` (Amber background pill, AlertCircle icon)
- `[🟢 22/100 · LOW]` (Emerald background pill, CheckCircle2 icon)
- `[🔵 08/100 · INFO]` (Blue background pill, Info icon)

---

## 2. ConfidencePill Component

Used for forensic origin certainty.

### Levels:
- `HIGH`: Confirmed with cryptographically aligned DKIM/SPF + trustworthy relay chain.
- `MEDIUM`: Relay sequence observed, public IP extracted with moderate verification.
- `LOW`: Anomalous or missing intermediate Received headers.
- `UNRELIABLE`: Signs of header forgery or untrusted upstream relays.

---

## 3. IOCChip Component

Displays network & host indicators with type badge and 1-click clipboard copy.

- **IP**: `[IP] 185.220.101.42` (with flags/ASN tooltip)
- **Domain**: `[DOMAIN] secure-login-micros0ft.com`
- **URL**: `[URL] https://bit.ly/3xX...`
- **Hash**: `[SHA-256] 7a9e3f...8b21`

---

## 4. StatCard Component

Compact telemetry card for overview dashboard.

- `title`: Metric label (e.g., "Active Investigations")
- `value`: Numerical representation (e.g., "14")
- `subtext`: Operational context (e.g., "3 high risk pending")
- `icon`: Lucide icon
- `variant`: Neutral, Critical, Warning, or Success

---

## 5. SystemStatusIndicator Component

Shows real-time connectivity between Frontend and FastAPI Backend.

- `LIVE`: Green dot + "API Connected · v1.0.0"
- `DEGRADED`: Amber dot + "Enrichment Service Delay"
- `DISCONNECTED`: Red dot + "Offline · Local Cache"
