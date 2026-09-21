# PROJECT_NAME Design System — Mobile Companion Application

> **Mobile Architecture & Investigator Triage Ergonomics**  
> Problem Statement SIH26106 | Mobile Companion App (React Native + Expo)

---

## 1. Core Purpose & Distinction

The mobile application is **NOT** a compressed clone of the web workstation.

- **Web Application** = Deep investigation, raw header analysis, graph exploration, evidence chain verification, formal reporting.
- **Mobile Application** = Immediate awareness, on-call alert triage, quick case review, one-touch escalation, and mobile IOC lookup.

```
Workflow:
ALERT NOTIFICATION
    ↓
QUICK CASE SUMMARY
    ↓
TRIAGE ACTION (Acknowledge / Escalate / Add Note / Open on Web)
```

---

## 2. Navigation Architecture

Bottom Navigation Bar with 4 primary destinations:
1. **Alerts** (`Bell` icon): Real-time critical threat stream, sorted by risk score.
2. **Cases** (`Briefcase` icon): Active assigned investigations with quick status chips.
3. **Quick Lookup** (`Search` icon): Rapid on-the-go IOC query (IP, Domain, URL).
4. **More** (`Menu` / `Sliders` icon): Backend connectivity status, analyst profile, notification settings, documentation.

---

## 3. Ergonomics & Touch Guidelines

- **Minimum Touch Target**: `44px × 44px` for all interactive buttons, tabs, and action cards.
- **Safe Area Insets**: Explicitly wrap headers and tab bars with `SafeAreaView` / `useSafeAreaInsets()` to accommodate notches, punch-holes, and gesture bars on iOS and Android.
- **Connectivity Indicator**: Display an ambient status pill at the top of screens (`Live Backend Connected: http://localhost:8000` or `Offline Mode`).
- **Action Buttons**: Prominent, single-hand reachable bottom sheets for quick triage:
  - `[Escalate to SOC Tier 2]` (Destructive/Warning accent)
  - `[Mark Reviewed]` (Success emerald accent)
  - `[Add Field Note]` (Neutral secondary)
  - `[Open Full Web Investigation]` (Deep blue primary)
