# PROJECT_NAME Design System — Web Investigation Workstation

> **Desktop Investigation Ergonomics & Guidelines**  
> Problem Statement SIH26106 | Primary Investigator Workstation

---

## 1. Web Layout Framework

The web application functions as an analyst command workstation. It uses a persistent high-utility shell:

```
+------------------------------------------------------------------------------------+
|  BRAND (PROJECT_NAME)  |  SEARCH / BREADCRUMBS  |  SYSTEM STATUS  | THEME | USER   |  TOP HEADER (56px)
+------------------------+-----------------------------------------------------------+
| [Overview]             |                                                           |
| [Email Analyzer]       |   MAIN WORKSTATION CANVAS                                 |
| [Investigations]       |   (Responsive Grid: 12-column layout)                     |
| [Alerts] (badge)       |                                                           |
| [Campaigns]            |   Card density: 8/10                                      |
| [Intelligence]         |   Padding: 24px (desktop) / 16px (tablet)                 |
| [Evidence]             |                                                           |  CONTENT AREA
| [Reports]              |                                                           |
| [AI Copilot]           |                                                           |
|                        |                                                           |
| [Settings]             |                                                           |
+------------------------+-----------------------------------------------------------+
| SIDEBAR (240px fixed)  | FOOTER / STATUS BAR (optional telemetry / build stamp)    |
+------------------------------------------------------------------------------------+
```

---

## 2. Responsive Breakpoints

| Token | Width | Target Device | Layout Adjustments |
| :--- | :--- | :--- | :--- |
| `sm` | `640px` | Small tablets | Sidebar collapses to drawer; single column cards |
| `md` | `768px` | Standard tablets | 2-column stats grid; condensed tables |
| `lg` | `1024px` | Small laptops | Persistent mini-sidebar (icon only) or full sidebar |
| `xl` | `1280px` | Desktop workstations | Full sidebar (240px); multi-pane investigation view |
| `2xl`| `1536px` | Dual monitors / SOC | Extended side-by-side header inspection + trace map |

---

## 3. Data Presentation Guidelines (Tables & Forensic Grids)

- **Horizontal Scroll Protection**: Tables must always be wrapped in `overflow-x-auto rounded-lg border border-border-subtle`.
- **Sticky Column Headers**: `thead th` must have `position: sticky; top: 0; background: var(--bg-surface-subtle); z-index: 10;`.
- **Monospace Cells**: IP, Domain, Hash, and Message-ID cells use `font-mono text-xs text-text-primary` with double-click or 1-click copy button.
- **Empty States**: Never show a blank void. Use an empty state illustration/icon, a clear descriptive title (*"No suspicious IOCs correlated yet"*), and a clear secondary action button.
- **Loading Skeleton**: Skeleton loaders must match exact card/table geometry with a subtle pulse animation (`animate-pulse bg-surface-subtle`).
