# PROJECT_NAME — System Architecture & Design Specification

> **SIH 2026 Problem Statement SIH26106**  
> AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

---

## 1. Architectural Philosophy: Modular Monolith

To guarantee completion and stability for the **September 6, 2026** MVP deadline on standard student hardware (Intel Core i5, 16 GB RAM, integrated graphics):

- We reject microservice bloat, distributed messaging queues, and unnecessary cloud orchestration.
- We implement a **FastAPI Modular Monolith** serving both Web and Mobile client applications from a single source of truth.
- High-performance, deterministic Python parsing and normalized risk engines drive initial analysis. Heuristic rule bases and scikit-learn models run locally without requiring high-end GPUs. Heavy transformer training is isolated to Google Colab.

---

## 2. Component Diagram

```
+-----------------------------------------------------------------------------------+
|                              PRIMARY CLIENTS                                      |
|                                                                                   |
|  [React + Vite + Tailwind Web Workstation]      [React Native + Expo Mobile App]   |
|  (Deep Forensic Investigation)                  (Rapid Alert Triage & Lookup)     |
+----------------------------------------+------------------------------------------+
                                         | REST / JSON
                                         v
+-----------------------------------------------------------------------------------+
|                        FASTAPI BACKEND GATEWAY (Port 8000)                        |
|                                                                                   |
|  +------------------+  +-------------------+  +------------------+                |
|  | /emails/analyze  |  | /cases & /alerts  |  | /intelligence    |                |
|  +--------+---------+  +---------+---------+  +--------+---------+                |
|           |                      |                     |                          |
|           v                      v                     v                          |
|  +------------------+  +-------------------+  +------------------+                |
|  | Forensic Engine  |  | Risk Engine (0-100|  | GeoIP / Threat   |                |
|  | (Headers/Relays) |  | ML+Auth+Infra+BEC)|  | Intel Adapters   |                |
|  +--------+---------+  +---------+---------+  +--------+---------+                |
|           |                      |                     |                          |
|           +----------------------+---------------------+                          |
|                                  |                                                |
|                                  v                                                |
|  +---------------------------------------------------------------+                |
|  | Append-Only Cryptographic Evidence Chain (SHA-256 Sequencing) |                |
|  +-------------------------------+-------------------------------+                |
+----------------------------------|------------------------------------------------+
                                   v
+-----------------------------------------------------------------------------------+
|                        POSTGRESQL RELATIONAL DATABASE                             |
|  Tables: Users, Cases, Emails, IOCs, Campaigns, EvidenceLedger, Alerts, AuditLogs |
+-----------------------------------------------------------------------------------+
```

---

## 3. Forensic Flow

```
1. DETECT       -> Email .eml parsed, SPF/DKIM/DMARC evaluated, BEC heuristics scanned.
2. TRACE        -> Received headers traversed backwards to isolate earliest reliable public IP.
3. ENRICH       -> IP/Domain enriched with GeoIP, ASN, RDAP, and reputation feeds.
4. CORRELATE    -> Shared infrastructure clustered into Campaigns and historical Cases.
5. INVESTIGATE  -> 0-100 Explainable Risk Score compiled across 4 distinct categories.
6. PRESERVE     -> Raw email hashed (SHA-256), sequenced in immutable append-only ledger.
```
