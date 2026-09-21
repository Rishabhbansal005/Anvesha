# Comprehensive Analysis Report: 42-Feature Cyber Datasets (ARFF)
**Target Datasets:** `KDDTest+.arff` & `KDDTest-21.arff`  
**Platform Alignment:** ANVESH — Cyber Forensic Intelligence & Email Threat Detection Platform  
**Attributes:** 42 Total Attributes (41 Input Telemetry Features + 1 Class Target)

---

## 1. Executive Summary

A deep forensic and statistical analysis was conducted on the `.arff` datasets located on your workstation:
1. `C:\Users\Ongkar\Downloads\KDDTest+.arff` (22,544 records)
2. `C:\Users\Ongkar\Downloads\KDDTest-21.arff` (11,850 records)

These datasets originate from the gold-standard **NSL-KDD Intrusion Detection Benchmark**, specifically curated with **42 attributes** (41 network/transport-layer connection features and 1 binary classification target: `normal` vs `anomaly`).

### High-Level Comparison

| Metric | `KDDTest+.arff` | `KDDTest-21.arff` | Variance / Significance |
| :--- | :--- | :--- | :--- |
| **Total Instances** | 22,544 | 11,850 | Subsampled benchmark containing harder anomalies |
| **Total Attributes** | 42 (41 features + 1 target) | 42 (41 features + 1 target) | Exact schema match |
| **Nominal Features** | 7 | 7 | Categorical strings (Protocol, Service, Flag, etc.) |
| **Numerical Features**| 34 | 34 | Continuous counts, bytes, and rate ratios |
| **Anomaly Ratio** | **56.92%** (12,833) | **81.84%** (9,698) | +24.92% higher attack concentration |
| **Normal Ratio** | **43.08%** (9,711) | **18.16%** (2,152) | Significantly reduced benign baseline |
| **Difficulty Level** | Standard Test Suite | Extreme (Hardest 21-model failure set) | Eliminates easily classified attacks |

---

## 2. Complete 42-Feature Catalog & Taxonomy

The 42 attributes are partitioned into four forensic telemetry groups:

### Group 1: Basic Connection Features (9 Features)
| # | Feature Name | Type | Description |
|---|---|---|---|
| 1 | `duration` | Numeric (seconds) | Length of connection in seconds (e.g. 0 to 57,715s) |
| 2 | `protocol_type` | Nominal (`tcp`, `udp`, `icmp`) | Transport layer protocol |
| 3 | `service` | Nominal (70 services) | Destination network service (`http`, `smtp`, `private`, `telnet`, `pop_3`, etc.) |
| 4 | `flag` | Nominal (11 flags) | Normal or error status flag (`SF`, `REJ`, `S0`, `RSTO`, `RSTR`, etc.) |
| 5 | `src_bytes` | Numeric (bytes) | Bytes sent from source to destination |
| 6 | `dst_bytes` | Numeric (bytes) | Bytes sent from destination to source |
| 7 | `land` | Nominal (`0`, `1`) | 1 if connection is from/to same host/port; 0 otherwise |
| 8 | `wrong_fragment` | Numeric (count) | Number of wrong fragments in transmission |
| 9 | `urgent` | Numeric (count) | Number of urgent packets |

### Group 2: Content & Host Privilege Features (13 Features)
| # | Feature Name | Type | Description |
|---|---|---|---|
| 10 | `hot` | Numeric (count) | Number of "hot" indicators (accessing system directories, executables) |
| 11 | `num_failed_logins` | Numeric (count) | Number of failed login attempts |
| 12 | `logged_in` | Nominal (`0`, `1`) | 1 if successfully authenticated/logged in; 0 otherwise |
| 13 | `num_compromised` | Numeric (count) | Number of compromised system states |
| 14 | `root_shell` | Numeric (`0`, `1`) | 1 if root shell was obtained |
| 15 | `su_attempted` | Numeric (`0`, `1`) | 1 if `su root` command was attempted |
| 16 | `num_root` | Numeric (count) | Number of "root" accesses |
| 17 | `num_file_creations`| Numeric (count) | Number of file creation operations |
| 18 | `num_shells` | Numeric (count) | Number of shell prompts spawned |
| 19 | `num_access_files` | Numeric (count) | Number of operations on access control files |
| 20 | `num_outbound_cmds` | Numeric (count) | Number of outbound commands in an FTP session |
| 21 | `is_host_login` | Nominal (`0`, `1`) | 1 if the login belongs to the "host" list |
| 22 | `is_guest_login` | Nominal (`0`, `1`) | 1 if the login is a "guest" account |

### Group 3: Time-Window Traffic Features (9 Features — 2-Second Observation Window)
| # | Feature Name | Type | Description |
|---|---|---|---|
| 23 | `count` | Numeric (count) | Number of connections to the same host as current connection |
| 24 | `srv_count` | Numeric (count) | Number of connections to the same service as current connection |
| 25 | `serror_rate` | Numeric (0.00–1.00) | % of connections that activated SYN errors |
| 26 | `srv_serror_rate` | Numeric (0.00–1.00) | % of connections that activated SYN errors for same service |
| 27 | `rerror_rate` | Numeric (0.00–1.00) | % of connections that activated REJ errors |
| 28 | `srv_rerror_rate` | Numeric (0.00–1.00) | % of connections that activated REJ errors for same service |
| 29 | `same_srv_rate` | Numeric (0.00–1.00) | % of connections to the same service |
| 30 | `diff_srv_rate` | Numeric (0.00–1.00) | % of connections to different services |
| 31 | `srv_diff_host_rate`| Numeric (0.00–1.00) | % of connections to different hosts for same service |

### Group 4: Host-Based Traffic Features (10 Features — 100-Connection Window)
| # | Feature Name | Type | Description |
|---|---|---|---|
| 32 | `dst_host_count` | Numeric (count) | Number of connections to destination host (capped at 255) |
| 33 | `dst_host_srv_count` | Numeric (count) | Number of connections to destination host with same service |
| 34 | `dst_host_same_srv_rate` | Numeric (0.00–1.00) | Percentage of same service connections to destination |
| 35 | `dst_host_diff_srv_rate` | Numeric (0.00–1.00) | Percentage of different service connections to destination |
| 36 | `dst_host_same_src_port_rate` | Numeric (0.00–1.00) | Percentage of connections from the same source port |
| 37 | `dst_host_srv_diff_host_rate` | Numeric (0.00–1.00) | Percentage of connections to different hosts |
| 38 | `dst_host_serror_rate` | Numeric (0.00–1.00) | Percentage of SYN errors on destination host |
| 39 | `dst_host_srv_serror_rate` | Numeric (0.00–1.00) | Percentage of SYN errors on destination host for same service |
| 40 | `dst_host_rerror_rate` | Numeric (0.00–1.00) | Percentage of REJ errors on destination host |
| 41 | `dst_host_srv_rerror_rate` | Numeric (0.00–1.00) | Percentage of REJ errors on destination host for same service |

### Target Attribute
| # | Feature Name | Type | Classes |
|---|---|---|---|
| 42 | `class` | Nominal | `normal` (Benign) vs. `anomaly` (Malicious / Attack) |

---

## 3. Protocol & Service Breakdown

### Protocols
- **`KDDTest+.arff`**: TCP: 18,880 (83.75%), UDP: 2,621 (11.63%), ICMP: 1,043 (4.63%)
- **`KDDTest-21.arff`**: TCP: 8,632 (72.84%), UDP: 2,238 (18.89%), ICMP: 980 (8.27%)

### Top Services Observed
- `http`: 7,853 instances
- `private`: 4,774 instances
- `telnet`: 1,626 instances
- `pop_3` (Email POP3 Protocol): 1,019 instances
- `smtp` (Email SMTP Protocol): 934 instances
- `domain_u` (DNS Protocol): 894 instances
- `ftp_data`: 851 instances

---

## 4. Top Predictive Features (Random Forest Feature Importance)

| Feature | Importance (`KDDTest+`) | Importance (`KDDTest-21`) | Forensic Significance |
| :--- | :---: | :---: | :--- |
| **`src_bytes`** | **20.43%** | **14.27%** | Extreme packet size skew identifies payloads vs. probes |
| **`dst_bytes`** | **13.25%** | **9.46%** | Data exfiltration vs. empty/denied responses |
| **`srv_count`** | 1.8% | **12.28%** | Burst connection density across services |
| **`protocol_type`** | 1.2% | **10.21%** | Shift between TCP/UDP/ICMP abuse |
| **`dst_host_rerror_rate`** | **7.09%** | 2.1% | REJ error rate signaling port scans |
| **`service`** | **6.66%** | **8.40%** | Specific service abuse (SMTP, Telnet, HTTP) |
| **`dst_host_diff_srv_rate`**| **6.69%** | 1.9% | Port diversity in reconnaissance |
| **`dst_host_same_srv_rate`**| **5.63%** | **4.57%** | Flood intensity on single service |
