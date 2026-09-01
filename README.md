# 🛡️ AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

**SIH26106 | Advanced Persistent Threat Monitoring**

A comprehensive, offline-first email forensics and threat intelligence platform built with Python and Streamlit. It parses raw email artifacts (`.eml`, `.txt`, `.csv`), runs machine learning classification with full explainability, verifies sender authentication protocols (SPF/DKIM/DMARC), tracks routing hops globally, and correlates threat campaigns across multiple evidence files.

---

## 🚀 Key Features

* **Dual Acquisition Modes:**
  * 📁 **Evidence File Upload:** Deep forensic analysis for individual `.eml`/`.txt` files or bulk `.eml` datasets via `.csv` with an interactive global IP tracking map.
  * ⚡ **Live IMAP Mailbox Interceptor:** Real-time connection to live mailboxes (e.g., Gmail via App Passwords) to pull and analyze unread traffic instantly.
* **Explainable ML Phishing Classifier:** Powered by TF-IDF (1-2 grams) and Logistic Regression (`classifier.py`) to calculate phishing probability while exposing exact coefficient terms driving the decision.
* **Authentication & BEC Detection:** Evaluates SPF, DKIM, and DMARC stamps alongside Business Email Compromise (BEC) behavioral patterns (payment pressure, executive impersonation)[cite: 4, 5, 7].
* **Interactive Global Routing Maps:** Visualizes email relay hops using Folium with satellite imagery toggles and animated routing arcs[cite: 5].
* **Identity Correlation Engine:** Builds a NetworkX graph (`correlate.py`) linking senders, domains, IPs, and crypto wallets to uncover multi-message threat campaigns.
* **Court-Ready Reports:** Generates exportable Markdown reports anchored with a cryptographic SHA-256 evidence hash.

---

## 📦 Prerequisites

* **Python 3.10+** installed on your system.
* **Git** installed to clone or push your repository.

---

## ⚙️ Installation & Setup Guide

### 1. Clone the Repository
```bash
git clone [https://github.com/heydrsubha-del/SMART-INDIA-HACKATHON-PROJECT-26106.git]
```
---



* **after downloading the file extract it to the desktop and make sure that you open that folder in terminal**

* **if you don't know how to do that just copy the address of that folder then open command Centre(cmd) in administrator mode or windows powershell then write**

```bash

**cd (address of that folder)**

```

* **now you can see that you are in the folder address**

____

## 2. Create and Activate a Virtual Environment (venv)

##  Create a virtual environment:

* **Windows powershell**
  
```bash
 python -m venv .venv

```
```bash

.venv\Scripts\Activate.ps1

```

----

* **If PowerShell blocks activation, run:**

```bash

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

```

then:
```bash

.venv\Scripts\Activate.ps1

```

----

## On Windows (PowerShell):


* **Ensure venv is active**

```bash

.\venv\Scripts\Activate

```

---


## On macOS / Linux:


* **Ensure venv is active**

```bash

source venv/bin/activate

```

---

## 3. Upgrade pip:

```bash

python -m pip install --upgrade pip

```

------


## 4. Install Dependencies
Ensure your virtual environment is active, then install the required Python packages:


* **On windows**

```bash

pip install --upgrade pip

```
```bash

pip install -r requirements.txt

```
```bash

pip install folium streamlit-folium

```

---


## 5. Launching the server


## on windows


* **Launch the application**

```bash

streamlit run app.py

```

## on mac/linux


* **Launch the application**

```bash

streamlit run app.py

```

---



The application will automatically spin up a local server and open your default browser at http://localhost:8501


___



# 📂 Project Architecture & Module Mapping

* **app.py:**
Main Streamlit SOC dashboard interface.  

* **analyzer.py:**
Unified analysis pipeline orchestrator.  

* **classifier.py:**
TF-IDF + Logistic Regression ML pipeline

* **email_parser.py:**
RFC-5322 parser & Received-chain extractor.

* **header_analysis.py:**
SPF/DKIM/DMARC & BEC heuristic evaluator. 

* **ioc_extract.py:**
Look-alike domain, URL, and crypto wallet extractor. 

* **geolocate.py:**
Offline/Online hybrid IP geolocation & routing tracer.

* **risk.py:**
Weighted threat-scoring fusion engine.  

* **correlate.py:**
NetworkX identity correlation graph builder

* **report.py:**
Markdown forensic report generator & SHA-256 hasher

* **config.py:**
Central configuration, paths, weights, and brand dictionaries.  

* **gen_data.py:**
Synthetic balanced training corpus generator.

* **live_scanner.py:**
IMAP live mailbox connector module

* **tracker.py:**
SQLite threat memory bank for repeat offenders


---

## 🏗️ Architecture Diagram

The following diagram shows how an email moves through the system, from ingestion to final threat scoring and forensic outputs.

```mermaid
flowchart LR

    A["📧 Email Input"]

    A1["📁 Evidence File<br/>.eml / .txt / .csv"]
    A2["📡 Live IMAP<br/>Mailbox"]

    B["📥 Ingestion & Validation"]

    C["✉️ Email Parser"]

    D["🔍 Feature Extraction"]

    D1["📨 Header Analysis<br/>SPF / DKIM / DMARC"]
    D2["🔗 URL & Link Analysis"]
    D3["🌐 Sender / IP Intelligence"]
    D4["📝 Content & Phishing Indicators"]

    E["🧠 Threat Analysis Engine"]

    E1["🤖 ML Phishing Classifier"]
    E2["⚙️ Rule-Based Detection"]
    E3["🌐 Threat Intelligence"]

    F["⚖️ Risk Aggregation"]

    G["🎯 Final Threat Score"]

    G1["🟢 LOW"]
    G2["🟡 MEDIUM"]
    G3["🟠 HIGH"]
    G4["🔴 CRITICAL"]

    H["📊 Forensic & SOC Outputs"]

    H1["📋 Detailed Email Analysis"]
    H2["🌍 Global IP Tracking"]
    H3["🛰️ Geolocation & Route Map"]
    H4["📄 Forensic Report"]
    H5["📥 CSV Export"]

    I["👨‍💻 Analyst Feedback"]

    J["✅ Verified Learning Samples"]

    K["🧠 Controlled Model Adaptation"]

    L["🗄️ Local Threat Intelligence Store"]

    A --> A1
    A --> A2

    A1 --> B
    A2 --> B

    B --> C
    C --> D

    D --> D1
    D --> D2
    D --> D3
    D --> D4

    D1 --> E
    D2 --> E
    D3 --> E
    D4 --> E

    L --> E3

    E --> E1
    E --> E2
    E --> E3

    E1 --> F
    E2 --> F
    E3 --> F

    F --> G

    G --> G1
    G --> G2
    G --> G3
    G --> G4

    G --> H

    H --> H1
    H --> H2
    H --> H3
    H --> H4
    H --> H5

    H1 --> I
    I --> J
    J --> K
    K --> E1

    classDef input fill:#172033,stroke:#00d2ff,color:#ffffff;
    classDef process fill:#111827,stroke:#3b82f6,color:#ffffff;
    classDef analysis fill:#172033,stroke:#a855f7,color:#ffffff;
    classDef score fill:#1f2937,stroke:#f59e0b,color:#ffffff;
    classDef output fill:#172033,stroke:#22c55e,color:#ffffff;
    classDef feedback fill:#172033,stroke:#ec4899,color:#ffffff;

    class A,A1,A2 input;
    class B,C,D,D1,D2,D3,D4 process;
    class E,E1,E2,E3,L analysis;
    class F,G,G1,G2,G3,G4 score;
    class H,H1,H2,H3,H4,H5 output;
    class I,J,K feedback;
