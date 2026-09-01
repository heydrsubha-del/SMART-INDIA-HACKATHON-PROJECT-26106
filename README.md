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

flowchart LR

    %% =========================
    %% 1. EMAIL ACQUISITION
    %% =========================
    A["📥 EMAIL ACQUISITION"]

    A1["Evidence File Upload<br/>.eml / .txt / .csv"]
    A2["Live IMAP Mailbox<br/>Interceptor"]

    A --> A1
    A --> A2

    %% =========================
    %% 2. INGESTION & PARSING
    %% =========================
    B["⚙️ INGEST & PARSE"]

    B1["Email Parser"]
    B2["Header Extraction"]
    B3["Body & Attachment Extraction"]
    B4["Received-Chain / Hop Extraction"]
    B5["Structured Email Data"]

    A1 --> B1
    A2 --> B1
    B1 --> B2
    B1 --> B3
    B1 --> B4
    B2 --> B5
    B3 --> B5
    B4 --> B5

    %% =========================
    %% 3. ANALYSIS ENGINES
    %% =========================
    C["🔍 ANALYSIS ENGINES"]

    C1["🤖 ML Phishing Classifier<br/>TF-IDF + Logistic Regression"]
    C2["🛡️ Authentication Analysis<br/>SPF / DKIM / DMARC"]
    C3["📋 Header & BEC Analysis<br/>Identity / Reply-To / Display Name"]
    C4["🔗 IOC Extraction<br/>URLs / Domains / IPs / Emails"]
    C5["🌍 Geolocation & Reputation<br/>IP / ASN / ISP / Infrastructure"]
    C6["💼 BEC Pattern Detector<br/>Urgency / Payment / Impersonation"]

    B5 --> C1
    B5 --> C2
    B5 --> C3
    B5 --> C4
    B5 --> C5
    B5 --> C6

    %% =========================
    %% 4. THREAT INTELLIGENCE
    %% =========================
    TI["🌐 THREAT INTELLIGENCE"]

    TI1["URLhaus Malware URLs"]
    TI2["Local Threat Intelligence"]
    TI3["IOC / Reputation Data"]

    TI --> TI1
    TI --> TI2
    TI --> TI3

    TI1 --> C4
    TI2 --> C4
    TI3 --> C5

    %% =========================
    %% 5. RISK SCORING
    %% =========================
    D["⚖️ RISK SCORING ENGINE"]

    D1["Weighted Risk Calculation<br/>Configurable Weights"]
    D2["Final Threat Score<br/>0 – 100"]
    D3["Risk Classification<br/>LOW / MEDIUM / HIGH / CRITICAL"]
    D4["Explainability<br/>Top Contributing Factors"]

    C1 --> D1
    C2 --> D1
    C3 --> D1
    C4 --> D1
    C5 --> D1
    C6 --> D1

    D1 --> D2
    D2 --> D3
    D2 --> D4

    %% =========================
    %% 6. OUTPUTS
    %% =========================
    E["📊 OUTPUT & FORENSICS"]

    E1["SOC Dashboard<br/>Threat Score & Findings"]
    E2["🌍 Global IP / Routing Map"]
    E3["🔗 Correlation Graph<br/>Cross-Email IOC Correlation"]
    E4["📄 Forensic Report<br/>Evidence Hash + Analysis"]
    E5["📥 CSV Export"]

    D3 --> E1
    D4 --> E1
    C5 --> E2
    C4 --> E3
    D2 --> E4
    D4 --> E4
    D2 --> E5

    %% =========================
    %% 7. ANALYST FEEDBACK
    %% =========================
    F["🧠 ANALYST FEEDBACK"]

    F1["Confirm Threat"]
    F2["False Positive"]
    F3["Verified Feedback"]
    F4["Adaptive Learning"]

    E1 --> F1
    E1 --> F2
    F1 --> F3
    F2 --> F3
    F3 --> F4

    F4 -.-> C1

    %% =========================
    %% 8. PERSISTENT / SUPPORTING
    %% =========================
    S["💾 SUPPORTING COMPONENTS"]

    S1["SQLite Threat Memory"]
    S2["ML Model<br/>model.joblib"]
    S3["Configuration<br/>config.py"]
    S4["Dataset<br/>emails.csv"]

    S --> S1
    S --> S2
    S --> S3
    S --> S4

    S1 -.-> C4
    S1 -.-> C5
    S2 -.-> C1
    S3 -.-> D1
    S4 -.-> C1