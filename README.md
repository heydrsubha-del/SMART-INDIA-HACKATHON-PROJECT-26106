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

