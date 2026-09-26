# ChainSentinel — Bitcoin Intelligence & Monitoring Agency Platform
**Team SYNTRIX — Smart India Hackathon (SIH 2026)**

ChainSentinel is a 100% air-gapped, offline-compatible Python AI & Cybersecurity intelligence platform for Bitcoin transaction correlation, network monitoring, dual-layer graph community detection, and explainable multi-factor risk analysis.

---

## 🚀 Quick Start Guide for VS Code

### 1. Prerequisites
- Python 3.9+ (Python 3.10 / 3.11 / 3.12 / 3.13 supported)

### 2. Setup & Installation
Open VS Code terminal inside the `ChainSentinel` directory and run:

```bash
# Optional: Create a virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Activate virtual environment (Linux/Mac)
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. Generate Synthetic Data (Optional, done automatically on launch)
```bash
python -c "from src.ingestion import generate_synthetic_datasets; generate_synthetic_datasets()"
```

### 4. Run the Streamlit Forensic Dashboard
```bash
streamlit run app.py
```

---

## 📁 Repository File Structure

```
ChainSentinel/
├── data/
│   ├── mock_p2p_logs.csv             # Raw P2P network layer logs (IPs, Ports, ASN, Anonymization Flags)
│   ├── mock_blockchain_txs.csv        # Bitcoin ledger transactions (Wallets, Amount, Fees, Ground Truth)
│   └── mock_investigation_data.csv   # Subpoenaed / KYC external authorized investigation records
├── src/
│   ├── __init__.py
│   ├── ingestion.py                  # Synthetic Dataset Generator & Data Normalizer
│   ├── graph_engine.py               # NetworkX MultiDiGraph & Louvain Community Clustering
│   └── ml_detector.py                # Isolation Forest, Multi-Factor Risk Engine & SHAP Explainer
├── dashboard/
│   ├── __init__.py
│   ├── overview.py                   # Page 1: Command Center Overview & KPI Analytics
│   ├── search.py                     # Page 2: Forensic Entity & Transaction Search
│   ├── graph_view.py                 # Page 3: Dual-Layer PyVis Interactive Network Graph
│   └── risk_explanation.py           # Page 4: SHAP Explainability & Model Evaluation Metrics
├── app.py                            # Main Streamlit Dashboard Router
├── requirements.txt                  # Python dependencies
└── README.md                         # Instructions & Setup Guide
```

---

## ⚖️ Legal Boundaries & Legal Policies

1. **Air-Gapped Execution**: 100% offline stack without cloud APIs or external graph databases (Neo4j).
2. **Observed IP vs. Investigation IP**:
   - **Observed IP**: P2P network endpoint observed in raw peer logs.
   - **Authorized Investigation IP**: External IP obtained strictly via authorized subpoenas, ISP warrants, or exchange KYC logs.
   - **No Decryption Claim**: ChainSentinel does NOT claim to break VPN encryption or directly extract original IPs from encrypted VPN streams.
3. **VPN Risk Policy**: VPN usage alone is an anonymization factor and **will NOT trigger a High or Critical fraud alert on its own** (capped at LOW risk <25 if all transactional behaviors are normal).

---

## 🏆 Key Architecture Features

- **Dual-Layer Graph Engine**: MultiDiGraph correlating Wallets, Observed IPs, Investigation IPs, and Transactions.
- **Community Clustering**: Louvain modularity algorithm detecting wallet/IP cluster IDs.
- **Machine Learning Anomaly Detection**: Unsupervised `IsolationForest` detecting anomalous transfer frequencies, peel chains, and mixer patterns.
- **Explainable AI (SHAP)**: Waterfall attribution explaining model predictions transparently.
- **Interactive Visualization**: PyVis interactive network graph + Plotly dark theme charts.
