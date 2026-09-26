import streamlit as st
import pandas as pd
import os

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="ChainSentinel - Bitcoin Intelligence & Monitoring Agency Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Dark Glassmorphism CSS Styling
st.markdown("""
<style>
    /* Main Background & Text Color */
    .stApp {
        background-color: #0F172A;
        color: #F8FAFC;
    }
    
    /* Glassmorphic Metric Cards */
    [data-testid="stMetricValue"] {
        font-size: 1.8rem !important;
        font-weight: 700 !important;
        color: #38BDF8 !important;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #1E293B !important;
        border-right: 1px solid #334155;
    }

    /* Subheaders and Headers */
    h1, h2, h3, h4 {
        color: #F8FAFC !important;
        font-family: 'Inter', sans-serif;
    }
    
    /* Success, Info, Warning Boxes */
    .stAlert {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

# Import internal pipeline modules
from src.ingestion import load_and_normalize_data, generate_synthetic_datasets
from src.graph_engine import build_dual_layer_graph, detect_entity_clusters, extract_graph_features
from src.ml_detector import extract_features, train_anomaly_detector, calculate_multi_factor_risk

from dashboard.overview import render_overview
from dashboard.search import render_search
from dashboard.graph_view import render_graph_view
from dashboard.risk_explanation import render_risk_explanation

@st.cache_data(show_spinner=False)
def initialize_pipeline():
    """
    Executes and caches data loading, graph building, Louvain clustering,
    and machine learning anomaly detection.
    """
    data_dir = "data"
    if not os.path.exists(os.path.join(data_dir, "mock_blockchain_txs.csv")):
        generate_synthetic_datasets(data_dir=data_dir)

    df_raw = load_and_normalize_data(data_dir=data_dir)
    G = build_dual_layer_graph(df_raw)
    G = detect_entity_clusters(G)
    df_feat = extract_graph_features(G, df_raw)

    X, feature_names = extract_features(df_feat)
    model, anomaly_scores = train_anomaly_detector(X)
    df_final = calculate_multi_factor_risk(df_feat, anomaly_scores)

    return df_final, G, model, feature_names

def main():
    # Sidebar Header & Branding
    st.sidebar.markdown("## 🛡️ **ChainSentinel**")
    st.sidebar.markdown("##### *Team SYNTRIX - SIH 2026*")
    st.sidebar.markdown("*Bitcoin Intelligence Agency Platform*")
    st.sidebar.markdown("---")

    # Data Pipeline Execution
    with st.spinner("Initializing ChainSentinel Intelligence Engine..."):
        df, G, model, feature_names = initialize_pipeline()

    # Sidebar Navigation Menu
    navigation = st.sidebar.radio(
        "Navigation Menu:",
        [
            "1. Command Center Overview",
            "2. Forensic Search",
            "3. Graph Network View",
            "4. Risk Explainability & Metrics"
        ]
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### System Status")
    st.sidebar.markdown("🟢 **Air-Gapped Stack:** Active")
    st.sidebar.markdown(f"📦 **Transactions Scanned:** {len(df)}")
    st.sidebar.markdown(f"🕸️ **Graph Nodes:** {len(G.nodes)}")
    st.sidebar.markdown("⚖️ **VPN Policy:** Strictly Enforced")
    st.sidebar.markdown("---")
    st.sidebar.caption("ChainSentinel v1.0.0 | SIH 2026 Prototype")

    # Route navigation to respective dashboard pages
    if navigation.startswith("1"):
        render_overview(df, G)
    elif navigation.startswith("2"):
        render_search(df)
    elif navigation.startswith("3"):
        render_graph_view(df, G)
    elif navigation.startswith("4"):
        render_risk_explanation(df, model, feature_names)

if __name__ == "__main__":
    main()
