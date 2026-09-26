import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
from src.ml_detector import explain_entity, evaluate_model_performance

def render_risk_explanation(df, model, feature_names):
    """
    Page 4: Model Explainability, Legal Policy & Performance Evaluation
    Includes SHAP explanations, legal disclaimer banner, and ML metrics.
    """
    st.markdown("## 🧠 Risk Explainability & Model Performance")
    st.markdown("*Transparent Anomaly Detection, Feature Attribution & Empirical Model Metrics*")
    st.markdown("---")

    # MANDATORY LEGAL DISCLAIMER BANNER
    st.warning("""
    ⚠️ **LEGAL & INVESTIGATIVE BOUNDARY DISCLAIMER**
    - **Investigation IP Data**: Investigation IP information displayed within ChainSentinel is strictly derived from authorized external investigative records (e.g., LEA subpoenas, exchange KYC logs, or FIU disclosures).
    - **VPN / Proxy Policy**: ChainSentinel does NOT claim to break VPN encryption or extract original IP addresses directly from encrypted VPN network streams.
    - **Anonymization Risk Rule**: VPN usage alone is classified as anonymization infrastructure and **does NOT trigger a High or Critical fraud alert on its own**. It contributes to high risk only when combined with multi-hopping, peel chains, or mixer activity.
    """)

    st.markdown("---")

    # Transaction Selector for SHAP Explanation
    st.subheader("🔍 Individual Transaction SHAP Feature Attribution")
    
    tx_list = df["transaction_id"].tolist()
    high_risk_txs = df[df["risk_level"].isin(["HIGH", "CRITICAL"])]["transaction_id"].tolist()

    col_sel1, col_sel2 = st.columns([2, 1])

    with col_sel1:
        selected_tx_id = st.selectbox("Select Transaction to Analyze:", options=high_risk_txs + [t for t in tx_list if t not in high_risk_txs])
    with col_sel2:
        st.markdown(f"**Selected TxID:** `{selected_tx_id}`")

    # Target row analysis
    tx_row = df[df["transaction_id"] == selected_tx_id].iloc[0]

    # Render risk summary metrics for selected transaction
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Risk Level", value=tx_row["risk_level"])
    with m2:
        st.metric("Composite Risk Score", value=f"{tx_row['risk_score']} / 100")
    with m3:
        st.metric("Behavioral Anomaly Score", value=f"{tx_row['anomaly_score']} / 100")
    with m4:
        st.metric("VPN Flag", value="YES" if tx_row["is_vpn"] else "NO")

    # Feature matrix sample for SHAP
    sample_df = pd.DataFrame([{col: float(tx_row[col]) if col in tx_row else 0.0 for col in feature_names}])

    # Compute SHAP values or fallback attribution
    contributions, shap_vals, expected_val = explain_entity(model, sample_df, feature_names)

    # Plot SHAP Waterfall / Feature Attribution Chart
    col_plot, col_table = st.columns([1.2, 0.8])

    with col_plot:
        st.markdown("##### Feature Importance Waterfall (SHAP Attribution)")
        
        feat_df = pd.DataFrame({
            "Feature": list(contributions.keys()),
            "Contribution": list(contributions.values())
        }).sort_values(by="Contribution", key=abs, ascending=True)

        fig_waterfall = go.Figure(go.Bar(
            x=feat_df["Contribution"],
            y=feat_df["Feature"],
            orientation='h',
            marker=dict(
                color=feat_df["Contribution"].apply(lambda v: "#EF4444" if v > 0 else "#10B981")
            )
        ))
        fig_waterfall.update_layout(
            title=f"Attribution Breakdown for {selected_tx_id}",
            xaxis_title="SHAP Value (Impact on Anomaly Score)",
            yaxis_title="Feature Name",
            template="plotly_dark",
            margin=dict(t=40, b=20, l=10, r=10)
        )
        st.plotly_chart(fig_waterfall, use_container_width=True)

    with col_table:
        st.markdown("##### Raw Feature Matrix Values")
        raw_feat_display = sample_df.T.reset_index()
        raw_feat_display.columns = ["Feature", "Value"]
        st.dataframe(raw_feat_display, use_container_width=True)

    st.markdown("---")

    # Model Evaluation Metrics Section
    st.subheader("📈 Model Evaluation & Performance Metrics")
    st.markdown("*Benchmarking Isolation Forest and Multi-Factor Detector against Ground-Truth Suspicious Activity Labels*")

    # Ground truth evaluation
    y_pred = (df["risk_score"] >= 50.0).astype(int)
    y_true = df["is_suspicious_ground_truth"].astype(int)

    metrics = evaluate_model_performance(y_true, y_pred)

    e1, e2, e3, e4 = st.columns(4)
    with e1:
        st.metric("Precision", value=f"{metrics['precision'] * 100:.1f}%")
    with e2:
        st.metric("Recall", value=f"{metrics['recall'] * 100:.1f}%")
    with e3:
        st.metric("F1-Score", value=f"{metrics['f1_score'] * 100:.1f}%")
    with e4:
        st.metric("False Positive Rate (FPR)", value=f"{metrics['false_positive_rate'] * 100:.2f}%")

    st.markdown("#### Confusion Matrix Heatmap")

    cm = metrics["confusion_matrix"]
    cm_df = pd.DataFrame(cm, index=["Actual Normal", "Actual Suspicious"], columns=["Predicted Normal", "Predicted Suspicious"])

    col_cm, col_notes = st.columns([1, 1])

    with col_cm:
        fig_cm = px.imshow(
            cm_df,
            text_auto=True,
            color_continuous_scale="Reds",
            title="Confusion Matrix Heatmap",
            labels=dict(x="Predicted Label", y="Actual Ground Truth", color="Count")
        )
        fig_cm.update_layout(template="plotly_dark", margin=dict(t=40, b=10, l=10, r=10))
        st.plotly_chart(fig_cm, use_container_width=True)

    with col_notes:
        st.markdown("""
        **Validation Takeaways:**
        - **True Positives (TP):** {tp} correctly identified malicious/suspicious Bitcoin transactions (Peel Chains & Mixer Clusters).
        - **True Negatives (TN):** {tn} benign Bitcoin transactions correctly cleared.
        - **False Positives (FP):** {fp} benign transactions flagged (Low FPR achieved).
        - **False Negatives (FN):** {fn} missed suspicious transactions.
        """.format(tp=metrics['tp'], tn=metrics['tn'], fp=metrics['fp'], fn=metrics['fn']))
