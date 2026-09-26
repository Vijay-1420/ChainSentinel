import streamlit as st
import plotly.express as px
import plotly.graph_objects as gg
import pandas as pd

def render_overview(df, G):
    """
    Page 1: Command Center Overview Dashboard
    Renders high-impact glassmorphic KPI cards and Plotly analytics.
    """
    st.markdown("## 🛡️ Command Center Overview")
    st.markdown("*Real-time Bitcoin Transaction Correlation, P2P Network Monitoring & Anomaly Intelligence*")
    st.markdown("---")

    # Calculate key metrics
    total_tx = len(df)
    unique_wallets = len(set(df["source_wallet"].tolist() + df["destination_wallet"].tolist()))
    unique_ips = df["source_ip"].nunique()
    vpn_tx_count = df[df["is_vpn"] == 1]["transaction_id"].nunique()
    vpn_pct = round((vpn_tx_count / total_tx) * 100, 1) if total_tx > 0 else 0
    
    flagged_threats = len(df[df["risk_level"].isin(["HIGH", "CRITICAL"])])
    critical_entities = len(df[df["risk_level"] == "CRITICAL"])

    # Render KPI Cards in 6 columns
    c1, c2, c3, c4, c5, c6 = st.columns(6)

    with c1:
        st.metric(label="Total Tx Scanned", value=f"{total_tx:,}")
    with c2:
        st.metric(label="Unique Wallets", value=f"{unique_wallets:,}")
    with c3:
        st.metric(label="Unique Observed IPs", value=f"{unique_ips:,}")
    with c4:
        st.metric(label="VPN/Tor Nodes", value=f"{vpn_tx_count} ({vpn_pct}%)")
    with c5:
        st.metric(label="Flagged Threats", value=f"{flagged_threats:,}", delta=f"{round(flagged_threats/total_tx*100, 1)}%")
    with c6:
        st.metric(label="Critical Entities", value=f"{critical_entities:,}", delta_color="inverse")

    st.markdown("---")

    # Analytics Section Layout
    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("📊 Threat Risk Level Distribution")
        risk_counts = df["risk_level"].value_counts().reset_index()
        risk_counts.columns = ["Risk Level", "Count"]

        color_map = {
            "CRITICAL": "#EF4444",
            "HIGH": "#F97316",
            "MEDIUM": "#FBBF24",
            "LOW": "#10B981"
        }

        fig_pie = px.pie(
            risk_counts,
            names="Risk Level",
            values="Count",
            color="Risk Level",
            color_discrete_map=color_map,
            hole=0.45,
            title="Transactions by Risk Category"
        )
        fig_pie.update_traces(textinfo="percent+label")
        fig_pie.update_layout(template="plotly_dark", margin=dict(t=40, b=10, l=10, r=10))
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_right:
        st.subheader("⚡ Anomaly Score vs. BTC Amount")
        fig_scatter = px.scatter(
            df,
            x="amount",
            y="anomaly_score",
            color="risk_level",
            size="risk_score",
            hover_data=["transaction_id", "source_wallet", "source_ip", "investigation_ip"],
            color_discrete_map=color_map,
            labels={"amount": "Transaction Amount (BTC)", "anomaly_score": "Behavioral Anomaly Score (0-100)"},
            title="Transaction Volume vs Behavioral Anomaly"
        )
        fig_scatter.update_layout(template="plotly_dark", margin=dict(t=40, b=10, l=10, r=10))
        st.plotly_chart(fig_scatter, use_container_width=True)

    st.markdown("---")
    col_timeline, col_geo = st.columns([1.2, 0.8])

    with col_timeline:
        st.subheader("📈 Chronological Transaction Stream & Threat Escalation")
        df_time = df.copy()
        df_time["time_bin"] = pd.to_datetime(df_time["timestamp"]).dt.floor("15min")
        timeline_df = df_time.groupby(["time_bin", "risk_level"]).size().unstack(fill_value=0).reset_index()

        fig_time = px.area(
            timeline_df,
            x="time_bin",
            y=[col for col in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] if col in timeline_df.columns],
            color_discrete_map=color_map,
            labels={"time_bin": "Time Window", "value": "Transaction Count"},
            title="Real-Time Risk Rate Stream"
        )
        fig_time.update_layout(template="plotly_dark", margin=dict(t=40, b=10, l=10, r=10))
        st.plotly_chart(fig_time, use_container_width=True)

    with col_geo:
        st.subheader("🌐 Top Observed Geographic Regions")
        geo_counts = df["country"].value_counts().head(8).reset_index()
        geo_counts.columns = ["Country", "Occurrences"]
        
        fig_bar = px.bar(
            geo_counts,
            x="Country",
            y="Occurrences",
            color="Occurrences",
            color_continuous_scale="Blues",
            title="P2P Traffic Origins"
        )
        fig_bar.update_layout(template="plotly_dark", margin=dict(t=40, b=10, l=10, r=10))
        st.plotly_chart(fig_bar, use_container_width=True)
