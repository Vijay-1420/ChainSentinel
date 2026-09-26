import streamlit as st
import pandas as pd

def render_search(df):
    """
    Page 2: Forensic Entity & Transaction Search
    Enforces strict distinction between Observed IP and Authorized Investigation IP.
    """
    st.markdown("## 🔍 Forensic Entity & Transaction Search")
    st.markdown("*Correlate Bitcoin Wallets, Observed P2P Network Nodes, and Authorized Subpoena Records*")
    st.markdown("---")

    # Search bar & entity selection
    col_input, col_type = st.columns([3, 1])

    with col_input:
        query = st.text_input("Enter Transaction ID, Bitcoin Wallet Address, Observed IP, or Investigation IP:",
                              placeholder="e.g. TX-2026-00015 or 1BtcNorm0001x9KqM or 185.220.101.42")
    with col_type:
        risk_filter = st.selectbox("Filter Risk Level:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

    # Quick Select suggestions
    st.markdown("**Quick Select Examples:**")
    ex_cols = st.columns(4)
    
    sample_critical = df[df["risk_level"] == "CRITICAL"]
    sample_peel = df[df["source_wallet"].str.contains("PeelChain", na=False)]
    sample_inv = df[df["investigation_ip"] != "N/A"]

    with ex_cols[0]:
        if st.button("Sample TxID"):
            query = df["transaction_id"].iloc[0]
    with ex_cols[1]:
        if st.button("Sample Peel Chain Wallet"):
            query = sample_peel["source_wallet"].iloc[0] if len(sample_peel) > 0 else df["source_wallet"].iloc[0]
    with ex_cols[2]:
        if st.button("Sample Observed IP"):
            query = df["source_ip"].iloc[0]
    with ex_cols[3]:
        if st.button("Sample Investigation IP"):
            query = sample_inv["investigation_ip"].iloc[0] if len(sample_inv) > 0 else "N/A"

    if not query:
        st.info("💡 Enter a query above or click a sample to initiate forensic correlation.")
        st.markdown("### Recent Flagged Transactions")
        display_df = df[df["risk_level"].isin(["HIGH", "CRITICAL"])].head(15)
        _render_transaction_table(display_df)
        return

    query_str = query.strip()

    # Search filter matching
    results = df[
        (df["transaction_id"].str.contains(query_str, case=False, na=False)) |
        (df["source_wallet"].str.contains(query_str, case=False, na=False)) |
        (df["destination_wallet"].str.contains(query_str, case=False, na=False)) |
        (df["source_ip"].str.contains(query_str, case=False, na=False)) |
        (df["destination_ip"].str.contains(query_str, case=False, na=False)) |
        (df["investigation_ip"].str.contains(query_str, case=False, na=False))
    ]

    if risk_filter != "ALL":
        results = results[results["risk_level"] == risk_filter]

    st.markdown(f"### Found **{len(results)}** matching records for query: `{query_str}`")

    if len(results) == 0:
        st.warning("No transactions found matching your criteria. Try refining your search query.")
        return

    # Entity Profile Summary Header
    st.markdown("---")
    st.subheader("📋 Entity Profile Summary")

    row0 = results.iloc[0]
    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(f"**Target Entity Query:** `{query_str}`")
        st.markdown(f"**Associated Wallets:** `{row0['source_wallet']}`")
        st.markdown(f"**Total Matching Volume:** `{results['amount'].sum():.4f} BTC`")

    with c2:
        # DISTINCT BADGE & LABELING DEMARCATION
        st.markdown("##### 🌐 Observed P2P Endpoint")
        st.markdown(f"**Observed IP:** `{row0['source_ip']}`")
        st.markdown(f"**Network Type:** `{row0['network_type']}` ({row0['ASN']})")
        st.markdown(f"**Location:** {row0['city']}, {row0['country']}")
        
        flags = []
        if row0['is_vpn']: flags.append("🛡️ VPN")
        if row0['is_proxy']: flags.append("🔄 Proxy")
        if row0['is_tor']: flags.append("🧅 TOR Exit")
        st.markdown(f"**Anonymization Flags:** {' | '.join(flags) if flags else 'None (Standard ISP)'}")

    with c3:
        # DISTINCT INVESTIGATION IP DEMARCATION
        st.markdown("##### ⚖️ Authorized Investigation IP")
        inv_ip_val = row0['investigation_ip']
        if inv_ip_val != "N/A" and str(inv_ip_val) != "nan":
            st.markdown(f"**Investigation IP:** `{inv_ip_val}` *(External Record)*")
            st.markdown(f"**Source Authority:** `{row0['investigation_source']}`")
            st.markdown(f"**Confidence Level:** `{row0['investigation_confidence']}%`")
        else:
            st.markdown("*No external subpoena or LEA record currently mapped for this transaction.*")

    st.markdown("---")
    st.subheader("📑 Associated Forensic Records")
    _render_transaction_table(results)

def _render_transaction_table(df_table):
    """
    Renders styled transaction data table.
    """
    cols_to_show = [
        "transaction_id", "timestamp", "source_wallet", "destination_wallet",
        "amount", "source_ip", "is_vpn", "investigation_ip",
        "anomaly_score", "risk_score", "risk_level"
    ]
    present_cols = [c for c in cols_to_show if c in df_table.columns]
    
    st.dataframe(
        df_table[present_cols].style.applymap(
            lambda val: "background-color: #7F1D1D; color: white; font-weight: bold;" if val == "CRITICAL"
            else ("background-color: #7C2D12; color: white;" if val == "HIGH"
            else ("background-color: #78350F; color: white;" if val == "MEDIUM" else "")),
            subset=["risk_level"] if "risk_level" in present_cols else []
        ),
        use_container_width=True
    )
