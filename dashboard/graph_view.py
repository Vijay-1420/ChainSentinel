import streamlit as st
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import plotly.graph_objects as go
import tempfile
import os

def render_graph_view(df, G):
    """
    Page 3: Dual-Layer Graph Network Visualizer
    Renders interactive PyVis network graph with color-coded nodes and community clusters.
    """
    st.markdown("## 🕸️ Dual-Layer Graph Network Visualization")
    st.markdown("*Correlating Network Infrastructure, Wallets, Communities, and Investigative Records*")
    st.markdown("---")

    # Legend Header
    st.markdown("""
    <div style="display: flex; gap: 20px; align-items: center; background-color: #1F2937; padding: 12px; border-radius: 8px; margin-bottom: 20px;">
        <span style="font-weight: bold; color: white;">Node Color Legend:</span>
        <span style="color: #3B82F6; font-weight: bold;">● Observed IP (Blue)</span>
        <span style="color: #10B981; font-weight: bold;">● Bitcoin Wallet (Green)</span>
        <span style="color: #8B5CF6; font-weight: bold;">● Authorized Investigation IP (Purple)</span>
        <span style="color: #EF4444; font-weight: bold;">● Critical Threat Transaction (Red)</span>
    </div>
    """, unsafe_allow_html=True)

    # Filter Sidebar/Controls
    col_f1, col_f2, col_f3 = st.columns(3)

    with col_f1:
        min_risk = st.slider("Filter Minimum Risk Score:", 0, 100, 25, step=5)
    with col_f2:
        available_clusters = ["ALL"] + sorted(list(set([data.get("cluster_id", 0) for _, data in G.nodes(data=True)])))
        selected_cluster = st.selectbox("Filter Louvain Community Cluster:", available_clusters)
    with col_f3:
        max_nodes = st.slider("Max Display Nodes:", 20, 200, 80, step=10)

    # Filter dataframe matching criteria
    filtered_df = df[df["risk_score"] >= min_risk]
    
    if selected_cluster != "ALL":
        filtered_df = filtered_df[filtered_df["cluster_id"] == selected_cluster]

    if len(filtered_df) == 0:
        st.warning("No nodes meet the active filter criteria. Try lowering the minimum risk threshold.")
        return

    # Build sub-graph for PyVis rendering
    sub_nodes = set()
    for idx, row in filtered_df.head(max_nodes).iterrows():
        sub_nodes.add(str(row["source_wallet"]))
        sub_nodes.add(str(row["destination_wallet"]))
        if str(row["source_ip"]) != "N/A" and str(row["source_ip"]) != "nan":
            sub_nodes.add(str(row["source_ip"]))
        if str(row["investigation_ip"]) != "N/A" and str(row["investigation_ip"]) != "nan":
            sub_nodes.add(str(row["investigation_ip"]))

    sub_G = G.subgraph(sub_nodes).copy()

    # Render PyVis Interactive Network Graph
    try:
        net = Network(height="600px", width="100%", bgcolor="#111827", font_color="#FFFFFF", directed=True)
        net.barnes_hut(gravity=-3000, central_gravity=0.3, spring_length=120)

        for node, data in sub_G.nodes(data=True):
            ntype = data.get("node_type", "wallet")
            label = str(node)
            short_label = label[:8] + "..." if len(label) > 14 else label

            if ntype == "observed_ip":
                color = "#3B82F6" # Blue
                shape = "diamond"
                title = f"Observed IP: {node}\nASN: {data.get('asn', 'N/A')}\nVPN: {data.get('is_vpn', 0)}\nCluster: {data.get('cluster_id', 0)}"
            elif ntype == "investigation_ip":
                color = "#8B5CF6" # Purple
                shape = "star"
                title = f"Authorized Investigation IP: {node}\nSource: {data.get('source', 'Subpoena')}\nConfidence: {data.get('confidence', 0)}%"
            else:
                # Wallet
                cid = data.get("cluster_id", 0)
                # If associated with critical risk tx, paint red
                matching_txs = filtered_df[(filtered_df["source_wallet"] == node) | (filtered_df["destination_wallet"] == node)]
                has_critical = len(matching_txs[matching_txs["risk_level"] == "CRITICAL"]) > 0

                color = "#EF4444" if has_critical else "#10B981" # Red if critical, Green standard
                shape = "dot"
                title = f"Bitcoin Wallet: {node}\nDegree: {sub_G.degree(node)}\nCluster ID: {cid}"

            net.add_node(node, label=short_label, title=title, color=color, shape=shape, size=18)

        for u, v, k, data in sub_G.edges(keys=True, data=True):
            rel = data.get("rel", "TRANSFER")
            tx_id = data.get("tx_id", "")
            amount = data.get("weight", 1.0)
            
            if rel == "LOGGED_FROM":
                edge_color = "#60A5FA"
                dashes = True
            elif rel == "AUTHORIZED_RECORD_LINK":
                edge_color = "#C084FC"
                dashes = True
            else:
                edge_color = "#EF4444" if data.get("is_suspicious") else "#34D399"
                dashes = False

            net.add_edge(u, v, title=f"Tx: {tx_id}\nAmount: {amount} BTC\nType: {rel}", color=edge_color, dashes=dashes, weight=2)

        # Save network to temporary HTML file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
            net.save_graph(tmp_file.name)
            tmp_path = tmp_file.name

        with open(tmp_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        components.html(html_content, height=620, scrolling=True)
        os.remove(tmp_path)

    except Exception as e:
        st.warning(f"PyVis renderer fallback due to: {e}. Displaying Plotly 2D Graph.")
        _render_plotly_graph_fallback(sub_G, filtered_df)

    st.markdown("---")
    st.subheader("📌 Graph Cluster Details")
    c_df = filtered_df[["source_wallet", "source_ip", "cluster_id", "cluster_size", "graph_centrality", "risk_score", "risk_level"]].drop_duplicates()
    st.dataframe(c_df, use_container_width=True)

def _render_plotly_graph_fallback(G, df):
    """
    Plotly graph fallback if PyVis html renderer is unavailable.
    """
    pos = nx.spring_layout(G, seed=42)
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1, color='#6B7280'), hoverinfo='none', mode='lines')

    node_x = []
    node_y = []
    node_color = []
    node_text = []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        data = G.nodes[node]
        ntype = data.get("node_type", "wallet")
        
        if ntype == "observed_ip":
            node_color.append("#3B82F6")
        elif ntype == "investigation_ip":
            node_color.append("#8B5CF6")
        else:
            node_color.append("#10B981")
        node_text.append(f"{node} ({ntype})")

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        text=node_text,
        marker=dict(color=node_color, size=14, line_width=2)
    )

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20,l=5,r=5,t=40),
                        template="plotly_dark",
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                    ))
    st.plotly_chart(fig, use_container_width=True)
