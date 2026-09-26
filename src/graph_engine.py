import networkx as nx
import community as community_louvain
import pandas as pd
import numpy as np

def build_dual_layer_graph(df):
    """
    Constructs a NetworkX MultiDiGraph connecting:
    - Source and Destination Bitcoin Wallets
    - Observed P2P IPs (Raw network layer endpoints)
    - Authorized Investigation IPs (Subpoenaed/KYC external records)
    """
    G = nx.MultiDiGraph()

    for idx, row in df.iterrows():
        tx_id = str(row["transaction_id"])
        src_wallet = str(row["source_wallet"])
        dst_wallet = str(row["destination_wallet"])
        src_ip = str(row["source_ip"])
        inv_ip = str(row["investigation_ip"])
        amount = float(row["amount"])
        fee = float(row["fee"])
        is_vpn = int(row.get("is_vpn", 0))
        is_proxy = int(row.get("is_proxy", 0))
        is_tor = int(row.get("is_tor", 0))
        gt_suspicious = int(row.get("is_suspicious_ground_truth", 0))

        # 1. Source Wallet Node
        if not G.has_node(src_wallet):
            G.add_node(src_wallet, node_type="wallet", label=src_wallet, category="Source Wallet", color="#10B981")

        # 2. Destination Wallet Node
        if not G.has_node(dst_wallet):
            G.add_node(dst_wallet, node_type="wallet", label=dst_wallet, category="Destination Wallet", color="#10B981")

        # Add Blockchain Transfer Edge
        G.add_edge(src_wallet, dst_wallet, key=tx_id, weight=amount, fee=fee, tx_id=tx_id, rel="BLOCKCHAIN_TRANSFER", is_suspicious=gt_suspicious)

        # 3. Observed IP Node
        if src_ip and src_ip != "nan" and src_ip != "N/A":
            if not G.has_node(src_ip):
                G.add_node(src_ip, node_type="observed_ip", label=src_ip, category="Observed IP",
                           is_vpn=is_vpn, is_proxy=is_proxy, is_tor=is_tor,
                           country=row.get("country", "Unknown"), asn=row.get("ASN", "Unknown"),
                           color="#3B82F6")
            
            # Edge from Observed IP to Source Wallet
            G.add_edge(src_ip, src_wallet, key=f"ip_log_{tx_id}", rel="LOGGED_FROM", tx_id=tx_id)

        # 4. Authorized Investigation IP Node (External Subpoena / KYC Record)
        if inv_ip and inv_ip != "N/A" and inv_ip != "nan":
            if not G.has_node(inv_ip):
                G.add_node(inv_ip, node_type="investigation_ip", label=inv_ip, category="Authorized Investigation IP",
                           source=row.get("investigation_source", "LEA Record"),
                           confidence=float(row.get("investigation_confidence", 0.0)),
                           color="#8B5CF6")
            
            # Edge from Authorized Investigation IP to Source Wallet
            G.add_edge(inv_ip, src_wallet, key=f"inv_link_{tx_id}", rel="AUTHORIZED_RECORD_LINK", tx_id=tx_id)

    return G

def detect_entity_clusters(G):
    """
    Applies Louvain community detection to detect graph clusters and attaches
    cluster_id and cluster_size to all nodes in G.
    """
    if len(G.nodes) == 0:
        return G

    # Convert MultiDiGraph to simple undirected graph for Louvain detection
    G_undirected = nx.Graph()
    for u, v, data in G.edges(data=True):
        weight = data.get("weight", 1.0)
        if G_undirected.has_edge(u, v):
            G_undirected[u][v]["weight"] += weight
        else:
            G_undirected.add_edge(u, v, weight=weight)

    # Copy isolated nodes
    for node in G.nodes():
        if not G_undirected.has_node(node):
            G_undirected.add_node(node)

    try:
        partition = community_louvain.best_partition(G_undirected)
    except Exception as e:
        print(f"[Graph Engine] Louvain partition fallback due to: {e}")
        # Fallback to connected components if Louvain fails
        partition = {}
        for cid, comp in enumerate(nx.connected_components(G_undirected)):
            for node in comp:
                partition[node] = cid

    # Calculate cluster sizes
    cluster_counts = {}
    for node, cid in partition.items():
        cluster_counts[cid] = cluster_counts.get(cid, 0) + 1

    # Attach cluster_id and cluster_size to graph nodes
    for node in G.nodes():
        cid = partition.get(node, 0)
        G.nodes[node]["cluster_id"] = cid
        G.nodes[node]["cluster_size"] = cluster_counts.get(cid, 1)

    return G

def extract_graph_features(G, df):
    """
    Extracts node-level graph metrics and attaches them to each transaction row in df:
    - wallet_degree
    - ip_degree
    - unique_wallet_count
    - unique_ip_count
    - graph_centrality
    - cluster_id
    - cluster_size
    """
    # Precompute degree centralities
    centrality = nx.degree_centrality(G)

    wallet_degrees = []
    ip_degrees = []
    unique_wallet_counts = []
    unique_ip_counts = []
    centralities = []
    cluster_ids = []
    cluster_sizes = []

    for idx, row in df.iterrows():
        src_wallet = str(row["source_wallet"])
        src_ip = str(row["source_ip"])

        # Wallet degree & centrality
        w_deg = G.degree(src_wallet) if G.has_node(src_wallet) else 0
        w_cent = centrality.get(src_wallet, 0.0)
        w_cid = G.nodes[src_wallet].get("cluster_id", 0) if G.has_node(src_wallet) else 0
        w_csize = G.nodes[src_wallet].get("cluster_size", 1) if G.has_node(src_wallet) else 1

        # IP degree
        ip_deg = G.degree(src_ip) if G.has_node(src_ip) else 0

        # Unique destination wallets connected to source wallet
        if G.has_node(src_wallet):
            neighbors = list(G.neighbors(src_wallet))
            u_wallets = len([n for n in neighbors if G.nodes[n].get("node_type") == "wallet"])
        else:
            u_wallets = 0

        # Unique IPs connected to source wallet
        if G.has_node(src_wallet):
            in_edges = G.in_edges(src_wallet, data=True)
            u_ips = len(set([u for u, v, d in in_edges if G.nodes[u].get("node_type") == "observed_ip"]))
        else:
            u_ips = 0

        wallet_degrees.append(w_deg)
        ip_degrees.append(ip_deg)
        unique_wallet_counts.append(u_wallets)
        unique_ip_counts.append(u_ips)
        centralities.append(round(w_cent, 4))
        cluster_ids.append(w_cid)
        cluster_sizes.append(w_csize)

    df_out = df.copy()
    df_out["wallet_degree"] = wallet_degrees
    df_out["ip_degree"] = ip_degrees
    df_out["unique_wallet_count"] = unique_wallet_counts
    df_out["unique_ip_count"] = unique_ip_counts
    df_out["graph_centrality"] = centralities
    df_out["cluster_id"] = cluster_ids
    df_out["cluster_size"] = cluster_sizes

    return df_out

if __name__ == "__main__":
    from src.ingestion import load_and_normalize_data
    df = load_and_normalize_data()
    G = build_dual_layer_graph(df)
    G = detect_entity_clusters(G)
    df_feat = extract_graph_features(G, df)
    print(f"[Graph Engine] Nodes: {len(G.nodes)}, Edges: {len(G.edges)}")
    print("[Graph Engine] Extracted features sample:\n", df_feat[["source_wallet", "wallet_degree", "cluster_id", "cluster_size"]].head())
