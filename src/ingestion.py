import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

def generate_synthetic_datasets(data_dir="data", num_transactions=250):
    """
    Generates 3 correlated synthetic CSV datasets for Project ChainSentinel:
    1. mock_p2p_logs.csv: Observed P2P network traffic logs.
    2. mock_blockchain_txs.csv: Bitcoin ledger transaction records.
    3. mock_investigation_data.csv: External authorized LEA / subpoena investigative records.
    """
    os.makedirs(data_dir, exist_ok=True)
    
    np.random.seed(42)
    random.seed(42)

    base_time = datetime(2026, 3, 15, 8, 0, 0)

    # Sample pools for IP generation and ISP/ASN data
    asns = ["AS15169 Google LLC", "AS16509 Amazon.com", "AS7922 Comcast", "AS7018 AT&T", "AS14061 DigitalOcean", "AS62041 Cloudflare", "AS20473 Choopa/Vultr", "AS9009 M247 Europe"]
    orgs = ["Google LLC", "Amazon Technologies", "Comcast Cable", "AT&T Internet Services", "DigitalOcean LLC", "Cloudflare Inc.", "Vultr Hosting", "M247 International"]
    countries = ["IN", "US", "DE", "SG", "GB", "NL", "JP", "CH", "SC", "CY"]
    regions = ["Maharashtra", "California", "Bavaria", "Central", "London", "North Holland", "Tokyo", "Zurich", "Mahé", "Nicosia"]
    cities = ["Mumbai", "San Francisco", "Munich", "Singapore", "London", "Amsterdam", "Tokyo", "Zurich", "Victoria", "Limassol"]

    p2p_rows = []
    tx_rows = []
    investigation_rows = []

    # Generate Wallet pools
    normal_wallets = [f"1BtcNorm{i:04d}x9KqM" for i in range(1, 50)]
    peel_chain_wallets = [f"3PeelChain{i:04d}w8VzT" for i in range(1, 30)]
    mixer_wallets = [f"bc1qMixerCluster{i:04d}p4Rz" for i in range(1, 20)]

    # Generate IP pools
    standard_ips = [f"185.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(40)]
    vpn_ips = [f"198.51.{random.randint(10, 200)}.{random.randint(1, 254)}" for _ in range(25)]
    tor_exit_nodes = [f"185.220.{random.randint(100, 105)}.{random.randint(1, 254)}" for _ in range(15)]
    investigation_ips = [f"203.0.113.{random.randint(1, 254)}" for _ in range(20)]

    current_time = base_time

    for i in range(1, num_transactions + 1):
        tx_id = f"TX-2026-{i:05d}"
        time_offset = random.randint(10, 300)
        current_time += timedelta(seconds=time_offset)
        timestamp_str = current_time.strftime("%Y-%m-%d %H:%M:%S")

        # Determine pattern type
        rand_val = random.random()
        
        if rand_val < 0.75:
            # Pattern A: Normal Bitcoin Transaction
            pattern_type = "NORMAL"
            source_wallet = random.choice(normal_wallets)
            dest_wallet = random.choice(normal_wallets)
            while dest_wallet == source_wallet:
                dest_wallet = random.choice(normal_wallets)
            amount = round(random.uniform(0.005, 2.5), 6)
            fee = round(amount * random.uniform(0.0001, 0.001), 6)
            is_suspicious_gt = 0

            source_ip = random.choice(standard_ips)
            dest_ip = random.choice(standard_ips)
            asn = random.choice(asns[:4])
            org = random.choice(orgs[:4])
            country = random.choice(["IN", "US", "DE", "GB"])
            region = random.choice(["Maharashtra", "California", "Bavaria", "London"])
            city = random.choice(["Mumbai", "San Francisco", "Munich", "London"])
            net_type = "Residential/Broadband"
            is_vpn = 1 if random.random() < 0.08 else 0
            is_proxy = 0
            is_tor = 0

        elif rand_val < 0.88:
            # Pattern B: Peel Chain (Rapid micro-transfers across sequential wallets)
            pattern_type = "PEEL_CHAIN"
            seq_idx = (i % 25)
            source_wallet = peel_chain_wallets[seq_idx]
            dest_wallet = peel_chain_wallets[(seq_idx + 1) % 25]
            amount = round(random.uniform(0.01, 0.5), 6)
            fee = round(0.00015, 6)
            is_suspicious_gt = 1

            source_ip = random.choice(standard_ips + vpn_ips)
            dest_ip = random.choice(standard_ips)
            asn = random.choice(asns[4:])
            org = random.choice(orgs[4:])
            country = random.choice(countries)
            region = random.choice(regions)
            city = random.choice(cities)
            net_type = "Hosting/Data Center"
            is_vpn = 1 if random.random() < 0.4 else 0
            is_proxy = 1 if random.random() < 0.2 else 0
            is_tor = 0

        else:
            # Pattern C: IP Hopping / Mixer Cluster (Anonymization infra + high wallet degree)
            pattern_type = "MIXER_CLUSTER"
            source_wallet = random.choice(mixer_wallets)
            dest_wallet = random.choice(mixer_wallets + normal_wallets[:5])
            amount = round(random.uniform(1.5, 12.0), 6)
            fee = round(amount * random.uniform(0.005, 0.02), 6)
            is_suspicious_gt = 1

            source_ip = random.choice(tor_exit_nodes if random.random() < 0.5 else vpn_ips)
            dest_ip = random.choice(standard_ips)
            asn = "AS9009 M247 Europe"
            org = "M247 International Anonymizer"
            country = random.choice(["NL", "SC", "CY", "CH"])
            region = random.choice(["North Holland", "Mahé", "Nicosia", "Zurich"])
            city = random.choice(["Amsterdam", "Victoria", "Limassol", "Zurich"])
            net_type = "Anonymized Relay / VPN Node"
            is_vpn = 1
            is_proxy = 1 if random.random() < 0.6 else 0
            is_tor = 1 if "185.220" in source_ip else 0

        source_port = random.randint(1024, 65535)
        dest_port = 8333 # Standard Bitcoin P2P port

        # Append P2P log
        p2p_rows.append({
            "timestamp": timestamp_str,
            "transaction_id": tx_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": dest_ip,
            "destination_port": dest_port,
            "ASN": asn,
            "organization": org,
            "country": country,
            "region": region,
            "city": city,
            "network_type": net_type,
            "is_vpn": is_vpn,
            "is_proxy": is_proxy,
            "is_tor": is_tor
        })

        # Append Blockchain Tx
        tx_rows.append({
            "timestamp": timestamp_str,
            "transaction_id": tx_id,
            "source_wallet": source_wallet,
            "destination_wallet": dest_wallet,
            "amount": amount,
            "fee": fee,
            "is_suspicious_ground_truth": is_suspicious_gt
        })

        # Subpoena / LEA Authorized Investigation Record (~20% subset of transactions)
        if pattern_type in ["PEEL_CHAIN", "MIXER_CLUSTER"] or random.random() < 0.10:
            inv_ip = random.choice(investigation_ips)
            inv_source = random.choice(["Exchange KYC Record (Subpoena)", "ISP Warrant Log", "FIU-IND Intelligence Disclosure", "Interpol Red Notice Annex"])
            inv_time = (current_time - timedelta(minutes=random.randint(5, 120))).strftime("%Y-%m-%d %H:%M:%S")
            inv_conf = round(random.uniform(85.0, 99.9), 2)
            
            investigation_rows.append({
                "transaction_id": tx_id,
                "investigation_ip": inv_ip,
                "investigation_source": inv_source,
                "investigation_timestamp": inv_time,
                "investigation_confidence": inv_conf
            })

    # Save to CSV files
    p2p_df = pd.DataFrame(p2p_rows)
    tx_df = pd.DataFrame(tx_rows)
    inv_df = pd.DataFrame(investigation_rows)

    p2p_path = os.path.join(data_dir, "mock_p2p_logs.csv")
    tx_path = os.path.join(data_dir, "mock_blockchain_txs.csv")
    inv_path = os.path.join(data_dir, "mock_investigation_data.csv")

    p2p_df.to_csv(p2p_path, index=False)
    tx_df.to_csv(tx_path, index=False)
    inv_df.to_csv(inv_path, index=False)

    print(f"[ChainSentinel Ingestion] Successfully generated {len(tx_df)} transaction records across:")
    print(f"  - {p2p_path}")
    print(f"  - {tx_path}")
    print(f"  - {inv_path}")
    return p2p_path, tx_path, inv_path

def load_and_normalize_data(data_dir="data"):
    """
    Reads the 3 CSV files from data_dir, merges them on transaction_id, fills missing values,
    normalizes datetimes, and returns a unified DataFrame.
    """
    p2p_path = os.path.join(data_dir, "mock_p2p_logs.csv")
    tx_path = os.path.join(data_dir, "mock_blockchain_txs.csv")
    inv_path = os.path.join(data_dir, "mock_investigation_data.csv")

    if not os.path.exists(p2p_path) or not os.path.exists(tx_path):
        print("[ChainSentinel Ingestion] Datasets missing. Generating synthetic data...")
        generate_synthetic_datasets(data_dir=data_dir)

    p2p_df = pd.read_csv(p2p_path)
    tx_df = pd.read_csv(tx_path)

    # Merge blockchain txs with P2P logs
    merged_df = pd.merge(tx_df, p2p_df, on="transaction_id", how="left", suffixes=("", "_p2p"))

    # Merge with authorized investigation records if present
    if os.path.exists(inv_path):
        inv_df = pd.read_csv(inv_path)
        merged_df = pd.merge(merged_df, inv_df, on="transaction_id", how="left")
    else:
        merged_df["investigation_ip"] = "N/A"
        merged_df["investigation_source"] = "N/A"
        merged_df["investigation_timestamp"] = "N/A"
        merged_df["investigation_confidence"] = 0.0

    # Fill missing values
    merged_df["is_vpn"] = merged_df["is_vpn"].fillna(0).astype(int)
    merged_df["is_proxy"] = merged_df["is_proxy"].fillna(0).astype(int)
    merged_df["is_tor"] = merged_df["is_tor"].fillna(0).astype(int)
    merged_df["investigation_ip"] = merged_df["investigation_ip"].fillna("N/A")
    merged_df["investigation_source"] = merged_df["investigation_source"].fillna("N/A")
    merged_df["investigation_confidence"] = merged_df["investigation_confidence"].fillna(0.0)

    # Convert timestamps
    merged_df["timestamp"] = pd.to_datetime(merged_df["timestamp"])
    merged_df = merged_df.sort_values(by="timestamp").reset_index(drop=True)

    return merged_df

if __name__ == "__main__":
    generate_synthetic_datasets()
    df = load_and_normalize_data()
    print("[ChainSentinel Ingestion] Data loaded successfully. Shape:", df.shape)
