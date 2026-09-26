from src.ingestion import load_and_normalize_data
from src.graph_engine import build_dual_layer_graph, detect_entity_clusters, extract_graph_features
from src.ml_detector import extract_features, train_anomaly_detector, calculate_multi_factor_risk, compute_entity_correlation, evaluate_model_performance

print("[Pipeline Test] Starting...")
df = load_and_normalize_data()
print(f"[Pipeline Test] Loaded {len(df)} transactions.")

G = build_dual_layer_graph(df)
G = detect_entity_clusters(G)
df_feat = extract_graph_features(G, df)
print(f"[Pipeline Test] Graph built with {len(G.nodes)} nodes and {len(G.edges)} edges.")

X, feats = extract_features(df_feat)
model, scores = train_anomaly_detector(X)
df_risk = calculate_multi_factor_risk(df_feat, scores)
corr = compute_entity_correlation(df_risk)

y_pred = (df_risk["risk_score"] >= 50.0).astype(int)
y_true = df_risk["is_suspicious_ground_truth"].astype(int)
metrics = evaluate_model_performance(y_true, y_pred)

print("[Pipeline Test] Risk level distribution:\n", df_risk['risk_level'].value_counts())
print("[Pipeline Test] Evaluation Metrics:\n", metrics)
print("[Pipeline Test] SUCCESS!")
