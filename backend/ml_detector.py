# backend/ml_detector.py
# Isolation Forest anomaly detector for Log Sentinel.
# Complements the rule-based detectors in detector.py.

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

import sys
sys.path.append('backend')
from features import build_feature_matrix


def detect_ml_anomalies(df, contamination=0.2):
    """
    Uses Isolation Forest to detect anomalous IPs based on behavioral features.

    Unlike rule-based detectors, this learns what 'normal' looks like from
    the data itself and flags anything statistically unusual.

    Args:
        df:            pandas DataFrame from load_log_dataframe()
        contamination: expected fraction of anomalous IPs (default 0.2 = 20%)

    Returns:
        A DataFrame of flagged IPs with anomaly scores and explanations
    """

    # Step 1: build feature matrix
    features_df, scaler = build_feature_matrix(df)

    # Step 2: separate IPs from numeric features
    ip_list      = features_df['ip'].values
    feature_matrix = features_df.drop(columns=['ip']).values

    # Step 3: train Isolation Forest
    model = IsolationForest(
        contamination=contamination,
        random_state=42,       # makes results reproducible
        n_estimators=100,      # number of trees in the forest
    )
    model.fit(feature_matrix)

    # Step 4: get predictions and anomaly scores
    predictions    = model.predict(feature_matrix)   # +1 = normal, -1 = anomaly
    anomaly_scores = model.decision_function(feature_matrix)  # more negative = more anomalous

    # Step 5: build results DataFrame
    results = pd.DataFrame({
        'ip':            ip_list,
        'prediction':    predictions,
        'anomaly_score': anomaly_scores.round(4),
    })

    # Step 6: filter to only flagged IPs
    flagged = results[results['prediction'] == -1].copy()

    # Step 7: sort by most anomalous first
    flagged = flagged.sort_values('anomaly_score', ascending=True).reset_index(drop=True)

    # Step 8: add feature values back so we can explain the detection
    flagged = flagged.merge(features_df, on='ip', how='left')

    # Step 9: generate plain-English explanations
    flagged['anomaly_type'] = 'ml_isolation_forest'
    flagged['explanation']  = flagged.apply(
        lambda row: _generate_explanation(row), axis=1
    )

    return flagged


def _generate_explanation(row):
    """
    Generates a plain-English explanation for why an IP was flagged by the model.
    Looks at which features are most extreme to explain the detection.
    """
    reasons = []

    if row['error_rate'] > 0.5:
        reasons.append(f"high error rate ({row['error_rate']:.2f} normalized score)")
    if row['night_traffic_ratio'] > 0.5:
        reasons.append(f"significant off-hours activity ({row['night_traffic_ratio']:.2f} normalized score)")
    if row['request_count'] > 0.5:
        reasons.append(f"unusually high request volume ({row['request_count']:.2f} normalized score)")
    if row['unique_paths'] > 0.5:
        reasons.append(f"probing many different paths ({row['unique_paths']:.2f} normalized score)")

    if not reasons:
        reasons.append("statistical outlier across multiple behavioral features")

    reason_text = "; ".join(reasons)
    return (
        f"Isolation Forest flagged this IP as anomalous (score: {row['anomaly_score']:.4f}). "
        f"Reasons: {reason_text}. "
        f"This was detected statistically — not by a fixed rule."
    )


if __name__ == '__main__':
    from parser import load_log_dataframe

    df = load_log_dataframe('data/sample.log')
    results = detect_ml_anomalies(df)

    print("=== ML ANOMALY DETECTION RESULTS ===\n")
    print(f"{len(results)} IP(s) flagged by Isolation Forest\n")

    for _, row in results.iterrows():
        print(f"IP: {row['ip']}")
        print(f"Anomaly Score: {row['anomaly_score']} (more negative = more suspicious)")
        print(f"Explanation: {row['explanation']}")
        print()