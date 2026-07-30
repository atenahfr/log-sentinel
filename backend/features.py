# backend/features.py
# Transforms raw log DataFrame into a numeric feature matrix for ML detection.
# Each row = one IP address. Each column = one behavioral feature.

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler


def build_feature_matrix(df):
    """
    Takes a raw log DataFrame and returns a numeric feature matrix
    with one row per IP address.

    Args:
        df: pandas DataFrame from load_log_dataframe()

    Returns:
        features_df: DataFrame with one row per IP and 5 feature columns
        scaler: fitted StandardScaler (needed to transform new data later)
    """

    # Make sure we have an hour column
    df = df.copy()
    df['hour'] = df['timestamp'].dt.hour

    # Group by IP and compute features
    features = df.groupby('ip').agg(

        # Feature 1: total number of requests
        request_count=('ip', 'count'),

        # Feature 2: fraction of requests that were errors (4xx or 5xx)
        error_rate=('status_code', lambda x: (x >= 400).sum() / len(x)),

        # Feature 3: how many different paths this IP visited
        unique_paths=('path', 'nunique'),

        # Feature 4: fraction of requests made between midnight and 6am
        night_traffic_ratio=('hour', lambda x: (x < 6).sum() / len(x)),

        # Feature 5: average response size in bytes
        avg_bytes=('bytes', 'mean'),

    ).reset_index()

    # Store IP separately — we need it to map results back later
    ip_list = features['ip'].values

    # Drop IP column — the model only sees numbers
    feature_matrix = features.drop(columns=['ip'])

    # Normalize: scale every feature to mean=0, std=1
    # This prevents features with large values (like request_count)
    # from dominating features with small values (like night_traffic_ratio)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(feature_matrix)

    # Convert back to DataFrame with column names
    scaled_df = pd.DataFrame(scaled, columns=feature_matrix.columns)
    scaled_df.insert(0, 'ip', ip_list)

    return scaled_df, scaler


if __name__ == '__main__':
    import sys
    sys.path.append('backend')
    from parser import load_log_dataframe

    df = load_log_dataframe('data/sample.log')
    features, scaler = build_feature_matrix(df)

    print("=== FEATURE MATRIX ===")
    print(features.to_string())
    print(f"\nShape: {features.shape} ({features.shape[0]} IPs, {features.shape[1]-1} features)")
    print("\n=== FEATURE STATS (should be ~0 mean, ~1 std) ===")
    print(features.drop(columns=['ip']).describe().round(2))