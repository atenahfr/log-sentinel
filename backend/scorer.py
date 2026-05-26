# backend/scorer.py
# Risk scoring system for Log Sentinel
# Each anomaly type carries a base score — multiple anomalies on one IP stack up

import pandas as pd

# Base scores for each anomaly type
SCORES = {
    'brute_force':        80,
    '404_spike':          40,
    '500_spike':          60,
    'off_hours_traffic':  30,
}

# Severity labels based on total score
def get_severity(score):
    """
    Converts a numeric score into a human-readable severity label.
    
    Args:
        score: integer risk score
    
    Returns:
        A severity string: Critical, High, Medium, or Low
    """
    if score >= 100:
        return 'Critical'
    elif score >= 70:
        return 'High'
    elif score >= 40:
        return 'Medium'
    else:
        return 'Low'


def score_anomalies(brute_force_df, spike_404_df, spike_500_df, offhours_df):
    """
    Takes all detected anomalies and produces a unified scored report per IP.
    
    Args:
        brute_force_df: DataFrame from detect_brute_force()
        spike_404_df:   DataFrame from detect_404_spike()
        spike_500_df:   DataFrame from detect_500_spike()
        offhours_df:    DataFrame from detect_off_hours_traffic()
    
    Returns:
        A DataFrame with one row per flagged IP, sorted by risk score descending
    """

    # Step 1: collect all flagged events into one list
    all_events = []

    for _, row in brute_force_df.iterrows():
        all_events.append({
            'ip':           row['ip'],
            'anomaly_type': row['anomaly_type'],
            'detail':       f"{row['failed_attempts']} failed login attempts",
            'explanation':  row['explanation'],
            'score':        SCORES['brute_force'],
        })

    for _, row in spike_404_df.iterrows():
        all_events.append({
            'ip':           row['ip'],
            'anomaly_type': row['anomaly_type'],
            'detail':       f"{row['error_count']} 404 errors",
            'explanation':  row['explanation'],
            'score':        SCORES['404_spike'],
        })

    for _, row in spike_500_df.iterrows():
        all_events.append({
            'ip':           row['ip'],
            'anomaly_type': row['anomaly_type'],
            'detail':       f"{row['error_count']} 500 errors",
            'explanation':  row['explanation'],
            'score':        SCORES['500_spike'],
        })

    for _, row in offhours_df.iterrows():
        all_events.append({
            'ip':           f"hour_{row['hour']}",
            'anomaly_type': row['anomaly_type'],
            'detail':       f"{row['request_count']} requests at hour {row['hour']}",
            'explanation':  row['explanation'],
            'score':        SCORES['off_hours_traffic'],
        })

    # Step 2: if nothing was flagged, return empty DataFrame
    if not all_events:
        return pd.DataFrame()

    # Step 3: convert to DataFrame
    events_df = pd.DataFrame(all_events)

    # Step 4: group by IP and sum scores — one IP can have multiple anomalies
    ip_scores = events_df.groupby('ip').agg(
        total_score=('score', 'sum'),
        anomaly_types=('anomaly_type', lambda x: ', '.join(x)),
        explanations=('explanation', lambda x: ' | '.join(x)),
    ).reset_index()

    # Step 5: add severity label
    ip_scores['severity'] = ip_scores['total_score'].apply(get_severity)

    # Step 6: sort by score descending — biggest threats first
    ip_scores = ip_scores.sort_values('total_score', ascending=False).reset_index(drop=True)

    return ip_scores


if __name__ == '__main__':
    import sys
    sys.path.append('backend')
    from parser import load_log_dataframe
    from detector import detect_brute_force, detect_404_spike, detect_500_spike, detect_off_hours_traffic

    df = load_log_dataframe('data/sample.log')

    bf  = detect_brute_force(df)
    s404 = detect_404_spike(df)
    s500 = detect_500_spike(df)
    off  = detect_off_hours_traffic(df)

    results = score_anomalies(bf, s404, s500, off)

    print("=== RISK SCORES ===\n")
    print(results[['ip', 'total_score', 'severity', 'anomaly_types']])
    print("\n=== FULL EXPLANATIONS ===\n")
    for _, row in results.iterrows():
        print(f"IP: {row['ip']}")
        print(f"Score: {row['total_score']} ({row['severity']})")
        print(f"Explanation: {row['explanations']}")
        print()