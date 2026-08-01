import sys
sys.path.append('backend')

import pandas as pd
from parser import load_log_dataframe
from detector import (
    detect_brute_force,
    detect_404_spike,
    detect_500_spike,
    detect_off_hours_traffic
)
from scorer import score_anomalies
from ml_detector import detect_ml_anomalies


def generate_report(log_filepath):
    """
    Runs the full Log Sentinel analysis pipeline on a log file.
    
    Args:
        log_filepath: path to the log file to analyze
    
    Returns:
        A dictionary with the complete analysis results
    """

    # Step 1: parse the log file into a DataFrame
    df = load_log_dataframe(log_filepath)

    # Step 2: run all rule-based detectors
    bf   = detect_brute_force(df)
    s404 = detect_404_spike(df)
    s500 = detect_500_spike(df)
    off  = detect_off_hours_traffic(df)

    # Step 3: score all rule-based anomalies
    scored = score_anomalies(bf, s404, s500, off)

    # Step 4: run ML detector
    ml_results = detect_ml_anomalies(df, contamination=0.3)

    # Step 5: build comparison — which IPs were caught by rules, ML, or both
    rule_ips = set(scored[~scored['ip'].str.startswith('hour_')]['ip'].values)
    ml_ips   = set(ml_results['ip'].values)

    comparison = {
        'caught_by_both':   list(rule_ips & ml_ips),
        'rules_only':       list(rule_ips - ml_ips),
        'ml_only':          list(ml_ips - rule_ips),
    }

    # Step 4: build requests per hour for the timeline chart
    df['hour'] = df['timestamp'].dt.hour
    requests_per_hour = df.groupby('hour').size().reset_index(name='count')
    timeline = requests_per_hour.to_dict(orient='records')

    # Step 5: get top offending IPs (exclude hour_ entries)
    ip_scores = scored[~scored['ip'].str.startswith('hour_')]
    top_offenders = ip_scores.head(5).to_dict(orient='records')

    # Step 6: count flagged events by type
    anomaly_counts = {
        'brute_force':       len(bf),
        '404_spike':         len(s404),
        '500_spike':         len(s500),
        'off_hours_traffic': len(off),
    }

    # Step 7: calculate overall risk score
    overall_risk = int(scored['total_score'].sum()) if not scored.empty else 0

    # Step 8: assemble the final report dictionary
    report = {
        'summary': {
            'total_requests':   len(df),
            'unique_ips':       df['ip'].nunique(),
            'time_range_start': str(df['timestamp'].min()),
            'time_range_end':   str(df['timestamp'].max()),
            'total_anomalies':  len(bf) + len(s404) + len(s500) + len(off),
            'overall_risk':     overall_risk,
        },
        'anomaly_counts':  anomaly_counts,
        'top_offenders':   top_offenders,
        'timeline':        timeline,
        'all_scores':      scored.to_dict(orient='records'),
        
        'ml_anomalies': ml_results[[
            'ip', 'anomaly_score', 'anomaly_type', 'explanation'
        ]].to_dict(orient='records'),
        'comparison':   comparison,
    }

    return report


if __name__ == '__main__':
    import json

    report = generate_report('data/sample.log')

    # Print summary section
    print("=== REPORT SUMMARY ===")
    print(json.dumps(report['summary'], indent=2))

    print("\n=== ANOMALY COUNTS ===")
    print(json.dumps(report['anomaly_counts'], indent=2))

    print("\n=== TOP OFFENDERS ===")
    for offender in report['top_offenders']:
        print(f"  {offender['ip']} — score {offender['total_score']} ({offender['severity']})")

    print("\n=== TIMELINE (requests per hour) ===")
    for entry in report['timeline']:
        bar = '█' * (entry['count'] // 3)
        print(f"  {entry['hour']:02d}:00  {bar} {entry['count']}")