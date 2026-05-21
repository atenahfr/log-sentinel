# backend/detector.py
# Anomaly detection functions for Log Sentinel

def detect_brute_force(df, threshold=10):
    """
    Detects brute force login attacks.
    
    A brute force attack = same IP making repeated failed login attempts.
    We define 'suspicious' as more than `threshold` failed attempts.
    
    Args:
        df: pandas DataFrame from parser.py
        threshold: how many failed attempts before we flag an IP (default 10)
    
    Returns:
        A DataFrame of flagged IPs with their attempt counts
    """

    # Step 1: filter for failed login attempts only
    failed_logins = df[(df['path'] == '/login') & (df['status_code'] == 401)]

    # Step 2: count how many times each IP appears in those failures
    ip_counts = failed_logins.groupby('ip').size().reset_index(name='failed_attempts')

    # Step 3: flag only IPs that exceed the threshold
    flagged = ip_counts[ip_counts['failed_attempts'] > threshold].copy()

    # Step 4: add a label so we know what type of anomaly this is
    flagged['anomaly_type'] = 'brute_force'

    return flagged


if __name__ == '__main__':
    import sys
    sys.path.append('backend')
    from parser import load_log_dataframe

    df = load_log_dataframe('data/sample.log')
    result = detect_brute_force(df)

    print("=== BRUTE FORCE DETECTION RESULTS ===")
    print(result)
    print(f"\n{len(result)} IP(s) flagged for brute force")