# backend/detector.py
# Anomaly detection functions for Log Sentinel.
#
# Each function takes a pandas DataFrame from parser.py and returns
# a DataFrame of flagged entries with anomaly_type and explanation columns.


def detect_brute_force(df, threshold=10):
    """
    Detects brute force login attacks.

    A brute force attack = same IP making repeated failed login attempts.
    We define 'suspicious' as more than `threshold` failed attempts.

    Args:
        df:        pandas DataFrame from load_log_dataframe()
        threshold: how many failed attempts before we flag an IP (default 10)

    Returns:
        DataFrame with columns: ip, failed_attempts, anomaly_type, explanation
    """
    # Filter for failed login attempts only
    failed_logins = df[(df['path'] == '/login') & (df['status_code'] == 401)]

    # Count how many times each IP appears in those failures
    ip_counts = failed_logins.groupby('ip').size().reset_index(name='failed_attempts')

    # Flag only IPs that exceed the threshold
    flagged = ip_counts[ip_counts['failed_attempts'] > threshold].copy()

    flagged['anomaly_type'] = 'brute_force'
    flagged['explanation'] = flagged['failed_attempts'].apply(
        lambda count: (
            f"This IP made {count} failed login attempts on /login. "
            f"Normal users fail 1-2 times at most. "
            f"This volume strongly suggests an automated brute force attack."
        )
    )

    return flagged


def detect_404_spike(df, threshold=10):
    """
    Detects directory scanning attacks.

    A 404 spike = same IP getting many 'page not found' responses.
    This usually means someone is probing for hidden files and admin pages.

    Args:
        df:        pandas DataFrame from load_log_dataframe()
        threshold: how many 404s before we flag an IP (default 10)

    Returns:
        DataFrame with columns: ip, error_count, anomaly_type, explanation
    """
    # Filter for 404 responses only
    not_found = df[df['status_code'] == 404]

    # Count 404s per IP
    ip_counts = not_found.groupby('ip').size().reset_index(name='error_count')

    # Flag IPs over threshold
    flagged = ip_counts[ip_counts['error_count'] > threshold].copy()

    flagged['anomaly_type'] = '404_spike'
    flagged['explanation'] = flagged['error_count'].apply(
        lambda count: (
            f"This IP triggered {count} 'page not found' errors. "
            f"This pattern suggests automated directory scanning — "
            f"probing for hidden files like /admin, /.env, or /config.php."
        )
    )

    return flagged


def detect_500_spike(df, threshold=5):
    """
    Detects server error spikes.

    A 500 spike = same IP triggering many server errors.
    This could mean someone is sending malformed requests or attempting injection.

    Args:
        df:        pandas DataFrame from load_log_dataframe()
        threshold: how many 500s before we flag an IP (default 5)

    Returns:
        DataFrame with columns: ip, error_count, anomaly_type, explanation
    """
    # Filter for 500 responses only
    server_errors = df[df['status_code'] == 500]

    # Count 500s per IP
    ip_counts = server_errors.groupby('ip').size().reset_index(name='error_count')

    # Flag IPs over threshold
    flagged = ip_counts[ip_counts['error_count'] > threshold].copy()

    flagged['anomaly_type'] = '500_spike'
    flagged['explanation'] = flagged['error_count'].apply(
        lambda count: (
            f"This IP caused {count} internal server errors. "
            f"Repeated 500 errors from one IP suggest malformed requests "
            f"or a possible injection attempt."
        )
    )

    return flagged


def detect_off_hours_traffic(df, std_multiplier=2):
    """
    Detects statistically abnormal traffic hours.

    Flags hours where traffic exceeds mean + (std_multiplier * std_dev).
    Also flags any activity between midnight and 6am as inherently suspicious.

    Args:
        df:             pandas DataFrame from load_log_dataframe()
        std_multiplier: standard deviations above mean to flag (default 2)

    Returns:
        DataFrame with columns: hour, request_count, anomaly_type, explanation
    """
    # Count requests per hour
    df['hour'] = df['timestamp'].dt.hour
    requests_per_hour = df.groupby('hour').size().reset_index(name='request_count')

    # Calculate mean and standard deviation
    mean = requests_per_hour['request_count'].mean()
    std  = requests_per_hour['request_count'].std()

    # Calculate the statistical threshold
    threshold = mean + (std_multiplier * std)

    # Flag hours that exceed the threshold OR fall in the off-hours window
    flagged = requests_per_hour[
        (requests_per_hour['request_count'] > threshold) |
        (requests_per_hour['hour'] < 6)
    ].copy()

    flagged['anomaly_type'] = 'off_hours_traffic'
    flagged['explanation'] = flagged.apply(
        lambda row: (
            f"Hour {row['hour']}:00 had {row['request_count']} requests. "
            f"The daily average is {mean:.1f} requests/hour "
            f"(threshold: {threshold:.1f}). "
            f"{'This hour falls in the suspicious 2am-6am window.' if row['hour'] < 6 else 'This exceeds the statistical threshold by more than 2 standard deviations.'}"
        ), axis=1
    )

    return flagged


if __name__ == '__main__':
    import sys
    sys.path.append('backend')
    from parser import load_log_dataframe

    df = load_log_dataframe('data/sample.log')

    print("=== BRUTE FORCE DETECTION ===")
    bf = detect_brute_force(df)
    print(bf)
    print(f"{len(bf)} IP(s) flagged\n")

    print("=== 404 SPIKE DETECTION ===")
    s404 = detect_404_spike(df)
    print(s404)
    print(f"{len(s404)} IP(s) flagged\n")

    print("=== 500 SPIKE DETECTION ===")
    s500 = detect_500_spike(df)
    print(s500)
    print(f"{len(s500)} IP(s) flagged\n")

    print("=== OFF HOURS / STATISTICAL ANOMALY DETECTION ===")
    offhours = detect_off_hours_traffic(df)
    print(offhours[['hour', 'request_count', 'anomaly_type']])
    print(f"\n{len(offhours)} hour(s) flagged\n")