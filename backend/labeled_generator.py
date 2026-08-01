# backend/labeled_generator.py
# Generates a labeled dataset for evaluating anomaly detectors.
# Produces a log file with known attackers and a CSV with ground truth labels.

import random
import csv
from datetime import datetime, timezone

def generate_labeled_dataset(
    n_normal=200,
    n_brute_force=10,
    n_scanners=10,
    n_error_spikers=10,
    seed=42
):
    """
    Generates a synthetic but realistic labeled log dataset.

    Args:
        n_normal:        number of normal IPs
        n_brute_force:   number of brute force attacker IPs
        n_scanners:      number of directory scanner IPs
        n_error_spikers: number of server error spike IPs
        seed:            random seed for reproducibility

    Returns:
        lines:  list of Apache log line strings
        labels: dict mapping each IP to its true label (0=normal, 1=attack)
    """
    random.seed(seed)

    lines  = []
    labels = {}
    base   = datetime(2024, 5, 15, 0, 0, 0, tzinfo=timezone.utc)

    paths_normal = [
        '/index.html', '/about.html', '/products',
        '/dashboard', '/contact', '/api/data'
    ]
    methods = ['GET', 'GET', 'GET', 'POST']

    # ── Normal IPs ──
    for i in range(n_normal):
        ip = f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
        labels[ip] = 0  # benign

        n_requests = random.randint(3, 30)
        for _ in range(n_requests):
            hour   = random.randint(8, 20)   # daytime only
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            ts     = base.replace(hour=hour, minute=minute, second=second)
            path   = random.choice(paths_normal)
            method = random.choice(methods)
            size   = random.randint(512, 8192)
            lines.append(
                f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"{method} {path} HTTP/1.1" 200 {size}'
            )

    # ── Brute Force Attackers ──
    attack_paths = ['/admin', '/.env', '/config.php', '/wp-admin', '/phpmyadmin', '/backup']
    for i in range(n_brute_force):
        ip = f'45.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
        labels[ip] = 1  # attacker

        n_attempts = random.randint(20, 60)
        for j in range(n_attempts):
            hour   = random.randint(0, 5)    # off-hours
            minute = j // 60
            second = j % 60
            ts     = base.replace(hour=hour, minute=minute, second=second)
            lines.append(
                f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"GET /login HTTP/1.1" 401 512'
            )

    # ── Directory Scanners ──
    for i in range(n_scanners):
        ip = f'198.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
        labels[ip] = 1  # attacker

        n_probes = random.randint(15, 40)
        for _ in range(n_probes):
            hour   = random.randint(0, 5)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            ts     = base.replace(hour=hour, minute=minute, second=second)
            path   = random.choice(attack_paths)
            lines.append(
                f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"GET {path} HTTP/1.1" 404 256'
            )

    # ── Server Error Spikers ──
    for i in range(n_error_spikers):
        ip = f'203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
        labels[ip] = 1  # attacker

        n_errors = random.randint(8, 20)
        for _ in range(n_errors):
            hour   = random.randint(12, 16)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            ts     = base.replace(hour=hour, minute=minute, second=second)
            lines.append(
                f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"POST /api/upload HTTP/1.1" 500 128'
            )

    random.shuffle(lines)
    return lines, labels


if __name__ == '__main__':
    import os

    lines, labels = generate_labeled_dataset()

    # Save log file
    log_path = 'data/labeled_sample.log'
    with open(log_path, 'w') as f:
        f.write('\n'.join(lines))

    # Save labels CSV
    csv_path = 'data/labeled_sample.csv'
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ip', 'true_label'])
        for ip, label in labels.items():
            writer.writerow([ip, label])

    # Print summary
    total     = len(labels)
    attackers = sum(1 for v in labels.values() if v == 1)
    normal    = sum(1 for v in labels.values() if v == 0)

    print(f"Generated {len(lines)} log lines")
    print(f"IPs: {total} total — {normal} normal, {attackers} attackers")
    print(f"Log saved to:    {log_path}")
    print(f"Labels saved to: {csv_path}")