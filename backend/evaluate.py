# backend/evaluate.py
# Evaluation framework for Log Sentinel anomaly detectors.
# Compares rule-based and ML detectors against labeled ground truth.

import sys
sys.path.append('backend')

import pandas as pd
from parser import load_log_dataframe
from detector import detect_brute_force, detect_404_spike, detect_500_spike
from ml_detector import detect_ml_anomalies


def load_ground_truth(csv_path):
    """
    Loads the labeled ground truth CSV.

    Args:
        csv_path: path to labeled_sample.csv

    Returns:
        dict mapping ip -> true_label (0=normal, 1=attack)
    """
    df = pd.read_csv(csv_path)
    return dict(zip(df['ip'], df['true_label']))


def get_rule_based_flagged(df):
    """
    Runs all rule-based detectors and returns the set of flagged IPs.
    Excludes hour_ entries from off-hours detection.
    """
    bf   = detect_brute_force(df, threshold=10)
    s404 = detect_404_spike(df, threshold=10)
    s500 = detect_500_spike(df, threshold=5)

    flagged_ips = set()
    for result_df in [bf, s404, s500]:
        flagged_ips.update(result_df['ip'].values)

    return flagged_ips


def get_ml_flagged(df, contamination=0.3):
    """
    Runs the Isolation Forest detector and returns the set of flagged IPs.
    """
    results = detect_ml_anomalies(df, contamination=contamination)
    return set(results['ip'].values)


def compute_metrics(flagged_ips, ground_truth):
    """
    Computes precision, recall, F1 and confusion matrix values.

    Args:
        flagged_ips:   set of IPs flagged by a detector
        ground_truth:  dict mapping ip -> true_label

    Returns:
        dict with tp, fp, fn, tn, precision, recall, f1
    """
    tp = fp = fn = tn = 0

    for ip, true_label in ground_truth.items():
        predicted_attack = ip in flagged_ips

        if true_label == 1 and predicted_attack:
            tp += 1   # correctly flagged attacker
        elif true_label == 0 and predicted_attack:
            fp += 1   # normal IP wrongly flagged
        elif true_label == 1 and not predicted_attack:
            fn += 1   # attacker we missed
        else:
            tn += 1   # normal IP correctly ignored

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)

    return {
        'tp':        tp,
        'fp':        fp,
        'fn':        fn,
        'tn':        tn,
        'precision': round(precision, 4),
        'recall':    round(recall, 4),
        'f1':        round(f1, 4),
    }


def evaluate_both(log_path, csv_path, contamination=0.3):
    """
    Runs full evaluation of both detectors against labeled ground truth.

    Args:
        log_path:      path to labeled log file
        csv_path:      path to ground truth CSV
        contamination: Isolation Forest contamination parameter

    Returns:
        dict with metrics for both detectors
    """
    df           = load_log_dataframe(log_path)
    ground_truth = load_ground_truth(csv_path)

    rule_flagged = get_rule_based_flagged(df)
    ml_flagged   = get_ml_flagged(df, contamination=contamination)

    rule_metrics = compute_metrics(rule_flagged, ground_truth)
    ml_metrics   = compute_metrics(ml_flagged,   ground_truth)

    return {
        'rule_based': rule_metrics,
        'ml':         ml_metrics,
        'rule_flagged_count': len(rule_flagged),
        'ml_flagged_count':   len(ml_flagged),
        'total_ips':          len(ground_truth),
        'total_attackers':    sum(ground_truth.values()),
    }


if __name__ == '__main__':
    results = evaluate_both(
        log_path='data/labeled_sample.log',
        csv_path='data/labeled_sample.csv',
        contamination=0.15,
    )

    print("=== EVALUATION RESULTS ===\n")
    print(f"Dataset: {results['total_ips']} IPs "
          f"({results['total_attackers']} attackers, "
          f"{results['total_ips'] - results['total_attackers']} normal)\n")

    print(f"{'Metric':<12} {'Rule-Based':>12} {'ML (IF)':>12}")
    print("-" * 38)

    rb = results['rule_based']
    ml = results['ml']

    print(f"{'Flagged':<12} {results['rule_flagged_count']:>12} {results['ml_flagged_count']:>12}")
    print(f"{'TP':<12} {rb['tp']:>12} {ml['tp']:>12}")
    print(f"{'FP':<12} {rb['fp']:>12} {ml['fp']:>12}")
    print(f"{'FN':<12} {rb['fn']:>12} {ml['fn']:>12}")
    print(f"{'TN':<12} {rb['tn']:>12} {ml['tn']:>12}")
    print("-" * 38)
    print(f"{'Precision':<12} {rb['precision']:>12} {ml['precision']:>12}")
    print(f"{'Recall':<12} {rb['recall']:>12} {ml['recall']:>12}")
    print(f"{'F1 Score':<12} {rb['f1']:>12} {ml['f1']:>12}")
    
    print("\n=== CONTAMINATION TUNING ===\n")
    print(f"{'Contamination':<15} {'Flagged':>8} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print("-" * 55)

    best_f1 = 0
    best_contamination = 0.3

    for c in [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]:
        r = evaluate_both(
            log_path='data/labeled_sample.log',
            csv_path='data/labeled_sample.csv',
            contamination=c
        )
        m = r['ml']
        print(f"{c:<15} {r['ml_flagged_count']:>8} {m['precision']:>10} {m['recall']:>8} {m['f1']:>8}")

        if m['f1'] > best_f1:
            best_f1 = m['f1']
            best_contamination = c

    print(f"\nBest contamination: {best_contamination} (F1 = {best_f1})")