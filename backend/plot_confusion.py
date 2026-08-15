# backend/plot_confusion.py
# Generates confusion matrix plots for both detectors.
# Run directly: python3 backend/plot_confusion.py

import sys
sys.path.append('backend')

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
from evaluate import evaluate_both


def plot_confusion_matrix(metrics, title, ax):
    """
    Draws a styled confusion matrix on a matplotlib axes object.

    Args:
        metrics: dict with tp, fp, fn, tn keys
        title:   string title for this matrix
        ax:      matplotlib axes to draw on
    """
    tp = metrics['tp']
    fp = metrics['fp']
    fn = metrics['fn']
    tn = metrics['tn']

    # Build 2x2 matrix
    matrix = np.array([[tn, fp], [fn, tp]])

    # Colors: green for correct, red for incorrect
    colors = np.array([
        ['#1a472a', '#7f1d1d'],  # TN=dark green, FP=dark red
        ['#7f1d1d', '#1a472a'],  # FN=dark red,  TP=dark green
    ])

    ax.set_facecolor('#0a0a0a')

    for i in range(2):
        for j in range(2):
            rect = patches.Rectangle(
                (j, 1-i), 1, 1,
                linewidth=1,
                edgecolor='#333333',
                facecolor=colors[i][j]
            )
            ax.add_patch(rect)

            # Main number
            ax.text(j + 0.5, 1 - i + 0.55,
                str(matrix[i][j]),
                ha='center', va='center',
                fontsize=28, fontweight='bold',
                color='white',
                fontfamily='monospace'
            )

            # Label
            label = ['TN', 'FP', 'FN', 'TP'][(i*2)+j]
            color = '#00ff88' if label in ['TP', 'TN'] else '#ff4444'
            ax.text(j + 0.5, 1 - i + 0.25,
                label,
                ha='center', va='center',
                fontsize=11, color=color,
                fontfamily='monospace'
            )

    # Axis labels
    ax.set_xlim(0, 2)
    ax.set_ylim(0, 2)
    ax.set_xticks([0.5, 1.5])
    ax.set_yticks([0.5, 1.5])
    ax.set_xticklabels(['Predicted\nNormal', 'Predicted\nAttack'],
                       color='#888888', fontsize=9)
    ax.set_yticklabels(['Actual\nAttack', 'Actual\nNormal'],
                       color='#888888', fontsize=9)
    ax.tick_params(colors='#555555')

    for spine in ax.spines.values():
        spine.set_edgecolor('#333333')

    # Title and metrics
    ax.set_title(title, color='#00ff88', fontsize=13,
                 fontfamily='monospace', pad=12)

    precision = metrics['precision']
    recall    = metrics['recall']
    f1        = metrics['f1']

    ax.text(1.0, -0.18,
        f'Precision: {precision:.4f}   Recall: {recall:.4f}   F1: {f1:.4f}',
        ha='center', va='center',
        fontsize=9, color='#888888',
        fontfamily='monospace',
        transform=ax.transData
    )


def generate_confusion_matrices():
    """
    Runs evaluation and saves confusion matrix plots for both detectors.
    """
    results = evaluate_both(
        log_path='data/labeled_sample.log',
        csv_path='data/labeled_sample.csv',
        contamination=0.15,
    )

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.patch.set_facecolor('#0a0a0a')
    fig.suptitle(
        'Log Sentinel — Anomaly Detector Evaluation',
        color='#00ff88', fontsize=14,
        fontfamily='monospace', y=1.02
    )

    plot_confusion_matrix(results['rule_based'], 'Rule-Based Detector', ax1)
    plot_confusion_matrix(results['ml'],         'Isolation Forest (ML)', ax2)

    plt.tight_layout(pad=2.0)
    plt.savefig('data/confusion_matrices.png',
                dpi=150, bbox_inches='tight',
                facecolor='#0a0a0a')
    plt.show()
    print("Saved to data/confusion_matrices.png")


if __name__ == '__main__':
    generate_confusion_matrices()