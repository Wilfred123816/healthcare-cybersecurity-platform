import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RESULTS_DIR = (
    PROJECT_ROOT
    / "data"
    / "benchmark"
    / "results"
)

BASELINE_FILE = (
    RESULTS_DIR
    / "baseline_detection_results.json"
)

TRUST_AWARE_FILE = (
    RESULTS_DIR
    / "trust_aware_detection_results.json"
)

OUTPUT_FILE = (
    RESULTS_DIR
    / "baseline_vs_trust_aware.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def percentage_change(baseline, improved):
    return round(
        (improved - baseline) * 100,
        2
    )


def main():

    baseline = load_json(BASELINE_FILE)
    trust_aware = load_json(TRUST_AWARE_FILE)

    baseline_metrics = baseline["metrics"]
    trust_metrics = trust_aware["metrics"]

    baseline_cm = baseline["confusion_matrix"]
    trust_cm = trust_aware["confusion_matrix"]

    comparison = {

        "comparison": "baseline_vs_trust_aware",

        "baseline": {
            "accuracy": baseline_metrics["accuracy"],
            "precision": baseline_metrics["precision"],
            "recall": baseline_metrics["recall"],
            "f1": baseline_metrics["f1"],
            "true_positive": baseline_cm["true_positive"],
            "true_negative": baseline_cm["true_negative"],
            "false_positive": baseline_cm["false_positive"],
            "false_negative": baseline_cm["false_negative"],
        },

        "trust_aware": {
            "accuracy": trust_metrics["accuracy"],
            "precision": trust_metrics["precision"],
            "recall": trust_metrics["recall"],
            "f1": trust_metrics["f1"],
            "true_positive": trust_cm["true_positive"],
            "true_negative": trust_cm["true_negative"],
            "false_positive": trust_cm["false_positive"],
            "false_negative": trust_cm["false_negative"],
        },

        "improvement": {
            "accuracy_percentage_points": percentage_change(
                baseline_metrics["accuracy"],
                trust_metrics["accuracy"]
            ),

            "precision_percentage_points": percentage_change(
                baseline_metrics["precision"],
                trust_metrics["precision"]
            ),

            "recall_percentage_points": percentage_change(
                baseline_metrics["recall"],
                trust_metrics["recall"]
            ),

            "f1_percentage_points": percentage_change(
                baseline_metrics["f1"],
                trust_metrics["f1"]
            ),

            "additional_true_positives": (
                trust_cm["true_positive"]
                - baseline_cm["true_positive"]
            ),

            "false_negative_reduction": (
                baseline_cm["false_negative"]
                - trust_cm["false_negative"]
            ),

            "false_positive_change": (
                trust_cm["false_positive"]
                - baseline_cm["false_positive"]
            ),
        }
    }

    print("=" * 60)
    print("21.10.3 BASELINE VS TRUST-AWARE COMPARISON")
    print("=" * 60)

    print()
    print("Metric Comparison")
    print("-" * 60)

    print(
        f"Accuracy:   "
        f"{baseline_metrics['accuracy']:.4f}"
        f"  ->  "
        f"{trust_metrics['accuracy']:.4f}"
    )

    print(
        f"Precision:  "
        f"{baseline_metrics['precision']:.4f}"
        f"  ->  "
        f"{trust_metrics['precision']:.4f}"
    )

    print(
        f"Recall:     "
        f"{baseline_metrics['recall']:.4f}"
        f"  ->  "
        f"{trust_metrics['recall']:.4f}"
    )

    print(
        f"F1 score:   "
        f"{baseline_metrics['f1']:.4f}"
        f"  ->  "
        f"{trust_metrics['f1']:.4f}"
    )

    print()
    print("Detection Changes")
    print("-" * 60)

    print(
        f"True positives:  "
        f"{baseline_cm['true_positive']}"
        f" -> "
        f"{trust_cm['true_positive']}"
    )

    print(
        f"False negatives: "
        f"{baseline_cm['false_negative']}"
        f" -> "
        f"{trust_cm['false_negative']}"
    )

    print(
        f"False positives: "
        f"{baseline_cm['false_positive']}"
        f" -> "
        f"{trust_cm['false_positive']}"
    )

    print()
    print("Improvement")
    print("-" * 60)

    improvement = comparison["improvement"]

    print(
        f"Accuracy improvement:  "
        f"{improvement['accuracy_percentage_points']:.2f} "
        f"percentage points"
    )

    print(
        f"Precision improvement: "
        f"{improvement['precision_percentage_points']:.2f} "
        f"percentage points"
    )

    print(
        f"Recall improvement:    "
        f"{improvement['recall_percentage_points']:.2f} "
        f"percentage points"
    )

    print(
        f"F1 improvement:        "
        f"{improvement['f1_percentage_points']:.2f} "
        f"percentage points"
    )

    print(
        f"Additional TPs:        "
        f"{improvement['additional_true_positives']}"
    )

    print(
        f"False negatives reduced by: "
        f"{improvement['false_negative_reduction']}"
    )

    print()

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            comparison,
            file,
            indent=2
        )

    print("Comparison saved to:")
    print(OUTPUT_FILE)

    print()
    print("=" * 60)
    print("COMPARISON COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()