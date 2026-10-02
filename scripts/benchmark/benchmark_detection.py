import json
from pathlib import Path

from Backend.app.detection.threat_detector import (
    ThreatDetectionEngine,
)

from scripts.benchmark.benchmark_loader import (
    validate_benchmark_dataset,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def calculate_metrics(tp, tn, fp, fn):
    """Calculate standard binary classification metrics."""

    total = tp + tn + fp + fn

    accuracy = (
        (tp + tn) / total
        if total
        else 0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0
    )

    if precision + recall > 0:
        f1 = (
            2 * precision * recall
            / (precision + recall)
        )
    else:
        f1 = 0

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main():

    print("=" * 60)
    print("23.4 BASELINE THREAT DETECTION BENCHMARK")
    print("=" * 60)

    dataset = validate_benchmark_dataset()

    events = dataset["events"]
    ground_truth_map = {
        row.event_id: row
        for row in dataset["ground_truth"]
    }

    metadata = dataset["metadata"]

    print(
        f"Benchmark dataset version: "
        f"{metadata['dataset_version']}"
    )

    print(
        f"Random seed: "
        f"{metadata['random_seed']}"
    )

    print(
        f"Events loaded: "
        f"{len(events)}"
    )

    print(
        f"Ground-truth records: "
        f"{len(ground_truth_map)}"
    )

    print()

    detector = ThreatDetectionEngine()

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    skipped_events = 0
    attack_events = 0
    normal_events = 0

    for event in events:

        truth = ground_truth_map.get(
            event.event_id
        )

        if truth is None:
            skipped_events += 1
            continue

        result = detector.detect(event)

        predicted_attack = result.threat_detected
        actual_attack = (
            truth.label == "attack"
        )

        if actual_attack:
            attack_events += 1
        else:
            normal_events += 1

        if predicted_attack and actual_attack:
            tp += 1

        elif not predicted_attack and not actual_attack:
            tn += 1

        elif predicted_attack and not actual_attack:
            fp += 1

        else:
            fn += 1

    events_evaluated = (
        tp + tn + fp + fn
    )

    metrics = calculate_metrics(
        tp,
        tn,
        fp,
        fn
    )

    results = {
        "benchmark": "baseline_detection",
        "dataset": {
            "version": metadata["dataset_version"],
            "split": metadata["split"],
            "random_seed": metadata["random_seed"],
            "events_loaded": len(events),
            "events_evaluated": events_evaluated,
            "events_skipped": skipped_events,
            "attack_events": attack_events,
            "normal_events": normal_events,
        },
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
        },
        "metrics": metrics,
    }

    print("Dataset")
    print("-" * 60)
    print(
        f"Events loaded:      {len(events)}"
    )
    print(
        f"Events evaluated:   {events_evaluated}"
    )
    print(
        f"Events skipped:     {skipped_events}"
    )
    print(
        f"Attack events:      {attack_events}"
    )
    print(
        f"Normal events:      {normal_events}"
    )
    print()

    print("Confusion Matrix")
    print("-" * 60)
    print(
        f"True positives:     {tp}"
    )
    print(
        f"True negatives:     {tn}"
    )
    print(
        f"False positives:    {fp}"
    )
    print(
        f"False negatives:    {fn}"
    )
    print()

    print("Metrics")
    print("-" * 60)
    print(
        f"Accuracy:           "
        f"{metrics['accuracy']:.4f}"
    )
    print(
        f"Precision:          "
        f"{metrics['precision']:.4f}"
    )
    print(
        f"Recall:             "
        f"{metrics['recall']:.4f}"
    )
    print(
        f"F1 score:           "
        f"{metrics['f1']:.4f}"
    )
    print()

    output_file = (
        PROJECT_ROOT
        / "data"
        / "benchmark"
        / "results"
        / "baseline_detection_results.json"
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            results,
            file,
            indent=2
        )

    print(
        "Result saved to:"
    )
    print(output_file)
    print()

    print("=" * 60)
    print("BASELINE BENCHMARK COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()