import json
import sys
from pathlib import Path

# Allow imports from the project root when the script is
# executed directly.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Backend.app.detection.scenario_correlator import (
    ScenarioThreatCorrelator,
)
from Backend.app.detection.threat_detector import (
    ThreatDetectionEngine,
)
from Backend.app.trust.trust_aware_detector import (
    TrustAwareDetector,
)
from Backend.app.trust.trust_engine import (
    TrustEngine,
)

from scripts.benchmark.benchmark_loader import (
    validate_benchmark_dataset,
)


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


def build_scenario_map(events):
    """Group benchmark events by scenario ID."""

    scenario_map = {}

    for event in events:
        scenario_map.setdefault(
            event.scenario_id,
            []
        ).append(event)

    return scenario_map


def main():

    print("=" * 60)
    print("23.5 TRUST-AWARE DETECTION BENCHMARK")
    print("=" * 60)

    dataset = validate_benchmark_dataset()

    events = dataset["events"]
    evidence_map = {
        row.event_id: row
        for row in dataset["evidence"]
    }
    ground_truth_map = {
        row.event_id: row
        for row in dataset["ground_truth"]
    }

    metadata = dataset["metadata"]

    scenario_map = build_scenario_map(
        events
    )

    print(
        f"Benchmark dataset version: "
        f"{metadata['dataset_version']}"
    )

    print(
        f"Random seed: "
        f"{metadata['random_seed']}"
    )

    print(
        f"Events loaded:           "
        f"{len(events)}"
    )

    print(
        f"Scenarios loaded:        "
        f"{len(scenario_map)}"
    )

    print(
        f"Evidence records:        "
        f"{len(evidence_map)}"
    )

    print(
        f"Ground-truth records:    "
        f"{len(ground_truth_map)}"
    )

    print()

    detection_engine = (
        ThreatDetectionEngine()
    )

    correlation_engine = (
        ScenarioThreatCorrelator()
    )

    trust_engine = TrustEngine()

    trust_aware_engine = (
        TrustAwareDetector()
    )

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    skipped_no_ground_truth = 0
    skipped_no_evidence = 0

    attack_events = 0
    normal_events = 0

    decision_counts = {}

    for event in events:

        truth = ground_truth_map.get(
            event.event_id
        )

        if truth is None:
            skipped_no_ground_truth += 1
            continue

        evidence = evidence_map.get(
            event.event_id
        )

        if evidence is None:
            skipped_no_evidence += 1
            continue

        detection_result = (
            detection_engine.detect(event)
        )

        scenario_events = scenario_map.get(
            event.scenario_id,
            []
        )

        scenario_result = (
            correlation_engine.correlate(
                scenario_events
            )
        )

        trust_result = (
            trust_engine.evaluate(
                evidence
            )
        )

        final_result = (
            trust_aware_engine.evaluate(
                detection_result,
                trust_result,
                scenario_result
            )
        )

        predicted_attack = (
            final_result.threat_detected
        )

        actual_attack = (
            truth.label == "attack"
        )

        if actual_attack:
            attack_events += 1
        else:
            normal_events += 1

        if predicted_attack and actual_attack:
            tp += 1

        elif (
            not predicted_attack
            and not actual_attack
        ):
            tn += 1

        elif predicted_attack and not actual_attack:
            fp += 1

        else:
            fn += 1

        decision = final_result.decision

        decision_counts[decision] = (
            decision_counts.get(decision, 0)
            + 1
        )

    events_evaluated = (
        tp + tn + fp + fn
    )

    metrics = calculate_metrics(
        tp,
        tn,
        fp,
        fn
    )

    poisoned_evidence = sum(
        1
        for evidence in dataset["evidence"]
        if evidence.is_poisoned
    )

    results = {
        "benchmark": "trust_aware_detection",
        "dataset": {
            "version": metadata["dataset_version"],
            "split": metadata["split"],
            "random_seed": metadata["random_seed"],
            "events_loaded": len(events),
            "events_evaluated": events_evaluated,
            "events_skipped_no_ground_truth": (
                skipped_no_ground_truth
            ),
            "events_skipped_no_evidence": (
                skipped_no_evidence
            ),
            "attack_events": attack_events,
            "normal_events": normal_events,
            "scenarios": len(scenario_map),
            "evidence_records": len(evidence_map),
            "poisoned_evidence_records": (
                poisoned_evidence
            ),
        },
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
        },
        "metrics": metrics,
        "decision_distribution": decision_counts,
    }

    print("Dataset")
    print("-" * 60)
    print(
        f"Events loaded:           "
        f"{len(events)}"
    )
    print(
        f"Events evaluated:        "
        f"{events_evaluated}"
    )
    print(
        f"Skipped - no truth:      "
        f"{skipped_no_ground_truth}"
    )
    print(
        f"Skipped - no evidence:   "
        f"{skipped_no_evidence}"
    )
    print(
        f"Attack events:           "
        f"{attack_events}"
    )
    print(
        f"Normal events:           "
        f"{normal_events}"
    )
    print(
        f"Scenarios:               "
        f"{len(scenario_map)}"
    )
    print(
        f"Poisoned evidence:       "
        f"{poisoned_evidence}"
    )
    print()

    print("Confusion Matrix")
    print("-" * 60)
    print(
        f"True positives:          {tp}"
    )
    print(
        f"True negatives:          {tn}"
    )
    print(
        f"False positives:         {fp}"
    )
    print(
        f"False negatives:         {fn}"
    )
    print()

    print("Metrics")
    print("-" * 60)
    print(
        f"Accuracy:                "
        f"{metrics['accuracy']:.4f}"
    )
    print(
        f"Precision:               "
        f"{metrics['precision']:.4f}"
    )
    print(
        f"Recall:                  "
        f"{metrics['recall']:.4f}"
    )
    print(
        f"F1 score:                "
        f"{metrics['f1']:.4f}"
    )
    print()

    print("Decision Distribution")
    print("-" * 60)

    for decision, count in sorted(
        decision_counts.items()
    ):
        print(
            f"{decision}: {count}"
        )

    print()

    output_file = (
        PROJECT_ROOT
        / "data"
        / "benchmark"
        / "results"
        / "trust_aware_detection_results.json"
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
    print("TRUST-AWARE BENCHMARK COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()