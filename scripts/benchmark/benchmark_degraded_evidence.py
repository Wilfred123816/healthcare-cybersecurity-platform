import copy
import json
import sys
from collections import Counter
from pathlib import Path


# Allow imports from the project root when executed directly.
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


RESULTS_DIR = (
    PROJECT_ROOT
    / "data"
    / "benchmark"
    / "results"
)

OUTPUT_FILE = (
    RESULTS_DIR
    / "degraded_evidence_impact_results.json"
)


def build_scenario_map(events):
    """Group benchmark events by scenario ID."""

    scenario_map = {}

    for event in events:
        scenario_map.setdefault(
            event.scenario_id,
            []
        ).append(event)

    return scenario_map


def degrade_evidence(evidence, profile):
    """
    Create an in-memory copy of evidence and degrade only
    observable evidence-quality attributes.

    No benchmark CSV data is modified.
    """

    degraded = copy.copy(evidence)

    if profile == "provenance_degraded":

        degraded.provenance = "unknown"

    elif profile == "integrity_degraded":

        degraded.integrity_status = "invalid"

    elif profile == "freshness_degraded":

        degraded.freshness_status = "stale"

    elif profile == "fully_degraded":

        degraded.provenance = "unknown"
        degraded.integrity_status = "invalid"
        degraded.freshness_status = "stale"
        degraded.consistency_status = "inconsistent"

    else:
        raise ValueError(
            f"Unknown degradation profile: {profile}"
        )

    return degraded


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


def evaluate_condition(
    events,
    scenario_map,
    evidence_map,
    ground_truth_map,
    detection_engine,
    correlation_engine,
    trust_engine,
    trust_aware_engine,
    profile=None,
):
    """
    Evaluate the benchmark under the original evidence
    condition or one controlled degradation profile.
    """

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    total_evaluated = 0
    skipped_no_truth = 0
    skipped_no_evidence = 0

    attack_events = 0
    normal_events = 0

    trust_scores = []

    decisions = Counter()

    event_results = {}

    for event in events:

        truth = ground_truth_map.get(
            event.event_id
        )

        if truth is None:
            skipped_no_truth += 1
            continue

        evidence = evidence_map.get(
            event.event_id
        )

        if evidence is None:
            skipped_no_evidence += 1
            continue

        # Detection is unchanged across all conditions.
        detection_result = detection_engine.detect(
            event
        )

        scenario_events = scenario_map.get(
            event.scenario_id,
            []
        )

        scenario_result = correlation_engine.correlate(
            scenario_events
        )

        # Original evidence or an in-memory degraded copy.
        evaluation_evidence = evidence

        if profile is not None:
            evaluation_evidence = degrade_evidence(
                evidence,
                profile
            )

        trust_result = trust_engine.evaluate(
            evaluation_evidence
        )

        final_result = trust_aware_engine.evaluate(
            detection_result,
            trust_result,
            scenario_result
        )

        actual_attack = (
            truth.label == "attack"
        )

        predicted_attack = (
            final_result.threat_detected
        )

        total_evaluated += 1

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

        trust_scores.append(
            trust_result.trust_score
        )

        decisions[
            final_result.decision
        ] += 1

        event_results[event.event_id] = {
            "trust_score": (
                trust_result.trust_score
            ),
            "trust_level": (
                trust_result.trust_level
            ),
            "decision": (
                final_result.decision
            ),
            "threat_detected": (
                final_result.threat_detected
            ),
            "final_score": (
                final_result.final_score
            ),
        }

    metrics = calculate_metrics(
        tp,
        tn,
        fp,
        fn
    )

    average_trust = (
        sum(trust_scores) / len(trust_scores)
        if trust_scores
        else 0
    )

    return {
        "dataset": {
            "events_evaluated": (
                total_evaluated
            ),
            "events_skipped_no_ground_truth": (
                skipped_no_truth
            ),
            "events_skipped_no_evidence": (
                skipped_no_evidence
            ),
            "attack_events": (
                attack_events
            ),
            "normal_events": (
                normal_events
            ),
        },
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
        },
        "metrics": metrics,
        "average_trust_score": round(
            average_trust,
            2
        ),
        "decision_distribution": dict(
            decisions
        ),
        "event_results": event_results,
    }


def compare_conditions(
    original_results,
    degraded_results
):
    """
    Measure how evidence degradation changes
    trust-aware decisions.
    """

    changed_decisions = 0
    changed_threat_status = 0

    decision_transitions = Counter()

    for event_id, original in (
        original_results["event_results"].items()
    ):

        degraded = (
            degraded_results["event_results"]
            .get(event_id)
        )

        if degraded is None:
            continue

        original_decision = (
            original["decision"]
        )

        degraded_decision = (
            degraded["decision"]
        )

        original_threat = (
            original["threat_detected"]
        )

        degraded_threat = (
            degraded["threat_detected"]
        )

        if original_decision != degraded_decision:

            changed_decisions += 1

            transition = (
                f"{original_decision}"
                f" -> "
                f"{degraded_decision}"
            )

            decision_transitions[
                transition
            ] += 1

        if original_threat != degraded_threat:
            changed_threat_status += 1

    return {
        "changed_decisions": (
            changed_decisions
        ),
        "changed_threat_status": (
            changed_threat_status
        ),
        "decision_transitions": dict(
            decision_transitions
        ),
    }


def main():

    print("=" * 60)
    print("23.7 DEGRADED-EVIDENCE IMPACT BENCHMARK")
    print("=" * 60)

    dataset = validate_benchmark_dataset()

    metadata = dataset["metadata"]

    events = dataset["events"]

    evidence_map = {
        row.event_id: row
        for row in dataset["evidence"]
    }

    ground_truth_map = {
        row.event_id: row
        for row in dataset["ground_truth"]
    }

    scenario_map = build_scenario_map(
        events
    )

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

    print()
    print(
        f"Benchmark dataset version: "
        f"{metadata['dataset_version']}"
    )

    print(
        f"Random seed: "
        f"{metadata['random_seed']}"
    )

    print(
        f"Split: "
        f"{metadata['split']}"
    )

    print(
        f"Events loaded:      "
        f"{len(events)}"
    )

    print(
        f"Evidence records:   "
        f"{len(evidence_map)}"
    )

    print(
        f"Ground truth:       "
        f"{len(ground_truth_map)}"
    )

    print(
        f"Scenarios:          "
        f"{len(scenario_map)}"
    )

    print()

    # ORIGINAL CONDITION

    original = evaluate_condition(
        events,
        scenario_map,
        evidence_map,
        ground_truth_map,
        detection_engine,
        correlation_engine,
        trust_engine,
        trust_aware_engine,
        profile=None,
    )

    print("Original Evidence Condition")
    print("-" * 60)

    print(
        f"Accuracy:           "
        f"{original['metrics']['accuracy']:.4f}"
    )

    print(
        f"Precision:          "
        f"{original['metrics']['precision']:.4f}"
    )

    print(
        f"Recall:             "
        f"{original['metrics']['recall']:.4f}"
    )

    print(
        f"F1 score:           "
        f"{original['metrics']['f1']:.4f}"
    )

    print(
        f"Average trust:      "
        f"{original['average_trust_score']:.2f}"
    )

    print()

    profiles = [
        "provenance_degraded",
        "integrity_degraded",
        "freshness_degraded",
        "fully_degraded",
    ]

    results = {
        "benchmark": (
            "degraded_evidence_impact"
        ),
        "dataset": {
            "version": (
                metadata["dataset_version"]
            ),
            "split": (
                metadata["split"]
            ),
            "random_seed": (
                metadata["random_seed"]
            ),
            "events_loaded": (
                len(events)
            ),
            "evidence_records": (
                len(evidence_map)
            ),
            "ground_truth_records": (
                len(ground_truth_map)
            ),
            "scenarios": (
                len(scenario_map)
            ),
        },
        "original": {
            key: value
            for key, value in original.items()
            if key != "event_results"
        },
        "profiles": {},
    }

    # DEGRADED CONDITIONS

    for profile in profiles:

        degraded = evaluate_condition(
            events,
            scenario_map,
            evidence_map,
            ground_truth_map,
            detection_engine,
            correlation_engine,
            trust_engine,
            trust_aware_engine,
            profile=profile,
        )

        comparison = compare_conditions(
            original,
            degraded
        )

        original_avg_trust = (
            original["average_trust_score"]
        )

        degraded_avg_trust = (
            degraded["average_trust_score"]
        )

        trust_reduction = round(
            original_avg_trust
            - degraded_avg_trust,
            2
        )

        results["profiles"][profile] = {
            "metrics": (
                degraded["metrics"]
            ),
            "confusion_matrix": (
                degraded["confusion_matrix"]
            ),
            "average_trust_score": (
                degraded[
                    "average_trust_score"
                ]
            ),
            "trust_reduction_from_original": (
                trust_reduction
            ),
            "decision_distribution": (
                degraded[
                    "decision_distribution"
                ]
            ),
            "impact": comparison,
        }

        print(profile)
        print("-" * 60)

        print(
            f"Average trust:      "
            f"{degraded['average_trust_score']:.2f}"
        )

        print(
            f"Trust reduction:    "
            f"{trust_reduction:.2f}"
        )

        print(
            f"Accuracy:           "
            f"{degraded['metrics']['accuracy']:.4f}"
        )

        print(
            f"Precision:          "
            f"{degraded['metrics']['precision']:.4f}"
        )

        print(
            f"Recall:             "
            f"{degraded['metrics']['recall']:.4f}"
        )

        print(
            f"F1 score:           "
            f"{degraded['metrics']['f1']:.4f}"
        )

        print(
            f"Changed decisions:  "
            f"{comparison['changed_decisions']}"
        )

        print(
            f"Threat-status changes: "
            f"{comparison['changed_threat_status']}"
        )

        print()

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=2
        )

    print("Result saved to:")
    print(OUTPUT_FILE)

    print()
    print("=" * 60)
    print("DEGRADED-EVIDENCE IMPACT BENCHMARK COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()