import json
from collections import Counter
from pathlib import Path

from Backend.app.trust.trust_engine import TrustEngine

from scripts.benchmark.benchmark_loader import (
    validate_benchmark_dataset,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RESULTS_DIR = (
    PROJECT_ROOT
    / "data"
    / "benchmark"
    / "results"
)

OUTPUT_FILE = (
    RESULTS_DIR
    / "poisoned_evidence_results.json"
)


def classify_trust_score(score):
    """Classify a trust score using the TrustEngine thresholds."""

    if score >= 90:
        return "high"

    if score >= 70:
        return "medium"

    return "low"


def calculate_group_statistics(records):
    """Calculate descriptive statistics for an evidence group."""

    if not records:
        return {
            "count": 0,
            "average_trust_score": 0,
            "minimum_trust_score": 0,
            "maximum_trust_score": 0,
            "trust_levels": {},
        }

    scores = [
        record["trust_score"]
        for record in records
    ]

    levels = Counter(
        record["trust_level"]
        for record in records
    )

    return {
        "count": len(records),
        "average_trust_score": round(
            sum(scores) / len(scores),
            2,
        ),
        "minimum_trust_score": min(scores),
        "maximum_trust_score": max(scores),
        "trust_levels": dict(levels),
    }


def main():

    print("=" * 60)
    print("23.6 POISONED-EVIDENCE RESISTANCE BENCHMARK")
    print("=" * 60)

    dataset = validate_benchmark_dataset()

    metadata = dataset["metadata"]
    evidence_records = dataset["evidence"]

    trust_engine = TrustEngine()

    poisoned_records = []
    clean_records = []

    poison_type_counts = Counter()

    downgraded_poisoned = 0
    high_trust_poisoned = 0

    for evidence in evidence_records:

        # The TrustEngine sees only observable evidence-quality
        # attributes. Evaluation labels remain separate.
        trust_result = trust_engine.evaluate(
            evidence
        )

        record = {
            "evidence_id": evidence.evidence_id,
            "event_id": evidence.event_id,
            "scenario_id": evidence.scenario_id,
            "source_type": evidence.source_type,
            "is_poisoned": bool(
                evidence.is_poisoned
            ),
            "poison_type": evidence.poison_type,
            "trust_score": trust_result.trust_score,
            "trust_level": classify_trust_score(
                trust_result.trust_score
            ),
            "provenance": evidence.provenance,
            "integrity_status": (
                evidence.integrity_status
            ),
            "freshness_status": (
                evidence.freshness_status
            ),
            "consistency_status": (
                evidence.consistency_status
            ),
        }

        if evidence.is_poisoned:

            poisoned_records.append(record)

            poison_type_counts[
                evidence.poison_type
            ] += 1

            if trust_result.trust_score < 90:
                downgraded_poisoned += 1
            else:
                high_trust_poisoned += 1

        else:

            clean_records.append(record)

    poisoned_stats = calculate_group_statistics(
        poisoned_records
    )

    clean_stats = calculate_group_statistics(
        clean_records
    )

    trust_difference = round(
        clean_stats["average_trust_score"]
        - poisoned_stats["average_trust_score"],
        2,
    )

    results = {
        "benchmark": (
            "poisoned_evidence_resistance"
        ),
        "dataset": {
            "version": metadata["dataset_version"],
            "split": metadata["split"],
            "random_seed": metadata["random_seed"],
            "total_evidence": len(evidence_records),
            "poisoned_evidence": len(
                poisoned_records
            ),
            "clean_evidence": len(
                clean_records
            ),
            "poison_type_distribution": (
                dict(poison_type_counts)
            ),
        },
        "poisoned_evidence": {
            "statistics": poisoned_stats,
            "records_downgraded_below_high": (
                downgraded_poisoned
            ),
            "records_remaining_high_trust": (
                high_trust_poisoned
            ),
        },
        "clean_evidence": {
            "statistics": clean_stats,
        },
        "trust_difference": {
            "clean_minus_poisoned": (
                trust_difference
            ),
        },
        "records": poisoned_records,
    }

    print()
    print("Dataset")
    print("-" * 60)
    print(
        f"Dataset version:      "
        f"{metadata['dataset_version']}"
    )
    print(
        f"Split:                "
        f"{metadata['split']}"
    )
    print(
        f"Total evidence:       "
        f"{len(evidence_records)}"
    )
    print(
        f"Poisoned evidence:    "
        f"{len(poisoned_records)}"
    )
    print(
        f"Clean evidence:       "
        f"{len(clean_records)}"
    )
    print()

    print("Poison Types")
    print("-" * 60)

    for poison_type, count in sorted(
        poison_type_counts.items()
    ):
        print(
            f"{poison_type}: {count}"
        )

    print()

    print("Poisoned Evidence Trust")
    print("-" * 60)
    print(
        f"Average trust score:   "
        f"{poisoned_stats['average_trust_score']:.2f}"
    )
    print(
        f"Minimum trust score:   "
        f"{poisoned_stats['minimum_trust_score']:.2f}"
    )
    print(
        f"Maximum trust score:   "
        f"{poisoned_stats['maximum_trust_score']:.2f}"
    )
    print()
    print(
        f"Downgraded below high: "
        f"{downgraded_poisoned}"
    )
    print(
        f"Remaining high trust:  "
        f"{high_trust_poisoned}"
    )

    print()

    print("Clean Evidence Trust")
    print("-" * 60)
    print(
        f"Average trust score:   "
        f"{clean_stats['average_trust_score']:.2f}"
    )
    print(
        f"Minimum trust score:   "
        f"{clean_stats['minimum_trust_score']:.2f}"
    )
    print(
        f"Maximum trust score:   "
        f"{clean_stats['maximum_trust_score']:.2f}"
    )

    print()

    print("Trust Difference")
    print("-" * 60)
    print(
        f"Clean average - poisoned average: "
        f"{trust_difference:.2f}"
    )

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

    print()
    print("Result saved to:")
    print(OUTPUT_FILE)
    print()
    print("=" * 60)
    print("POISONED-EVIDENCE BENCHMARK COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()