import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RESULTS_DIR = (
    PROJECT_ROOT
    / "data"
    / "benchmark"
    / "results"
)

OUTPUT_FILE = (
    RESULTS_DIR
    / "system_level_benchmark_report.json"
)


def load_result(filename):
    path = RESULTS_DIR / filename

    if not path.exists():
        raise FileNotFoundError(
            f"Required benchmark file was not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def percentage(value):
    return round(value * 100, 2)


def main():

    print("=" * 70)
    print("21.10.9 SYSTEM-LEVEL BENCHMARK CONSOLIDATION")
    print("=" * 70)

    # LOAD ALL BENCHMARK RESULTS

    baseline = load_result(
        "baseline_detection_results.json"
    )

    trust_aware = load_result(
        "trust_aware_detection_results.json"
    )

    comparison = load_result(
        "baseline_vs_trust_aware.json"
    )

    poisoned = load_result(
        "poisoned_evidence_results.json"
    )

    degraded = load_result(
        "degraded_evidence_impact_results.json"
    )

    api_performance = load_result(
        "api_performance_results.json"
    )

    scalability = load_result(
        "api_scalability_results.json"
    )

    reliability = load_result(
        "api_reliability_results.json"
    )

    # DETECTION PERFORMANCE

    baseline_metrics = (
        baseline["metrics"]
    )

    baseline_cm = (
        baseline["confusion_matrix"]
    )

    trust_metrics = (
        trust_aware["metrics"]
    )

    trust_cm = (
        trust_aware["confusion_matrix"]
    )

    improvement = (
        comparison["improvement"]
    )

    detection_performance = {

        "baseline": {
            "accuracy": baseline_metrics["accuracy"],
            "precision": baseline_metrics["precision"],
            "recall": baseline_metrics["recall"],
            "f1": baseline_metrics["f1"],

            "true_positive":
                baseline_cm["true_positive"],

            "true_negative":
                baseline_cm["true_negative"],

            "false_positive":
                baseline_cm["false_positive"],

            "false_negative":
                baseline_cm["false_negative"],
        },

        "trust_aware": {
            "accuracy": trust_metrics["accuracy"],
            "precision": trust_metrics["precision"],
            "recall": trust_metrics["recall"],
            "f1": trust_metrics["f1"],

            "true_positive":
                trust_cm["true_positive"],

            "true_negative":
                trust_cm["true_negative"],

            "false_positive":
                trust_cm["false_positive"],

            "false_negative":
                trust_cm["false_negative"],
        },

        "improvement": {
            "accuracy_percentage_points":
                improvement[
                    "accuracy_percentage_points"
                ],

            "precision_percentage_points":
                improvement[
                    "precision_percentage_points"
                ],

            "recall_percentage_points":
                improvement[
                    "recall_percentage_points"
                ],

            "f1_percentage_points":
                improvement[
                    "f1_percentage_points"
                ],

            "additional_true_positives":
                improvement[
                    "additional_true_positives"
                ],

            "false_negative_reduction":
                improvement[
                    "false_negative_reduction"
                ],
        },
    }

    # POISONED EVIDENCE

    poisoned_stats = (
        poisoned[
            "poisoned_evidence"
        ][
            "statistics"
        ]
    )

    clean_stats = (
        poisoned[
            "clean_evidence"
        ][
            "statistics"
        ]
    )

    poisoned_summary = {

        "total_evidence":
            poisoned[
                "dataset"
            ][
                "total_evidence"
            ],

        "poisoned_evidence":
            poisoned[
                "dataset"
            ][
                "poisoned_evidence"
            ],

        "clean_evidence":
            poisoned[
                "dataset"
            ][
                "clean_evidence"
            ],

        "poison_type_distribution":
            poisoned[
                "dataset"
            ][
                "poison_type_distribution"
            ],

        "poisoned_average_trust":
            poisoned_stats[
                "average_trust_score"
            ],

        "poisoned_minimum_trust":
            poisoned_stats[
                "minimum_trust_score"
            ],

        "poisoned_maximum_trust":
            poisoned_stats[
                "maximum_trust_score"
            ],

        "poisoned_downgraded_below_high":
            poisoned[
                "poisoned_evidence"
            ][
                "records_downgraded_below_high"
            ],

        "clean_average_trust":
            clean_stats[
                "average_trust_score"
            ],

        "clean_minimum_trust":
            clean_stats[
                "minimum_trust_score"
            ],

        "clean_maximum_trust":
            clean_stats[
                "maximum_trust_score"
            ],

        "trust_difference":
            poisoned[
                "trust_difference"
            ][
                "clean_minus_poisoned"
            ],
    }

    # DEGRADED EVIDENCE

    degraded_profiles = {}

    for profile, result in (
        degraded["profiles"].items()
    ):

        degraded_profiles[profile] = {

            "average_trust_score":
                result[
                    "average_trust_score"
                ],

            "trust_reduction":
                result[
                    "trust_reduction_from_original"
                ],

            "accuracy":
                result[
                    "metrics"
                ][
                    "accuracy"
                ],

            "precision":
                result[
                    "metrics"
                ][
                    "precision"
                ],

            "recall":
                result[
                    "metrics"
                ][
                    "recall"
                ],

            "f1":
                result[
                    "metrics"
                ][
                    "f1"
                ],

            "changed_decisions":
                result[
                    "impact"
                ][
                    "changed_decisions"
                ],

            "changed_threat_status":
                result[
                    "impact"
                ][
                    "changed_threat_status"
                ],

            "decision_transitions":
                result[
                    "impact"
                ][
                    "decision_transitions"
                ],
        }

    # API PERFORMANCE

    performance_summary = {}

    for endpoint, result in (
        api_performance[
            "endpoints"
        ].items()
    ):

        latency = (
            result["latency_ms"]
        )

        performance_summary[endpoint] = {

            "success_rate_percent":
                result[
                    "success_rate_percent"
                ],

            "average_latency_ms":
                latency["average"],

            "median_latency_ms":
                latency["median"],

            "p95_latency_ms":
                latency["p95"],

            "maximum_latency_ms":
                latency["maximum"],
        }

    # SCALABILITY

    scalability_summary = {}

    for endpoint, endpoint_data in (
        scalability[
            "endpoints"
        ].items()
    ):

        scalability_summary[endpoint] = {}

        levels = (
            endpoint_data[
                "concurrency_levels"
            ]
        )

        for concurrency, result in (
            levels.items()
        ):

            scalability_summary[endpoint][
                concurrency
            ] = {

                "success_rate_percent":
                    result[
                        "success_rate_percent"
                    ],

                "average_latency_ms":
                    result[
                        "latency_ms"
                    ][
                        "average"
                    ],

                "p95_latency_ms":
                    result[
                        "latency_ms"
                    ][
                        "p95"
                    ],

                "throughput_requests_per_second":
                    result[
                        "throughput_requests_per_second"
                    ],
            }

    # RELIABILITY

    reliability_summary = {

        "total_requests":
            reliability[
                "overall"
            ][
                "total_requests"
            ],

        "successful_requests":
            reliability[
                "overall"
            ][
                "successful_requests"
            ],

        "failed_requests":
            reliability[
                "overall"
            ][
                "failed_requests"
            ],

        "success_rate_percent":
            reliability[
                "overall"
            ][
                "success_rate_percent"
            ],

        "benchmark_duration_seconds":
            reliability[
                "overall"
            ][
                "benchmark_duration_seconds"
            ],
    }

    reliability_endpoints = {}

    for endpoint, result in (
        reliability[
            "endpoints"
        ].items()
    ):

        reliability_endpoints[endpoint] = {

            "success_rate_percent":
                result[
                    "success_rate_percent"
                ],

            "average_latency_ms":
                result[
                    "latency_ms"
                ][
                    "average"
                ],

            "p95_latency_ms":
                result[
                    "latency_ms"
                ][
                    "p95"
                ],

            "latency_drift_ms":
                result[
                    "latency_drift"
                ][
                    "average_difference_ms"
                ],

            "latency_drift_percent":
                result[
                    "latency_drift"
                ][
                    "average_change_percent"
                ],
        }

    # KNOWN SYSTEM FINDINGS

    findings = [
        {
            "finding":
                "Trust-aware detection substantially improved "
                "attack detection on the benchmark dataset.",
            "evidence": (
                "Recall increased from "
                f"{percentage(baseline_metrics['recall']):.2f}% "
                "to "
                f"{percentage(trust_metrics['recall']):.2f}%."
            ),
        },

        {
            "finding":
                "Trust-aware detection reduced false negatives "
                "on the evaluated benchmark events.",
            "evidence": (
                f"False negatives decreased from "
                f"{baseline_cm['false_negative']} "
                f"to "
                f"{trust_cm['false_negative']}."
            ),
        },

        {
            "finding":
                "Poisoned evidence received lower trust than "
                "clean evidence.",
            "evidence": (
                f"Average poisoned trust was "
                f"{poisoned_stats['average_trust_score']}, "
                f"compared with "
                f"{clean_stats['average_trust_score']} "
                "for clean evidence."
            ),
        },

        {
            "finding":
                "The unified-events endpoint showed higher "
                "latency under concurrent load.",
            "evidence":
                (
                    "The scalability benchmark recorded "
                    "increasing latency as concurrency increased."
                ),
        },

        {
            "finding":
                "The dashboard summary endpoint is the main "
                "measured API latency bottleneck.",
            "evidence":
                (
                    "Its average latency was substantially higher "
                    "than the other tested endpoints."
                ),
        },

        {
            "finding":
                "The API remained reliable under the tested "
                "sequential and concurrent workloads.",
            "evidence": (
                "All measured scalability and reliability "
                "requests succeeded."
            ),
        },
    ]

    # LIMITATIONS

    limitations = [

        "The benchmark dataset is synthetic data generated locally.",

        "The results do not establish performance on unseen "
        "real-world healthcare data.",

        "The trust-aware and scenario-correlation rules were "
        "developed around the generated attack scenarios.",

        "The 100% trust-aware detection result should therefore "
        "not be interpreted as guaranteed generalisation.",

        "API measurements were performed on the local "
        "development environment rather than production "
        "cloud infrastructure.",

        "The dashboard summary endpoint exhibited substantially "
        "higher latency than the other measured endpoints.",
    ]

    # CONSOLIDATED REPORT

    report = {

        "benchmark":
            "21.10_system_level_benchmark",

        "status":
            "completed",

        "benchmark_components": {
            "21.10.1":
                "baseline_detection",

            "21.10.2":
                "trust_aware_detection",

            "21.10.3":
                "baseline_vs_trust_aware",

            "21.10.4":
                "poisoned_evidence_resistance",

            "21.10.5":
                "degraded_evidence_impact",

            "21.10.6":
                "api_performance",

            "21.10.7":
                "api_scalability",

            "21.10.8":
                "api_reliability",
        },

        "detection_performance":
            detection_performance,

        "poisoned_evidence":
            poisoned_summary,

        "degraded_evidence":
            degraded_profiles,

        "api_performance":
            performance_summary,

        "api_scalability":
            scalability_summary,

        "api_reliability": {
            "overall":
                reliability_summary,

            "endpoints":
                reliability_endpoints,
        },

        "findings":
            findings,

        "limitations":
            limitations,
    }

    # SAVE

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
            report,
            file,
            indent=2
        )

    # CONSOLE SUMMARY

    print()
    print("Benchmark components loaded:")
    print("-" * 70)

    for code, name in (
        report[
            "benchmark_components"
        ].items()
    ):

        print(
            f"{code}: {name}"
        )

    print()

    print("Detection Performance")
    print("-" * 70)

    print(
        f"Baseline accuracy:   "
        f"{percentage(baseline_metrics['accuracy']):.2f}%"
    )

    print(
        f"Baseline recall:     "
        f"{percentage(baseline_metrics['recall']):.2f}%"
    )

    print(
        f"Baseline F1:         "
        f"{percentage(baseline_metrics['f1']):.2f}%"
    )

    print(
        f"Trust-aware accuracy:"
        f" "
        f"{percentage(trust_metrics['accuracy']):.2f}%"
    )

    print(
        f"Trust-aware recall:  "
        f"{percentage(trust_metrics['recall']):.2f}%"
    )

    print(
        f"Trust-aware F1:      "
        f"{percentage(trust_metrics['f1']):.2f}%"
    )

    print()

    print("Poisoned Evidence")
    print("-" * 70)

    print(
        f"Poisoned records:    "
        f"{poisoned_summary['poisoned_evidence']}"
    )

    print(
        f"Average poison trust:"
        f" "
        f"{poisoned_summary['poisoned_average_trust']:.2f}"
    )

    print(
        f"Average clean trust: "
        f"{poisoned_summary['clean_average_trust']:.2f}"
    )

    print(
        f"Trust difference:    "
        f"{poisoned_summary['trust_difference']:.2f}"
    )

    print()

    print("Reliability")
    print("-" * 70)

    print(
        f"Total requests:     "
        f"{reliability_summary['total_requests']}"
    )

    print(
        f"Successful:         "
        f"{reliability_summary['successful_requests']}"
    )

    print(
        f"Failed:             "
        f"{reliability_summary['failed_requests']}"
    )

    print(
        f"Success rate:       "
        f"{reliability_summary['success_rate_percent']:.2f}%"
    )

    print()

    print("Result saved to:")
    print(OUTPUT_FILE)

    print()
    print("=" * 70)
    print("SYSTEM-LEVEL BENCHMARK CONSOLIDATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
