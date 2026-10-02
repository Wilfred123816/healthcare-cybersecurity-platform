import json
import statistics
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RESULTS_DIR = (
    PROJECT_ROOT
    / "data"
    / "benchmark"
    / "results"
)

OUTPUT_FILE = (
    RESULTS_DIR
    / "api_reliability_results.json"
)

BASE_URL = "http://127.0.0.1:8000"

REQUESTS_PER_ENDPOINT = 50

TIMEOUT_SECONDS = 30

ENDPOINTS = {
    "health":
        "/api/health",

    "dashboard_summary":
        "/api/dashboard/summary",

    "unified_events":
        "/api/unified/events",

    "detection":
        "/api/detection/event/EHR-000001f9",

    "trust_aware_detection":
        "/api/trust-aware/event/EHR-000001f9",

    "investigation":
        "/api/investigation/scenario/SCENARIO-005",

    "attack_path":
        "/api/investigation/scenario/SCENARIO-005/attack-path",
}


def perform_request(path):
    url = BASE_URL + path

    request = Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
        },
    )

    start = time.perf_counter()

    try:
        with urlopen(
            request,
            timeout=TIMEOUT_SECONDS,
        ) as response:

            response.read()

            elapsed_ms = (
                time.perf_counter() - start
            ) * 1000

            return {
                "success": (
                    200
                    <= response.status
                    < 300
                ),
                "status_code": response.status,
                "latency_ms": elapsed_ms,
                "error": None,
            }

    except HTTPError as error:

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        return {
            "success": False,
            "status_code": error.code,
            "latency_ms": elapsed_ms,
            "error": (
                f"HTTP {error.code}: "
                f"{error.reason}"
            ),
        }

    except URLError as error:

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        return {
            "success": False,
            "status_code": None,
            "latency_ms": elapsed_ms,
            "error": (
                f"URL error: {error.reason}"
            ),
        }

    except Exception as error:

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        return {
            "success": False,
            "status_code": None,
            "latency_ms": elapsed_ms,
            "error": str(error),
        }


def percentile(values, percentile_value):

    if not values:
        return 0

    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    position = (
        (len(ordered) - 1)
        * percentile_value
        / 100
    )

    lower = int(position)
    upper = lower + 1

    if upper >= len(ordered):
        return ordered[lower]

    weight = position - lower

    return (
        ordered[lower]
        + weight
        * (
            ordered[upper]
            - ordered[lower]
        )
    )


def summarize_latencies(values):

    if not values:
        return {
            "minimum": 0,
            "average": 0,
            "median": 0,
            "p95": 0,
            "maximum": 0,
        }

    return {
        "minimum": round(
            min(values),
            2
        ),
        "average": round(
            statistics.mean(values),
            2
        ),
        "median": round(
            statistics.median(values),
            2
        ),
        "p95": round(
            percentile(values, 95),
            2
        ),
        "maximum": round(
            max(values),
            2
        ),
    }


def benchmark_endpoint(name, path):

    print("=" * 60)
    print(f"ENDPOINT: {name}")
    print(f"PATH:     {path}")
    print("=" * 60)

    results = []

    endpoint_start = time.perf_counter()

    for request_number in range(
        1,
        REQUESTS_PER_ENDPOINT + 1
    ):

        result = perform_request(
            path
        )

        result["request_number"] = (
            request_number
        )

        results.append(result)

    endpoint_duration = (
        time.perf_counter()
        - endpoint_start
    )

    latencies = [
        result["latency_ms"]
        for result in results
    ]

    successful = sum(
        result["success"]
        for result in results
    )

    failed = (
        len(results)
        - successful
    )

    success_rate = (
        successful
        / len(results)
        * 100
        if results
        else 0
    )

    # FIRST VS SECOND HALF

    midpoint = len(latencies) // 2

    first_half = latencies[:midpoint]
    second_half = latencies[midpoint:]

    first_half_summary = summarize_latencies(
        first_half
    )

    second_half_summary = summarize_latencies(
        second_half
    )

    # LATENCY DRIFT

    average_first = (
        first_half_summary["average"]
    )

    average_second = (
        second_half_summary["average"]
    )

    latency_drift_ms = round(
        average_second
        - average_first,
        2
    )

    if average_first > 0:

        latency_drift_percent = round(
            (
                (
                    average_second
                    - average_first
                )
                / average_first
            )
            * 100,
            2
        )

    else:
        latency_drift_percent = 0

    # ERROR DETAILS

    errors = [
        result["error"]
        for result in results
        if result["error"]
    ]

    status_codes = {}

    for result in results:

        code = result["status_code"]

        key = (
            str(code)
            if code is not None
            else "no_status"
        )

        status_codes[key] = (
            status_codes.get(key, 0)
            + 1
        )

    summary = {
        "path": path,

        "requests": len(results),

        "successful_requests":
            successful,

        "failed_requests":
            failed,

        "success_rate_percent":
            round(success_rate, 2),

        "latency_ms":
            summarize_latencies(latencies),

        "first_half": {
            "requests": len(first_half),
            "latency_ms":
                first_half_summary,
        },

        "second_half": {
            "requests": len(second_half),
            "latency_ms":
                second_half_summary,
        },

        "latency_drift": {
            "average_difference_ms":
                latency_drift_ms,

            "average_change_percent":
                latency_drift_percent,
        },

        "status_codes":
            status_codes,

        "errors":
            errors[:10],

        "duration_seconds":
            round(
                endpoint_duration,
                2
            ),
    }

    # DISPLAY

    print()

    print(
        f"Requests:          "
        f"{len(results)}"
    )

    print(
        f"Successful:        "
        f"{successful}"
    )

    print(
        f"Failed:            "
        f"{failed}"
    )

    print(
        f"Success rate:      "
        f"{success_rate:.2f}%"
    )

    print()

    print("Overall latency")
    print("-" * 60)

    overall = summary["latency_ms"]

    print(
        f"Minimum:           "
        f"{overall['minimum']:.2f} ms"
    )

    print(
        f"Average:           "
        f"{overall['average']:.2f} ms"
    )

    print(
        f"Median:            "
        f"{overall['median']:.2f} ms"
    )

    print(
        f"P95:               "
        f"{overall['p95']:.2f} ms"
    )

    print(
        f"Maximum:           "
        f"{overall['maximum']:.2f} ms"
    )

    print()

    print("Stability comparison")
    print("-" * 60)

    print(
        f"First-half average:  "
        f"{average_first:.2f} ms"
    )

    print(
        f"Second-half average: "
        f"{average_second:.2f} ms"
    )

    print(
        f"Latency drift:       "
        f"{latency_drift_ms:.2f} ms "
        f"({latency_drift_percent:.2f}%)"
    )

    if errors:

        print()

        print("Sample errors")
        print("-" * 60)

        for error in errors:
            print(error)

    print()

    return summary


def main():

    print()
    print("=" * 60)
    print("21.10.8 API RELIABILITY AND STABILITY BENCHMARK")
    print("=" * 60)

    print()

    print(
        f"Requests per endpoint: "
        f"{REQUESTS_PER_ENDPOINT}"
    )

    print(
        f"Total endpoints:        "
        f"{len(ENDPOINTS)}"
    )

    print(
        f"Expected total requests:"
        f" "
        f"{REQUESTS_PER_ENDPOINT * len(ENDPOINTS)}"
    )

    print()

    benchmark_start = time.perf_counter()

    endpoint_results = {}

    for name, path in ENDPOINTS.items():

        endpoint_results[name] = (
            benchmark_endpoint(
                name,
                path
            )
        )

    total_duration = (
        time.perf_counter()
        - benchmark_start
    )

    # OVERALL RESULTS

    total_requests = sum(
        result["requests"]
        for result in endpoint_results.values()
    )

    total_successful = sum(
        result["successful_requests"]
        for result in endpoint_results.values()
    )

    total_failed = (
        total_requests
        - total_successful
    )

    overall_success_rate = (
        total_successful
        / total_requests
        * 100
        if total_requests
        else 0
    )

    benchmark_result = {
        "benchmark":
            "api_reliability",

        "configuration": {
            "base_url":
                BASE_URL,

            "requests_per_endpoint":
                REQUESTS_PER_ENDPOINT,

            "timeout_seconds":
                TIMEOUT_SECONDS,

            "endpoints_tested":
                len(ENDPOINTS),
        },

        "endpoints":
            endpoint_results,

        "overall": {
            "total_requests":
                total_requests,

            "successful_requests":
                total_successful,

            "failed_requests":
                total_failed,

            "success_rate_percent":
                round(
                    overall_success_rate,
                    2
                ),

            "benchmark_duration_seconds":
                round(
                    total_duration,
                    2
                ),
        },
    }

    # OVERALL DISPLAY

    print("=" * 60)
    print("OVERALL RELIABILITY SUMMARY")
    print("=" * 60)

    print()

    print(
        f"Total requests:     "
        f"{total_requests}"
    )

    print(
        f"Successful:         "
        f"{total_successful}"
    )

    print(
        f"Failed:             "
        f"{total_failed}"
    )

    print(
        f"Success rate:       "
        f"{overall_success_rate:.2f}%"
    )

    print(
        f"Total duration:     "
        f"{total_duration:.2f} s"
    )

    print()

    # SAVE RESULTS

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
            benchmark_result,
            file,
            indent=2
        )

    print(
        "Result saved to:"
    )

    print(OUTPUT_FILE)

    print()
    print("=" * 60)
    print("RELIABILITY BENCHMARK COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
