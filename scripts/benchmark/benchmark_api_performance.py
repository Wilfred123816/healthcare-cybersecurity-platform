import json
import statistics
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# PROJECT PATHS

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RESULTS_DIR = (
    PROJECT_ROOT
    / "data"
    / "benchmark"
    / "results"
)

OUTPUT_FILE = (
    RESULTS_DIR
    / "api_performance_results.json"
)

# CONFIGURATION

BASE_URL = "http://127.0.0.1:8000"

REQUESTS_PER_ENDPOINT = 30
WARMUP_REQUESTS = 3

TIMEOUT_SECONDS = 15

KNOWN_EVENT_ID = "EHR-000001f9"
KNOWN_SCENARIO_ID = "SCENARIO-005"


ENDPOINTS = {
    "health": "/api/health",

    "dashboard_summary":
        "/api/dashboard/summary",

    "unified_events":
        "/api/unified/events",

    "detection":
        f"/api/detection/event/{KNOWN_EVENT_ID}",

    "trust_aware_detection":
        f"/api/trust-aware/event/{KNOWN_EVENT_ID}",

    "investigation":
        f"/api/investigation/scenario/{KNOWN_SCENARIO_ID}",

    "attack_path":
        f"/api/investigation/scenario/"
        f"{KNOWN_SCENARIO_ID}/attack-path",
}

# HTTP REQUEST

def perform_request(path):
    """
    Perform one GET request and return:
        success, status_code, elapsed_ms, error
    """

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

            status_code = response.status

            success = (
                200 <= status_code < 300
            )

            return (
                success,
                status_code,
                elapsed_ms,
                None,
            )

    except HTTPError as error:

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        return (
            False,
            error.code,
            elapsed_ms,
            f"HTTP {error.code}: {error.reason}",
        )

    except URLError as error:

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        return (
            False,
            None,
            elapsed_ms,
            f"URL error: {error.reason}",
        )

    except Exception as error:

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        return (
            False,
            None,
            elapsed_ms,
            str(error),
        )
# PERCENTILE
def percentile(values, percentile_value):
    """
    Calculate a simple percentile using linear interpolation.
    """

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

# ENDPOINT BENCHMARK

def benchmark_endpoint(name, path):

    print("=" * 60)
    print(f"ENDPOINT: {name}")
    print(f"PATH:     {path}")
    print("=" * 60)

    # WARM-UP

    print(
        f"Warm-up requests: {WARMUP_REQUESTS}"
    )

    for _ in range(WARMUP_REQUESTS):
        perform_request(path)

    # MEASURED REQUESTS

    latencies = []
    status_codes = []
    errors = []

    successful_requests = 0
    failed_requests = 0

    print(
        f"Measured requests: {REQUESTS_PER_ENDPOINT}"
    )

    for _ in range(REQUESTS_PER_ENDPOINT):

        (
            success,
            status_code,
            elapsed_ms,
            error,
        ) = perform_request(path)

        latencies.append(
            elapsed_ms
        )

        status_codes.append(
            status_code
        )

        if success:

            successful_requests += 1

        else:

            failed_requests += 1

            if error:
                errors.append(error)

    # STATISTICS

    average_ms = (
        statistics.mean(latencies)
        if latencies
        else 0
    )

    median_ms = (
        statistics.median(latencies)
        if latencies
        else 0
    )

    minimum_ms = (
        min(latencies)
        if latencies
        else 0
    )

    maximum_ms = (
        max(latencies)
        if latencies
        else 0
    )

    p95_ms = percentile(
        latencies,
        95
    )

    success_rate = (
        successful_requests
        / REQUESTS_PER_ENDPOINT
        * 100
        if REQUESTS_PER_ENDPOINT
        else 0
    )

    result = {
        "path": path,
        "requests": REQUESTS_PER_ENDPOINT,

        "successful_requests":
            successful_requests,

        "failed_requests":
            failed_requests,

        "success_rate_percent":
            round(success_rate, 2),

        "latency_ms": {
            "minimum":
                round(minimum_ms, 2),

            "average":
                round(average_ms, 2),

            "median":
                round(median_ms, 2),

            "p95":
                round(p95_ms, 2),

            "maximum":
                round(maximum_ms, 2),
        },

        "status_codes":
            dict(
                (
                    str(code),
                    status_codes.count(code)
                )
                for code in set(status_codes)
            ),

        "errors": errors[:5],
    }

    # DISPLAY

    print()
    print(
        f"Successful:        "
        f"{successful_requests}"
    )

    print(
        f"Failed:            "
        f"{failed_requests}"
    )

    print(
        f"Success rate:      "
        f"{success_rate:.2f}%"
    )

    print()
    print("Latency")
    print("-" * 60)

    print(
        f"Minimum:           "
        f"{minimum_ms:.2f} ms"
    )

    print(
        f"Average:           "
        f"{average_ms:.2f} ms"
    )

    print(
        f"Median:            "
        f"{median_ms:.2f} ms"
    )

    print(
        f"P95:               "
        f"{p95_ms:.2f} ms"
    )

    print(
        f"Maximum:           "
        f"{maximum_ms:.2f} ms"
    )

    if errors:

        print()
        print("Sample errors")
        print("-" * 60)

        for error in errors:
            print(error)

    print()

    return result

# MAIN

def main():

    print()
    print("=" * 60)
    print("21.10.6 API PERFORMANCE BENCHMARK")
    print("=" * 60)
    print()

    print(
        f"Base URL:           {BASE_URL}"
    )

    print(
        f"Requests/endpoint:  "
        f"{REQUESTS_PER_ENDPOINT}"
    )

    print(
        f"Warm-up/endpoint:   "
        f"{WARMUP_REQUESTS}"
    )

    print()

    results = {}

    benchmark_start = time.perf_counter()

    for name, path in ENDPOINTS.items():

        results[name] = benchmark_endpoint(
            name,
            path
        )

    total_benchmark_time = (
        time.perf_counter()
        - benchmark_start
    )

    # OVERALL SUMMARY

    total_requests = sum(
        result["requests"]
        for result in results.values()
    )

    total_successful = sum(
        result["successful_requests"]
        for result in results.values()
    )

    total_failed = sum(
        result["failed_requests"]
        for result in results.values()
    )

    overall_success_rate = (
        total_successful
        / total_requests
        * 100
        if total_requests
        else 0
    )

    all_latency_values = []

    for result in results.values():

        latency_result = result["latency_ms"]

        all_latency_values.extend(
            [
                latency_result["minimum"],
                latency_result["maximum"],
                latency_result["average"],
            ]
        )

    benchmark_results = {
        "benchmark":
            "api_performance",

        "configuration": {
            "base_url":
                BASE_URL,

            "requests_per_endpoint":
                REQUESTS_PER_ENDPOINT,

            "warmup_requests":
                WARMUP_REQUESTS,

            "timeout_seconds":
                TIMEOUT_SECONDS,
        },

        "endpoints":
            results,

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
                    total_benchmark_time,
                    2
                ),
        },
    }

    # DISPLAY SUMMARY

    print("=" * 60)
    print("OVERALL API PERFORMANCE SUMMARY")
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
        f"Overall success:    "
        f"{overall_success_rate:.2f}%"
    )

    print(
        f"Benchmark duration: "
        f"{total_benchmark_time:.2f} s"
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
            benchmark_results,
            file,
            indent=2
        )

    print(
        "Result saved to:"
    )

    print(OUTPUT_FILE)

    print()
    print("=" * 60)
    print("API PERFORMANCE BENCHMARK COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
