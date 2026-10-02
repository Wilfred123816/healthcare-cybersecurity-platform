import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    / "api_scalability_results.json"
)

BASE_URL = "http://127.0.0.1:8000"

REQUESTS_PER_LEVEL = 20

TIMEOUT_SECONDS = 30

CONCURRENCY_LEVELS = [
    1,
    5,
    10,
]

ENDPOINTS = {
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
                f"URL error: "
                f"{error.reason}"
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


def run_load_test(path, concurrency):

    results = []

    start = time.perf_counter()

    with ThreadPoolExecutor(
        max_workers=concurrency
    ) as executor:

        futures = [
            executor.submit(
                perform_request,
                path
            )
            for _ in range(REQUESTS_PER_LEVEL)
        ]

        for future in as_completed(
            futures
        ):

            results.append(
                future.result()
            )

    total_duration = (
        time.perf_counter()
        - start
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

    average = (
        statistics.mean(latencies)
        if latencies
        else 0
    )

    median = (
        statistics.median(latencies)
        if latencies
        else 0
    )

    minimum = (
        min(latencies)
        if latencies
        else 0
    )

    maximum = (
        max(latencies)
        if latencies
        else 0
    )

    p95 = percentile(
        latencies,
        95
    )

    success_rate = (
        successful
        / len(results)
        * 100
        if results
        else 0
    )

    throughput = (
        len(results)
        / total_duration
        if total_duration > 0
        else 0
    )

    return {
        "concurrency": concurrency,

        "requests": len(results),

        "successful_requests":
            successful,

        "failed_requests":
            failed,

        "success_rate_percent":
            round(success_rate, 2),

        "latency_ms": {
            "minimum":
                round(minimum, 2),

            "average":
                round(average, 2),

            "median":
                round(median, 2),

            "p95":
                round(p95, 2),

            "maximum":
                round(maximum, 2),
        },

        "throughput_requests_per_second":
            round(throughput, 2),

        "duration_seconds":
            round(
                total_duration,
                2
            ),
    }


def main():

    print("=" * 60)
    print("21.10.7 API SCALABILITY BENCHMARK")
    print("=" * 60)

    print()
    print(
        f"Requests per level: "
        f"{REQUESTS_PER_LEVEL}"
    )

    print(
        f"Concurrency levels: "
        f"{CONCURRENCY_LEVELS}"
    )

    print()

    benchmark_start = time.perf_counter()

    all_results = {}

    for name, path in ENDPOINTS.items():

        print("=" * 60)
        print(f"ENDPOINT: {name}")
        print(f"PATH:     {path}")
        print("=" * 60)

        endpoint_results = {}

        for concurrency in CONCURRENCY_LEVELS:

            print(
                f"Testing concurrency "
                f"level: {concurrency}"
            )

            result = run_load_test(
                path,
                concurrency
            )

            endpoint_results[
                str(concurrency)
            ] = result

            print(
                f"  Success: "
                f"{result['success_rate_percent']:.2f}%"
            )

            print(
                f"  Average: "
                f"{result['latency_ms']['average']:.2f} ms"
            )

            print(
                f"  Median: "
                f"{result['latency_ms']['median']:.2f} ms"
            )

            print(
                f"  P95: "
                f"{result['latency_ms']['p95']:.2f} ms"
            )

            print(
                f"  Throughput: "
                f"{result['throughput_requests_per_second']:.2f} req/s"
            )

            print()

        all_results[name] = {
            "path": path,
            "concurrency_levels":
                endpoint_results,
        }

    duration = (
        time.perf_counter()
        - benchmark_start
    )

    results = {
        "benchmark":
            "api_scalability",

        "configuration": {
            "base_url": BASE_URL,
            "requests_per_level":
                REQUESTS_PER_LEVEL,
            "concurrency_levels":
                CONCURRENCY_LEVELS,
            "timeout_seconds":
                TIMEOUT_SECONDS,
        },

        "endpoints":
            all_results,

        "benchmark_duration_seconds":
            round(duration, 2),
    }

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

    print("=" * 60)
    print("SCALABILITY BENCHMARK COMPLETE")
    print("=" * 60)

    print()
    print(
        "Result saved to:"
    )

    print(OUTPUT_FILE)

    print()


if __name__ == "__main__":
    main()
