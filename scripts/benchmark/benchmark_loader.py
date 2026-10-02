import csv
import json
from pathlib import Path
from types import SimpleNamespace


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = PROJECT_ROOT / "data" / "benchmark"


def _read_csv(filename):
    """Read a benchmark CSV file and return its rows."""

    path = BENCHMARK_DIR / filename

    if not path.exists():
        raise FileNotFoundError(
            f"Benchmark file not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8",
        newline=""
    ) as file:
        return list(csv.DictReader(file))


def _to_bool(value):
    """Convert a CSV boolean value into Python bool or None."""

    if value is None:
        return None

    normalized = str(value).strip().lower()

    if normalized in {
        "true",
        "1",
        "yes",
        "y",
    }:
        return True

    if normalized in {
        "false",
        "0",
        "no",
        "n",
    }:
        return False

    return None


def _to_int(value):
    """Convert a numeric CSV value into int or 0."""

    if value is None:
        return 0

    normalized = str(value).strip()

    if not normalized:
        return 0

    return int(float(normalized))


def _event_from_row(row, source_type):
    """
    Convert one benchmark CSV row into the common event
    representation expected by the detection engines.
    """

    data = {
        "event_id": row.get("event_id"),
        "scenario_id": row.get("scenario_id"),
        "timestamp": row.get("timestamp"),
        "source_type": source_type,
        "user_id": row.get("user_id"),
        "device_id": row.get("device_id"),
        "patient_id": row.get("patient_id"),
    }

    if source_type == "identity":
        data.update(
            {
                "event_type": row.get("event_type"),
                "source_ip": row.get("source_ip"),
                "success": _to_bool(
                    row.get("success")
                ),
            }
        )

    elif source_type == "endpoint":
        data.update(
            {
                "event_type": row.get("event_type"),
                "process": row.get("process"),
            }
        )

    elif source_type == "network":
        data.update(
            {
                "source_ip": row.get("source_ip"),
                "destination_ip": row.get(
                    "destination_ip"
                ),
                "bytes_out": _to_int(
                    row.get("bytes_out")
                ),
                "protocol": row.get("protocol"),
            }
        )

    elif source_type == "ehr":
        resource_type = row.get(
            "resource_type"
        )

        data.update(
            {
                "event_type": resource_type,
                "resource_type": resource_type,
                "action": row.get("action"),
            }
        )

    return SimpleNamespace(**data)


def load_events():
    """
    Load all benchmark events from the benchmark CSV files.

    The benchmark contains no database dependency.
    """

    events = []

    source_files = [
        ("identity_events.csv", "identity"),
        ("endpoint_events.csv", "endpoint"),
        ("network_events.csv", "network"),
        ("ehr_events.csv", "ehr"),
    ]

    for filename, source_type in source_files:

        rows = _read_csv(filename)

        for row in rows:
            events.append(
                _event_from_row(
                    row,
                    source_type
                )
            )

    # Stable ordering makes benchmark execution reproducible.
    events.sort(
        key=lambda event: (
            event.timestamp or "",
            event.event_id or "",
        )
    )

    return events


def load_evidence():
    """
    Load benchmark security evidence.

    Poisoning fields are retained for evaluation but are not
    interpreted by the TrustEngine.
    """

    rows = _read_csv(
        "security_evidence.csv"
    )

    evidence = []

    for row in rows:
        evidence.append(
            SimpleNamespace(
                evidence_id=row.get(
                    "evidence_id"
                ),
                event_id=row.get(
                    "event_id"
                ),
                scenario_id=row.get(
                    "scenario_id"
                ),
                source_type=row.get(
                    "source_type"
                ),
                provenance=row.get(
                    "provenance"
                ),
                integrity_status=row.get(
                    "integrity_status"
                ),
                freshness_status=row.get(
                    "freshness_status"
                ),
                consistency_status=row.get(
                    "consistency_status"
                ),
                is_poisoned=_to_bool(
                    row.get("is_poisoned")
                ),
                poison_type=row.get(
                    "poison_type"
                ),
            )
        )

    return evidence


def load_ground_truth():
    """Load benchmark ground-truth records."""

    rows = _read_csv(
        "ground_truth.csv"
    )

    return [
        SimpleNamespace(
            event_id=row.get(
                "event_id"
            ),
            scenario_id=row.get(
                "scenario_id"
            ),
            event_source=row.get(
                "event_source"
            ),
            label=row.get(
                "label"
            ),
            attack_type=row.get(
                "attack_type"
            ),
        )
        for row in rows
    ]


def load_ground_truth_map():
    """Return benchmark ground truth keyed by event ID."""

    return {
        row.event_id: row
        for row in load_ground_truth()
    }


def load_evidence_map():
    """Return benchmark evidence keyed by event ID."""

    return {
        row.event_id: row
        for row in load_evidence()
    }


def load_metadata():
    """Load benchmark dataset metadata."""

    path = (
        BENCHMARK_DIR
        / "dataset_metadata.json"
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Benchmark metadata not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def validate_benchmark_dataset():
    """
    Validate the benchmark dataset before running evaluation.
    """

    metadata = load_metadata()
    events = load_events()
    evidence = load_evidence()
    ground_truth = load_ground_truth()

    expected_total = metadata[
        "statistics"
    ]["total_events"]

    expected_normal = metadata[
        "statistics"
    ]["normal_events"]

    expected_attack = metadata[
        "statistics"
    ]["attack_events"]

    expected_poisoned = metadata[
        "statistics"
    ]["poisoned_evidence"]

    actual_normal = sum(
        1
        for row in ground_truth
        if row.label == "normal"
    )

    actual_attack = sum(
        1
        for row in ground_truth
        if row.label == "attack"
    )

    actual_poisoned = sum(
        1
        for row in evidence
        if row.is_poisoned
    )

    if len(events) != expected_total:
        raise ValueError(
            f"Benchmark event count mismatch: "
            f"{len(events)} != {expected_total}"
        )

    if len(evidence) != expected_total:
        raise ValueError(
            f"Benchmark evidence count mismatch: "
            f"{len(evidence)} != {expected_total}"
        )

    if len(ground_truth) != expected_total:
        raise ValueError(
            f"Benchmark ground-truth count mismatch: "
            f"{len(ground_truth)} != {expected_total}"
        )

    if actual_normal != expected_normal:
        raise ValueError(
            f"Benchmark normal count mismatch: "
            f"{actual_normal} != {expected_normal}"
        )

    if actual_attack != expected_attack:
        raise ValueError(
            f"Benchmark attack count mismatch: "
            f"{actual_attack} != {expected_attack}"
        )

    if actual_poisoned != expected_poisoned:
        raise ValueError(
            f"Benchmark poisoned-evidence count mismatch: "
            f"{actual_poisoned} != {expected_poisoned}"
        )

    event_ids = {
        event.event_id
        for event in events
    }

    evidence_ids = {
        row.event_id
        for row in evidence
    }

    truth_ids = {
        row.event_id
        for row in ground_truth
    }

    if event_ids != evidence_ids:
        raise ValueError(
            "Benchmark events and evidence "
            "do not contain the same event IDs."
        )

    if event_ids != truth_ids:
        raise ValueError(
            "Benchmark events and ground truth "
            "do not contain the same event IDs."
        )

    return {
        "metadata": metadata,
        "events": events,
        "evidence": evidence,
        "ground_truth": ground_truth,
    }