import csv
import json
import random
from pathlib import Path
from collections import Counter


# CONFIGURATION

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"

RANDOM_SEED = 42

random.seed(RANDOM_SEED)


# CSV HELPERS

def read_csv(file_path):
    """Read a CSV file and return a list of dictionaries."""

    with open(
        file_path,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        return list(csv.DictReader(file))


def write_csv(file_path, rows):
    """Write rows to a CSV file."""

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if not rows:
        print(f"WARNING: No rows to write to {file_path}")
        return

    fieldnames = list(rows[0].keys())

    with open(
        file_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)

    print(f"Created: {file_path}")


# LOAD RAW DATA

def load_raw_data():

    print("\nLoading raw datasets...")

    identity = read_csv(
        RAW_DIR / "identity_events.csv"
    )

    endpoint = read_csv(
        RAW_DIR / "endpoint_events.csv"
    )

    network = read_csv(
        RAW_DIR / "network_events.csv"
    )

    ehr = read_csv(
        RAW_DIR / "ehr_events.csv"
    )

    evidence = read_csv(
        RAW_DIR / "security_evidence.csv"
    )

    ground_truth = read_csv(
        RAW_DIR / "ground_truth.csv"
    )

    print(f"Identity events: {len(identity)}")
    print(f"Endpoint events: {len(endpoint)}")
    print(f"Network events: {len(network)}")
    print(f"EHR events: {len(ehr)}")
    print(f"Evidence records: {len(evidence)}")
    print(f"Ground-truth records: {len(ground_truth)}")

    return {
        "identity": identity,
        "endpoint": endpoint,
        "network": network,
        "ehr": ehr,
        "evidence": evidence,
        "ground_truth": ground_truth
    }

# CREATE SCENARIO SPLIT

def create_scenario_split(data):

    print("\nCreating reproducible scenario split...")

    attack_scenarios = set()

    for event_type in [
        "identity",
        "endpoint",
        "network",
        "ehr"
    ]:

        for event in data[event_type]:

            scenario_id = event["scenario_id"]

            if scenario_id != "NORMAL":
                attack_scenarios.add(scenario_id)

    attack_scenarios = sorted(attack_scenarios)

    print(
        f"Found {len(attack_scenarios)} attack scenarios."
    )

    random.shuffle(attack_scenarios)

    total = len(attack_scenarios)

    development_end = round(total * 0.60)
    validation_end = round(total * 0.80)

    development = set(
        attack_scenarios[:development_end]
    )

    validation = set(
        attack_scenarios[
            development_end:validation_end
        ]
    )

    benchmark = set(
        attack_scenarios[validation_end:]
    )

    print("\nAttack scenario allocation:")

    print(
        f"Development: {len(development)} scenarios"
    )

    print(
        f"Validation:  {len(validation)} scenarios"
    )

    print(
        f"Benchmark:   {len(benchmark)} scenarios"
    )

    return {
        "development": development,
        "validation": validation,
        "benchmark": benchmark
    }


# SPLIT NORMAL EVENTS

def split_normal_events(data):

    print("\nDistributing normal events across all datasets...")

    normal_split = {
        "development": {},
        "validation": {},
        "benchmark": {}
    }

    for event_type in [
        "identity",
        "endpoint",
        "network",
        "ehr"
    ]:

        normal_events = [
            event
            for event in data[event_type]
            if event["scenario_id"] == "NORMAL"
        ]

        random.shuffle(normal_events)

        total = len(normal_events)

        development_end = round(total * 0.60)
        validation_end = round(total * 0.80)

        normal_split["development"][event_type] = (
            normal_events[:development_end]
        )

        normal_split["validation"][event_type] = (
            normal_events[
                development_end:validation_end
            ]
        )

        normal_split["benchmark"][event_type] = (
            normal_events[validation_end:]
        )

        print(
            f"{event_type}: "
            f"{len(normal_split['development'][event_type])} development, "
            f"{len(normal_split['validation'][event_type])} validation, "
            f"{len(normal_split['benchmark'][event_type])} benchmark"
        )

    return normal_split

# ASSIGN EVENTS TO SPLITS

def create_event_splits(data, scenario_splits):

    print("\nCreating event-level datasets...")

    normal_events = split_normal_events(data)

    splits = {
        "development": {
            "identity": [],
            "endpoint": [],
            "network": [],
            "ehr": []
        },
        "validation": {
            "identity": [],
            "endpoint": [],
            "network": [],
            "ehr": []
        },
        "benchmark": {
            "identity": [],
            "endpoint": [],
            "network": [],
            "ehr": []
        }
    }

    event_types = [
        "identity",
        "endpoint",
        "network",
        "ehr"
    ]

    for event_type in event_types:

        # Add normal events
        for split_name in splits:

            splits[split_name][event_type].extend(
                normal_events[split_name][event_type]
            )

        # Add attack events
        for event in data[event_type]:

            scenario_id = event["scenario_id"]

            if scenario_id == "NORMAL":
                continue

            for split_name, scenarios in scenario_splits.items():

                if scenario_id in scenarios:

                    splits[split_name][event_type].append(
                        event
                    )

                    break

    return splits

# ADD EVIDENCE AND GROUND TRUTH

def attach_supporting_data(
    data,
    event_splits
):

    print("\nAttaching evidence and ground truth...")

    final_splits = {}

    for split_name, dataset in event_splits.items():

        event_ids = set()

        for event_type in [
            "identity",
            "endpoint",
            "network",
            "ehr"
        ]:

            for event in dataset[event_type]:

                event_ids.add(event["event_id"])

        evidence = [
            item
            for item in data["evidence"]
            if item["event_id"] in event_ids
        ]

        ground_truth = [
            item
            for item in data["ground_truth"]
            if item["event_id"] in event_ids
        ]

        final_splits[split_name] = {
            **dataset,
            "evidence": evidence,
            "ground_truth": ground_truth
        }

        print(
            f"{split_name}: "
            f"{len(event_ids)} events, "
            f"{len(evidence)} evidence records, "
            f"{len(ground_truth)} ground-truth records"
        )

    return final_splits

# DATASET STATISTICS

def calculate_statistics(dataset):

    statistics = {}

    total_events = 0
    attack_events = 0
    normal_events = 0

    attack_types = Counter()

    for event_type in [
        "identity",
        "endpoint",
        "network",
        "ehr"
    ]:

        events = dataset[event_type]

        total_events += len(events)

        for event in events:

            if event["label"] == "attack":

                attack_events += 1

                attack_types[
                    event["attack_type"]
                ] += 1

            else:

                normal_events += 1

    poisoned = sum(
        1
        for item in dataset["evidence"]
        if item["is_poisoned"].lower() == "true"
    )

    statistics["total_events"] = total_events
    statistics["normal_events"] = normal_events
    statistics["attack_events"] = attack_events
    statistics["poisoned_evidence"] = poisoned
    statistics["evidence_records"] = len(
        dataset["evidence"]
    )
    statistics["ground_truth_records"] = len(
        dataset["ground_truth"]
    )
    statistics["attack_types"] = dict(
        attack_types
    )

    return statistics

# SAVE DATASET

def save_split(
    split_name,
    dataset
):

    output_dir = DATA_DIR / split_name

    print(
        f"\nSaving {split_name.upper()} dataset..."
    )

    # Event datasets

    write_csv(
        output_dir / "identity_events.csv",
        dataset["identity"]
    )

    write_csv(
        output_dir / "endpoint_events.csv",
        dataset["endpoint"]
    )

    write_csv(
        output_dir / "network_events.csv",
        dataset["network"]
    )

    write_csv(
        output_dir / "ehr_events.csv",
        dataset["ehr"]
    )

    # Evidence

    write_csv(
        output_dir / "security_evidence.csv",
        dataset["evidence"]
    )

    # Ground truth

    write_csv(
        output_dir / "ground_truth.csv",
        dataset["ground_truth"]
    )

    # Metadata

    statistics = calculate_statistics(
        dataset
    )

    metadata = {
        "dataset_version": "2.1",
        "random_seed": RANDOM_SEED,
        "split": split_name,
        "purpose": (
            "Synthetic healthcare cybersecurity "
            "research dataset"
        ),
        "data_source": (
            "Synthetic data generated locally; "
            "no real patient data"
        ),
        "statistics": statistics
    }

    metadata_file = (
        output_dir / "dataset_metadata.json"
    )

    with open(
        metadata_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metadata,
            file,
            indent=4
        )

    print(
        f"Created: {metadata_file}"
    )

# VALIDATE SPLITS

def validate_dataset(splits):

    print("\n")
    print("=" * 70)
    print("DATASET VALIDATION")
    print("=" * 70)

    overall_valid = True

    for split_name, dataset in splits.items():

        print(
            f"\nChecking {split_name.upper()}..."
        )

        event_ids = set()

        for event_type in [
            "identity",
            "endpoint",
            "network",
            "ehr"
        ]:

            for event in dataset[event_type]:

                event_ids.add(
                    event["event_id"]
                )

        evidence_ids = {
            item["event_id"]
            for item in dataset["evidence"]
        }

        truth_ids = {
            item["event_id"]
            for item in dataset["ground_truth"]
        }

        # Check evidence references

        missing_evidence = (
            event_ids - evidence_ids
        )

        if missing_evidence:

            print(
                f"WARNING: {len(missing_evidence)} "
                f"events have no evidence record."
            )

            overall_valid = False

        else:

            print(
                "PASS: Every event has an evidence record."
            )

        # Check ground truth

        missing_truth = (
            event_ids - truth_ids
        )

        if missing_truth:

            print(
                f"WARNING: {len(missing_truth)} "
                f"events have no ground-truth record."
            )

            overall_valid = False

        else:

            print(
                "PASS: Every event has a ground-truth record."
            )

        # Check duplicate event IDs

        total_event_rows = sum(
            len(dataset[event_type])
            for event_type in [
                "identity",
                "endpoint",
                "network",
                "ehr"
            ]
        )

        if len(event_ids) != total_event_rows:

            print(
                "WARNING: Duplicate event IDs detected."
            )

            overall_valid = False

        else:

            print(
                "PASS: Event IDs are unique."
            )

        # Statistics

        statistics = calculate_statistics(
            dataset
        )

        print(
            f"Total events:       "
            f"{statistics['total_events']}"
        )

        print(
            f"Normal events:      "
            f"{statistics['normal_events']}"
        )

        print(
            f"Attack events:      "
            f"{statistics['attack_events']}"
        )

        print(
            f"Evidence records:   "
            f"{statistics['evidence_records']}"
        )

        print(
            f"Poisoned evidence:  "
            f"{statistics['poisoned_evidence']}"
        )

    print("\n" + "=" * 70)

    if overall_valid:

        print(
            "DATASET VALIDATION PASSED"
        )

    else:

        print(
            "DATASET VALIDATION FOUND PROBLEMS"
        )

    print("=" * 70)

    return overall_valid

# MAIN

def main():

    print("=" * 70)
    print("HEALTHCARE CYBERSECURITY DATA PREPARATION - VERSION 2.1")
    print("=" * 70)

    data = load_raw_data()

    scenario_splits = create_scenario_split(
        data
    )

    event_splits = create_event_splits(
        data,
        scenario_splits
    )

    final_splits = attach_supporting_data(
        data,
        event_splits
    )

    valid = validate_dataset(
        final_splits
    )

    if not valid:

        print(
            "\nDataset preparation stopped because "
            "validation found problems."
        )

        return

    print("\nSaving validated datasets...")

    for split_name, dataset in final_splits.items():

        save_split(
            split_name,
            dataset
        )

    print("\n")
    print("=" * 70)
    print("VERSION 2.1 DATASET PREPARATION COMPLETE")
    print("=" * 70)

    print("\nCreated datasets:")

    for split_name in [
        "development",
        "validation",
        "benchmark"
    ]:

        statistics = calculate_statistics(
            final_splits[split_name]
        )

        print(
            f"\n{split_name.upper()}"
        )

        print(
            f"  Total events: "
            f"{statistics['total_events']}"
        )

        print(
            f"  Normal events: "
            f"{statistics['normal_events']}"
        )

        print(
            f"  Attack events: "
            f"{statistics['attack_events']}"
        )

        print(
            f"  Evidence: "
            f"{statistics['evidence_records']}"
        )

        print(
            f"  Ground truth: "
            f"{statistics['ground_truth_records']}"
        )

        print(
            f"  Poisoned evidence: "
            f"{statistics['poisoned_evidence']}"
        )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()