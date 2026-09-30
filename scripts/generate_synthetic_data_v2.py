import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


# CONFIGURATION

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# Deterministic ID counters.
# Each prefix gets its own counter so that generated IDs are
# reproducible without consuming values from the seeded random stream.
ID_COUNTERS = {}

START_DATE = datetime(2026, 8, 1)
END_DATE = datetime(2026, 8, 7)


# HELPER FUNCTIONS

def generate_id(prefix):
    """Generate a deterministic, unique ID for the current dataset run."""

    ID_COUNTERS[prefix] = (
        ID_COUNTERS.get(prefix, 0) + 1
    )

    return f"{prefix}-{ID_COUNTERS[prefix]:08x}"


def write_csv(file_path, rows, fieldnames):
    """Write rows to a CSV file."""

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

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


def timestamp_for(
    base_time,
    minutes_after=0
):
    """Create a timestamp a certain number of minutes after base_time."""

    value = (
        base_time
        + timedelta(minutes=minutes_after)
    )

    return value.strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def random_base_time():
    """Generate a random starting time for a scenario."""

    total_seconds = int(
        (
            END_DATE - START_DATE
        ).total_seconds()
    )

    random_seconds = random.randint(
        0,
        total_seconds
    )

    return (
        START_DATE
        + timedelta(seconds=random_seconds)
    )


# USERS

def generate_users(
    number_of_users=50
):

    departments = [
        "Emergency",
        "Radiology",
        "Pharmacy",
        "Cardiology",
        "Laboratory",
        "Administration",
        "IT"
    ]

    roles = [
        "doctor",
        "nurse",
        "technician",
        "administrator",
        "analyst"
    ]

    users = []

    for _ in range(number_of_users):

        users.append({
            "user_id": generate_id("USER"),
            "department": random.choice(
                departments
            ),
            "role": random.choice(
                roles
            )
        })

    return users


# DEVICES

def generate_devices(
    number_of_devices=30
):

    device_types = [
        "workstation",
        "laptop",
        "server",
        "medical_device"
    ]

    devices = []

    for _ in range(number_of_devices):

        devices.append({
            "device_id": generate_id(
                "DEVICE"
            ),
            "device_type": random.choice(
                device_types
            )
        })

    return devices


# NORMAL EVENTS

def generate_normal_events(
    users,
    devices
):

    identity_events = []
    endpoint_events = []
    network_events = []
    ehr_events = []

    identity_types = [
        "login",
        "logout",
        "failed_login",
        "password_change"
    ]

    endpoint_types = [
        "process_start",
        "file_access",
        "file_modify",
        "login",
        "software_update"
    ]

    processes = [
        "browser",
        "ehr_client",
        "office",
        "email_client",
        "system_service"
    ]

    resource_types = [
        "Patient",
        "Observation",
        "MedicationRequest",
        "Encounter",
        "DiagnosticReport"
    ]

    actions = [
        "read",
        "create",
        "update"
    ]

    # Identity

    for _ in range(1000):

        user = random.choice(users)
        device = random.choice(devices)

        event_type = random.choice(
            identity_types
        )

        success = True

        if event_type == "failed_login":
            success = False

        identity_events.append({
            "event_id": generate_id(
                "IDENTITY"
            ),
            "scenario_id": "NORMAL",
            "timestamp": timestamp_for(
                random_base_time()
            ),
            "user_id": user["user_id"],
            "device_id": device["device_id"],
            "event_type": event_type,
            "source_ip": (
                f"10.0.{random.randint(1, 10)}."
                f"{random.randint(1, 254)}"
            ),
            "success": success,
            "label": "normal",
            "attack_type": "none"
        })

    # Endpoint

    for _ in range(1000):

        user = random.choice(users)
        device = random.choice(devices)

        endpoint_events.append({
            "event_id": generate_id(
                "ENDPOINT"
            ),
            "scenario_id": "NORMAL",
            "timestamp": timestamp_for(
                random_base_time()
            ),
            "user_id": user["user_id"],
            "device_id": device["device_id"],
            "event_type": random.choice(
                endpoint_types
            ),
            "process": random.choice(
                processes
            ),
            "label": "normal",
            "attack_type": "none"
        })

    # Network

    for _ in range(1000):

        user = random.choice(users)
        device = random.choice(devices)

        network_events.append({
            "event_id": generate_id(
                "NETWORK"
            ),
            "scenario_id": "NORMAL",
            "timestamp": timestamp_for(
                random_base_time()
            ),
            "user_id": user["user_id"],
            "device_id": device["device_id"],
            "source_ip": (
                f"10.0.{random.randint(1, 10)}."
                f"{random.randint(1, 254)}"
            ),
            "destination_ip": (
                f"10.0.{random.randint(1, 10)}."
                f"{random.randint(1, 254)}"
            ),
            "bytes_out": random.randint(
                500,
                100000
            ),
            "protocol": random.choice(
                ["HTTPS", "TCP", "DNS"]
            ),
            "label": "normal",
            "attack_type": "none"
        })

    # EHR

    for _ in range(500):

        user = random.choice(users)

        ehr_events.append({
            "event_id": generate_id(
                "EHR"
            ),
            "scenario_id": "NORMAL",
            "timestamp": timestamp_for(
                random_base_time()
            ),
            "patient_id": generate_id(
                "PATIENT"
            ),
            "user_id": user["user_id"],
            "resource_type": random.choice(
                resource_types
            ),
            "action": random.choice(
                actions
            ),
            "label": "normal",
            "attack_type": "none"
        })

    return (
        identity_events,
        endpoint_events,
        network_events,
        ehr_events
    )


# CREDENTIAL ABUSE SCENARIOS

def create_credential_abuse_scenario(
    scenario_id,
    user,
    device
):

    base_time = random_base_time()

    events = {
        "identity": [],
        "endpoint": [],
        "network": [],
        "ehr": []
    }

    source_ip = "198.51.100.25"

    # Failed login 1
    events["identity"].append({
        "event_id": generate_id(
            "IDENTITY"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            0
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "failed_login",
        "source_ip": source_ip,
        "success": False,
        "label": "attack",
        "attack_type": "credential_abuse"
    })

    # Failed login 2
    events["identity"].append({
        "event_id": generate_id(
            "IDENTITY"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            1
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "failed_login",
        "source_ip": source_ip,
        "success": False,
        "label": "attack",
        "attack_type": "credential_abuse"
    })

    # Successful login
    events["identity"].append({
        "event_id": generate_id(
            "IDENTITY"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            2
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "login",
        "source_ip": source_ip,
        "success": True,
        "label": "attack",
        "attack_type": "credential_abuse"
    })

    # Privilege escalation
    events["identity"].append({
        "event_id": generate_id(
            "IDENTITY"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            4
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "privilege_change",
        "source_ip": source_ip,
        "success": True,
        "label": "attack",
        "attack_type": "credential_abuse"
    })

    # Endpoint activity
    events["endpoint"].append({
        "event_id": generate_id(
            "ENDPOINT"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            5
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "suspicious_process",
        "process": "unknown_process",
        "label": "attack",
        "attack_type": "credential_abuse"
    })

    # EHR access
    events["ehr"].append({
        "event_id": generate_id(
            "EHR"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            7
        ),
        "patient_id": generate_id(
            "PATIENT"
        ),
        "user_id": user["user_id"],
        "resource_type": "Patient",
        "action": "read",
        "label": "attack",
        "attack_type": "credential_abuse"
    })

    return events


# RANSOMWARE SCENARIOS

def create_ransomware_scenario(
    scenario_id,
    user,
    device
):

    base_time = random_base_time()

    events = {
        "identity": [],
        "endpoint": [],
        "network": [],
        "ehr": []
    }

    source_ip = "198.51.100.50"

    # Suspicious login
    events["identity"].append({
        "event_id": generate_id(
            "IDENTITY"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            0
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "login",
        "source_ip": source_ip,
        "success": True,
        "label": "attack",
        "attack_type": "ransomware"
    })

    # Suspicious process
    events["endpoint"].append({
        "event_id": generate_id(
            "ENDPOINT"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            3
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "suspicious_process",
        "process": "file_encryption_process",
        "label": "attack",
        "attack_type": "ransomware"
    })

    # Multiple file modifications
    for minute in [4, 5, 6]:

        events["endpoint"].append({
            "event_id": generate_id(
                "ENDPOINT"
            ),
            "scenario_id": scenario_id,
            "timestamp": timestamp_for(
                base_time,
                minute
            ),
            "user_id": user["user_id"],
            "device_id": device["device_id"],
            "event_type": "mass_file_modify",
            "process": "file_encryption_process",
            "label": "attack",
            "attack_type": "ransomware"
        })

    # Network communication
    events["network"].append({
        "event_id": generate_id(
            "NETWORK"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            8
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "source_ip": "10.0.1.20",
        "destination_ip": "203.0.113.40",
        "bytes_out": 250000,
        "protocol": "HTTPS",
        "label": "attack",
        "attack_type": "ransomware"
    })

    return events


# DATA EXFILTRATION SCENARIOS

def create_exfiltration_scenario(
    scenario_id,
    user,
    device
):

    base_time = random_base_time()

    events = {
        "identity": [],
        "endpoint": [],
        "network": [],
        "ehr": []
    }

    # Login
    events["identity"].append({
        "event_id": generate_id(
            "IDENTITY"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            0
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "login",
        "source_ip": "198.51.100.75",
        "success": True,
        "label": "attack",
        "attack_type": "data_exfiltration"
    })

    # EHR access
    for minute in [2, 3, 4]:

        events["ehr"].append({
            "event_id": generate_id(
                "EHR"
            ),
            "scenario_id": scenario_id,
            "timestamp": timestamp_for(
                base_time,
                minute
            ),
            "patient_id": generate_id(
                "PATIENT"
            ),
            "user_id": user["user_id"],
            "resource_type": random.choice(
                [
                    "Patient",
                    "Observation",
                    "DiagnosticReport"
                ]
            ),
            "action": "read",
            "label": "attack",
            "attack_type": "data_exfiltration"
        })

    # Large outbound transfer
    events["network"].append({
        "event_id": generate_id(
            "NETWORK"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            6
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "source_ip": "10.0.2.20",
        "destination_ip": "203.0.113.80",
        "bytes_out": 50000000,
        "protocol": "HTTPS",
        "label": "attack",
        "attack_type": "data_exfiltration"
    })

    return events


# PRIVILEGE ABUSE SCENARIOS

def create_privilege_abuse_scenario(
    scenario_id,
    user,
    device
):

    base_time = random_base_time()

    events = {
        "identity": [],
        "endpoint": [],
        "network": [],
        "ehr": []
    }

    events["identity"].append({
        "event_id": generate_id(
            "IDENTITY"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            0
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "login",
        "source_ip": "198.51.100.90",
        "success": True,
        "label": "attack",
        "attack_type": "privilege_abuse"
    })

    events["identity"].append({
        "event_id": generate_id(
            "IDENTITY"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            2
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "privilege_change",
        "source_ip": "198.51.100.90",
        "success": True,
        "label": "attack",
        "attack_type": "privilege_abuse"
    })

    events["endpoint"].append({
        "event_id": generate_id(
            "ENDPOINT"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            4
        ),
        "user_id": user["user_id"],
        "device_id": device["device_id"],
        "event_type": "privileged_activity",
        "process": "admin_tool",
        "label": "attack",
        "attack_type": "privilege_abuse"
    })

    events["ehr"].append({
        "event_id": generate_id(
            "EHR"
        ),
        "scenario_id": scenario_id,
        "timestamp": timestamp_for(
            base_time,
            6
        ),
        "patient_id": generate_id(
            "PATIENT"
        ),
        "user_id": user["user_id"],
        "resource_type": "DiagnosticReport",
        "action": "update",
        "label": "attack",
        "attack_type": "privilege_abuse"
    })

    return events


# MERGE SCENARIO EVENTS

def add_scenario_events(
    scenario_events,
    identity_events,
    endpoint_events,
    network_events,
    ehr_events
):

    identity_events.extend(
        scenario_events["identity"]
    )

    endpoint_events.extend(
        scenario_events["endpoint"]
    )

    network_events.extend(
        scenario_events["network"]
    )

    ehr_events.extend(
        scenario_events["ehr"]
    )


# EVIDENCE RECORDS

def create_evidence_records(
    identity_events,
    endpoint_events,
    network_events,
    ehr_events
):

    evidence = []

    provenance_by_source = {
        "identity": "identity_provider",
        "endpoint": "endpoint_sensor",
        "network": "network_sensor",
        "ehr": "ehr_system"
    }

    all_events = []

    for event in identity_events:
        all_events.append(
            ("identity", event)
        )

    for event in endpoint_events:
        all_events.append(
            ("endpoint", event)
        )

    for event in network_events:
        all_events.append(
            ("network", event)
        )

    for event in ehr_events:
        all_events.append(
            ("ehr", event)
        )

    for source, event in all_events:

        evidence.append({
            "evidence_id": generate_id(
                "EVIDENCE"
            ),
            "event_id": event["event_id"],
            "scenario_id": event["scenario_id"],
            "source_type": source,
            "provenance": provenance_by_source[
                source
            ],
            "integrity_status": "valid",
            "freshness_status": "fresh",
            "consistency_status": "consistent",
            "is_poisoned": False,
            "poison_type": "none"
        })

    return evidence


# POISONED EVIDENCE

def create_poisoned_evidence(
    evidence,
    attack_event_ids
):

    poisoned_count = 0

    # Select approximately 20% of attack evidence
    attack_evidence = [
        item
        for item in evidence
        if item["event_id"] in attack_event_ids
    ]

    number_to_poison = max(
        1,
        int(
            len(attack_evidence) * 0.20
        )
    )

    selected = random.sample(
        attack_evidence,
        min(
            number_to_poison,
            len(attack_evidence)
        )
    )

    for item in selected:

        item["is_poisoned"] = True

        poison_type = random.choice([
            "incorrect_label",
            "stale_evidence",
            "integrity_failure",
            "provenance_issue"
        ])

        item["poison_type"] = poison_type

        if poison_type == "incorrect_label":

            item["consistency_status"] = (
                "inconsistent"
            )

        elif poison_type == "stale_evidence":

            item["freshness_status"] = (
                "stale"
            )

        elif poison_type == "integrity_failure":

            item["integrity_status"] = (
                "suspicious"
            )

        elif poison_type == "provenance_issue":

            item["provenance"] = "unknown"

        poisoned_count += 1

    return poisoned_count


# GROUND TRUTH

def create_ground_truth(
    identity_events,
    endpoint_events,
    network_events,
    ehr_events
):

    ground_truth = []

    all_events = []

    for event in identity_events:
        all_events.append(
            ("identity", event)
        )

    for event in endpoint_events:
        all_events.append(
            ("endpoint", event)
        )

    for event in network_events:
        all_events.append(
            ("network", event)
        )

    for event in ehr_events:
        all_events.append(
            ("ehr", event)
        )

    for source, event in all_events:

        ground_truth.append({
            "event_id": event["event_id"],
            "scenario_id": event["scenario_id"],
            "event_source": source,
            "label": event["label"],
            "attack_type": event["attack_type"]
        })

    return ground_truth


# DATASET SPLITTING

def split_events_by_scenario(
    identity_events,
    endpoint_events,
    network_events,
    ehr_events
):

    attack_scenarios = sorted({
        event["scenario_id"]
        for event in identity_events
        if event["scenario_id"] != "NORMAL"
    })

    random.shuffle(
        attack_scenarios
    )

    total = len(
        attack_scenarios
    )

    development_end = int(
        total * 0.60
    )

    validation_end = int(
        total * 0.80
    )

    development_scenarios = set(
        attack_scenarios[
            :development_end
        ]
    )

    validation_scenarios = set(
        attack_scenarios[
            development_end:validation_end
        ]
    )

    benchmark_scenarios = set(
        attack_scenarios[
            validation_end:
        ]
    )

    def get_split(event):

        scenario = event["scenario_id"]

        if scenario == "NORMAL":
            return "development"

        if scenario in development_scenarios:
            return "development"

        if scenario in validation_scenarios:
            return "validation"

        if scenario in benchmark_scenarios:
            return "benchmark"

        return "development"

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

    for event in identity_events:

        splits[
            get_split(event)
        ]["identity"].append(
            event
        )

    for event in endpoint_events:

        splits[
            get_split(event)
        ]["endpoint"].append(
            event
        )

    for event in network_events:

        splits[
            get_split(event)
        ]["network"].append(
            event
        )

    for event in ehr_events:

        splits[
            get_split(event)
        ]["ehr"].append(
            event
        )

    return splits


# SAVE DATASET

def save_dataset(
    directory,
    dataset
):

    directory.mkdir(
        parents=True,
        exist_ok=True
    )

    identity_fields = [
        "event_id",
        "scenario_id",
        "timestamp",
        "user_id",
        "device_id",
        "event_type",
        "source_ip",
        "success",
        "label",
        "attack_type"
    ]

    endpoint_fields = [
        "event_id",
        "scenario_id",
        "timestamp",
        "user_id",
        "device_id",
        "event_type",
        "process",
        "label",
        "attack_type"
    ]

    network_fields = [
        "event_id",
        "scenario_id",
        "timestamp",
        "user_id",
        "device_id",
        "source_ip",
        "destination_ip",
        "bytes_out",
        "protocol",
        "label",
        "attack_type"
    ]

    ehr_fields = [
        "event_id",
        "scenario_id",
        "timestamp",
        "patient_id",
        "user_id",
        "resource_type",
        "action",
        "label",
        "attack_type"
    ]

    write_csv(
        directory / "identity_events.csv",
        dataset["identity"],
        identity_fields
    )

    write_csv(
        directory / "endpoint_events.csv",
        dataset["endpoint"],
        endpoint_fields
    )

    write_csv(
        directory / "network_events.csv",
        dataset["network"],
        network_fields
    )

    write_csv(
        directory / "ehr_events.csv",
        dataset["ehr"],
        ehr_fields
    )


# MAIN

def main():

    print("=" * 70)
    print(
        "HEALTHCARE CYBERSECURITY "
        "SYNTHETIC DATA GENERATOR - VERSION 2"
    )
    print("=" * 70)

    # USERS AND DEVICES

    print("\nGenerating users...")

    users = generate_users(50)

    print(
        f"Generated {len(users)} users."
    )

    print("\nGenerating devices...")

    devices = generate_devices(30)

    print(
        f"Generated {len(devices)} devices."
    )

    # NORMAL EVENTS

    print(
        "\nGenerating normal activity..."
    )

    (
        identity_events,
        endpoint_events,
        network_events,
        ehr_events
    ) = generate_normal_events(
        users,
        devices
    )

    print(
        "Normal identity events: "
        f"{len(identity_events)}"
    )

    print(
        "Normal endpoint events: "
        f"{len(endpoint_events)}"
    )

    print(
        "Normal network events: "
        f"{len(network_events)}"
    )

    print(
        "Normal EHR events: "
        f"{len(ehr_events)}"
    )

    # ATTACK SCENARIOS

    print(
        "\nGenerating attack scenarios..."
    )

    scenario_number = 1

    # Credential abuse - 5 scenarios
    for _ in range(5):

        scenario_id = (
            f"SCENARIO-{scenario_number:03d}"
        )

        scenario_number += 1

        scenario = (
            create_credential_abuse_scenario(
                scenario_id,
                random.choice(users),
                random.choice(devices)
            )
        )

        add_scenario_events(
            scenario,
            identity_events,
            endpoint_events,
            network_events,
            ehr_events
        )

    # Ransomware - 5 scenarios
    for _ in range(5):

        scenario_id = (
            f"SCENARIO-{scenario_number:03d}"
        )

        scenario_number += 1

        scenario = (
            create_ransomware_scenario(
                scenario_id,
                random.choice(users),
                random.choice(devices)
            )
        )

        add_scenario_events(
            scenario,
            identity_events,
            endpoint_events,
            network_events,
            ehr_events
        )

    # Data exfiltration - 5 scenarios
    for _ in range(5):

        scenario_id = (
            f"SCENARIO-{scenario_number:03d}"
        )

        scenario_number += 1

        scenario = (
            create_exfiltration_scenario(
                scenario_id,
                random.choice(users),
                random.choice(devices)
            )
        )

        add_scenario_events(
            scenario,
            identity_events,
            endpoint_events,
            network_events,
            ehr_events
        )

    # Privilege abuse - 5 scenarios
    for _ in range(5):

        scenario_id = (
            f"SCENARIO-{scenario_number:03d}"
        )

        scenario_number += 1

        scenario = (
            create_privilege_abuse_scenario(
                scenario_id,
                random.choice(users),
                random.choice(devices)
            )
        )

        add_scenario_events(
            scenario,
            identity_events,
            endpoint_events,
            network_events,
            ehr_events
        )

    # COLLECT ATTACK EVENT IDS

    all_attack_events = (
        [
            event
            for event in identity_events
            if event["label"] == "attack"
        ]
        +
        [
            event
            for event in endpoint_events
            if event["label"] == "attack"
        ]
        +
        [
            event
            for event in network_events
            if event["label"] == "attack"
        ]
        +
        [
            event
            for event in ehr_events
            if event["label"] == "attack"
        ]
    )

    attack_event_ids = {
        event["event_id"]
        for event in all_attack_events
    }

    print(
        "Generated "
        f"{len(attack_event_ids)} "
        "attack-related events."
    )

    # GROUND TRUTH

    ground_truth = create_ground_truth(
        identity_events,
        endpoint_events,
        network_events,
        ehr_events
    )

    # EVIDENCE

    print(
        "\nGenerating security evidence..."
    )

    evidence = create_evidence_records(
        identity_events,
        endpoint_events,
        network_events,
        ehr_events
    )

    poisoned_count = (
        create_poisoned_evidence(
            evidence,
            attack_event_ids
        )
    )

    print(
        "Poisoned evidence records: "
        f"{poisoned_count}"
    )

    # SAVE RAW DATA

    raw_dir = DATA_DIR / "raw"

    print(
        "\nSaving raw datasets..."
    )

    write_csv(
        raw_dir / "users.csv",
        users,
        [
            "user_id",
            "department",
            "role"
        ]
    )

    write_csv(
        raw_dir / "devices.csv",
        devices,
        [
            "device_id",
            "device_type"
        ]
    )

    save_dataset(
        raw_dir,
        {
            "identity": identity_events,
            "endpoint": endpoint_events,
            "network": network_events,
            "ehr": ehr_events
        }
    )

    write_csv(
        raw_dir / "security_evidence.csv",
        evidence,
        [
            "evidence_id",
            "event_id",
            "scenario_id",
            "source_type",
            "provenance",
            "integrity_status",
            "freshness_status",
            "consistency_status",
            "is_poisoned",
            "poison_type"
        ]
    )

    write_csv(
        raw_dir / "ground_truth.csv",
        ground_truth,
        [
            "event_id",
            "scenario_id",
            "event_source",
            "label",
            "attack_type"
        ]
    )

    # SPLIT DATA

    print(
        "\nCreating "
        "development/validation/benchmark splits..."
    )

    splits = split_events_by_scenario(
        identity_events,
        endpoint_events,
        network_events,
        ehr_events
    )

    for split_name, dataset in splits.items():

        print(
            f"\nSaving {split_name.upper()} dataset..."
        )

        save_dataset(
            DATA_DIR / split_name,
            dataset
        )

    # SUMMARY

    print(
        "\n" + "=" * 70
    )

    print(
        "VERSION 2 DATA GENERATION COMPLETE"
    )

    print(
        "=" * 70
    )

    print("\nAttack scenarios:")

    print(
        "  Credential abuse:     5"
    )

    print(
        "  Ransomware:           5"
    )

    print(
        "  Data exfiltration:    5"
    )

    print(
        "  Privilege abuse:      5"
    )

    print(
        "  Total:               20"
    )

    print("\nDataset splits:")

    print(
        "  Development: 60% of attack scenarios"
    )

    print(
        "  Validation:  20% of attack scenarios"
    )

    print(
        "  Benchmark:   20% of attack scenarios"
    )

    print("\nRandom seed:")

    print(
        f"  {RANDOM_SEED}"
    )

    print(
        "\nDeterministic IDs:"
    )

    print(
        "  Enabled"
    )

    print(
        "\n" + "=" * 70
    )


if __name__ == "__main__":
    main()