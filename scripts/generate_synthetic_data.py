import csv
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path


# CONFIGURATION

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

RANDOM_SEED = 42

random.seed(RANDOM_SEED)


# HELPER FUNCTIONS

def generate_id(prefix):
    """Create a unique ID such as USER-a12b34."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def random_timestamp(start_date, end_date):
    """Generate a random timestamp between two dates."""
    total_seconds = int((end_date - start_date).total_seconds())
    random_seconds = random.randint(0, total_seconds)

    timestamp = start_date + timedelta(seconds=random_seconds)

    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def write_csv(file_path, rows, fieldnames):
    """Write a list of dictionaries to a CSV file."""

    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(rows)

    print(f"Created: {file_path}")


# SYNTHETIC USERS

def generate_users(number_of_users=50):

    users = []

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

    for _ in range(number_of_users):

        user_id = generate_id("USER")

        users.append({
            "user_id": user_id,
            "department": random.choice(departments),
            "role": random.choice(roles)
        })

    return users


# SYNTHETIC DEVICES

def generate_devices(number_of_devices=30):

    devices = []

    device_types = [
        "workstation",
        "laptop",
        "server",
        "medical_device"
    ]

    for _ in range(number_of_devices):

        device_id = generate_id("DEVICE")

        devices.append({
            "device_id": device_id,
            "device_type": random.choice(device_types)
        })

    return devices


# IDENTITY EVENTS

def generate_identity_events(users, devices, number_of_events=1000):

    events = []

    start_date = datetime(2026, 8, 1)
    end_date = datetime(2026, 8, 7)

    event_types = [
        "login",
        "logout",
        "failed_login",
        "password_change",
        "privilege_change"
    ]

    for _ in range(number_of_events):

        user = random.choice(users)
        device = random.choice(devices)

        event_type = random.choice(event_types)

        success = True

        if event_type == "failed_login":
            success = False

        events.append({
            "event_id": generate_id("IDENTITY"),
            "timestamp": random_timestamp(start_date, end_date),
            "user_id": user["user_id"],
            "device_id": device["device_id"],
            "event_type": event_type,
            "source_ip": f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}",
            "success": success,
            "scenario": "normal"
        })

    return events


# ENDPOINT EVENTS

def generate_endpoint_events(users, devices, number_of_events=1000):

    events = []

    start_date = datetime(2026, 8, 1)
    end_date = datetime(2026, 8, 7)

    event_types = [
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

    for _ in range(number_of_events):

        user = random.choice(users)
        device = random.choice(devices)

        events.append({
            "event_id": generate_id("ENDPOINT"),
            "timestamp": random_timestamp(start_date, end_date),
            "user_id": user["user_id"],
            "device_id": device["device_id"],
            "event_type": random.choice(event_types),
            "process": random.choice(processes),
            "scenario": "normal"
        })

    return events


# NETWORK EVENTS

def generate_network_events(users, devices, number_of_events=1000):

    events = []

    start_date = datetime(2026, 8, 1)
    end_date = datetime(2026, 8, 7)

    for _ in range(number_of_events):

        user = random.choice(users)
        device = random.choice(devices)

        bytes_out = random.randint(500, 100000)

        events.append({
            "event_id": generate_id("NETWORK"),
            "timestamp": random_timestamp(start_date, end_date),
            "user_id": user["user_id"],
            "device_id": device["device_id"],
            "source_ip": f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}",
            "destination_ip": f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}",
            "bytes_out": bytes_out,
            "protocol": random.choice(["HTTPS", "TCP", "DNS"]),
            "scenario": "normal"
        })

    return events


# SYNTHETIC EHR EVENTS

def generate_ehr_events(users, number_of_events=500):

    events = []

    start_date = datetime(2026, 8, 1)
    end_date = datetime(2026, 8, 7)

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

    for _ in range(number_of_events):

        user = random.choice(users)

        events.append({
            "event_id": generate_id("EHR"),
            "timestamp": random_timestamp(start_date, end_date),
            "patient_id": generate_id("PATIENT"),
            "user_id": user["user_id"],
            "resource_type": random.choice(resource_types),
            "action": random.choice(actions),
            "scenario": "normal"
        })

    return events

# GROUND TRUTH

def generate_ground_truth(identity_events, endpoint_events, network_events, ehr_events):

    rows = []

    for event in identity_events:

        rows.append({
            "event_id": event["event_id"],
            "event_source": "identity",
            "label": "normal",
            "attack_type": "none"
        })

    for event in endpoint_events:

        rows.append({
            "event_id": event["event_id"],
            "event_source": "endpoint",
            "label": "normal",
            "attack_type": "none"
        })

    for event in network_events:

        rows.append({
            "event_id": event["event_id"],
            "event_source": "network",
            "label": "normal",
            "attack_type": "none"
        })

    for event in ehr_events:

        rows.append({
            "event_id": event["event_id"],
            "event_source": "ehr",
            "label": "normal",
            "attack_type": "none"
        })

    return rows


# MAIN PROGRAM

def main():

    print("=" * 60)
    print("HEALTHCARE CYBERSECURITY SYNTHETIC DATA GENERATOR")
    print("=" * 60)

    print("\nGenerating users...")
    users = generate_users()

    print(f"Generated {len(users)} users.")

    print("\nGenerating devices...")
    devices = generate_devices()

    print(f"Generated {len(devices)} devices.")

    print("\nGenerating identity events...")
    identity_events = generate_identity_events(users, devices)

    print(f"Generated {len(identity_events)} identity events.")

    print("\nGenerating endpoint events...")
    endpoint_events = generate_endpoint_events(users, devices)

    print(f"Generated {len(endpoint_events)} endpoint events.")

    print("\nGenerating network events...")
    network_events = generate_network_events(users, devices)

    print(f"Generated {len(network_events)} network events.")

    print("\nGenerating EHR events...")
    ehr_events = generate_ehr_events(users)

    print(f"Generated {len(ehr_events)} EHR events.")

    print("\nGenerating ground truth...")
    ground_truth = generate_ground_truth(
        identity_events,
        endpoint_events,
        network_events,
        ehr_events
    )

    # SAVE RAW DATA

    raw_dir = DATA_DIR / "raw"

    write_csv(
        raw_dir / "users.csv",
        users,
        ["user_id", "department", "role"]
    )

    write_csv(
        raw_dir / "devices.csv",
        devices,
        ["device_id", "device_type"]
    )

    write_csv(
        raw_dir / "identity_events.csv",
        identity_events,
        [
            "event_id",
            "timestamp",
            "user_id",
            "device_id",
            "event_type",
            "source_ip",
            "success",
            "scenario"
        ]
    )

    write_csv(
        raw_dir / "endpoint_events.csv",
        endpoint_events,
        [
            "event_id",
            "timestamp",
            "user_id",
            "device_id",
            "event_type",
            "process",
            "scenario"
        ]
    )

    write_csv(
        raw_dir / "network_events.csv",
        network_events,
        [
            "event_id",
            "timestamp",
            "user_id",
            "device_id",
            "source_ip",
            "destination_ip",
            "bytes_out",
            "protocol",
            "scenario"
        ]
    )

    write_csv(
        raw_dir / "ehr_events.csv",
        ehr_events,
        [
            "event_id",
            "timestamp",
            "patient_id",
            "user_id",
            "resource_type",
            "action",
            "scenario"
        ]
    )

    write_csv(
        raw_dir / "ground_truth.csv",
        ground_truth,
        [
            "event_id",
            "event_source",
            "label",
            "attack_type"
        ]
    )

    print("\n" + "=" * 60)
    print("DATA GENERATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()