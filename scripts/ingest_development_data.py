import sys
from pathlib import Path

import pandas as pd
# PROJECT PATH

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# DATABASE IMPORTS

from sqlalchemy import delete

from Backend.app.database import SessionLocal

from Backend.app.models import (
    User,
    Device,
    IdentityEvent,
    EndpointEvent,
    NetworkEvent,
    EHREvent,
    SecurityEvidence,
    GroundTruth,
)
# DATA DIRECTORIES

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

DEVELOPMENT_DATA_DIR = (
    PROJECT_ROOT / "data" / "development"
)
# CSV LOADER

def load_csv(directory, filename):

    filepath = directory / filename

    if not filepath.exists():

        raise FileNotFoundError(
            f"Dataset file not found: {filepath}"
        )

    return pd.read_csv(filepath)

# MAIN INGESTION FUNCTION

def main():

    print("=" * 70)
    print("HEALTHCARE CYBERSECURITY DEVELOPMENT DATA INGESTION")
    print("=" * 70)

    print()
    print("Data sources:")
    print(f"Master data:       {RAW_DATA_DIR}")
    print(f"Development data:  {DEVELOPMENT_DATA_DIR}")
    # LOAD MASTER DATA

    print()
    print("Loading master data...")

    users_df = load_csv(
        RAW_DATA_DIR,
        "users.csv"
    )

    devices_df = load_csv(
        RAW_DATA_DIR,
        "devices.csv"
    )

    print(f"Users:              {len(users_df)}")
    print(f"Devices:            {len(devices_df)}")
    # LOAD DEVELOPMENT DATA

    print()
    print("Loading development datasets...")

    identity_df = load_csv(
        DEVELOPMENT_DATA_DIR,
        "identity_events.csv"
    )

    endpoint_df = load_csv(
        DEVELOPMENT_DATA_DIR,
        "endpoint_events.csv"
    )

    network_df = load_csv(
        DEVELOPMENT_DATA_DIR,
        "network_events.csv"
    )

    ehr_df = load_csv(
        DEVELOPMENT_DATA_DIR,
        "ehr_events.csv"
    )

    evidence_df = load_csv(
        DEVELOPMENT_DATA_DIR,
        "security_evidence.csv"
    )

    ground_truth_df = load_csv(
        DEVELOPMENT_DATA_DIR,
        "ground_truth.csv"
    )

    print(f"Identity events:     {len(identity_df)}")
    print(f"Endpoint events:     {len(endpoint_df)}")
    print(f"Network events:      {len(network_df)}")
    print(f"EHR events:          {len(ehr_df)}")
    print(f"Security evidence:   {len(evidence_df)}")
    print(f"Ground truth:        {len(ground_truth_df)}")
    # CONNECT TO DATABASE

    print()
    print("Connecting to PostgreSQL...")

    db = SessionLocal()

    try:
        # CLEAR EXISTING DATA

        print()
        print("Clearing existing database data...")

        db.execute(delete(SecurityEvidence))
        db.execute(delete(GroundTruth))
        db.execute(delete(EHREvent))
        db.execute(delete(NetworkEvent))
        db.execute(delete(EndpointEvent))
        db.execute(delete(IdentityEvent))
        db.execute(delete(Device))
        db.execute(delete(User))

        db.commit()

        print("Existing data cleared.")
        # USERS

        print()
        print("Inserting users...")

        for _, row in users_df.iterrows():

            user = User(
                user_id=row["user_id"],
                department=row["department"],
                role=row["role"],
            )

            db.add(user)

        db.commit()

        print(
            f"Inserted {len(users_df)} users."
        )
        # DEVICES

        print()
        print("Inserting devices...")

        for _, row in devices_df.iterrows():

            device = Device(
                device_id=row["device_id"],
                device_type=row["device_type"],
            )

            db.add(device)

        db.commit()

        print(
            f"Inserted {len(devices_df)} devices."
        )
        # IDENTITY EVENTS

        print()
        print("Inserting identity events...")

        for _, row in identity_df.iterrows():

            event = IdentityEvent(
                event_id=row["event_id"],
                scenario_id=row["scenario_id"],
                timestamp=pd.to_datetime(
                    row["timestamp"]
                ),
                user_id=row["user_id"],
                device_id=row["device_id"],
                event_type=row["event_type"],
                source_ip=row["source_ip"],
                success=bool(row["success"]),
                label=row["label"],
                attack_type=row["attack_type"],
            )

            db.add(event)

        db.commit()

        print(
            f"Inserted {len(identity_df)} identity events."
        )
        # ENDPOINT EVENTS

        print()
        print("Inserting endpoint events...")

        for _, row in endpoint_df.iterrows():

            event = EndpointEvent(
                event_id=row["event_id"],
                scenario_id=row["scenario_id"],
                timestamp=pd.to_datetime(
                    row["timestamp"]
                ),
                user_id=row["user_id"],
                device_id=row["device_id"],
                event_type=row["event_type"],
                process=row["process"],
                label=row["label"],
                attack_type=row["attack_type"],
            )

            db.add(event)

        db.commit()

        print(
            f"Inserted {len(endpoint_df)} endpoint events."
        )
        # NETWORK EVENTS

        print()
        print("Inserting network events...")

        for _, row in network_df.iterrows():

            event = NetworkEvent(
                event_id=row["event_id"],
                scenario_id=row["scenario_id"],
                timestamp=pd.to_datetime(
                    row["timestamp"]
                ),
                user_id=row["user_id"],
                device_id=row["device_id"],
                source_ip=row["source_ip"],
                destination_ip=row["destination_ip"],
                bytes_out=int(row["bytes_out"]),
                protocol=row["protocol"],
                label=row["label"],
                attack_type=row["attack_type"],
            )

            db.add(event)

        db.commit()

        print(
            f"Inserted {len(network_df)} network events."
        )
        # EHR EVENTS

        print()
        print("Inserting EHR events...")

        for _, row in ehr_df.iterrows():

            event = EHREvent(
                event_id=row["event_id"],
                scenario_id=row["scenario_id"],
                timestamp=pd.to_datetime(
                    row["timestamp"]
                ),
                patient_id=row["patient_id"],
                user_id=row["user_id"],
                resource_type=row["resource_type"],
                action=row["action"],
                label=row["label"],
                attack_type=row["attack_type"],
            )

            db.add(event)

        db.commit()

        print(
            f"Inserted {len(ehr_df)} EHR events."
        )
        # SECURITY EVIDENCE

        print()
        print("Inserting security evidence...")

        for _, row in evidence_df.iterrows():

            evidence = SecurityEvidence(
                evidence_id=row["evidence_id"],
                event_id=row["event_id"],
                scenario_id=row["scenario_id"],
                source_type=row["source_type"],
                provenance=row["provenance"],
                integrity_status=row[
                    "integrity_status"
                ],
                freshness_status=row[
                    "freshness_status"
                ],
                consistency_status=row[
                    "consistency_status"
                ],
                is_poisoned=bool(
                    row["is_poisoned"]
                ),
                poison_type=row["poison_type"],
            )

            db.add(evidence)

        db.commit()

        print(
            f"Inserted {len(evidence_df)} "
            "security evidence records."
        )
        # GROUND TRUTH

        print()
        print("Inserting ground truth...")

        for _, row in ground_truth_df.iterrows():

            truth = GroundTruth(
                event_id=row["event_id"],
                scenario_id=row["scenario_id"],
                event_source=row[
                    "event_source"
                ],
                label=row["label"],
                attack_type=row[
                    "attack_type"
                ],
            )

            db.add(truth)

        db.commit()

        print(
            f"Inserted {len(ground_truth_df)} "
            "ground-truth records."
        )

        # SUCCESS

        print()
        print("=" * 70)
        print("DEVELOPMENT DATA INGESTION COMPLETE")
        print("=" * 70)

    except Exception as error:

        db.rollback()

        print()
        print("=" * 70)
        print("INGESTION FAILED")
        print("=" * 70)

        print()
        print("Error:")
        print(error)

        raise

    finally:

        db.close()

# ENTRY POINT

if __name__ == "__main__":
    main()