import subprocess
import sys
from pathlib import Path
from Backend.app.database import Base, engine

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Backend.app.database import Base, SessionLocal
from Backend.app.models import (
    Device,
    EHREvent,
    EndpointEvent,
    GroundTruth,
    IdentityEvent,
    NetworkEvent,
    SecurityEvidence,
    User,
)


def database_counts(db):
    return {
        "users": db.query(User).count(),
        "devices": db.query(Device).count(),
        "identity_events": db.query(IdentityEvent).count(),
        "endpoint_events": db.query(EndpointEvent).count(),
        "network_events": db.query(NetworkEvent).count(),
        "ehr_events": db.query(EHREvent).count(),
        "security_evidence": db.query(SecurityEvidence).count(),
        "ground_truth": db.query(GroundTruth).count(),
    }


def main():
    print("=" * 70)
    print("DOCKER DATABASE INITIALIZATION")
    print("=" * 70)

    print()
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        counts = database_counts(db)

        print()
        print("Current database state:")

        for name, count in counts.items():
            print(f"  {name}: {count}")

        all_empty = all(
            count == 0
            for count in counts.values()
        )

        all_populated = all(
            count > 0
            for count in counts.values()
        )

        if all_empty:
            print()
            print("Database is empty.")
            print("Loading development dataset...")

            ingestion_script = (
                PROJECT_ROOT
                / "scripts"
                / "ingest_development_data.py"
            )

            subprocess.run(
                [
                    sys.executable,
                    str(ingestion_script),
                ],
                check=True,
                cwd=str(PROJECT_ROOT),
            )

            print()
            print("Development dataset loaded successfully.")

        elif all_populated:
            print()
            print("Database already contains data.")
            print("Skipping destructive development ingestion.")

        else:
            raise RuntimeError(
                "Database contains partial application data. "
                "Refusing to modify it automatically."
            )

    finally:
        db.close()

    print()
    print("=" * 70)
    print("DOCKER DATABASE INITIALIZATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
