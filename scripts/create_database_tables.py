import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from Backend.app.database import Base, engine

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


print("=" * 70)
print("CREATING HEALTHCARE CYBERSECURITY DATABASE TABLES")
print("=" * 70)


Base.metadata.create_all(bind=engine)


print()
print("Database tables created successfully.")
print()
print("Created tables:")

for table in Base.metadata.sorted_tables:
    print(f"  - {table.name}")


print()
print("=" * 70)