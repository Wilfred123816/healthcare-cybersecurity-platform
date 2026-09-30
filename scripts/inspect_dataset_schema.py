from pathlib import Path
import pandas as pd


DATA_DIR = Path("data/raw")


FILES = [
    "users.csv",
    "devices.csv",
    "identity_events.csv",
    "endpoint_events.csv",
    "network_events.csv",
    "ehr_events.csv",
    "security_evidence.csv",
    "ground_truth.csv",
]


print("=" * 70)
print("HEALTHCARE CYBERSECURITY DATASET SCHEMA INSPECTION")
print("=" * 70)


for filename in FILES:

    filepath = DATA_DIR / filename

    print()
    print("-" * 70)
    print(f"FILE: {filename}")
    print("-" * 70)

    if not filepath.exists():
        print(f"ERROR: File not found: {filepath}")
        continue

    df = pd.read_csv(filepath)

    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")

    print("\nColumns:")

    for column in df.columns:
        print(f"  - {column}")

    print("\nData types:")

    for column, dtype in df.dtypes.items():
        print(f"  - {column}: {dtype}")

    print("\nFirst 2 records:")

    print(df.head(2).to_string(index=False))


print()
print("=" * 70)
print("SCHEMA INSPECTION COMPLETE")
print("=" * 70)