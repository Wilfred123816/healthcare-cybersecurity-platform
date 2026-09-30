import pandas as pd
from pathlib import Path


DATA_DIR = Path("data/development")


def show_attack_events(filename, columns):
    """
    Display observable fields for attack events only.
    Ground-truth attack labels are used ONLY for analysis here,
    not by the detection engine.
    """

    path = DATA_DIR / filename

    df = pd.read_csv(path)

    attacks = df[df["label"] == "attack"].copy()

    print()
    print("=" * 80)
    print(f"{filename.upper()} - ATTACK EVENTS")
    print("=" * 80)

    if attacks.empty:
        print("No attack events found.")
        return

    available_columns = [
        column
        for column in columns
        if column in attacks.columns
    ]

    print(
        attacks[available_columns]
        .to_string(index=False)
    )


def main():

    print("=" * 80)
    print("ATTACK PATTERN INSPECTION")
    print("=" * 80)
    # Identity

    show_attack_events(
        "identity_events.csv",
        [
            "event_id",
            "scenario_id",
            "timestamp",
            "event_type",
            "source_ip",
            "success",
            "attack_type",
        ],
    )

    # Endpoint

    show_attack_events(
        "endpoint_events.csv",
        [
            "event_id",
            "scenario_id",
            "timestamp",
            "event_type",
            "process",
            "attack_type",
        ],
    )
    # Network

    show_attack_events(
        "network_events.csv",
        [
            "event_id",
            "scenario_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "bytes_out",
            "protocol",
            "attack_type",
        ],
    )
    # EHR

    show_attack_events(
        "ehr_events.csv",
        [
            "event_id",
            "scenario_id",
            "timestamp",
            "resource_type",
            "action",
            "attack_type",
        ],
    )


if __name__ == "__main__":
    main()