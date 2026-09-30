import sys
from pathlib import Path
from collections import Counter

# Add project root to Python import path
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from sqlalchemy.orm import Session

from Backend.app.database import SessionLocal

from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.models.ground_truth import GroundTruth

from Backend.app.detection.threat_detector import (
    ThreatDetectionEngine
)


def convert_to_detection_event(event, source_type):

    data = {
        "event_id": event.event_id,
        "scenario_id": event.scenario_id,
        "source_type": source_type,
    }

    if source_type == "identity":

        data.update(
            {
                "event_type": event.event_type,
                "success": event.success,
            }
        )

    elif source_type == "endpoint":

        data.update(
            {
                "event_type": event.event_type,
                "process": event.process,
            }
        )

    elif source_type == "network":

        data.update(
            {
                "bytes_out": event.bytes_out,
                "protocol": event.protocol,
                "destination_ip": event.destination_ip,
            }
        )

    elif source_type == "ehr":

        data.update(
            {
                "event_type": event.resource_type,
                "action": event.action,
            }
        )

    return type(
        "DetectionEvent",
        (),
        data
    )()


def main():

    db: Session = SessionLocal()

    try:

        engine = ThreatDetectionEngine()

        all_events = []

        # Identity
        for event in db.query(IdentityEvent).all():
            all_events.append(
                (event, "identity")
            )

        # Endpoint
        for event in db.query(EndpointEvent).all():
            all_events.append(
                (event, "endpoint")
            )

        # Network
        for event in db.query(NetworkEvent).all():
            all_events.append(
                (event, "network")
            )

        # EHR
        for event in db.query(EHREvent).all():
            all_events.append(
                (event, "ehr")
            )

        false_positives = []
        false_negatives = []

        for event, source_type in all_events:

            ground_truth = (
                db.query(GroundTruth)
                .filter(
                    GroundTruth.event_id == event.event_id
                )
                .first()
            )

            if ground_truth is None:
                continue

            detection_event = convert_to_detection_event(
                event,
                source_type
            )

            result = engine.detect(
                detection_event
            )

            actual_attack = (
                ground_truth.label == "attack"
            )

            predicted_attack = result.threat_detected

            # False positive
            if predicted_attack and not actual_attack:

                false_positives.append(
                    {
                        "event_id": event.event_id,
                        "source_type": source_type,
                        "event_type": getattr(
                            event,
                            "event_type",
                            None
                        ),
                        "score": result.score,
                        "detection_type": result.detection_type,
                    }
                )

            # False negative
            elif not predicted_attack and actual_attack:

                false_negatives.append(
                    {
                        "event_id": event.event_id,
                        "source_type": source_type,
                        "event_type": getattr(
                            event,
                            "event_type",
                            None
                        ),
                        "score": result.score,
                        "attack_type": ground_truth.attack_type,
                    }
                )

        # FALSE POSITIVE ANALYSIS

        print("=" * 70)
        print("FALSE POSITIVE ANALYSIS")
        print("=" * 70)

        print(
            f"Total false positives: {len(false_positives)}"
        )

        print()

        source_counts = Counter(
            item["source_type"]
            for item in false_positives
        )

        print("False positives by source:")
        for source, count in source_counts.items():
            print(
                f"  {source}: {count}"
            )

        print()

        detection_counts = Counter(
            item["detection_type"]
            for item in false_positives
        )

        print("False positives by detection type:")
        for detection_type, count in detection_counts.most_common():
            print(
                f"  {detection_type}: {count}"
            )

        # FALSE NEGATIVE ANALYSIS

        print()
        print("=" * 70)
        print("FALSE NEGATIVE ANALYSIS")
        print("=" * 70)

        print(
            f"Total false negatives: {len(false_negatives)}"
        )

        print()

        attack_counts = Counter(
            item["attack_type"]
            for item in false_negatives
        )

        print("False negatives by attack type:")
        for attack_type, count in attack_counts.items():
            print(
                f"  {attack_type}: {count}"
            )

        print()

        source_counts = Counter(
            item["source_type"]
            for item in false_negatives
        )

        print("False negatives by source:")
        for source, count in source_counts.items():
            print(
                f"  {source}: {count}"
            )

        print()
        print("=" * 70)
        print("ANALYSIS COMPLETE")
        print("=" * 70)

    finally:

        db.close()


if __name__ == "__main__":
    main()