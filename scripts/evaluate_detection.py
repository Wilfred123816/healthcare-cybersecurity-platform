import sys
from pathlib import Path

# Add the project root directory to Python's import path
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collections import Counter

from sqlalchemy.orm import Session

from Backend.app.database import SessionLocal
from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.models.ground_truth import GroundTruth
from Backend.app.detection.threat_detector import ThreatDetectionEngine


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


def calculate_metrics(
    true_positive,
    true_negative,
    false_positive,
    false_negative,
):

    total = (
        true_positive
        + true_negative
        + false_positive
        + false_negative
    )

    accuracy = (
        (true_positive + true_negative) / total
        if total > 0
        else 0
    )

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive) > 0
        else 0
    )

    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative) > 0
        else 0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0
    )

    return accuracy, precision, recall, f1


def main():

    db: Session = SessionLocal()

    try:

        print("=" * 60)
        print("THREAT DETECTION ENGINE EVALUATION")
        print("=" * 60)

        engine = ThreatDetectionEngine()

        true_positive = 0
        true_negative = 0
        false_positive = 0
        false_negative = 0

        prediction_counts = Counter()
        ground_truth_counts = Counter()

        # Load all events

        all_events = []

        identity_events = db.query(IdentityEvent).all()

        for event in identity_events:
            all_events.append(
                (event, "identity")
            )

        endpoint_events = db.query(EndpointEvent).all()

        for event in endpoint_events:
            all_events.append(
                (event, "endpoint")
            )

        network_events = db.query(NetworkEvent).all()

        for event in network_events:
            all_events.append(
                (event, "network")
            )

        ehr_events = db.query(EHREvent).all()

        for event in ehr_events:
            all_events.append(
                (event, "ehr")
            )

        print(f"Total events loaded: {len(all_events)}")

        # Evaluate every event

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

            predicted_attack = result.threat_detected

            actual_attack = (
                ground_truth.label == "attack"
            )

            prediction_counts[
                "attack" if predicted_attack else "normal"
            ] += 1

            ground_truth_counts[
                "attack" if actual_attack else "normal"
            ] += 1

            if predicted_attack and actual_attack:
                true_positive += 1

            elif not predicted_attack and not actual_attack:
                true_negative += 1

            elif predicted_attack and not actual_attack:
                false_positive += 1

            elif not predicted_attack and actual_attack:
                false_negative += 1
        # Metrics

        accuracy, precision, recall, f1 = calculate_metrics(
            true_positive,
            true_negative,
            false_positive,
            false_negative,
        )

        print()
        print("=" * 60)
        print("RESULTS")
        print("=" * 60)

        print(f"Ground-truth normal events : {ground_truth_counts['normal']}")
        print(f"Ground-truth attack events : {ground_truth_counts['attack']}")

        print()
        print(f"Predicted normal events    : {prediction_counts['normal']}")
        print(f"Predicted attack events    : {prediction_counts['attack']}")

        print()
        print("CONFUSION MATRIX")
        print("-" * 40)

        print(f"True Positives  : {true_positive}")
        print(f"True Negatives  : {true_negative}")
        print(f"False Positives : {false_positive}")
        print(f"False Negatives : {false_negative}")

        print()
        print("PERFORMANCE METRICS")
        print("-" * 40)

        print(f"Accuracy  : {accuracy:.4f}")
        print(f"Precision : {precision:.4f}")
        print(f"Recall    : {recall:.4f}")
        print(f"F1-score  : {f1:.4f}")

        print()
        print("=" * 60)
        print("EVALUATION COMPLETE")
        print("=" * 60)

    finally:
        db.close()


if __name__ == "__main__":
    main()