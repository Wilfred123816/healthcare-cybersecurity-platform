import sys
from pathlib import Path

#PROJECT ROOT#

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy.orm import Session

from Backend.app.database import SessionLocal
from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.models.ground_truth import GroundTruth

from Backend.app.detection.threat_detector import ThreatDetectionEngine
from Backend.app.detection.scenario_correlator import ScenarioThreatCorrelator

# DETECTION EVENT

@dataclass
class DetectionEvent:
    event_id: str
    scenario_id: str
    source_type: str

    event_type: str = ""
    success: object = None
    process: str = ""

    bytes_out: int = 0
    destination_ip: str = ""
    protocol: str = ""

    action: str = ""
    resource_type: str = ""
# LOAD ALL EVENTS

def load_events(db: Session):

    events = []
    # IDENTITY EVENTS

    identity_events = db.query(
        IdentityEvent
    ).all()

    for event in identity_events:

        events.append(
            DetectionEvent(
                event_id=event.event_id,
                scenario_id=event.scenario_id,
                source_type="identity",
                event_type=event.event_type,
                success=event.success
            )
        )
    # ENDPOINT EVENTS

    endpoint_events = db.query(
        EndpointEvent
    ).all()

    for event in endpoint_events:

        events.append(
            DetectionEvent(
                event_id=event.event_id,
                scenario_id=event.scenario_id,
                source_type="endpoint",
                event_type=event.event_type,
                process=event.process
            )
        )
    # NETWORK EVENTS

    network_events = db.query(
        NetworkEvent
    ).all()

    for event in network_events:

        events.append(
            DetectionEvent(
                event_id=event.event_id,
                scenario_id=event.scenario_id,
                source_type="network",
                bytes_out=event.bytes_out,
                destination_ip=event.destination_ip,
                protocol=event.protocol
            )
        )
    # EHR EVENTS

    ehr_events = db.query(
        EHREvent
    ).all()

    for event in ehr_events:

        events.append(
            DetectionEvent(
                event_id=event.event_id,
                scenario_id=event.scenario_id,
                source_type="ehr",
                event_type=event.resource_type,
                action=event.action,
                resource_type=event.resource_type
            )
        )

    return events
# LOAD GROUND TRUTH

def load_ground_truth(db: Session):

    rows = db.query(
        GroundTruth
    ).all()

    return {
        row.event_id: row
        for row in rows
    }
# MAIN EVALUATION

def main():

    print("=" * 60)
    print("SCENARIO CORRELATION ENGINE EVALUATION")
    print("=" * 60)

    db = SessionLocal()

    try:

        # LOAD DATA

        events = load_events(db)

        ground_truth = load_ground_truth(db)

        print(
            f"Total events loaded: {len(events)}"
        )
        # GROUP EVENTS BY SCENARIO

        scenario_events = defaultdict(list)

        for event in events:

            scenario_events[
                event.scenario_id
            ].append(event)

        print(
            f"Total scenarios found: "
            f"{len(scenario_events)}"
        )

        # RUN EVENT-LEVEL DETECTOR

        event_detector = ThreatDetectionEngine()

        event_results = {}

        for event in events:

            result = event_detector.detect(
                event
            )

            event_results[
                event.event_id
            ] = result

        # RUN SCENARIO CORRELATOR

        correlator = ScenarioThreatCorrelator()

        scenario_results = {}

        for scenario_id, scenario_event_list in (
            scenario_events.items()
        ):

            result = correlator.correlate(
                scenario_event_list
            )

            scenario_results[
                scenario_id
            ] = result

        # COMBINED DECISION

        true_positive = 0
        true_negative = 0
        false_positive = 0
        false_negative = 0

        for event in events:

            truth = ground_truth.get(
                event.event_id
            )

            if truth is None:
                continue

            # Ground truth is used ONLY for evaluation.
            actual_attack = (
                truth.label.lower() == "attack"
            )

            event_result = event_results[
                event.event_id
            ]

            scenario_result = scenario_results[
                event.scenario_id
            ]
            # FINAL PREDICTION
            #
            # A threat is detected when either:
            #
            # 1. The event-level detector identifies
            #    strong suspicious behaviour.
            #
            # OR
            #
            # 2. The scenario-level correlator identifies
            #    a combination of suspicious behaviours.
            #
            # Neither component receives:
            #   - label
            #   - attack_type
            #
            # during detection.

            predicted_attack = (
                event_result.threat_detected
                or scenario_result.threat_detected
            )

            # CONFUSION MATRIX

            if predicted_attack and actual_attack:

                true_positive += 1

            elif (
                not predicted_attack
                and not actual_attack
            ):

                true_negative += 1

            elif predicted_attack and not actual_attack:

                false_positive += 1

            elif (
                not predicted_attack
                and actual_attack
            ):

                false_negative += 1
        # METRICS

        total = (
            true_positive
            + true_negative
            + false_positive
            + false_negative
        )

        accuracy = (
            (true_positive + true_negative)
            / total
            if total
            else 0
        )

        precision = (
            true_positive
            / (true_positive + false_positive)
            if (
                true_positive
                + false_positive
            )
            else 0
        )

        recall = (
            true_positive
            / (true_positive + false_negative)
            if (
                true_positive
                + false_negative
            )
            else 0
        )

        f1 = (
            2
            * precision
            * recall
            / (precision + recall)
            if (
                precision + recall
            )
            else 0
        )
        # OUTPUT

        print()
        print("=" * 60)
        print("RESULTS")
        print("=" * 60)

        print(
            f"Ground-truth normal events : "
            f"{true_negative + false_positive}"
        )

        print(
            f"Ground-truth attack events : "
            f"{true_positive + false_negative}"
        )

        print()

        print(
            f"Predicted normal events    : "
            f"{true_negative + false_negative}"
        )

        print(
            f"Predicted attack events    : "
            f"{true_positive + false_positive}"
        )

        print()

        print("CONFUSION MATRIX")
        print("-" * 40)

        print(
            f"True Positives  : "
            f"{true_positive}"
        )

        print(
            f"True Negatives  : "
            f"{true_negative}"
        )

        print(
            f"False Positives : "
            f"{false_positive}"
        )

        print(
            f"False Negatives : "
            f"{false_negative}"
        )

        print()

        print("PERFORMANCE METRICS")
        print("-" * 40)

        print(
            f"Accuracy  : "
            f"{accuracy:.4f}"
        )

        print(
            f"Precision : "
            f"{precision:.4f}"
        )

        print(
            f"Recall    : "
            f"{recall:.4f}"
        )

        print(
            f"F1-score  : "
            f"{f1:.4f}"
        )

        # CORRELATION SUMMARY

        correlated_scenarios = sum(
            1
            for result in scenario_results.values()
            if result.threat_detected
        )

        print()

        print("CORRELATION SUMMARY")
        print("-" * 40)

        print(
            f"Scenarios analysed       : "
            f"{len(scenario_results)}"
        )

        print(
            f"Scenarios flagged       : "
            f"{correlated_scenarios}"
        )

        print()

        print("=" * 60)
        print("EVALUATION COMPLETE")
        print("=" * 60)

    finally:

        db.close()
# ENTRY POINT

if __name__ == "__main__":
    main()