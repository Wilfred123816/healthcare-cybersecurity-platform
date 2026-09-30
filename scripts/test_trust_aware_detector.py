import sys
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass


# ADD PROJECT ROOT TO PYTHON PATH

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# IMPORT APPLICATION COMPONENTS

from Backend.app.database import SessionLocal

from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.models.security_evidence import SecurityEvidence
from Backend.app.models.ground_truth import GroundTruth

from Backend.app.detection.threat_detector import (
    ThreatDetectionEngine
)

from Backend.app.detection.scenario_correlator import (
    ScenarioThreatCorrelator
)

from Backend.app.trust.trust_engine import (
    TrustEngine
)

from Backend.app.trust.trust_aware_detector import (
    TrustAwareDetector
)


# COMMON EVENT STRUCTURE

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


# CONVERT DATABASE EVENT

def convert_to_detection_event(
    event,
    source_type
):

    data = {
        "event_id": event.event_id,
        "scenario_id": event.scenario_id,
        "source_type": source_type,
    }

    if source_type == "identity":

        data.update({
            "event_type": event.event_type,
            "success": event.success,
        })

    elif source_type == "endpoint":

        data.update({
            "event_type": event.event_type,
            "process": event.process,
        })

    elif source_type == "network":

        data.update({
            "bytes_out": event.bytes_out,
            "destination_ip": event.destination_ip,
            "protocol": event.protocol,
        })

    elif source_type == "ehr":

        data.update({
            "event_type": event.resource_type,
            "action": event.action,
            "resource_type": event.resource_type,
        })

    return DetectionEvent(**data)


# MAIN TEST

def main():

    db = SessionLocal()

    try:

        print()
        print("=" * 70)
        print("TRUST-AWARE DETECTION ENGINE TEST")
        print("=" * 70)

        # LOAD EVENTS

        events = []

        identity_events = db.query(
            IdentityEvent
        ).all()

        endpoint_events = db.query(
            EndpointEvent
        ).all()

        network_events = db.query(
            NetworkEvent
        ).all()

        ehr_events = db.query(
            EHREvent
        ).all()

        for event in identity_events:
            events.append(
                convert_to_detection_event(
                    event,
                    "identity"
                )
            )

        for event in endpoint_events:
            events.append(
                convert_to_detection_event(
                    event,
                    "endpoint"
                )
            )

        for event in network_events:
            events.append(
                convert_to_detection_event(
                    event,
                    "network"
                )
            )

        for event in ehr_events:
            events.append(
                convert_to_detection_event(
                    event,
                    "ehr"
                )
            )

        print()
        print(
            f"Total events loaded: {len(events)}"
        )

        # GROUP EVENTS BY SCENARIO

        scenarios = defaultdict(list)

        for event in events:
            scenarios[event.scenario_id].append(
                event
            )

        print(
            f"Total scenarios found: {len(scenarios)}"
        )

        # LOAD EVIDENCE

        evidence_records = db.query(
            SecurityEvidence
        ).all()

        evidence_by_event = {
            evidence.event_id: evidence
            for evidence in evidence_records
        }

        # LOAD GROUND TRUTH

        ground_truth_records = db.query(
            GroundTruth
        ).all()

        ground_truth_by_event = {
            record.event_id: record
            for record in ground_truth_records
        }

        # INITIALIZE ENGINES

        detection_engine = (
            ThreatDetectionEngine()
        )

        correlation_engine = (
            ScenarioThreatCorrelator()
        )

        trust_engine = TrustEngine()

        trust_aware_engine = (
            TrustAwareDetector()
        )

        # RUN TRUST-AWARE DETECTION

        results = []

        for scenario_id, scenario_events in (
            scenarios.items()
        ):

            # Scenario-level correlation
            scenario_result = (
                correlation_engine.correlate(
                    scenario_events
                )
            )

            for event in scenario_events:

                detection_result = (
                    detection_engine.detect(
                        event
                    )
                )

                evidence = (
                    evidence_by_event.get(
                        event.event_id
                    )
                )

                if evidence is None:
                    continue

                trust_result = (
                    trust_engine.evaluate(
                        evidence
                    )
                )

                final_result = (
                    trust_aware_engine.evaluate(
                        detection_result,
                        trust_result,
                        scenario_result
                    )
                )

                results.append(
                    (
                        final_result,
                        ground_truth_by_event.get(
                            event.event_id
                        )
                    )
                )

        # SUMMARIZE DECISIONS

        confirmed = 0
        probable = 0
        verification = 0
        normal = 0
        insufficient = 0

        original_threats = 0
        final_threats = 0

        for result, ground_truth in results:

            if (
                result.decision
                == "confirmed_threat"
            ):
                confirmed += 1

            elif (
                result.decision
                == "probable_threat"
            ):
                probable += 1

            elif (
                result.decision
                == "requires_verification"
            ):
                verification += 1

            elif (
                result.decision
                == "normal_activity"
            ):
                normal += 1

            elif (
                result.decision
                == "insufficient_evidence"
            ):
                insufficient += 1

            if result.original_detection:
                original_threats += 1

            if result.threat_detected:
                final_threats += 1

        # DISPLAY RESULTS

        print()
        print("-" * 70)
        print("TRUST-AWARE RESULTS")
        print("-" * 70)

        print(
            f"Confirmed threats          : "
            f"{confirmed}"
        )

        print(
            f"Probable threats           : "
            f"{probable}"
        )

        print(
            f"Requires verification      : "
            f"{verification}"
        )

        print(
            f"Normal activity            : "
            f"{normal}"
        )

        print(
            f"Insufficient evidence      : "
            f"{insufficient}"
        )

        print()

        print(
            f"Original detection threats : "
            f"{original_threats}"
        )

        print(
            f"Final trust-aware threats  : "
            f"{final_threats}"
        )

        # SHOW CURRENT KNOWN ATTACK

        # Do not use a hard-coded generated ID.
        # Select an attack event dynamically from the
        # current ground-truth dataset.

        attack_candidates = [
            (result, ground_truth)
            for result, ground_truth in results
            if (
                ground_truth is not None
                and getattr(
                    ground_truth,
                    "label",
                    ""
                ) == "attack"
            )
        ]

        known_attack = None
        known_attack_ground_truth = None

        if attack_candidates:

            # Sort by event ID so selection is deterministic.
            attack_candidates.sort(
                key=lambda item: item[0].event_id
            )

            (
                known_attack,
                known_attack_ground_truth
            ) = attack_candidates[0]

        print()
        print("-" * 70)
        print("KNOWN ATTACK TEST")
        print("-" * 70)

        if known_attack:

            print(
                f"Event ID          : "
                f"{known_attack.event_id}"
            )

            print(
                f"Scenario ID       : "
                f"{known_attack.scenario_id}"
            )

            print(
                f"Ground truth      : "
                f"{known_attack_ground_truth.label}"
            )

            print(
                f"Attack type       : "
                f"{known_attack_ground_truth.attack_type}"
            )

            print(
                f"Event detection   : "
                f"{known_attack.detection_score}"
            )

            print(
                f"Scenario detection: "
                f"{known_attack.scenario_score}"
            )

            print(
                f"Trust score       : "
                f"{known_attack.trust_score}"
            )

            print(
                f"Final score       : "
                f"{known_attack.final_score}"
            )

            print(
                f"Decision          : "
                f"{known_attack.decision}"
            )

            print(
                f"Severity          : "
                f"{known_attack.severity}"
            )

            print(
                f"Confidence        : "
                f"{known_attack.confidence}"
            )

            print("Reasons:")

            for reason in known_attack.reasons:

                print(
                    f"  - {reason}"
                )

        else:

            raise AssertionError(
                "No attack event was found "
                "in the current development dataset."
            )

        print()
        print("=" * 70)
        print("TEST COMPLETE")
        print("=" * 70)

    finally:

        db.close()


# RUN

if __name__ == "__main__":
    main()