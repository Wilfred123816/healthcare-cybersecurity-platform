from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from Backend.app.database import get_db

from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent

from Backend.app.models.security_evidence import SecurityEvidence

from Backend.app.detection.threat_detector import ThreatDetectionEngine
from Backend.app.detection.scenario_correlator import ScenarioThreatCorrelator

from Backend.app.trust.trust_engine import TrustEngine
from Backend.app.trust.trust_aware_detector import TrustAwareDetector


router = APIRouter(
    prefix="/api/trust-aware",
    tags=["Trust-Aware Detection"]
)


# FIND EVENT

def find_event(
    db: Session,
    event_id: str
):

    event = (
        db.query(IdentityEvent)
        .filter(
            IdentityEvent.event_id == event_id
        )
        .first()
    )

    if event:
        return event, "identity"

    event = (
        db.query(EndpointEvent)
        .filter(
            EndpointEvent.event_id == event_id
        )
        .first()
    )

    if event:
        return event, "endpoint"

    event = (
        db.query(NetworkEvent)
        .filter(
            NetworkEvent.event_id == event_id
        )
        .first()
    )

    if event:
        return event, "network"

    event = (
        db.query(EHREvent)
        .filter(
            EHREvent.event_id == event_id
        )
        .first()
    )

    if event:
        return event, "ehr"

    return None, None


# CONVERT DATABASE EVENT TO DETECTION EVENT

def convert_to_detection_event(
    event,
    source_type
):

    data = {
        "event_id": event.event_id,
        "scenario_id": event.scenario_id,
        "source_type": source_type,
    }

    # IDENTITY EVENT
    if source_type == "identity":

        data.update({
            "event_type": event.event_type,
            "success": event.success,
        })

    # ENDPOINT EVENT
    elif source_type == "endpoint":

        data.update({
            "event_type": event.event_type,
            "process": event.process,
        })

    # NETWORK EVENT
    elif source_type == "network":

        data.update({
            "bytes_out": event.bytes_out,
            "destination_ip": event.destination_ip,
            "protocol": event.protocol,
        })

    # EHR EVENT
    elif source_type == "ehr":

        data.update({
            "event_type": event.resource_type,
            "action": event.action,
            "resource_type": event.resource_type,
        })

    return type(
        "DetectionEvent",
        (),
        data
    )()


# GET ALL EVENTS BELONGING TO A SCENARIO

def get_scenario_events(
    db: Session,
    scenario_id: str
):

    events = []

    # IDENTITY EVENTS

    identity_events = (
        db.query(IdentityEvent)
        .filter(
            IdentityEvent.scenario_id == scenario_id
        )
        .all()
    )

    # ENDPOINT EVENTS

    endpoint_events = (
        db.query(EndpointEvent)
        .filter(
            EndpointEvent.scenario_id == scenario_id
        )
        .all()
    )

    # NETWORK EVENTS

    network_events = (
        db.query(NetworkEvent)
        .filter(
            NetworkEvent.scenario_id == scenario_id
        )
        .all()
    )

    # EHR EVENTS

    ehr_events = (
        db.query(EHREvent)
        .filter(
            EHREvent.scenario_id == scenario_id
        )
        .all()
    )

    # CONVERT EVENTS

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

    return events


# TRUST-AWARE EVENT EVALUATION

@router.get("/event/{event_id}")
def evaluate_trust_aware_event(
    event_id: str,
    db: Session = Depends(get_db)
):

    # FIND REQUESTED EVENT

    event, source_type = find_event(
        db,
        event_id
    )

    if event is None:

        raise HTTPException(
            status_code=404,
            detail=f"Event {event_id} was not found."
        )

    # FIND SECURITY EVIDENCE

    evidence = (
        db.query(SecurityEvidence)
        .filter(
            SecurityEvidence.event_id == event_id
        )
        .first()
    )

    if evidence is None:

        raise HTTPException(
            status_code=404,
            detail=(
                f"No security evidence was found "
                f"for event {event_id}."
            )
        )

    # CONVERT EVENT

    detection_event = convert_to_detection_event(
        event,
        source_type
    )

    # INITIALIZE ENGINES

    detection_engine = ThreatDetectionEngine()

    correlation_engine = ScenarioThreatCorrelator()

    trust_engine = TrustEngine()

    trust_aware_engine = TrustAwareDetector()

    # EVENT-LEVEL THREAT DETECTION

    detection_result = detection_engine.detect(
        detection_event
    )

    # SCENARIO-LEVEL CORRELATION

    scenario_events = get_scenario_events(
        db,
        event.scenario_id
    )

    scenario_result = correlation_engine.correlate(
        scenario_events
    )

    # EVIDENCE TRUST EVALUATION

    trust_result = trust_engine.evaluate(
        evidence
    )

    # FINAL TRUST-AWARE DECISION

    final_result = trust_aware_engine.evaluate(
        detection_result,
        trust_result,
        scenario_result
    )

    # API RESPONSE

    return {
        "event_id": final_result.event_id,

        "scenario_id": final_result.scenario_id,

        "source_type": final_result.source_type,

        # Event-level detection
        "original_detection": (
            final_result.original_detection
        ),

        "detection_score": (
            final_result.detection_score
        ),

        # Scenario-level correlation
        "scenario_detection": (
            final_result.scenario_detection
        ),

        "scenario_score": (
            final_result.scenario_score
        ),

        # Evidence trust
        "trust_score": (
            final_result.trust_score
        ),

        # Combined result
        "final_score": (
            final_result.final_score
        ),

        "threat_detected": (
            final_result.threat_detected
        ),

        "decision": (
            final_result.decision
        ),

        "severity": (
            final_result.severity
        ),

        "confidence": (
            final_result.confidence
        ),

        "reasons": (
            final_result.reasons
        ),
    }