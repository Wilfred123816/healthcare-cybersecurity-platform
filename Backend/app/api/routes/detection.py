from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from Backend.app.database import get_db
from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.detection.threat_detector import ThreatDetectionEngine


router = APIRouter(
    prefix="/api/detection",
    tags=["Threat Detection"]
)


def find_event(db: Session, event_id: str):

    event = (
        db.query(IdentityEvent)
        .filter(IdentityEvent.event_id == event_id)
        .first()
    )

    if event:
        return event, "identity"

    event = (
        db.query(EndpointEvent)
        .filter(EndpointEvent.event_id == event_id)
        .first()
    )

    if event:
        return event, "endpoint"

    event = (
        db.query(NetworkEvent)
        .filter(NetworkEvent.event_id == event_id)
        .first()
    )

    if event:
        return event, "network"

    event = (
        db.query(EHREvent)
        .filter(EHREvent.event_id == event_id)
        .first()
    )

    if event:
        return event, "ehr"

    return None, None


def convert_to_detection_event(event, source_type):

    data = {
        "event_id": event.event_id,
        "scenario_id": event.scenario_id,
        "source_type": source_type,
    }

    # Identity fields
    if source_type == "identity":
        data.update(
            {
                "event_type": event.event_type,
                "success": event.success,
            }
        )

    # Endpoint fields
    elif source_type == "endpoint":
        data.update(
            {
                "event_type": event.event_type,
                "process": event.process,
            }
        )

    # Network fields
    elif source_type == "network":
        data.update(
            {
                "bytes_out": event.bytes_out,
                "protocol": event.protocol,
            }
        )

    # EHR fields
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


@router.get("/event/{event_id}")
def detect_event(
    event_id: str,
    db: Session = Depends(get_db)
):

    event, source_type = find_event(
        db,
        event_id
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail=f"Event {event_id} was not found."
        )

    detection_event = convert_to_detection_event(
        event,
        source_type
    )

    engine = ThreatDetectionEngine()

    result = engine.detect(
        detection_event
    )

    return {
    "event_id": result.event_id,
    "scenario_id": result.scenario_id,
    "source_type": result.source_type,
    "threat_detected": result.threat_detected,
    "severity": result.severity,
    "detection_type": result.detection_type,
    "confidence": result.confidence,
    "score": result.score,
    "reasons": result.reasons,
}