from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from Backend.app.database import get_db
from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.schemas.unified_event import UnifiedEvent


router = APIRouter(
    prefix="/api/unified",
    tags=["Unified Events"]
)


@router.get("/events", response_model=list[UnifiedEvent])
def get_unified_events(
    db: Session = Depends(get_db)
):
    unified_events = []

    # Identity events
    identity_events = db.query(IdentityEvent).all()

    for event in identity_events:
        unified_events.append(
            UnifiedEvent(
                event_id=event.event_id,
                scenario_id=event.scenario_id,
                timestamp=event.timestamp,
                source_type="identity",
                user_id=event.user_id,
                device_id=event.device_id,
                event_type=event.event_type,
                source_ip=event.source_ip,
                success=event.success,
                label=event.label,
                attack_type=event.attack_type
            )
        )

    # Endpoint events
    endpoint_events = db.query(EndpointEvent).all()

    for event in endpoint_events:
        unified_events.append(
            UnifiedEvent(
                event_id=event.event_id,
                scenario_id=event.scenario_id,
                timestamp=event.timestamp,
                source_type="endpoint",
                user_id=event.user_id,
                device_id=event.device_id,
                event_type=event.event_type,
                process=event.process,
                label=event.label,
                attack_type=event.attack_type
            )
        )

    # Network events
    network_events = db.query(NetworkEvent).all()

    for event in network_events:
        unified_events.append(
            UnifiedEvent(
                event_id=event.event_id,
                scenario_id=event.scenario_id,
                timestamp=event.timestamp,
                source_type="network",
                user_id=event.user_id,
                device_id=event.device_id,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                bytes_out=event.bytes_out,
                protocol=event.protocol,
                label=event.label,
                attack_type=event.attack_type
            )
        )

    # EHR events
    ehr_events = db.query(EHREvent).all()

    for event in ehr_events:
        unified_events.append(
            UnifiedEvent(
                event_id=event.event_id,
                scenario_id=event.scenario_id,
                timestamp=event.timestamp,
                source_type="ehr",
                user_id=event.user_id,
                patient_id=event.patient_id,
                event_type=event.resource_type,
                action=event.action,
                label=event.label,
                attack_type=event.attack_type
            )
        )

    # Sort all events chronologically
    unified_events.sort(
        key=lambda event: event.timestamp
    )

    return unified_events