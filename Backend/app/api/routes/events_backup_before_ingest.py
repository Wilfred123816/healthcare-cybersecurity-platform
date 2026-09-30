from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from Backend.app.database import get_db
from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.models.security_evidence import SecurityEvidence


router = APIRouter(
    prefix="/api",
    tags=["Events"]
)


@router.get("/events/identity")
def get_identity_events(
    db: Session = Depends(get_db)
):
    events = (
        db.query(IdentityEvent)
        .limit(50)
        .all()
    )

    return events


@router.get("/events/endpoint")
def get_endpoint_events(
    db: Session = Depends(get_db)
):
    events = (
        db.query(EndpointEvent)
        .limit(50)
        .all()
    )

    return events


@router.get("/events/network")
def get_network_events(
    db: Session = Depends(get_db)
):
    events = (
        db.query(NetworkEvent)
        .limit(50)
        .all()
    )

    return events


@router.get("/events/ehr")
def get_ehr_events(
    db: Session = Depends(get_db)
):
    events = (
        db.query(EHREvent)
        .limit(50)
        .all()
    )

    return events


@router.get("/evidence")
def get_security_evidence(
    db: Session = Depends(get_db)
):
    evidence = (
        db.query(SecurityEvidence)
        .limit(50)
        .all()
    )

    return evidence


@router.get("/evidence/{event_id}")
def get_evidence_for_event(
    event_id: str,
    db: Session = Depends(get_db)
):
    evidence = (
        db.query(SecurityEvidence)
        .filter(SecurityEvidence.event_id == event_id)
        .all()
    )

    if not evidence:
        raise HTTPException(
            status_code=404,
            detail=f"No security evidence found for event {event_id}"
        )

    return evidence