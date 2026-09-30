from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from Backend.app.database import get_db
from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.models.security_evidence import SecurityEvidence
from Backend.app.models.user import User
from Backend.app.models.device import Device


router = APIRouter(
    prefix="/api",
    tags=["Events"]
)


# ============================================================
# EXISTING EVENT ENDPOINTS
# ============================================================

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


# ============================================================
# DEMONSTRATION EVENT INGESTION
# ============================================================

class DemoEventRequest(BaseModel):
    event_type: str = Field(
        default="mass_file_modify",
        min_length=1,
        max_length=100
    )

    process: str = Field(
        default="file_encryption_process",
        min_length=1,
        max_length=150
    )

    scenario_id: str = Field(
        default="DEMO-SCENARIO-001",
        min_length=1,
        max_length=60
    )


@router.post("/events/ingest")
def ingest_demo_event(
    request: DemoEventRequest,
    db: Session = Depends(get_db)
):
    """
    Create a synthetic endpoint security event for the
    end-to-end backend integration demonstration.

    The event is written to PostgreSQL together with
    corresponding security evidence.
    """

    # --------------------------------------------------------
    # Find an existing valid user and device.
    # EndpointEvent has foreign-key requirements for both.
    # --------------------------------------------------------

    user = (
        db.query(User)
        .first()
    )

    device = (
        db.query(Device)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=500,
            detail="No users are available in the database."
        )

    if device is None:
        raise HTTPException(
            status_code=500,
            detail="No devices are available in the database."
        )

    # --------------------------------------------------------
    # Generate unique IDs.
    # --------------------------------------------------------

    event_id = f"DEMO-ENDPOINT-{uuid4().hex[:8]}"
    evidence_id = f"DEMO-EVIDENCE-{uuid4().hex[:8]}"

    timestamp = datetime.utcnow()

    # --------------------------------------------------------
    # Create endpoint security event.
    #
    # label and attack_type are retained only because the
    # existing database schema requires them.
    #
    # The detection engine does NOT use them for detection.
    # --------------------------------------------------------

    endpoint_event = EndpointEvent(
        event_id=event_id,
        scenario_id=request.scenario_id,
        timestamp=timestamp,
        user_id=user.user_id,
        device_id=device.device_id,
        event_type=request.event_type,
        process=request.process,
        label="normal",
        attack_type="none"
    )

    # --------------------------------------------------------
    # Create corresponding security evidence.
    #
    # provenance "demo_api" is intentionally visible during
    # the demonstration. The TrustEngine will score it based
    # on its configured provenance rules.
    # --------------------------------------------------------

    evidence = SecurityEvidence(
        evidence_id=evidence_id,
        event_id=event_id,
        scenario_id=request.scenario_id,
        source_type="endpoint",
        provenance="demo_api",
        integrity_status="valid",
        freshness_status="fresh",
        consistency_status="consistent",
        is_poisoned=False,
        poison_type="none"
    )

    try:
        # ----------------------------------------------------
        # Store both records in PostgreSQL.
        # ----------------------------------------------------

        db.add(endpoint_event)
        db.add(evidence)

        db.commit()

        db.refresh(endpoint_event)
        db.refresh(evidence)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Unable to store demonstration event: {exc}"
        )

    return {
        "status": "success",
        "message": "Demonstration security event ingested successfully.",
        "event": {
            "event_id": endpoint_event.event_id,
            "scenario_id": endpoint_event.scenario_id,
            "source_type": "endpoint",
            "timestamp": endpoint_event.timestamp,
            "user_id": endpoint_event.user_id,
            "device_id": endpoint_event.device_id,
            "event_type": endpoint_event.event_type,
            "process": endpoint_event.process
        },
        "evidence": {
            "evidence_id": evidence.evidence_id,
            "event_id": evidence.event_id,
            "provenance": evidence.provenance,
            "integrity_status": evidence.integrity_status,
            "freshness_status": evidence.freshness_status,
            "consistency_status": evidence.consistency_status
        }
    }