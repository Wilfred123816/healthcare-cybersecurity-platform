from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from Backend.app.database import get_db

from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.models.security_evidence import SecurityEvidence

from Backend.app.investigation.investigation_service import (
    InvestigationService
)


router = APIRouter(
    prefix="/api/investigation",
    tags=["Investigation"]
)


@router.get("/scenario/{scenario_id}")
def investigate_scenario(
    scenario_id: str,
    db: Session = Depends(get_db)
):
    """
    Build an investigation context for a scenario
    and return the structured investigation result.
    """


    # LOAD EVENTS

    identity_events = (
        db.query(IdentityEvent)
        .filter(
            IdentityEvent.scenario_id == scenario_id
        )
        .all()
    )

    endpoint_events = (
        db.query(EndpointEvent)
        .filter(
            EndpointEvent.scenario_id == scenario_id
        )
        .all()
    )

    network_events = (
        db.query(NetworkEvent)
        .filter(
            NetworkEvent.scenario_id == scenario_id
        )
        .all()
    )

    ehr_events = (
        db.query(EHREvent)
        .filter(
            EHREvent.scenario_id == scenario_id
        )
        .all()
    )

    evidence_records = (
        db.query(SecurityEvidence)
        .filter(
            SecurityEvidence.scenario_id == scenario_id
        )
        .all()
    )


    # CHECK WHETHER SCENARIO EXISTS

    total_events = (
        len(identity_events)
        + len(endpoint_events)
        + len(network_events)
        + len(ehr_events)
    )

    if total_events == 0:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No events found for scenario "
                f"'{scenario_id}'."
            )
        )


    # BUILD INVESTIGATION CONTEXT

    service = InvestigationService()

    context = service.build_context(
        scenario_id=scenario_id,
        identity_events=identity_events,
        endpoint_events=endpoint_events,
        network_events=network_events,
        ehr_events=ehr_events,
        evidence_records=evidence_records
    )


    # RUN INVESTIGATION REASONING

    result = service.investigate(context)


    # CONVERT RESULT TO API RESPONSE


    return {
        "scenario_id": result.scenario_id,
        "incident_detected": result.incident_detected,
        "incident_type": result.incident_type,
        "severity": result.severity,
        "summary": result.summary,

        "affected_users": result.affected_users,
        "affected_devices": result.affected_devices,
        "source_types": result.source_types,

        "findings": [
            {
                "category": finding.category,
                "severity": finding.severity,
                "description": finding.description,
                "event_ids": finding.event_ids,
            }
            for finding in result.findings
        ],

        "timeline": result.timeline,

        "evidence_quality": result.evidence_quality,

        "recommended_action": (
            result.recommended_action
        ),

        "event_count": len(context.events),
        "evidence_count": len(context.evidence),
    }