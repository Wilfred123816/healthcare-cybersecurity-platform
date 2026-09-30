from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from Backend.app.database import get_db
from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent

from Backend.app.investigation.investigation_service import InvestigationService
from Backend.app.investigation.attack_path_service import AttackPathService


router = APIRouter(
    prefix="/api/investigation",
    tags=["Attack Path"],
)


@router.get("/scenario/{scenario_id}/attack-path")
def reconstruct_attack_path(
    scenario_id: str,
    db: Session = Depends(get_db),
):
    identity_events = (
        db.query(IdentityEvent)
        .filter(IdentityEvent.scenario_id == scenario_id)
        .all()
    )

    endpoint_events = (
        db.query(EndpointEvent)
        .filter(EndpointEvent.scenario_id == scenario_id)
        .all()
    )

    network_events = (
        db.query(NetworkEvent)
        .filter(NetworkEvent.scenario_id == scenario_id)
        .all()
    )

    ehr_events = (
        db.query(EHREvent)
        .filter(EHREvent.scenario_id == scenario_id)
        .all()
    )

    all_events = (
        identity_events
        + endpoint_events
        + network_events
        + ehr_events
    )

    if not all_events:
        raise HTTPException(
            status_code=404,
            detail=f"No events found for scenario '{scenario_id}'.",
        )

    investigation_service = InvestigationService()

    context = investigation_service.build_context(
        scenario_id=scenario_id,
        identity_events=identity_events,
        endpoint_events=endpoint_events,
        network_events=network_events,
        ehr_events=ehr_events,
        evidence_records=[],
    )

    attack_path_service = AttackPathService()

    result = attack_path_service.reconstruct(context)

    return {
        "scenario_id": result.scenario_id,
        "attack_path_detected": result.attack_path_detected,
        "path_type": result.path_type,
        "summary": result.summary,
        "node_count": len(result.nodes),
        "nodes": [
            {
                "node_id": node.node_id,
                "stage": node.stage,
                "source_type": node.source_type,
                "event_id": node.event_id,
                "event_type": node.event_type,
                "description": node.description,
                "timestamp": node.timestamp,
            }
            for node in result.nodes
        ],
    }
