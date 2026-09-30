from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from Backend.app.database import get_db
from Backend.app.models.security_evidence import SecurityEvidence
from Backend.app.trust.trust_engine import TrustEngine


router = APIRouter(
    prefix="/api/trust",
    tags=["Trust Evaluation"]
)


@router.get("/evidence/{evidence_id}")
def evaluate_evidence(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    """
    Evaluate the trustworthiness of a single security evidence record.
    """

    evidence = (
        db.query(SecurityEvidence)
        .filter(
            SecurityEvidence.evidence_id == evidence_id
        )
        .first()
    )

    if evidence is None:
        raise HTTPException(
            status_code=404,
            detail=f"Evidence {evidence_id} was not found."
        )

    engine = TrustEngine()

    result = engine.evaluate(evidence)

    return {
        "evidence_id": result.evidence_id,
        "event_id": result.event_id,
        "scenario_id": result.scenario_id,
        "source_type": result.source_type,

        "trust_score": result.trust_score,
        "trust_level": result.trust_level,

        "provenance": result.provenance,
        "provenance_score": result.provenance_score,

        "integrity_status": result.integrity_status,
        "integrity_score": result.integrity_score,

        "freshness_status": result.freshness_status,
        "freshness_score": result.freshness_score,

        "consistency_status": result.consistency_status,
        "consistency_score": result.consistency_score,

        "reasons": result.reasons,
    }