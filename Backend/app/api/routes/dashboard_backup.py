from types import SimpleNamespace

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from Backend.app.database import get_db

from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.models.security_evidence import SecurityEvidence

from Backend.app.detection.threat_detector import ThreatDetectionEngine
from Backend.app.trust.trust_engine import TrustEngine


router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"]
)


def convert_to_detection_event(event, source_type):
    """
    Convert a database event into a common event object.

    The detection engine uses attribute-style access,
    so SimpleNamespace is used instead of a dictionary.
    """

    return SimpleNamespace(
        event_id=event.event_id,
        scenario_id=event.scenario_id,
        source_type=source_type,
        timestamp=event.timestamp,

        event_type=getattr(
            event,
            "event_type",
            "network_activity"
        ),

        user_id=getattr(
            event,
            "user_id",
            None
        ),

        device_id=getattr(
            event,
            "device_id",
            None
        ),

        success=getattr(
            event,
            "success",
            None
        ),

        process=getattr(
            event,
            "process",
            None
        ),

        bytes_out=getattr(
            event,
            "bytes_out",
            0
        ) or 0,

        destination_ip=getattr(
            event,
            "destination_ip",
            None
        ),

        action=getattr(
            event,
            "action",
            None
        ),
    )


def get_all_events(db: Session):
    """
    Load identity, endpoint, network and EHR events
    and convert them into a common event format.
    """

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

    events = []

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


def get_detection_summary(events):
    """
    Run the baseline threat detection engine
    and calculate dashboard statistics.
    """

    detector = ThreatDetectionEngine()

    total_events = len(events)

    threats_detected = 0
    normal_events = 0

    high_severity = 0
    medium_severity = 0
    low_severity = 0

    for event in events:

        result = detector.detect(event)

        if result.threat_detected:
            threats_detected += 1
        else:
            normal_events += 1

        if result.severity == "high":
            high_severity += 1

        elif result.severity == "medium":
            medium_severity += 1

        else:
            low_severity += 1

    return {
        "total_events": total_events,
        "threats_detected": threats_detected,
        "normal_events": normal_events,
        "high_severity": high_severity,
        "medium_severity": medium_severity,
        "low_severity": low_severity,
    }


def get_trust_result(trust_engine, evidence):
    """
    Run the trust engine.

    This helper supports the trust engine method used
    by the current project.
    """

    if hasattr(trust_engine, "calculate_trust"):
        return trust_engine.calculate_trust(evidence)

    if hasattr(trust_engine, "evaluate"):
        return trust_engine.evaluate(evidence)

    raise AttributeError(
        "TrustEngine does not contain a supported "
        "trust calculation method."
    )


def get_trust_summary(db: Session):
    """
    Calculate evidence trust statistics.
    """

    evidence_records = db.query(
        SecurityEvidence
    ).all()

    trust_engine = TrustEngine()

    high_trust = 0
    medium_trust = 0
    low_trust = 0

    trust_scores = []

    for evidence in evidence_records:

        result = get_trust_result(
            trust_engine,
            evidence
        )

        trust_score = result.trust_score

        trust_scores.append(
            trust_score
        )

        if trust_score >= 90:
            high_trust += 1

        elif trust_score >= 70:
            medium_trust += 1

        else:
            low_trust += 1

    total_evidence = len(
        evidence_records
    )

    if trust_scores:

        average_trust = round(
            sum(trust_scores) /
            len(trust_scores),
            2
        )

        minimum_trust = min(
            trust_scores
        )

        maximum_trust = max(
            trust_scores
        )

    else:

        average_trust = 0
        minimum_trust = 0
        maximum_trust = 0

    return {
        "total_evidence": total_evidence,
        "high_trust": high_trust,
        "medium_trust": medium_trust,
        "low_trust": low_trust,
        "average_trust": average_trust,
        "minimum_trust": minimum_trust,
        "maximum_trust": maximum_trust,
    }


def get_source_summary(events):
    """
    Count events by security data source.
    """

    summary = {
        "identity": 0,
        "endpoint": 0,
        "network": 0,
        "ehr": 0,
    }

    for event in events:

        source_type = event.source_type

        if source_type in summary:
            summary[source_type] += 1

    return summary


def get_scenario_summary(events):
    """
    Group events by scenario.
    """

    scenarios = {}

    for event in events:

        scenario_id = event.scenario_id

        if scenario_id not in scenarios:

            scenarios[scenario_id] = {
                "scenario_id": scenario_id,
                "event_count": 0,
                "source_types": set(),
            }

        scenarios[
            scenario_id
        ]["event_count"] += 1

        scenarios[
            scenario_id
        ]["source_types"].add(
            event.source_type
        )

    results = []

    for scenario in scenarios.values():

        results.append(
            {
                "scenario_id":
                    scenario["scenario_id"],

                "event_count":
                    scenario["event_count"],

                "source_types":
                    sorted(
                        list(
                            scenario[
                                "source_types"
                            ]
                        )
                    ),
            }
        )

    results.sort(
        key=lambda item:
            item["event_count"],
        reverse=True
    )

    return results


@router.get("/summary")
def dashboard_summary(
    db: Session = Depends(get_db)
):
    """
    Main dashboard summary endpoint.

    Returns:

    - total events
    - detected threats
    - normal events
    - severity distribution
    - evidence trust statistics
    - event source distribution
    - scenario information
    """

    events = get_all_events(
        db
    )

    detection_summary = get_detection_summary(
        events
    )

    trust_summary = get_trust_summary(
        db
    )

    source_summary = get_source_summary(
        events
    )

    scenario_summary = get_scenario_summary(
        events
    )

    return {

        "status": "success",

        "overview": {

            "total_events":
                detection_summary[
                    "total_events"
                ],

            "threats_detected":
                detection_summary[
                    "threats_detected"
                ],

            "normal_events":
                detection_summary[
                    "normal_events"
                ],

            "high_severity":
                detection_summary[
                    "high_severity"
                ],

            "medium_severity":
                detection_summary[
                    "medium_severity"
                ],

            "low_severity":
                detection_summary[
                    "low_severity"
                ],
        },

        "trust":
            trust_summary,

        "events_by_source":
            source_summary,

        "scenario_count":
            len(
                scenario_summary
            ),

        "top_scenarios":
            scenario_summary[:10],
    }