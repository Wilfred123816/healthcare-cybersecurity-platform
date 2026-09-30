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
from Backend.app.detection.scenario_correlator import ScenarioThreatCorrelator

from Backend.app.trust.trust_engine import TrustEngine
from Backend.app.trust.trust_aware_detector import TrustAwareDetector


router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"]
)


def convert_to_detection_event(event, source_type):
    """
    Convert a database event into the common event structure
    required by the detection and correlation engines.
    """

    return SimpleNamespace(
        event_id=event.event_id,
        scenario_id=event.scenario_id,
        source_type=source_type,
        timestamp=event.timestamp,

        event_type=getattr(
            event,
            "event_type",
            None
        ) or (
            "ehr_activity"
            if source_type == "ehr"
            else "network_activity"
            if source_type == "network"
            else ""
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

        protocol=getattr(
            event,
            "protocol",
            None
        ),

        action=getattr(
            event,
            "action",
            None
        ),

        resource_type=getattr(
            event,
            "resource_type",
            None
        ),
    )


def get_all_events(db: Session):
    """
    Retrieve all security events from PostgreSQL
    and convert them to the common detection format.
    """

    events = []

    identity_events = db.query(IdentityEvent).all()
    endpoint_events = db.query(EndpointEvent).all()
    network_events = db.query(NetworkEvent).all()
    ehr_events = db.query(EHREvent).all()

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


def get_scenario_events(events):
    """
    Group events by scenario for scenario-level correlation.
    """

    scenarios = {}

    for event in events:
        scenario_id = event.scenario_id

        if scenario_id not in scenarios:
            scenarios[scenario_id] = []

        scenarios[scenario_id].append(event)

    return scenarios


def get_dashboard_detection_results(db, events):
    """
    Run the complete trust-aware detection pipeline.

    This function deliberately does not use ground-truth labels
    or poison metadata for operational detection decisions.
    """

    detection_engine = ThreatDetectionEngine()
    correlation_engine = ScenarioThreatCorrelator()
    trust_engine = TrustEngine()
    trust_aware_engine = TrustAwareDetector()

    scenario_groups = get_scenario_events(events)

    # Calculate scenario correlation once per scenario.
    scenario_results = {}

    for scenario_id, scenario_events in scenario_groups.items():
        scenario_results[scenario_id] = (
            correlation_engine.correlate(
                scenario_events
            )
        )

    results = []

    for event in events:

        # Event-level detection
        detection_result = detection_engine.detect(
            event
        )

        # Scenario-level correlation
        scenario_result = scenario_results.get(
            event.scenario_id
        )

        # Evidence for this event
        evidence = (
            db.query(SecurityEvidence)
            .filter(
                SecurityEvidence.event_id == event.event_id
            )
            .first()
        )

        if evidence is None:
            continue

        # Evidence trust
        trust_result = trust_engine.evaluate(
            evidence
        )

        # Final trust-aware decision
        final_result = trust_aware_engine.evaluate(
            detection_result,
            trust_result,
            scenario_result
        )

        results.append(
            {
                "event": event,
                "detection": detection_result,
                "trust": trust_result,
                "final": final_result,
            }
        )

    return results


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

        if event.source_type in summary:
            summary[event.source_type] += 1

    return summary


def get_scenario_summary(events):
    """
    Summarise scenarios using actual database events.
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

        scenarios[scenario_id]["event_count"] += 1

        scenarios[scenario_id]["source_types"].add(
            event.source_type
        )

    results = []

    for scenario in scenarios.values():

        results.append(
            {
                "scenario_id": scenario["scenario_id"],
                "event_count": scenario["event_count"],
                "source_types": sorted(
                    list(
                        scenario["source_types"]
                    )
                ),
            }
        )

    results.sort(
        key=lambda item: item["event_count"],
        reverse=True
    )

    return results


def get_threat_category_summary(results):
    """
    Produce operational threat categories from observable
    detection behaviour.

    Ground-truth attack labels are deliberately not used here.
    """

    categories = {
        "credential_abuse": 0,
        "privilege_abuse": 0,
        "data_exfiltration": 0,
        "ransomware": 0,
    }

    counted_events = set()

    for item in results:

        final_result = item["final"]
        detection_result = item["detection"]
        event = item["event"]

        if not final_result.threat_detected:
            continue

        event_id = event.event_id

        if event_id in counted_events:
            continue

        counted_events.add(event_id)

        event_type = (
            getattr(
                event,
                "event_type",
                ""
            )
            or ""
        ).lower()

        detection_type = (
            getattr(
                detection_result,
                "detection_type",
                ""
            )
            or ""
        ).lower()

        if (
            event_type in {
                "failed_login",
                "login",
            }
            or
            detection_type
            == "suspicious_authentication"
        ):
            categories["credential_abuse"] += 1

        elif (
            event_type in {
                "privilege_change",
                "privileged_activity",
            }
            or
            detection_type
            in {
                "privilege_change_activity",
                "privileged_activity",
            }
        ):
            categories["privilege_abuse"] += 1

        elif (
            detection_type
            in {
                "large_data_transfer",
                "elevated_data_transfer",
                "unusual_ehr_access",
            }
        ):
            categories["data_exfiltration"] += 1

        elif (
            detection_type
            in {
                "file_encryption_activity",
                "mass_file_modification",
            }
        ):
            categories["ransomware"] += 1

    return categories


@router.get("/summary")
def dashboard_summary(
    db: Session = Depends(get_db)
):

    # Load real events from PostgreSQL.
    events = get_all_events(db)

    # Run the complete detection/trust pipeline.
    results = get_dashboard_detection_results(
        db,
        events
    )

    total_events = len(events)

    confirmed_threats = 0
    probable_threats = 0
    low_trust_threats = 0
    normal_events = 0

    high_severity = 0
    medium_severity = 0
    low_severity = 0

    trust_scores = []

    for item in results:

        final_result = item["final"]
        trust_result = item["trust"]

        trust_scores.append(
            trust_result.trust_score
        )

        if final_result.threat_detected:

            if final_result.decision == "confirmed_threat":
                confirmed_threats += 1

            elif final_result.decision == "probable_threat":
                probable_threats += 1

            elif final_result.decision == "requires_verification":
                low_trust_threats += 1

        else:
            normal_events += 1

        if final_result.severity == "high":
            high_severity += 1

        elif final_result.severity == "medium":
            medium_severity += 1

        else:
            low_severity += 1

    threats_detected = (
        confirmed_threats
        + probable_threats
        + low_trust_threats
    )

    if trust_scores:

        average_trust = round(
            sum(trust_scores)
            / len(trust_scores),
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

    scenario_summary = get_scenario_summary(
        events
    )

    source_summary = get_source_summary(
        events
    )

    threat_categories = get_threat_category_summary(
        results
    )

    return {

        "status": "success",

        "overview": {

            "total_events": total_events,

            "threats_detected": threats_detected,

            "confirmed_threats": confirmed_threats,

            "probable_threats": probable_threats,

            "low_trust_threats": low_trust_threats,

            "normal_events": normal_events,

            "high_severity": high_severity,

            "medium_severity": medium_severity,

            "low_severity": low_severity,
        },

        "trust": {

            "total_evidence": len(
                results
            ),

            "high_trust": sum(
                1
                for item in results
                if item["trust"].trust_score >= 90
            ),

            "medium_trust": sum(
                1
                for item in results
                if 70 <= item["trust"].trust_score < 90
            ),

            "low_trust": sum(
                1
                for item in results
                if item["trust"].trust_score < 70
            ),

            "average_trust": average_trust,

            "minimum_trust": minimum_trust,

            "maximum_trust": maximum_trust,
        },

        "events_by_source": source_summary,

        "scenario_count": len(
            scenario_summary
        ),

        "top_scenarios": scenario_summary[:10],

        "threat_categories": threat_categories,
    }