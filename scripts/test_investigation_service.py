import sys
from pathlib import Path

# ADD PROJECT ROOT TO PYTHON PATH

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# IMPORT DATABASE

from Backend.app.database import SessionLocal

from Backend.app.models.identity_event import IdentityEvent
from Backend.app.models.endpoint_event import EndpointEvent
from Backend.app.models.network_event import NetworkEvent
from Backend.app.models.ehr_event import EHREvent
from Backend.app.models.security_evidence import SecurityEvidence

from Backend.app.investigation.investigation_service import (
    InvestigationService
)

# TEST

def main():

    db = SessionLocal()

    try:

        print()
        print("=" * 70)
        print("INVESTIGATION DATA AGGREGATION TEST")
        print("=" * 70)

        scenario_id = "SCENARIO-005"

        # LOAD SCENARIO EVENTS

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

        # DISPLAY SUMMARY

        print()
        print(f"Scenario ID: {context.scenario_id}")

        print()
        print("-" * 70)
        print("EVENT COUNTS")
        print("-" * 70)

        print(
            f"Identity events : {len(identity_events)}"
        )

        print(
            f"Endpoint events : {len(endpoint_events)}"
        )

        print(
            f"Network events  : {len(network_events)}"
        )

        print(
            f"EHR events      : {len(ehr_events)}"
        )

        print(
            f"Total events    : {len(context.events)}"
        )

        print(
            f"Evidence records: {len(context.evidence)}"
        )

        # DISPLAY NORMALIZED EVENTS

        print()
        print("-" * 70)
        print("NORMALIZED EVENTS")
        print("-" * 70)

        for event in context.events:

            print(
                f"{event.event_id} | "
                f"{event.source_type} | "
                f"{event.event_type or event.action} | "
                f"user={event.user_id} | "
                f"device={event.device_id}"
            )

        # DISPLAY EVIDENCE SUMMARY

        print()
        print("-" * 70)
        print("EVIDENCE")
        print("-" * 70)

        for evidence in context.evidence:

            print(
                f"{evidence.evidence_id} | "
                f"event={evidence.event_id} | "
                f"source={evidence.source_type} | "
                f"provenance={evidence.provenance} | "
                f"integrity={evidence.integrity_status} | "
                f"freshness={evidence.freshness_status} | "
                f"consistency={evidence.consistency_status}"
            )

        print()
        print("=" * 70)
        print("INVESTIGATION AGGREGATION TEST COMPLETE")
        print("=" * 70)

    finally:

        db.close()

# RUN

if __name__ == "__main__":
    main()