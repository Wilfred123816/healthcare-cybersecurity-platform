import sys
from pathlib import Path
from collections import Counter

# Add the project root to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from Backend.app.database import SessionLocal
from Backend.app.models.security_evidence import SecurityEvidence
from Backend.app.trust.trust_engine import TrustEngine

def main():
    db = SessionLocal()
    engine = TrustEngine()

    try:
        evidence_records = (
            db.query(SecurityEvidence)
            .order_by(SecurityEvidence.evidence_id)
            .all()
        )

        print("=" * 60)
        print("TRUST ENGINE EVALUATION")
        print("=" * 60)

        print(f"Total evidence records: {len(evidence_records)}")

        if not evidence_records:
            print("No evidence records found.")
            return

        results = []

        for evidence in evidence_records:
            result = engine.evaluate(evidence)
            results.append(result)

        trust_levels = Counter(
            result.trust_level
            for result in results
        )

        print()
        print("=" * 60)
        print("TRUST LEVEL SUMMARY")
        print("=" * 60)

        print(f"High trust   : {trust_levels.get('high', 0)}")
        print(f"Medium trust : {trust_levels.get('medium', 0)}")
        print(f"Low trust    : {trust_levels.get('low', 0)}")

        scores = [
            result.trust_score
            for result in results
        ]

        print()
        print("=" * 60)
        print("TRUST SCORE SUMMARY")
        print("=" * 60)

        print(f"Minimum score : {min(scores):.2f}")
        print(f"Maximum score : {max(scores):.2f}")
        print(f"Average score : {sum(scores) / len(scores):.2f}")

        print()
        print("=" * 60)
        print("SAMPLE TRUST RESULTS")
        print("=" * 60)

        for result in results[:10]:
            print()
            print(f"Evidence ID       : {result.evidence_id}")
            print(f"Event ID          : {result.event_id}")
            print(f"Scenario ID       : {result.scenario_id}")
            print(f"Source type       : {result.source_type}")
            print(f"Trust score       : {result.trust_score}")
            print(f"Trust level       : {result.trust_level}")
            print(f"Provenance score  : {result.provenance_score}")
            print(f"Integrity score   : {result.integrity_score}")
            print(f"Freshness score   : {result.freshness_score}")
            print(f"Consistency score : {result.consistency_score}")

            print("Reasons:")
            for reason in result.reasons:
                print(f"  - {reason}")

        print()
        print("=" * 60)
        print("POISONED-EVIDENCE EVALUATION")
        print("=" * 60)

        poisoned_records = [
            evidence
            for evidence in evidence_records
            if evidence.is_poisoned
        ]

        print(f"Poisoned records in dataset: {len(poisoned_records)}")

        if poisoned_records:
            poisoned_results = []

            for evidence in poisoned_records:
                result = engine.evaluate(evidence)
                poisoned_results.append(result)

                print()
                print(f"Evidence ID : {result.evidence_id}")
                print(f"Event ID    : {result.event_id}")
                print(f"Trust score : {result.trust_score}")
                print(f"Trust level : {result.trust_level}")
                print(f"Poison type : {evidence.poison_type}")

            poisoned_scores = [
                result.trust_score
                for result in poisoned_results
            ]

            print()
            print(
                f"Average poisoned-evidence trust score: "
                f"{sum(poisoned_scores) / len(poisoned_scores):.2f}"
            )

        print()
        print("=" * 60)
        print("TRUST ENGINE EVALUATION COMPLETE")
        print("=" * 60)

    finally:
        db.close()


if __name__ == "__main__":
    main()