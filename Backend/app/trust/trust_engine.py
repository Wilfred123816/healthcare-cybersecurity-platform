from dataclasses import dataclass


@dataclass
class TrustResult:
    evidence_id: str
    event_id: str
    scenario_id: str
    source_type: str

    trust_score: float
    trust_level: str

    provenance: str
    provenance_score: float

    integrity_status: str
    integrity_score: float

    freshness_status: str
    freshness_score: float

    consistency_status: str
    consistency_score: float

    reasons: list[str]


class TrustEngine:
    """
    Evidence trust evaluation engine.

    The engine evaluates the reliability of security evidence using
    observable evidence-quality characteristics.

    It deliberately does NOT use:
        - is_poisoned
        - poison_type
        - label
        - attack_type

    These fields are reserved for later evaluation and benchmarking.
    """

    PROVENANCE_SCORES = {
        "synthetic_generator": 100,
        "system": 100,
        "security_sensor": 100,
        "identity_provider": 95,
        "endpoint_sensor": 95,
        "network_sensor": 95,
        "ehr_system": 95,
        "unknown": 40,
    }

    INTEGRITY_SCORES = {
        "valid": 100,
        "verified": 100,
        "invalid": 20,
        "failed": 20,
        "unknown": 40,
    }

    FRESHNESS_SCORES = {
        "fresh": 100,
        "recent": 90,
        "stale": 40,
        "expired": 20,
        "unknown": 40,
    }

    CONSISTENCY_SCORES = {
        "consistent": 100,
        "verified": 100,
        "inconsistent": 20,
        "conflicting": 20,
        "unknown": 40,
    }

    def _normalize_value(self, value) -> str:
        """
        Convert an evidence attribute into a normalized string.

        None or empty values are represented as 'unknown'.
        """
        if value is None:
            return "unknown"

        normalized_value = str(value).strip().lower()

        if not normalized_value:
            return "unknown"

        return normalized_value

    def _lookup_score(self, value, score_map) -> float:
        """
        Convert an evidence attribute into a normalized trust score.
        """
        normalized_value = self._normalize_value(value)

        return score_map.get(
            normalized_value,
            score_map["unknown"]
        )

    def evaluate(self, evidence) -> TrustResult:
        """
        Evaluate the trustworthiness of a single evidence record.
        """

        # NORMALIZE ORIGINAL EVIDENCE ATTRIBUTES

        provenance = self._normalize_value(
            evidence.provenance
        )

        integrity_status = self._normalize_value(
            evidence.integrity_status
        )

        freshness_status = self._normalize_value(
            evidence.freshness_status
        )

        consistency_status = self._normalize_value(
            evidence.consistency_status
        )

        # CALCULATE INDIVIDUAL TRUST DIMENSION SCORES

        provenance_score = self._lookup_score(
            provenance,
            self.PROVENANCE_SCORES
        )

        integrity_score = self._lookup_score(
            integrity_status,
            self.INTEGRITY_SCORES
        )

        freshness_score = self._lookup_score(
            freshness_status,
            self.FRESHNESS_SCORES
        )

        consistency_score = self._lookup_score(
            consistency_status,
            self.CONSISTENCY_SCORES
        )

        # CALCULATE OVERALL TRUST SCORE

        trust_score = (
            provenance_score * 0.25
            + integrity_score * 0.30
            + freshness_score * 0.20
            + consistency_score * 0.25
        )

        trust_score = round(
            trust_score,
            2
        )

        # CLASSIFY TRUST LEVEL

        if trust_score >= 90:
            trust_level = "high"

        elif trust_score >= 70:
            trust_level = "medium"

        else:
            trust_level = "low"

        # BUILD EXPLANATION REASONS

        reasons = []

        if provenance_score >= 90:
            reasons.append(
                "Evidence provenance is considered reliable."
            )

        elif provenance_score < 60:
            reasons.append(
                "Evidence provenance is uncertain."
            )

        if integrity_score >= 90:
            reasons.append(
                "Evidence integrity is valid."
            )

        elif integrity_score < 60:
            reasons.append(
                "Evidence integrity is questionable."
            )

        if freshness_score >= 90:
            reasons.append(
                "Evidence is sufficiently fresh."
            )

        elif freshness_score < 60:
            reasons.append(
                "Evidence may be stale or outdated."
            )

        if consistency_score >= 90:
            reasons.append(
                "Evidence is consistent with related information."
            )

        elif consistency_score < 60:
            reasons.append(
                "Evidence contains consistency concerns."
            )

        if not reasons:
            reasons.append(
                "No strong evidence-quality indicators were identified."
            )

        # RETURN COMPLETE TRUST RESULT

        return TrustResult(
            evidence_id=evidence.evidence_id,
            event_id=evidence.event_id,
            scenario_id=evidence.scenario_id,
            source_type=evidence.source_type,

            trust_score=trust_score,
            trust_level=trust_level,

            provenance=provenance,
            provenance_score=provenance_score,

            integrity_status=integrity_status,
            integrity_score=integrity_score,

            freshness_status=freshness_status,
            freshness_score=freshness_score,

            consistency_status=consistency_status,
            consistency_score=consistency_score,

            reasons=reasons,
        )