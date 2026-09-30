from dataclasses import dataclass


@dataclass
class TrustAwareResult:
    event_id: str
    scenario_id: str
    source_type: str

    threat_detected: bool
    original_detection: bool
    scenario_detection: bool

    detection_score: int
    scenario_score: int
    trust_score: float

    final_score: float
    decision: str
    severity: str
    confidence: float

    reasons: list[str]


class TrustAwareDetector:
    """
    Combines event-level detection, scenario-level correlation,
    and evidence trust into a final security assessment.

    The detector itself does not access ground-truth fields such as:

        - label
        - attack_type
        - is_poisoned
        - poison_type

    Those fields remain reserved for evaluation and benchmarking.
    """

    def evaluate(
        self,
        detection_result,
        trust_result,
        scenario_result=None
    ):

        detection_score = detection_result.score
        trust_score = trust_result.trust_score

        scenario_score = 0
        scenario_detection = False

        if scenario_result is not None:
            scenario_score = scenario_result.score
            scenario_detection = (
                scenario_result.threat_detected
            )

        # COMBINE EVENT AND SCENARIO DETECTION

        combined_detection_score = max(
            detection_score,
            scenario_score
        )

        original_detection = (
            detection_result.threat_detected
            or scenario_detection
        )

        reasons = []

        if detection_result.threat_detected:
            reasons.append(
                "Event-level threat detection identified "
                "suspicious behaviour."
            )

        if scenario_detection:
            reasons.append(
                "Scenario-level correlation identified "
                "a multi-event suspicious behaviour pattern."
            )

        if not original_detection:
            reasons.append(
                "Neither event-level detection nor scenario "
                "correlation identified a threat."
            )

        # TRUST-AWARE SCORE

        final_score = (
            combined_detection_score * 0.60
            + trust_score * 0.40
        )

        final_score = round(
            final_score,
            2
        )

        # FINAL DECISION

        if original_detection and trust_score >= 90:

            threat_detected = True
            decision = "confirmed_threat"

            if combined_detection_score >= 80:
                severity = "high"
            else:
                severity = "medium"

            confidence = min(
                0.98,
                0.60 + (final_score / 250)
            )

            reasons.append(
                "Threat indicators are supported by "
                "highly trusted evidence."
            )

        elif original_detection and trust_score >= 70:

            threat_detected = True
            decision = "probable_threat"

            severity = "medium"

            confidence = min(
                0.90,
                0.50 + (final_score / 250)
            )

            reasons.append(
                "Threat indicators are supported by "
                "moderately trusted evidence."
            )

            reasons.append(
                "Additional verification is recommended "
                "before high-impact response."
            )

        elif original_detection and trust_score < 70:

            threat_detected = False
            decision = "requires_verification"

            severity = "low"

            confidence = 0.40

            reasons.append(
                "Threat indicators were detected, but "
                "evidence trust is low."
            )

            reasons.append(
                "The result should be verified before "
                "treating it as a confirmed threat."
            )

        elif not original_detection and trust_score >= 70:

            threat_detected = False
            decision = "normal_activity"

            severity = "low"

            confidence = max(
                0.10,
                min(
                    0.85,
                    trust_score / 100
                )
            )

            reasons.append(
                "Evidence has sufficient trust to support "
                "the normal assessment."
            )

        else:

            threat_detected = False
            decision = "insufficient_evidence"

            severity = "low"

            confidence = 0.25

            reasons.append(
                "Evidence trust is low, so the normal "
                "assessment is uncertain."
            )

        return TrustAwareResult(
            event_id=detection_result.event_id,
            scenario_id=detection_result.scenario_id,
            source_type=detection_result.source_type,

            threat_detected=threat_detected,
            original_detection=original_detection,
            scenario_detection=scenario_detection,

            detection_score=detection_score,
            scenario_score=scenario_score,
            trust_score=trust_score,

            final_score=final_score,
            decision=decision,
            severity=severity,
            confidence=round(
                confidence,
                2
            ),

            reasons=reasons
        )