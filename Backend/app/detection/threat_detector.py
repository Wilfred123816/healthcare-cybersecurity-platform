from dataclasses import dataclass


@dataclass
class DetectionResult:
    event_id: str
    scenario_id: str
    source_type: str
    threat_detected: bool
    severity: str
    detection_type: str
    confidence: float
    score: int
    reasons: list[str]


class ThreatDetectionEngine:
    """
    Independent rule-based threat detection engine.

    The detector uses only observable event characteristics.

    It does NOT use:
        - label
        - attack_type

    Weak behaviours are treated as suspicious signals.
    Strong behaviours can trigger a threat detection.
    """

    def detect(self, event) -> DetectionResult:

        score = 0
        reasons = []
        detection_type = "normal_activity"

        # IDENTITY EVENTS

        if event.source_type == "identity":

            success = getattr(event, "success", None)

            event_type = (
                getattr(event, "event_type", "") or ""
            ).lower()

            # Failed authentication
            #
            # A single failed login is not enough to declare
            # an attack. It is retained as a suspicious signal.
            #

            if success is False:

                score += 25

                reasons.append(
                    "Identity event contains a failed authentication action."
                )

                detection_type = "suspicious_authentication"

            # Privilege change

            if event_type == "privilege_change":

                score += 60

                reasons.append(
                    "Identity event contains a privilege change."
                )

                detection_type = "privilege_change_activity"

        # ENDPOINT EVENTS

        elif event.source_type == "endpoint":

            process = (
                getattr(event, "process", "") or ""
            ).lower()

            event_type = (
                getattr(event, "event_type", "") or ""
            ).lower()

            # Suspicious process

            if event_type == "suspicious_process":

                score += 60

                reasons.append(
                    "Endpoint event represents suspicious process activity."
                )

                detection_type = "suspicious_process_activity"

            # File encryption

            if (
                event_type == "suspicious_process"
                and "encryption" in process
            ):

                score += 30

                reasons.append(
                    "Endpoint process is associated with file encryption activity."
                )

                detection_type = "file_encryption_activity"

            # Mass file modification

            if event_type == "mass_file_modify":

                score += 70

                reasons.append(
                    "Endpoint event represents mass file modification."
                )

                detection_type = "mass_file_modification"

            # Privileged activity

            if event_type == "privileged_activity":

                score += 65

                reasons.append(
                    "Endpoint event represents privileged administrative activity."
                )

                detection_type = "privileged_activity"

        # NETWORK EVENTS

        elif event.source_type == "network":

            bytes_out = getattr(
                event,
                "bytes_out",
                0
            ) or 0

            destination_ip = (
                getattr(
                    event,
                    "destination_ip",
                    ""
                ) or ""
            )

            # Very large outbound transfer

            if bytes_out >= 10_000_000:

                score += 80

                reasons.append(
                    "Network event contains unusually high outbound data volume."
                )

                detection_type = "large_data_transfer"

            # Elevated outbound transfer


            elif bytes_out >= 1_000_000:

                score += 50

                reasons.append(
                    "Network event contains elevated outbound data volume."
                )

                detection_type = "elevated_data_transfer"

            # External destination

            if destination_ip.startswith("203.0.113."):

                score += 20

                reasons.append(
                    "Network event communicates with an external destination."
                )
        # EHR EVENTS

        elif event.source_type == "ehr":

            action = (
                getattr(event, "action", "") or ""
            ).lower()

            # EHR update
            #
            # A normal user can legitimately update records,
            # therefore an update alone is not a threat.
            #

            if action == "update":

                score += 20

                reasons.append(
                    "EHR event contains a record update operation."
                )

                detection_type = "ehr_modification"

            # Bulk access

            if action in {
                "bulk_export",
                "mass_access",
                "bulk_download",
            }:

                score += 80

                reasons.append(
                    "EHR event represents potentially unusual bulk data access."
                )

                detection_type = "unusual_ehr_access"

        # FINAL DECISION

        # Only scores of 50 or higher are considered threats.
        #
        # This prevents weak signals such as:
        #   - one failed login
        #   - ordinary EHR update
        #
        # from generating large numbers of false positives.

        if score >= 50:

            threat_detected = True

            if score >= 80:
                severity = "high"
            else:
                severity = "medium"

            confidence = min(
                0.95,
                0.50 + (score / 200)
            )

        else:

            threat_detected = False
            severity = "low"

            if score > 0:
                confidence = 0.30
            else:
                confidence = 0.10

        # Normal event

        if not reasons:

            reasons.append(
                "No independent suspicious behaviour rule was triggered."
            )

        return DetectionResult(
            event_id=event.event_id,
            scenario_id=event.scenario_id,
            source_type=event.source_type,
            threat_detected=threat_detected,
            severity=severity,
            detection_type=detection_type,
            confidence=round(confidence, 2),
            score=score,
            reasons=reasons,
        )