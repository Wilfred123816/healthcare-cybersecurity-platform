from dataclasses import dataclass


@dataclass
class ScenarioCorrelationResult:
    scenario_id: str
    threat_detected: bool
    severity: str
    detection_type: str
    confidence: float
    score: int
    reasons: list[str]


class ScenarioThreatCorrelator:
    """
    Correlates observable behaviours across multiple events
    belonging to the same scenario.

    This component does NOT use:
        - ground-truth labels
        - attack_type

    It relies only on observable event characteristics.
    """

    def correlate(self, events) -> ScenarioCorrelationResult:

        if not events:
            return ScenarioCorrelationResult(
                scenario_id="UNKNOWN",
                threat_detected=False,
                severity="low",
                detection_type="normal_activity",
                confidence=0.10,
                score=0,
                reasons=["No events were provided."]
            )

        scenario_id = events[0].scenario_id

        score = 0
        reasons = []
        detection_types = set()

        identity_failed = False
        identity_privilege_change = False

        endpoint_suspicious = False
        endpoint_encryption = False
        endpoint_mass_modify = False
        endpoint_privileged = False

        network_large_transfer = False
        network_elevated_transfer = False

        ehr_reads = 0
        ehr_updates = 0
        ehr_bulk_access = False

        # EXTRACT OBSERVABLE BEHAVIOURS

        for event in events:

            source_type = getattr(
                event,
                "source_type",
                ""
            )

            # IDENTITY
            if source_type == "identity":

                success = getattr(
                    event,
                    "success",
                    None
                )

                event_type = (
                    getattr(
                        event,
                        "event_type",
                        ""
                    ) or ""
                ).lower()

                if success is False:
                    identity_failed = True

                if event_type == "privilege_change":
                    identity_privilege_change = True

            # ENDPOINT
            elif source_type == "endpoint":

                event_type = (
                    getattr(
                        event,
                        "event_type",
                        ""
                    ) or ""
                ).lower()

                process = (
                    getattr(
                        event,
                        "process",
                        ""
                    ) or ""
                ).lower()

                if event_type == "suspicious_process":
                    endpoint_suspicious = True

                    if "encryption" in process:
                        endpoint_encryption = True

                if event_type == "mass_file_modify":
                    endpoint_mass_modify = True

                if event_type == "privileged_activity":
                    endpoint_privileged = True

            # NETWORK
            elif source_type == "network":

                bytes_out = getattr(
                    event,
                    "bytes_out",
                    0
                ) or 0

                if bytes_out >= 10_000_000:
                    network_large_transfer = True

                elif bytes_out >= 1_000_000:
                    network_elevated_transfer = True

            # EHR
            elif source_type == "ehr":

                action = (
                    getattr(
                        event,
                        "action",
                        ""
                    ) or ""
                ).lower()

                resource_type = (
                    getattr(
                        event,
                        "resource_type",
                        ""
                    ) or ""
                ).lower()

                if action in {
                    "read",
                    "access",
                    "view"
                }:
                    ehr_reads += 1

                if action == "update":
                    ehr_updates += 1

                if action in {
                    "bulk_export",
                    "mass_access",
                    "bulk_download"
                }:
                    ehr_bulk_access = True

        # CORRELATION RULE 1
        # AUTHENTICATION + PRIVILEGE CHANGE

        if identity_failed and identity_privilege_change:

            score += 50

            reasons.append(
                "Failed authentication activity is correlated "
                "with a privilege change."
            )

            detection_types.add(
                "authentication_privilege_correlation"
            )

        # CORRELATION RULE 2
        # SUSPICIOUS PROCESS + FILE MODIFICATION

        if endpoint_suspicious and endpoint_mass_modify:

            score += 60

            reasons.append(
                "Suspicious endpoint process activity is correlated "
                "with mass file modification."
            )

            detection_types.add(
                "endpoint_file_activity_correlation"
            )

        # CORRELATION RULE 3
        # ENCRYPTION + MASS FILE MODIFICATION

        if endpoint_encryption and endpoint_mass_modify:

            score += 40

            reasons.append(
                "File encryption activity is correlated "
                "with mass file modification."
            )

            detection_types.add(
                "file_encryption_correlation"
            )

        # CORRELATION RULE 4
        # LARGE NETWORK TRANSFER + EHR READS

        if network_large_transfer and ehr_reads >= 2:

            score += 70

            reasons.append(
                "Large outbound data transfer is correlated "
                "with multiple EHR read operations."
            )

            detection_types.add(
                "data_access_exfiltration_correlation"
            )

        # CORRELATION RULE 5
        # AUTHENTICATION + EHR ACCESS + NETWORK TRANSFER

        if (
            identity_failed
            and ehr_reads >= 2
            and network_large_transfer
        ):

            score += 30

            reasons.append(
                "Authentication activity, repeated EHR access, "
                "and large outbound transfer occur together."
            )

            detection_types.add(
                "cross_domain_data_access_correlation"
            )
        # CORRELATION RULE 6
        # PRIVILEGE CHANGE + PRIVILEGED ENDPOINT ACTIVITY

        if identity_privilege_change and endpoint_privileged:

            score += 60

            reasons.append(
                "Identity privilege change is correlated "
                "with privileged endpoint activity."
            )

            detection_types.add(
                "privilege_escalation_correlation"
            )

        # CORRELATION RULE 7
        # PRIVILEGED ACTIVITY + EHR UPDATE

        if endpoint_privileged and ehr_updates > 0:

            score += 40

            reasons.append(
                "Privileged endpoint activity is correlated "
                "with EHR record modification."
            )

            detection_types.add(
                "privileged_ehr_modification_correlation"
            )

        # CORRELATION RULE 8
        # MASS FILE MODIFICATION + NETWORK TRANSFER

        if endpoint_mass_modify and (
            network_large_transfer
            or network_elevated_transfer
        ):

            score += 50

            reasons.append(
                "Mass file modification is correlated "
                "with outbound network data transfer."
            )

            detection_types.add(
                "file_network_correlation"
            )
        # FINAL DECISION

        if score >= 80:

            threat_detected = True
            severity = "high"

            confidence = min(
                0.95,
                0.55 + (score / 200)
            )

        elif score >= 50:

            threat_detected = True
            severity = "medium"

            confidence = min(
                0.90,
                0.50 + (score / 200)
            )

        else:

            threat_detected = False
            severity = "low"

            confidence = 0.20 if score > 0 else 0.10

        if detection_types:

            detection_type = "+".join(
                sorted(detection_types)
            )

        else:

            detection_type = "normal_activity"

        if not reasons:

            reasons.append(
                "No multi-event suspicious behaviour pattern "
                "was identified."
            )

        return ScenarioCorrelationResult(
            scenario_id=scenario_id,
            threat_detected=threat_detected,
            severity=severity,
            detection_type=detection_type,
            confidence=round(confidence, 2),
            score=score,
            reasons=reasons
        )