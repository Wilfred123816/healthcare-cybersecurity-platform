from dataclasses import dataclass, field


@dataclass
class InvestigationEvent:
    """
    Normalized representation of a security event
    used by the investigation layer.
    """

    event_id: str
    scenario_id: str
    source_type: str

    event_type: str = ""
    timestamp: object = None

    user_id: str = ""
    device_id: str = ""
    patient_id: str = ""

    success: object = None

    process: str = ""

    source_ip: str = ""
    destination_ip: str = ""

    bytes_out: int = 0
    protocol: str = ""

    action: str = ""
    resource_type: str = ""


@dataclass
class InvestigationEvidence:
    """
    Normalized security evidence associated with an event.
    """

    evidence_id: str
    event_id: str
    scenario_id: str
    source_type: str

    provenance: str
    integrity_status: str
    freshness_status: str
    consistency_status: str


@dataclass
class InvestigationContext:
    """
    Complete investigation context for a scenario.
    """

    scenario_id: str

    events: list[InvestigationEvent] = field(
        default_factory=list
    )

    evidence: list[InvestigationEvidence] = field(
        default_factory=list
    )


@dataclass
class InvestigationFinding:
    """
    A single investigation finding identified
    from observable event behaviour.
    """

    category: str
    severity: str
    description: str
    event_ids: list[str] = field(
        default_factory=list
    )


@dataclass
class InvestigationResult:
    """
    Structured investigation conclusion for a scenario.
    """

    scenario_id: str
    incident_detected: bool
    incident_type: str
    severity: str

    summary: str

    affected_users: list[str] = field(
        default_factory=list
    )

    affected_devices: list[str] = field(
        default_factory=list
    )

    source_types: list[str] = field(
        default_factory=list
    )

    findings: list[InvestigationFinding] = field(
        default_factory=list
    )

    timeline: list[str] = field(
        default_factory=list
    )

    evidence_quality: str = "unknown"

    recommended_action: str = ""


class InvestigationService:
    """
    Builds a normalized investigation context and
    produces a rule-based investigation conclusion.

    This service does not use:

        - ground-truth labels
        - attack_type
        - is_poisoned
        - poison_type

    Those fields remain reserved for evaluation.
    """
    # EVENT NORMALIZATION

    @staticmethod
    def normalize_event(
        event,
        source_type
    ):

        data = {
            "event_id": event.event_id,
            "scenario_id": event.scenario_id,
            "source_type": source_type,
        }

        # COMMON IDENTIFIERS

        if hasattr(event, "user_id"):
            data["user_id"] = event.user_id or ""

        if hasattr(event, "device_id"):
            data["device_id"] = event.device_id or ""

        if hasattr(event, "timestamp"):
            data["timestamp"] = event.timestamp


        # IDENTITY


        if source_type == "identity":

            data.update({
                "event_type": getattr(
                    event,
                    "event_type",
                    ""
                ) or "",

                "success": getattr(
                    event,
                    "success",
                    None
                ),

                "source_ip": getattr(
                    event,
                    "source_ip",
                    ""
                ) or "",
            })


        # ENDPOINT


        elif source_type == "endpoint":

            data.update({
                "event_type": getattr(
                    event,
                    "event_type",
                    ""
                ) or "",

                "process": getattr(
                    event,
                    "process",
                    ""
                ) or "",
            })


        # NETWORK

        elif source_type == "network":

            data.update({
                "source_ip": getattr(
                    event,
                    "source_ip",
                    ""
                ) or "",

                "destination_ip": getattr(
                    event,
                    "destination_ip",
                    ""
                ) or "",

                "bytes_out": getattr(
                    event,
                    "bytes_out",
                    0
                ) or 0,

                "protocol": getattr(
                    event,
                    "protocol",
                    ""
                ) or "",
            })

        # EHR

        elif source_type == "ehr":

            data.update({
                "patient_id": getattr(
                    event,
                    "patient_id",
                    ""
                ) or "",

                "action": getattr(
                    event,
                    "action",
                    ""
                ) or "",

                "resource_type": getattr(
                    event,
                    "resource_type",
                    ""
                ) or "",

                "event_type": getattr(
                    event,
                    "resource_type",
                    ""
                ) or "",
            })

        return InvestigationEvent(
            **data
        )

    # EVIDENCE NORMALIZATION

    @staticmethod
    def normalize_evidence(
        evidence
    ):

        return InvestigationEvidence(
            evidence_id=evidence.evidence_id,
            event_id=evidence.event_id,
            scenario_id=evidence.scenario_id,
            source_type=evidence.source_type,
            provenance=evidence.provenance,
            integrity_status=evidence.integrity_status,
            freshness_status=evidence.freshness_status,
            consistency_status=evidence.consistency_status,
        )

    # BUILD INVESTIGATION CONTEXT

    def build_context(
        self,
        scenario_id,
        identity_events,
        endpoint_events,
        network_events,
        ehr_events,
        evidence_records
    ):

        events = []

        # NORMALIZE IDENTITY EVENTS

        for event in identity_events:

            events.append(
                self.normalize_event(
                    event,
                    "identity"
                )
            )


        # NORMALIZE ENDPOINT EVENTS

        for event in endpoint_events:

            events.append(
                self.normalize_event(
                    event,
                    "endpoint"
                )
            )


        # NORMALIZE NETWORK EVENTS

        for event in network_events:

            events.append(
                self.normalize_event(
                    event,
                    "network"
                )
            )

        # NORMALIZE EHR EVENTS
        for event in ehr_events:

            events.append(
                self.normalize_event(
                    event,
                    "ehr"
                )
            )

        # NORMALIZE EVIDENCE
        evidence = []

        for record in evidence_records:

            evidence.append(
                self.normalize_evidence(
                    record
                )
            )

        # SORT EVENTS CHRONOLOGICALLY

        events.sort(
            key=lambda item: (
                item.timestamp is None,
                item.timestamp
            )
        )

        return InvestigationContext(
            scenario_id=scenario_id,
            events=events,
            evidence=evidence
        )
    # INVESTIGATION REASONING
    def investigate(
        self,
        context: InvestigationContext
    ) -> InvestigationResult:
        """
        Analyze an investigation context and produce
        a structured incident conclusion.

        The reasoning uses observable event behaviour
        and evidence quality only.
        """

        events = context.events
        evidence = context.evidence

        findings = []

        # COLLECT AFFECTED ENTITIES

        affected_users = sorted({
            event.user_id
            for event in events
            if event.user_id
        })

        affected_devices = sorted({
            event.device_id
            for event in events
            if event.device_id
        })

        source_types = sorted({
            event.source_type
            for event in events
            if event.source_type
        })

        # INDEX EVENTS BY TYPE

        failed_logins = [
            event for event in events
            if event.source_type == "identity"
            and event.event_type.lower() == "failed_login"
        ]

        privilege_changes = [
            event for event in events
            if event.source_type == "identity"
            and event.event_type.lower() == "privilege_change"
        ]

        suspicious_processes = [
            event for event in events
            if event.source_type == "endpoint"
            and event.event_type.lower() == "suspicious_process"
        ]

        mass_file_modifications = [
            event for event in events
            if event.source_type == "endpoint"
            and event.event_type.lower() == "mass_file_modify"
        ]

        ehr_activity = [
            event for event in events
            if event.source_type == "ehr"
        ]

        large_transfers = [
            event for event in events
            if event.source_type == "network"
            and event.bytes_out >= 10_000_000
        ]

        # FINDING 1: FAILED AUTHENTICATION

        if len(failed_logins) >= 2:

            findings.append(
                InvestigationFinding(
                    category="credential_activity",
                    severity="medium",
                    description=(
                        "Multiple failed authentication events "
                        "were observed for the same investigation."
                    ),
                    event_ids=[
                        event.event_id
                        for event in failed_logins
                    ]
                )
            )

        elif failed_logins:

            findings.append(
                InvestigationFinding(
                    category="authentication_anomaly",
                    severity="low",
                    description=(
                        "A failed authentication event was observed."
                    ),
                    event_ids=[
                        event.event_id
                        for event in failed_logins
                    ]
                )
            )

        # FINDING 2: PRIVILEGE CHANGE

        if privilege_changes:

            findings.append(
                InvestigationFinding(
                    category="privilege_escalation",
                    severity="high",
                    description=(
                        "A privilege change occurred during "
                        "the investigation scenario."
                    ),
                    event_ids=[
                        event.event_id
                        for event in privilege_changes
                    ]
                )
            )

        # FINDING 3: SUSPICIOUS ENDPOINT PROCESS

        if suspicious_processes:

            findings.append(
                InvestigationFinding(
                    category="endpoint_activity",
                    severity="high",
                    description=(
                        "Suspicious process activity was observed "
                        "on an endpoint associated with the scenario."
                    ),
                    event_ids=[
                        event.event_id
                        for event in suspicious_processes
                    ]
                )
            )

        # FINDING 4: MASS FILE MODIFICATION

        if mass_file_modifications:

            findings.append(
                InvestigationFinding(
                    category="file_modification",
                    severity="high",
                    description=(
                        "Mass file modification activity was observed."
                    ),
                    event_ids=[
                        event.event_id
                        for event in mass_file_modifications
                    ]
                )
            )

        # FINDING 5: LARGE DATA TRANSFER

        if large_transfers:

            findings.append(
                InvestigationFinding(
                    category="data_transfer",
                    severity="high",
                    description=(
                        "A large outbound network transfer "
                        "was observed."
                    ),
                    event_ids=[
                        event.event_id
                        for event in large_transfers
                    ]
                )
            )

        # FINDING 6: EHR ACTIVITY

        if ehr_activity:

            findings.append(
                InvestigationFinding(
                    category="ehr_activity",
                    severity="medium",
                    description=(
                        "Healthcare record activity was observed "
                        "during the investigation scenario."
                    ),
                    event_ids=[
                        event.event_id
                        for event in ehr_activity
                    ]
                )
            )

        # DETERMINE INCIDENT TYPE

        incident_type = "normal_activity"

        if (
            privilege_changes
            and suspicious_processes
        ):
            incident_type = "privilege_abuse"

        elif (
            failed_logins
            and privilege_changes
        ):
            incident_type = "credential_and_privilege_activity"

        elif (
            suspicious_processes
            and mass_file_modifications
        ):
            incident_type = "ransomware_like_activity"

        elif (
            large_transfers
            and ehr_activity
        ):
            incident_type = "potential_data_exfiltration"

        elif failed_logins:
            incident_type = "suspicious_authentication"

        elif privilege_changes:
            incident_type = "privilege_change_activity"

        elif suspicious_processes:
            incident_type = "suspicious_endpoint_activity"

        elif large_transfers:
            incident_type = "large_data_transfer"

        elif ehr_activity:
            incident_type = "ehr_activity"

        # DETERMINE INCIDENT STATUS

        incident_detected = len(findings) > 0

        # DETERMINE SEVERITY

        severity = "low"

        if any(
            finding.severity == "high"
            for finding in findings
        ):
            severity = "high"

        elif any(
            finding.severity == "medium"
            for finding in findings
        ):
            severity = "medium"

        # EVIDENCE QUALITY

        evidence_quality = self._assess_evidence_quality(
            evidence
        )

        # BUILD SUMMARY

        if incident_detected:

            summary = (
                f"Investigation of {context.scenario_id} identified "
                f"{incident_type.replace('_', ' ')} involving "
                f"{len(events)} correlated security events. "
                f"The investigation produced {len(findings)} "
                f"observable finding(s)."
            )

        else:

            summary = (
                f"Investigation of {context.scenario_id} did not "
                f"identify a significant suspicious behaviour pattern "
                f"across the available security events."
            )

        # BUILD TIMELINE

        timeline = self._build_timeline(events)

        # RECOMMENDED ACTION

        recommended_action = (
            self._recommend_action(
                incident_detected=incident_detected,
                incident_type=incident_type,
                severity=severity,
                evidence_quality=evidence_quality
            )
        )

        return InvestigationResult(
            scenario_id=context.scenario_id,
            incident_detected=incident_detected,
            incident_type=incident_type,
            severity=severity,
            summary=summary,
            affected_users=affected_users,
            affected_devices=affected_devices,
            source_types=source_types,
            findings=findings,
            timeline=timeline,
            evidence_quality=evidence_quality,
            recommended_action=recommended_action
        )

    # EVIDENCE QUALITY ASSESSMENT

    @staticmethod
    def _assess_evidence_quality(
        evidence
    ):

        if not evidence:
            return "insufficient"

        high_quality = 0

        for record in evidence:

            if (
                record.integrity_status
                in {"valid", "verified"}
                and record.freshness_status
                in {"fresh", "recent"}
                and record.consistency_status
                in {"consistent", "verified"}
                and record.provenance
                not in {"unknown", ""}
            ):
                high_quality += 1

        quality_ratio = (
            high_quality / len(evidence)
        )

        if quality_ratio >= 0.90:
            return "high"

        if quality_ratio >= 0.70:
            return "medium"

        return "low"

    # TIMELINE

    @staticmethod
    def _build_timeline(
        events
    ):

        timeline = []

        for event in events:

            timestamp = (
                str(event.timestamp)
                if event.timestamp is not None
                else "unknown time"
            )

            description = (
                event.event_type
                or event.action
                or event.resource_type
                or "security event"
            )

            timeline.append(
                f"{timestamp} | "
                f"{event.source_type} | "
                f"{description} | "
                f"{event.event_id}"
            )

        return timeline

    # RESPONSE RECOMMENDATION

    @staticmethod
    def _recommend_action(
        incident_detected,
        incident_type,
        severity,
        evidence_quality
    ):

        if not incident_detected:

            if evidence_quality in {
                "low",
                "insufficient"
            }:
                return (
                    "Continue monitoring and obtain additional "
                    "security evidence before making a final assessment."
                )

            return (
                "No immediate response is required. "
                "Continue routine monitoring."
            )

        if evidence_quality in {
            "low",
            "insufficient"
        }:
            return (
                "Verify the available evidence before taking "
                "high-impact response actions."
            )

        if severity == "high":

            return (
                "Escalate the incident for security response, "
                "validate the affected accounts and endpoints, "
                "and investigate related activity before containment."
            )

        if incident_type == "suspicious_authentication":

            return (
                "Review the affected account authentication activity "
                "and verify whether the observed login behaviour "
                "was authorized."
            )

        if incident_type == "ehr_activity":

            return (
                "Review the affected user's healthcare record activity "
                "and verify that the access was authorized."
            )

        return (
            "Escalate for analyst review and investigate "
            "related events before taking response actions."
        )