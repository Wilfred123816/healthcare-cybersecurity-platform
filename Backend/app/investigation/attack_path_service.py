from dataclasses import dataclass


@dataclass
class AttackPathNode:
    node_id: int
    stage: str
    source_type: str
    event_id: str
    event_type: str
    description: str
    timestamp: str


@dataclass
class AttackPathResult:
    scenario_id: str
    attack_path_detected: bool
    path_type: str
    nodes: list[AttackPathNode]
    summary: str


class AttackPathService:

    def reconstruct(self, context):
        events = sorted(
            context.events,
            key=lambda event: event.timestamp
        )

        nodes = []

        for index, event in enumerate(events, start=1):
            nodes.append(
                AttackPathNode(
                    node_id=index,
                    stage=self._determine_stage(event),
                    source_type=event.source_type,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    description=self._event_description(event),
                    timestamp=str(event.timestamp),
                )
            )

        path_type = self._classify_path(events)

        attack_path_detected = path_type != "normal_activity"

        if attack_path_detected:
            summary = (
                f"Attack-path reconstruction for {context.scenario_id} "
                f"identified a {path_type.replace('_', ' ')} pattern "
                f"across {len(nodes)} correlated security events."
            )
        else:
            summary = (
                f"Attack-path reconstruction for {context.scenario_id} "
                f"did not identify a clear attack pattern across "
                f"{len(nodes)} security events."
            )

        return AttackPathResult(
            scenario_id=context.scenario_id,
            attack_path_detected=attack_path_detected,
            path_type=path_type,
            nodes=nodes,
            summary=summary,
        )

    def _determine_stage(self, event):
        event_type = (event.event_type or "").lower()
        source_type = event.source_type

        if event_type in {"failed_login", "login"}:
            return "initial_access"

        if event_type in {"privilege_change", "privileged_activity"}:
            return "privilege_escalation"

        if event_type in {
            "suspicious_process",
            "mass_file_modify",
        }:
            return "execution"

        if source_type == "network":
            return "network_activity"

        if source_type == "ehr":
            return "data_access"

        return "activity"

    def _event_description(self, event):
        event_type = (event.event_type or "").lower()

        descriptions = {
            "failed_login": (
                "A failed authentication attempt was observed."
            ),
            "login": (
                "A successful authentication event was observed."
            ),
            "privilege_change": (
                "A privilege change was observed for the investigation."
            ),
            "suspicious_process": (
                "Suspicious endpoint process activity was observed."
            ),
            "mass_file_modify": (
                "Mass file modification activity was observed."
            ),
        }

        if event_type in descriptions:
            return descriptions[event_type]

        if event.source_type == "network":
            return "Network activity was observed during the investigation."

        if event.source_type == "ehr":
            return "Healthcare record activity was observed during the investigation."

        return (
            f"{event.source_type} event '{event.event_type}' "
            "was observed during the investigation."
        )

    def _classify_path(self, events):
        event_types = {
            (event.event_type or "").lower()
            for event in events
        }

        source_types = {
            event.source_type
            for event in events
        }

        if (
            "privilege_change" in event_types
            and "suspicious_process" in event_types
        ):
            return "privilege_abuse"

        if (
            "failed_login" in event_types
            and "privilege_change" in event_types
        ):
            return "credential_to_privilege_escalation"

        if (
            "suspicious_process" in event_types
            and "mass_file_modify" in event_types
        ):
            return "ransomware_like_activity"

        if (
            "network" in source_types
            and "ehr" in source_types
        ):
            return "data_access_and_network_activity"

        if "failed_login" in event_types:
            return "authentication_anomaly"

        return "normal_activity"
