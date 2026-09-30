import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  FileSearch,
  Monitor,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  Users,
} from "lucide-react";

import "./Investigation.css";

function formatTimestamp(value) {
  if (!value) {
    return "Time not available";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function getSeverityClass(value) {
  const severity = String(
    value || ""
  ).toLowerCase();

  if (
    severity.includes("critical") ||
    severity.includes("high")
  ) {
    return "investigation-danger";
  }

  if (severity.includes("medium")) {
    return "investigation-warning";
  }

  if (severity.includes("low")) {
    return "investigation-success";
  }

  return "investigation-neutral";
}

function getFindingText(finding, index) {
  if (typeof finding === "string") {
    return finding;
  }

  return (
    finding?.title ||
    finding?.finding ||
    finding?.description ||
    `Finding ${index + 1}`
  );
}

function getFindingDescription(finding) {
  if (!finding || typeof finding !== "object") {
    return "";
  }

  return (
    finding.description ||
    finding.details ||
    finding.reason ||
    ""
  );
}

function getEntityValue(entity, fallback) {
  if (typeof entity === "string") {
    return entity;
  }

  return (
    entity?.user_id ||
    entity?.device_id ||
    entity?.id ||
    entity?.name ||
    fallback
  );
}

export default function Investigation({
  events = [],
  scenarioIds = [],
  selectedScenario,
  investigation,
  investigationLoading = false,
  onSelectScenario,
}) {
  const findings =
    investigation?.findings || [];

  const timeline =
    investigation?.timeline || [];

  const affectedUsers =
    investigation?.affected_users || [];

  const affectedDevices =
    investigation?.affected_devices || [];

  const sourceTypes =
    investigation?.source_types || [];

  const evidenceQuality =
    investigation?.evidence_quality;

  const recommendedAction =
    investigation?.recommended_action;

  return (
    <section className="investigation-page">
      {/* HEADER */}

      <div className="investigation-header">
        <div>
          <div className="investigation-eyebrow">
            <FileSearch size={15} />
            Incident Investigation Centre
          </div>

          <h1>
            Security Investigation
          </h1>

          <p>
            Analyse correlated security scenarios,
            affected entities, evidence quality and
            investigation timelines.
          </p>
        </div>

        <div className="investigation-status">
          <span className="investigation-status-dot" />

          <div>
            <strong>
              Investigation Service Online
            </strong>

            <span>
              Backend analysis available
            </span>
          </div>
        </div>
      </div>

      {/* WORKSPACE */}

      <div className="investigation-workspace">
        {/* SCENARIO LIST */}

        <div className="investigation-panel">
          <div className="investigation-panel-header">
            <div>
              <span>
                Correlated scenarios
              </span>

              <h2>
                Select Scenario
              </h2>
            </div>

            <span className="investigation-count">
              {scenarioIds.length}
            </span>
          </div>

          <div className="scenario-list">
            {scenarioIds.map(
              (scenarioId) => {
                const eventCount =
                  events.filter(
                    (event) =>
                      event.scenario_id ===
                      scenarioId
                  ).length;

                return (
                  <button
                    type="button"
                    key={scenarioId}
                    className={`scenario-row ${
                      selectedScenario ===
                      scenarioId
                        ? "selected"
                        : ""
                    }`}
                    onClick={() =>
                      onSelectScenario?.(
                        scenarioId
                      )
                    }
                  >
                    <div className="scenario-icon">
                      SC
                    </div>

                    <div className="scenario-details">
                      <strong>
                        {scenarioId}
                      </strong>

                      <span>
                        Correlated security
                        scenario
                      </span>
                    </div>

                    <div className="scenario-events">
                      {eventCount}
                      <small>
                        events
                      </small>
                    </div>
                  </button>
                );
              }
            )}
          </div>
        </div>

        {/* INVESTIGATION RESULT */}

        <div className="investigation-panel">
          <div className="investigation-panel-header">
            <div>
              <span>
                Backend investigation
              </span>

              <h2>
                Investigation Result
              </h2>
            </div>

            <ShieldCheck size={21} />
          </div>

          {investigationLoading ? (
            <div className="investigation-loading">
              <div className="investigation-spinner" />

              <strong>
                Running investigation...
              </strong>

              <span>
                Analysing the selected security
                scenario.
              </span>
            </div>
          ) : !investigation ? (
            <div className="investigation-empty">
              <ShieldAlert size={40} />

              <h3>
                No scenario selected
              </h3>

              <p>
                Select a scenario from the
                list to view the backend
                investigation results.
              </p>
            </div>
          ) : (
            <>
              <div className="investigation-hero">
                <div className="investigation-hero-icon">
                  {investigation.incident_detected ? (
                    <AlertTriangle size={25} />
                  ) : (
                    <CheckCircle2 size={25} />
                  )}
                </div>

                <div>
                  <span>
                    {investigation.incident_detected
                      ? "Incident detected"
                      : "No incident detected"}
                  </span>

                  <h3>
                    {investigation.incident_type ||
                      "Security investigation"}
                  </h3>

                  <strong
                    className={getSeverityClass(
                      investigation.severity
                    )}
                  >
                    {investigation.severity ||
                      "Severity not provided"}
                  </strong>
                </div>
              </div>

              <div className="investigation-summary-grid">
                <div>
                  <span>
                    Scenario
                  </span>

                  <strong>
                    {investigation.scenario_id ||
                      selectedScenario ||
                      "N/A"}
                  </strong>
                </div>

                <div>
                  <span>
                    Events
                  </span>

                  <strong>
                    {investigation.event_count ??
                      0}
                  </strong>
                </div>

                <div>
                  <span>
                    Evidence
                  </span>

                  <strong>
                    {investigation.evidence_count ??
                      0}
                  </strong>
                </div>

                <div>
                  <span>
                    Source types
                  </span>

                  <strong>
                    {Array.isArray(
                      sourceTypes
                    )
                      ? sourceTypes.join(
                          ", "
                        )
                      : sourceTypes ||
                        "N/A"}
                  </strong>
                </div>
              </div>

              <div className="investigation-summary-box">
                <span>
                  Investigation summary
                </span>

                <p>
                  {investigation.summary ||
                    "No investigation summary was returned by the backend."}
                </p>
              </div>
            </>
          )}
        </div>
      </div>

      {investigation && (
        <>
          {/* FINDINGS + CONTEXT */}

          <div className="investigation-two-column">
            <div className="investigation-panel">
              <div className="investigation-panel-header">
                <div>
                  <span>
                    Investigation observations
                  </span>

                  <h2>
                    Findings
                  </h2>
                </div>

                <ShieldAlert size={20} />
              </div>

              {findings.length === 0 ? (
                <div className="investigation-empty compact">
                  <CheckCircle2 size={28} />

                  <p>
                    No investigation findings
                    were returned.
                  </p>
                </div>
              ) : (
                <div className="finding-list">
                  {findings.map(
                    (finding, index) => (
                      <div
                        className="finding-item"
                        key={index}
                      >
                        <div className="finding-number">
                          {index + 1}
                        </div>

                        <div>
                          <strong>
                            {getFindingText(
                              finding,
                              index
                            )}
                          </strong>

                          {getFindingDescription(
                            finding
                          ) && (
                            <p>
                              {getFindingDescription(
                                finding
                              )}
                            </p>
                          )}
                        </div>
                      </div>
                    )
                  )}
                </div>
              )}
            </div>

            <div className="investigation-panel">
              <div className="investigation-panel-header">
                <div>
                  <span>
                    Entities involved
                  </span>

                  <h2>
                    Investigation Context
                  </h2>
                </div>

                <Users size={20} />
              </div>

              <div className="context-grid">
                <div className="context-card">
                  <div>
                    <UserRound size={17} />
                  </div>

                  <span>
                    Affected users
                  </span>

                  <strong>
                    {affectedUsers.length}
                  </strong>
                </div>

                <div className="context-card">
                  <div>
                    <Monitor size={17} />
                  </div>

                  <span>
                    Affected devices
                  </span>

                  <strong>
                    {affectedDevices.length}
                  </strong>
                </div>

                <div className="context-card">
                  <div>
                    <Database size={17} />
                  </div>

                  <span>
                    Evidence quality
                  </span>

                  <strong>
                    {typeof evidenceQuality ===
                    "object"
                      ? evidenceQuality?.classification ||
                        evidenceQuality?.trust_level ||
                        evidenceQuality?.score ||
                        "Available"
                      : evidenceQuality ||
                        "N/A"}
                  </strong>
                </div>

                <div className="context-card">
                  <div>
                    <ShieldCheck size={17} />
                  </div>

                  <span>
                    Sources
                  </span>

                  <strong>
                    {sourceTypes.length ||
                      0}
                  </strong>
                </div>
              </div>
            </div>
          </div>

          {/* TIMELINE */}

          <div className="investigation-panel">
            <div className="investigation-panel-header">
              <div>
                <span>
                  Chronological reconstruction
                </span>

                <h2>
                  Investigation Timeline
                </h2>
              </div>

              <Clock3 size={20} />
            </div>

            {timeline.length === 0 ? (
              <div className="investigation-empty compact">
                <p>
                  No timeline entries were
                  returned by the backend.
                </p>
              </div>
            ) : (
              <div className="investigation-timeline">
                {timeline.map(
                  (item, index) => {
                    const text =
                      typeof item ===
                      "string"
                        ? item
                        : item.event_id ||
                          item.description ||
                          item.event_type ||
                          `Timeline event ${
                            index + 1
                          }`;

                    const timestamp =
                      typeof item ===
                      "object"
                        ? item.timestamp ||
                          item.time ||
                          ""
                        : "";

                    const source =
                      typeof item ===
                      "object"
                        ? item.source_type ||
                          item.source ||
                          ""
                        : "";

                    return (
                      <div
                        className="timeline-item"
                        key={index}
                      >
                        <div className="timeline-marker">
                          {index + 1}
                        </div>

                        {index <
                          timeline.length -
                            1 && (
                          <div className="timeline-line" />
                        )}

                        <div className="timeline-content">
                          <strong>
                            {text}
                          </strong>

                          <span>
                            {timestamp
                              ? formatTimestamp(
                                  timestamp
                                )
                              : "Time not available"}

                            {source
                              ? ` · ${source}`
                              : ""}
                          </span>
                        </div>
                      </div>
                    );
                  }
                )}
              </div>
            )}
          </div>

          {/* ENTITIES */}

          <div className="investigation-two-column">
            <div className="investigation-panel">
              <div className="investigation-panel-header">
                <div>
                  <span>
                    Identity context
                  </span>

                  <h2>
                    Affected Users
                  </h2>
                </div>

                <UserRound size={20} />
              </div>

              {affectedUsers.length ===
              0 ? (
                <div className="investigation-empty compact">
                  <p>
                    No affected users were
                    returned.
                  </p>
                </div>
              ) : (
                <div className="entity-list">
                  {affectedUsers.map(
                    (user, index) => (
                      <div
                        className="entity-row"
                        key={index}
                      >
                        <div className="entity-icon">
                          <UserRound
                            size={16}
                          />
                        </div>

                        <div>
                          <strong>
                            {getEntityValue(
                              user,
                              "User"
                            )}
                          </strong>

                          {typeof user ===
                            "object" &&
                            (user.name ||
                              user.role) && (
                              <span>
                                {user.name ||
                                  user.role}
                              </span>
                            )}
                        </div>
                      </div>
                    )
                  )}
                </div>
              )}
            </div>

            <div className="investigation-panel">
              <div className="investigation-panel-header">
                <div>
                  <span>
                    Endpoint context
                  </span>

                  <h2>
                    Affected Devices
                  </h2>
                </div>

                <Monitor size={20} />
              </div>

              {affectedDevices.length ===
              0 ? (
                <div className="investigation-empty compact">
                  <p>
                    No affected devices were
                    returned.
                  </p>
                </div>
              ) : (
                <div className="entity-list">
                  {affectedDevices.map(
                    (
                      device,
                      index
                    ) => (
                      <div
                        className="entity-row"
                        key={index}
                      >
                        <div className="entity-icon">
                          <Monitor
                            size={16}
                          />
                        </div>

                        <div>
                          <strong>
                            {getEntityValue(
                              device,
                              "Device"
                            )}
                          </strong>

                          {typeof device ===
                            "object" &&
                            (device.device_type ||
                              device.name) && (
                              <span>
                                {device.device_type ||
                                  device.name}
                              </span>
                            )}
                        </div>
                      </div>
                    )
                  )}
                </div>
              )}
            </div>
          </div>

          {/* RECOMMENDATION */}

          <div className="investigation-panel">
            <div className="investigation-panel-header">
              <div>
                <span>
                  Backend recommendation
                </span>

                <h2>
                  Recommended Action
                </h2>
              </div>

              <ShieldCheck size={20} />
            </div>

            <div className="recommendation-box">
              <CheckCircle2 size={20} />

              <div>
                <strong>
                  Recommended Response
                </strong>

                <p>
                  {typeof recommendedAction ===
                  "object"
                    ? recommendedAction?.action ||
                      recommendedAction?.description ||
                      JSON.stringify(
                        recommendedAction
                      )
                    : recommendedAction ||
                      "No recommendation was returned."}
                </p>
              </div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}