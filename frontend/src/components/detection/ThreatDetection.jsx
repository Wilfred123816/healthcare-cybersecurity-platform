import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  CircleGauge,
  Clock3,
  Database,
  FileSearch,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  UserRound,
  Wifi,
} from "lucide-react";

import "./ThreatDetection.css";

function formatValue(
  value,
  fallback = "Not available"
) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return fallback;
  }

  return value;
}

function formatTimestamp(value) {
  if (!value) {
    return "Not available";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function getEventId(event) {
  return (
    event?.event_id ||
    event?.id ||
    "Unknown"
  );
}

function getEventType(event) {
  return (
    event?.event_type ||
    event?.type ||
    event?.event_category ||
    "Unknown"
  );
}

function getSource(event) {
  return (
    event?.source_type ||
    event?.source ||
    event?.data_source ||
    "Unknown"
  );
}

function getEventTimestamp(event) {
  return (
    event?.timestamp ||
    event?.created_at
  );
}

function getDescription(event) {
  return (
    event?.description ||
    event?.action ||
    event?.event_name ||
    `${getEventType(event)} event`
  );
}

function getSeverity(result) {
  const value = String(
    result?.severity ||
      result?.threat_severity ||
      result?.risk_level ||
      ""
  ).toLowerCase();

  if (value === "critical") {
    return "critical";
  }

  if (value === "high") {
    return "high";
  }

  if (value === "medium") {
    return "medium";
  }

  if (value === "low") {
    return "low";
  }

  return "unknown";
}

function getThreatScore(result) {
  return (
    result?.score ??
    result?.threat_score ??
    result?.detection_score ??
    null
  );
}

function getConfidence(result) {
  return (
    result?.confidence ??
    result?.confidence_score ??
    null
  );
}

function getDecision(result) {
  return (
    result?.decision ||
    result?.classification ||
    result?.threat_status ||
    result?.status ||
    "Not assessed"
  );
}

function getTrustScore(result) {
  return (
    result?.trust_score ??
    result?.evidence_trust_score ??
    null
  );
}

function getScenarioScore(result) {
  return (
    result?.scenario_score ??
    null
  );
}

function getFinalScore(result) {
  return (
    result?.final_score ??
    result?.trust_aware_score ??
    null
  );
}

function formatScore(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "—";
  }

  const number = Number(value);

  if (Number.isNaN(number)) {
    return value;
  }

  return number.toFixed(1);
}

function getSeverityClass(severity) {
  return `detection-severity-${severity}`;
}

function getDecisionClass(decision) {
  const value = String(
    decision
  ).toLowerCase();

  if (value.includes("confirmed")) {
    return "decision-confirmed";
  }

  if (value.includes("probable")) {
    return "decision-probable";
  }

  if (
    value.includes("verification") ||
    value.includes("insufficient")
  ) {
    return "decision-verification";
  }

  if (value.includes("normal")) {
    return "decision-normal";
  }

  return "decision-unknown";
}

function getSourceIcon(source) {
  const value = String(
    source
  ).toLowerCase();

  if (value.includes("network")) {
    return <Wifi size={23} />;
  }

  if (value.includes("identity")) {
    return <UserRound size={23} />;
  }

  if (value.includes("ehr")) {
    return <Database size={23} />;
  }

  if (value.includes("endpoint")) {
    return <Activity size={23} />;
  }

  return <Activity size={23} />;
}

export default function ThreatDetection({
  selectedEvent,
  detection,
  trustAware,
  detectionLoading = false,
  trustLoading = false,
  onSelectEvent,
}) {
  if (!selectedEvent) {
    return (
      <section className="threat-detection-page">
        <div className="detection-empty">
          <ShieldAlert size={42} />

          <h2>
            Select a security event
          </h2>

          <p>
            Choose an event from Security Events
            to view its detection assessment.
          </p>
        </div>
      </section>
    );
  }

  const eventId =
    getEventId(selectedEvent);

  const eventType =
    getEventType(selectedEvent);

  const source =
    getSource(selectedEvent);

  const description =
    getDescription(selectedEvent);

  const timestamp =
    getEventTimestamp(selectedEvent);

  const severity =
    getSeverity(detection);

  const threatScore =
    getThreatScore(detection);

  const confidence =
    getConfidence(detection);

  const decision =
    getDecision(trustAware);

  const trustScore =
    getTrustScore(trustAware);

  const scenarioScore =
    getScenarioScore(trustAware);

  const finalScore =
    getFinalScore(trustAware);

  return (
    <section className="threat-detection-page">

      {/* EVENT NAVIGATION */}

      <div className="detection-navigation">
        <button
          type="button"
          className="detection-back-button"
          onClick={() =>
            onSelectEvent?.(null)
          }
        >
          <ArrowLeft size={16} />
          Change Event
        </button>

        <span>
          Security assessment
        </span>
      </div>

      {/* PAGE HEADER */}

      <div className="detection-header">
        <div>
          <div className="detection-eyebrow">
            <Shield size={15} />
            Threat Detection Command Centre
          </div>

          <h1>
            Security Assessment
          </h1>

          <p>
            Review baseline detection results
            and the trust-aware security
            assessment for this event.
          </p>
        </div>

        <div className="detection-event-id">
          <span>EVENT ID</span>

          <strong>
            {eventId}
          </strong>
        </div>
      </div>

      {/* EVENT CONTEXT */}

      <div className="detection-context-card">
        <div className="detection-context-main">

          <div className="detection-context-icon">
            {getSourceIcon(source)}
          </div>

          <div>
            <span className="detection-context-label">
              Event activity
            </span>

            <h2>
              {description}
            </h2>

            <div className="detection-context-meta">
              <span>
                {eventType}
              </span>

              <span>
                {source}
              </span>

              <span>
                <Clock3 size={13} />

                {formatTimestamp(
                  timestamp
                )}
              </span>
            </div>
          </div>

        </div>
      </div>

      {/* OVERVIEW CARDS */}

      <div className="detection-overview-grid">

        <div
          className={`detection-status-card ${getSeverityClass(
            severity
          )}`}
        >
          <div className="detection-status-icon">
            <AlertTriangle size={21} />
          </div>

          <div>
            <span>
              Baseline severity
            </span>

            <strong>
              {severity === "unknown"
                ? "Not assessed"
                : severity}
            </strong>
          </div>
        </div>

        <div className="detection-score-card">
          <div className="detection-score-icon">
            <CircleGauge size={21} />
          </div>

          <div>
            <span>
              Threat score
            </span>

            <strong>
              {formatScore(
                threatScore
              )}
            </strong>
          </div>
        </div>

        <div className="detection-score-card">
          <div className="detection-score-icon">
            <Target size={21} />
          </div>

          <div>
            <span>
              Confidence
            </span>

            <strong>
              {formatScore(
                confidence
              )}
            </strong>
          </div>
        </div>

        <div
          className={`detection-status-card ${getDecisionClass(
            decision
          )}`}
        >
          <div className="detection-status-icon">
            <ShieldCheck size={21} />
          </div>

          <div>
            <span>
              Trust-aware decision
            </span>

            <strong>
              {decision}
            </strong>
          </div>
        </div>

      </div>

      {/* ASSESSMENT PANELS */}

      <div className="detection-analysis-grid">

        {/* BASELINE */}

        <div className="detection-panel">

          <div className="detection-panel-header">
            <div>
              <span>
                Baseline assessment
              </span>

              <h2>
                Threat Detection Engine
              </h2>
            </div>

            <ShieldAlert size={21} />
          </div>

          {detectionLoading ? (
            <div className="detection-loading">
              <div className="detection-spinner" />

              <span>
                Running detection assessment...
              </span>
            </div>
          ) : (
            <div className="detection-result-body">

              <div className="metric-row">
                <span>
                  Event ID
                </span>

                <strong>
                  {formatValue(
                    detection?.event_id ||
                      eventId
                  )}
                </strong>
              </div>

              <div className="metric-row">
                <span>
                  Threat detected
                </span>

                <strong
                  className={
                    detection?.threat_detected
                      ? "detection-severity-high"
                      : "detection-severity-low"
                  }
                >
                  {detection?.threat_detected
                    ? "Threat Detected"
                    : "No Threat"}
                </strong>
              </div>

              <div className="metric-row">
                <span>
                  Threat score
                </span>

                <strong>
                  {formatScore(
                    threatScore
                  )}
                </strong>
              </div>

              <div className="metric-row">
                <span>
                  Severity
                </span>

                <strong
                  className={getSeverityClass(
                    severity
                  )}
                >
                  {formatValue(
                    detection?.severity ||
                      detection?.threat_severity ||
                      detection?.risk_level,
                    "Not assessed"
                  )}
                </strong>
              </div>

              <div className="metric-row">
                <span>
                  Detection type
                </span>

                <strong>
                  {formatValue(
                    detection?.detection_type,
                    "Not specified"
                  )}
                </strong>
              </div>

              <div className="metric-row">
                <span>
                  Confidence
                </span>

                <strong>
                  {formatScore(
                    confidence
                  )}
                </strong>
              </div>

              <div className="detection-reason-box">
                <FileSearch size={18} />

                <div>
                  <span>
                    Detection result
                  </span>

                  <p>
                    {formatValue(
                      detection?.explanation ||
                        detection?.reason ||
                        detection?.message ||
                        detection?.finding,
                      detection?.threat_detected
                        ? "The backend detection engine identified suspicious activity for this event."
                        : "The backend detection engine did not identify a threat for this event."
                    )}
                  </p>
                </div>
              </div>

              {Array.isArray(
                detection?.reasons
              ) &&
                detection.reasons.length > 0 && (
                  <div className="detection-reason-box">
                    <AlertTriangle size={18} />

                    <div>
                      <span>
                        Detection reasons
                      </span>

                      <ul className="detection-reasons-list">
                        {detection.reasons.map(
                          (reason, index) => (
                            <li
                              key={index}
                            >
                              {reason}
                            </li>
                          )
                        )}
                      </ul>
                    </div>
                  </div>
                )}

            </div>
          )}
        </div>

        {/* TRUST-AWARE */}

        <div className="detection-panel trust-aware-panel">

          <div className="detection-panel-header">
            <div>
              <span>
                Evidence-aware assessment
              </span>

              <h2>
                Trust-Aware Detection
              </h2>
            </div>

            <ShieldCheck size={21} />
          </div>

          {trustLoading ? (
            <div className="detection-loading">
              <div className="detection-spinner" />

              <span>
                Evaluating evidence
                trustworthiness...
              </span>
            </div>
          ) : (
            <div className="detection-result-body">

              <div className="trust-score-display">

                <div>
                  <span>
                    Trust score
                  </span>

                  <strong>
                    {formatScore(
                      trustScore
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    Scenario score
                  </span>

                  <strong>
                    {formatScore(
                      scenarioScore
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    Final score
                  </span>

                  <strong>
                    {formatScore(
                      finalScore
                    )}
                  </strong>
                </div>

              </div>

              <div className="metric-row">
                <span>
                  Decision
                </span>

                <strong
                  className={getDecisionClass(
                    decision
                  )}
                >
                  {decision}
                </strong>
              </div>

              <div className="metric-row">
                <span>
                  Final severity
                </span>

                <strong
                  className={getSeverityClass(
                    getSeverity(
                      trustAware
                    )
                  )}
                >
                  {formatValue(
                    trustAware?.severity,
                    "Not assessed"
                  )}
                </strong>
              </div>

              <div className="detection-reason-box">
                <ShieldCheck size={18} />

                <div>
                  <span>
                    Trust-aware explanation
                  </span>

                  <p>
                    {formatValue(
                      trustAware?.explanation ||
                        trustAware?.reason ||
                        trustAware?.message ||
                        trustAware?.finding,
                      "The backend trust-aware detection service returned the assessment shown above."
                    )}
                  </p>
                </div>
              </div>

            </div>
          )}

        </div>
      </div>

      {/* EVENT DATA */}

      <div className="detection-panel">

        <div className="detection-panel-header">
          <div>
            <span>
              Event context
            </span>

            <h2>
              Observable Event Data
            </h2>
          </div>

          <Activity size={21} />
        </div>

        <div className="event-details-grid">

          <div>
            <span>
              Event ID
            </span>

            <strong>
              {eventId}
            </strong>
          </div>

          <div>
            <span>
              Event type
            </span>

            <strong>
              {eventType}
            </strong>
          </div>

          <div>
            <span>
              Source
            </span>

            <strong>
              {source}
            </strong>
          </div>

          <div>
            <span>
              Timestamp
            </span>

            <strong>
              {formatTimestamp(
                timestamp
              )}
            </strong>
          </div>

        </div>
      </div>

      {/* FOOTER NOTE */}

      <div className="detection-footer-note">
        <CheckCircle2 size={17} />

        <span>
          Detection results are generated
          from the platform's current backend
          assessment. No frontend threat
          classification is being inferred
          independently.
        </span>
      </div>

    </section>
  );
}