import { useEffect, useState } from "react";
import api from "./api";
import "./App.css";

function App() {
  const [events, setEvents] = useState([]);
  const [health, setHealth] = useState(null);
  const [dashboard, setDashboard] = useState(null);

  const [selectedEvent, setSelectedEvent] = useState(null);
  const [detection, setDetection] = useState(null);
  const [trustAware, setTrustAware] = useState(null);

  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [evidenceTrust, setEvidenceTrust] = useState(null);

  const [selectedScenario, setSelectedScenario] = useState(null);
  const [investigation, setInvestigation] = useState(null);

  const [activeView, setActiveView] = useState("overview");

  const [loading, setLoading] = useState(true);
  const [detectionLoading, setDetectionLoading] = useState(false);
  const [trustLoading, setTrustLoading] = useState(false);
  const [investigationLoading, setInvestigationLoading] =
    useState(false);

  const [error, setError] = useState("");

  useEffect(() => {
    loadDashboard();
  }, []);

  async function loadDashboard() {
    try {
      setLoading(true);
      setError("");

      const [
        healthResponse,
        eventsResponse,
        dashboardResponse,
      ] = await Promise.all([
        api.get("/api/health"),
        api.get("/api/unified/events"),
        api.get("/api/dashboard/summary"),
      ]);

      setHealth(healthResponse.data);
      setEvents(eventsResponse.data);
      setDashboard(dashboardResponse.data);
    } catch (err) {
      console.error("Dashboard loading error:", err);
      setError("Unable to load dashboard data.");
    } finally {
      setLoading(false);
    }
  }

  async function loadDetection(event) {
    try {
      setDetectionLoading(true);
      setError("");

      setSelectedEvent(event);

      const [
        detectionResponse,
        trustAwareResponse,
      ] = await Promise.all([
        api.get(
          `/api/detection/event/${event.event_id}`
        ),
        api.get(
          `/api/trust-aware/event/${event.event_id}`
        ),
      ]);

      setDetection(detectionResponse.data);
      setTrustAware(trustAwareResponse.data);
    } catch (err) {
      console.error(
        "Detection loading error:",
        err
      );

      setError(
        "Unable to load threat detection results."
      );

      setDetection(null);
      setTrustAware(null);
    } finally {
      setDetectionLoading(false);
    }
  }

  async function loadEvidenceTrust(event) {
    try {
      setTrustLoading(true);
      setError("");

      setSelectedEvent(event);
      setSelectedEvidence(null);
      setEvidenceTrust(null);

      const evidenceResponse = await api.get(
        `/api/evidence/${event.event_id}`
      );

      const responseData =
        evidenceResponse.data;

      const evidenceList =
        Array.isArray(responseData)
          ? responseData
          : responseData?.value || [];

      if (
        !Array.isArray(evidenceList) ||
        evidenceList.length === 0
      ) {
        setError(
          "No evidence was found for the selected event."
        );
        return;
      }

      const evidence = evidenceList[0];

      setSelectedEvidence(evidence);

      if (!evidence.evidence_id) {
        setError(
          "Evidence was returned without an evidence ID."
        );
        return;
      }

      const trustResponse = await api.get(
        `/api/trust/evidence/${evidence.evidence_id}`
      );

      setEvidenceTrust(
        trustResponse.data
      );
    } catch (err) {
      console.error(
        "Evidence trust error:",
        err
      );

      setError(
        err?.response?.data?.detail ||
          "Unable to load evidence trust information."
      );

      setSelectedEvidence(null);
      setEvidenceTrust(null);
    } finally {
      setTrustLoading(false);
    }
  }

  async function loadInvestigation(
    scenarioId
  ) {
    try {
      setInvestigationLoading(true);
      setError("");

      setSelectedScenario(scenarioId);
      setInvestigation(null);

      const response = await api.get(
        `/api/investigation/scenario/${scenarioId}`
      );

      setInvestigation(
        response.data
      );
    } catch (err) {
      console.error(
        "Investigation loading error:",
        err
      );

      setError(
        err?.response?.data?.detail ||
          "Unable to load investigation information."
      );

      setInvestigation(null);
    } finally {
      setInvestigationLoading(false);
    }
  }

  function handleNavigation(view) {
    setActiveView(view);
    setError("");

    if (view === "overview") {
      setSelectedEvent(null);
      setDetection(null);
      setTrustAware(null);
      setSelectedEvidence(null);
      setEvidenceTrust(null);
      setSelectedScenario(null);
      setInvestigation(null);
    }

    if (view === "detection") {
      setSelectedEvidence(null);
      setEvidenceTrust(null);
      setSelectedScenario(null);
      setInvestigation(null);
    }

    if (view === "trust") {
      setDetection(null);
      setTrustAware(null);
      setSelectedScenario(null);
      setInvestigation(null);
    }

    if (view === "investigation") {
      setDetection(null);
      setTrustAware(null);
      setSelectedEvidence(null);
      setEvidenceTrust(null);
    }
  }

  function getEventIcon(sourceType) {
    if (sourceType === "identity") {
      return "ID";
    }

    if (sourceType === "endpoint") {
      return "EP";
    }

    if (sourceType === "network") {
      return "NW";
    }

    return "EH";
  }

  /*
   * Create a unique list of scenario IDs from
   * events returned by the backend.
   */
  const scenarioIds = [
    ...new Set(
      events
        .map((event) => event.scenario_id)
        .filter(Boolean)
    ),
  ];

  /*
   * Investigation response helpers.
   *
   * These use the actual backend field names while
   * keeping the frontend tolerant of minor response
   * variations.
   */
  const investigationFindings =
    investigation?.findings || [];

  const investigationTimeline =
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

  const overview = dashboard?.overview || {};
  const trust = dashboard?.trust || {};
  const threatCategories =
    dashboard?.threat_categories || {};

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon">HC</div>

          <div>
            <h2>HealthSec</h2>
            <span>Cyber Platform</span>
          </div>
        </div>

        <nav>
          <button
            className={`nav-item ${
              activeView === "overview"
                ? "active"
                : ""
            }`}
            onClick={() =>
              handleNavigation("overview")
            }
          >
            <span>□</span>
            Overview
          </button>

          <button
            className={`nav-item ${
              activeView === "events"
                ? "active"
                : ""
            }`}
            onClick={() =>
              handleNavigation("events")
            }
          >
            <span>◈</span>
            Security Events
          </button>

          <button
            className={`nav-item ${
              activeView === "detection"
                ? "active"
                : ""
            }`}
            onClick={() =>
              handleNavigation("detection")
            }
          >
            <span>⚠</span>
            Threat Detection
          </button>

          <button
            className={`nav-item ${
              activeView === "trust"
                ? "active"
                : ""
            }`}
            onClick={() =>
              handleNavigation("trust")
            }
          >
            <span>◆</span>
            Evidence Trust
          </button>

          <button
            className={`nav-item ${
              activeView === "investigation"
                ? "active"
                : ""
            }`}
            onClick={() =>
              handleNavigation(
                "investigation"
              )
            }
          >
            <span>⌕</span>
            Investigation
          </button>

          <button
            className={`nav-item ${
              activeView === "attack-path"
                ? "active"
                : ""
            }`}
            onClick={() =>
              handleNavigation(
                "attack-path"
              )
            }
          >
            <span>↳</span>
            Attack Paths
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot"></span>

            <div>
              <strong>System Online</strong>
              <small>API connected</small>
            </div>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <h1>
              {activeView === "detection"
                ? "Threat Detection"
                : activeView === "events"
                ? "Security Events"
                : activeView === "trust"
                ? "Evidence Trust"
                : activeView ===
                  "investigation"
                ? "Investigation"
                : activeView ===
                  "attack-path"
                ? "Attack Paths"
                : "Security Overview"}
            </h1>

            <p>
              {activeView === "detection"
                ? "Observable behaviour analysis and trust-aware threat classification"
                : activeView === "trust"
                ? "Evidence provenance, integrity, freshness and consistency assessment"
                : activeView ===
                  "investigation"
                ? "Scenario investigation and incident analysis"
                : activeView ===
                  "attack-path"
                ? "Chronological reconstruction of security scenarios"
                : "Healthcare cybersecurity monitoring and threat intelligence"}
            </p>
          </div>

          <button
            className="refresh-button"
            onClick={loadDashboard}
          >
            ↻ Refresh
          </button>
        </header>

        {error && (
          <div className="error-message">
            {error}
          </div>
        )}

        {loading ? (
          <div className="loading">
            Loading security data...
          </div>
        ) : (
          <>
            {/*OVERVIEW*/}

            {activeView === "overview" && (
              <>
                <section className="status-banner">
                  <div>
                    <span className="status-dot"></span>

                    <strong>
                      Healthcare Cybersecurity Platform
                      is operational
                    </strong>
                  </div>

                  <span className="api-status">
                    API:{" "}
                    {health
                      ? "Connected"
                      : "Unavailable"}
                  </span>
                </section>

                <section className="stats-grid">
                  <div className="stat-card">
                    <div className="stat-label">
                      Total Events
                    </div>

                    <div className="stat-value">
                      {overview.total_events ?? 0}
                    </div>

                    <div className="stat-description">
                      Security events monitored
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">
                      Threats Detected
                    </div>

                    <div className="stat-value threat-value">
                      {overview.threats_detected ?? 0}
                    </div>

                    <div className="stat-description">
                      Events identified as threats
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">
                      Confirmed Threats
                    </div>

                    <div className="stat-value confirmed-value">
                      {overview.confirmed_threats ?? 0}
                    </div>

                    <div className="stat-description">
                      High-trust confirmed incidents
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">
                      Active Scenarios
                    </div>

                    <div className="stat-value">
                      {dashboard?.scenario_count ??
                        0}
                    </div>

                    <div className="stat-description">
                      Correlated security scenarios
                    </div>
                  </div>
                </section>

                <section className="dashboard-grid">
                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>
                          Recent Security Events
                        </h2>

                        <p>
                          Latest events received from
                          the backend
                        </p>
                      </div>

                      <span className="panel-badge">
                        {events.length} events
                      </span>
                    </div>

                    <div className="event-list">
                      {events
                        .slice(0, 8)
                        .map((event) => (
                          <div
                            className="event-row"
                            key={event.event_id}
                          >
                            <div className="event-icon">
                              {getEventIcon(
                                event.source_type
                              )}
                            </div>

                            <div className="event-details">
                              <strong>
                                {event.event_type}
                              </strong>

                              <span>
                                {event.source_type} ·{" "}
                                {event.event_id}
                              </span>
                            </div>

                            <div className="event-scenario">
                              {event.scenario_id}
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>

                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>
                          Security Summary
                        </h2>

                        <p>
                          Current platform
                          assessment
                        </p>
                      </div>
                    </div>

                    <div className="summary-list">
                      <div className="summary-item">
                        <span>
                          Normal activity
                        </span>

                        <strong>
                          {overview.normal_events ??
                            0}
                        </strong>
                      </div>

                      <div className="summary-item">
                        <span>
                          Detected threats
                        </span>

                        <strong className="danger-text">
                          {overview.threats_detected ??
                            0}
                        </strong>
                      </div>

                      <div className="summary-item">
                        <span>
                          Confirmed threats
                        </span>

                        <strong className="danger-text">
                          {overview.confirmed_threats ??
                            0}
                        </strong>
                      </div>

                      <div className="summary-item">
                        <span>
                          Probable threats
                        </span>

                        <strong className="warning-text">
                          {overview.probable_threats ??
                            0}
                        </strong>
                      </div>

                      <div className="summary-item">
                        <span>
                          Low-trust threats
                        </span>

                        <strong>
                          {overview.low_trust_threats ??
                            0}
                        </strong>
                      </div>
                    </div>

                    <div className="security-note">
                      <strong>
                        Trust-aware detection
                      </strong>

                      <p>
                        Threat decisions combine
                        observable behaviour with
                        evidence trust to reduce
                        unreliable security alerts.
                      </p>
                    </div>
                  </div>
                </section>

                <section className="panel">
                  <div className="panel-header">
                    <div>
                      <h2>
                        Threat Intelligence
                      </h2>

                      <p>
                        Detected attack categories in
                        the development dataset
                      </p>
                    </div>
                  </div>

                  <div className="threat-grid">
                    <div className="threat-card">
                      <span>
                        Credential Abuse
                      </span>

                      <strong>
                        {threatCategories.credential_abuse ??
                          0}
                      </strong>
                    </div>

                    <div className="threat-card">
                      <span>
                        Privilege Abuse
                      </span>

                      <strong>
                        {threatCategories.privilege_abuse ??
                          0}
                      </strong>
                    </div>

                    <div className="threat-card">
                      <span>
                        Data Exfiltration
                      </span>

                      <strong>
                        {threatCategories.data_exfiltration ??
                          0}
                      </strong>
                    </div>

                    <div className="threat-card">
                      <span>
                        Ransomware
                      </span>

                      <strong>
                        {threatCategories.ransomware ??
                          0}
                      </strong>
                    </div>
                  </div>
                </section>
              </>
            )}

            {/*THREAT DETECTION*/}

            {activeView === "detection" && (
              <section className="dashboard-grid">
                <div className="panel">
                  <div className="panel-header">
                    <div>
                      <h2>
                        Select Security Event
                      </h2>

                      <p>
                        Choose an event to run the
                        backend detection engine
                      </p>
                    </div>

                    <span className="panel-badge">
                      {events.length} events
                    </span>
                  </div>

                  <div className="event-list">
                    {events
                      .slice(0, 20)
                      .map((event) => (
                        <button
                          className={`event-row event-select ${
                            selectedEvent?.event_id ===
                            event.event_id
                              ? "selected-event"
                              : ""
                          }`}
                          key={event.event_id}
                          onClick={() =>
                            loadDetection(event)
                          }
                        >
                          <div className="event-icon">
                            {getEventIcon(
                              event.source_type
                            )}
                          </div>

                          <div className="event-details">
                            <strong>
                              {event.event_type}
                            </strong>

                            <span>
                              {event.source_type} ·{" "}
                              {event.event_id}
                            </span>
                          </div>

                          <div className="event-scenario">
                            {event.scenario_id}
                          </div>
                        </button>
                      ))}
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-header">
                    <div>
                      <h2>
                        Detection Result
                      </h2>

                      <p>
                        Results returned by the backend
                        detection APIs
                      </p>
                    </div>
                  </div>

                  {detectionLoading && (
                    <div className="loading">
                      Running threat detection...
                    </div>
                  )}

                  {!detectionLoading &&
                    !detection && (
                      <div className="security-note">
                        <strong>
                          No event selected
                        </strong>

                        <p>
                          Select a security event to view
                          its detection and trust-aware
                          classification.
                        </p>
                      </div>
                    )}

                  {!detectionLoading &&
                    detection && (
                      <>
                        <div className="summary-list">
                          <div className="summary-item">
                            <span>Event ID</span>

                            <strong>
                              {detection.event_id}
                            </strong>
                          </div>

                          <div className="summary-item">
                            <span>Source</span>

                            <strong>
                              {detection.source_type}
                            </strong>
                          </div>

                          <div className="summary-item">
                            <span>Detection</span>

                            <strong
                              className={
                                detection.threat_detected
                                  ? "danger-text"
                                  : ""
                              }
                            >
                              {detection.threat_detected
                                ? "Threat Detected"
                                : "No Threat"}
                            </strong>
                          </div>

                          <div className="summary-item">
                            <span>Severity</span>

                            <strong>
                              {detection.severity}
                            </strong>
                          </div>

                          <div className="summary-item">
                            <span>
                              Detection Type
                            </span>

                            <strong>
                              {detection.detection_type}
                            </strong>
                          </div>

                          <div className="summary-item">
                            <span>
                              Detection Score
                            </span>

                            <strong>
                              {detection.score}
                            </strong>
                          </div>

                          <div className="summary-item">
                            <span>
                              Confidence
                            </span>

                            <strong>
                              {detection.confidence}
                            </strong>
                          </div>
                        </div>

                        <div className="security-note">
                          <strong>
                            Detection Reasons
                          </strong>

                          <ul>
                            {detection.reasons?.map(
                              (
                                reason,
                                index
                              ) => (
                                <li
                                  key={
                                    index
                                  }
                                >
                                  {reason}
                                </li>
                              )
                            )}
                          </ul>
                        </div>

                        {trustAware && (
                          <div className="security-note">
                            <strong>
                              Trust-Aware Classification
                            </strong>

                            <div className="summary-list">
                              <div className="summary-item">
                                <span>
                                  Trust Score
                                </span>

                                <strong>
                                  {
                                    trustAware.trust_score
                                  }
                                </strong>
                              </div>

                              <div className="summary-item">
                                <span>
                                  Scenario Score
                                </span>

                                <strong>
                                  {
                                    trustAware.scenario_score
                                  }
                                </strong>
                              </div>

                              <div className="summary-item">
                                <span>
                                  Final Score
                                </span>

                                <strong>
                                  {
                                    trustAware.final_score
                                  }
                                </strong>
                              </div>

                              <div className="summary-item">
                                <span>
                                  Decision
                                </span>

                                <strong>
                                  {
                                    trustAware.decision
                                  }
                                </strong>
                              </div>

                              <div className="summary-item">
                                <span>
                                  Final Severity
                                </span>

                                <strong>
                                  {
                                    trustAware.severity
                                  }
                                </strong>
                              </div>
                            </div>
                          </div>
                        )}
                      </>
                    )}
                </div>
              </section>
            )}

            {/* =====================================================
                SECURITY EVENTS
            ====================================================== */}

            {activeView === "events" && (
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>
                      Security Events
                    </h2>

                    <p>
                      Events retrieved directly from
                      the backend API
                    </p>
                  </div>

                  <span className="panel-badge">
                    {events.length} events
                  </span>
                </div>

                <div className="event-list">
                  {events.map((event) => (
                    <button
                      className="event-row event-select"
                      key={event.event_id}
                      onClick={() => {
                        setActiveView(
                          "detection"
                        );

                        loadDetection(event);
                      }}
                    >
                      <div className="event-icon">
                        {getEventIcon(
                          event.source_type
                        )}
                      </div>

                      <div className="event-details">
                        <strong>
                          {event.event_type}
                        </strong>

                        <span>
                          {event.source_type} ·{" "}
                          {event.event_id}
                        </span>
                      </div>

                      <div className="event-scenario">
                        {event.scenario_id}
                      </div>
                    </button>
                  ))}
                </div>
              </section>
            )}

            {/* =====================================================
                EVIDENCE TRUST
            ====================================================== */}

            {activeView === "trust" && (
              <>
                <section className="stats-grid">
                  <div className="stat-card">
                    <div className="stat-label">
                      Total Evidence
                    </div>

                    <div className="stat-value">
                      {trust.total_evidence ?? 0}
                    </div>

                    <div className="stat-description">
                      Evidence records evaluated
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">
                      High Trust
                    </div>

                    <div className="stat-value confirmed-value">
                      {trust.high_trust ?? 0}
                    </div>

                    <div className="stat-description">
                      High-confidence evidence
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">
                      Medium Trust
                    </div>

                    <div className="stat-value">
                      {trust.medium_trust ?? 0}
                    </div>

                    <div className="stat-description">
                      Evidence requiring attention
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">
                      Low Trust
                    </div>

                    <div className="stat-value threat-value">
                      {trust.low_trust ?? 0}
                    </div>

                    <div className="stat-description">
                      Low-confidence evidence
                    </div>
                  </div>
                </section>

                <section className="dashboard-grid">
                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>
                          Select Evidence
                        </h2>

                        <p>
                          Select an event to inspect
                          its evidence trust score
                        </p>
                      </div>

                      <span className="panel-badge">
                        {events.length} events
                      </span>
                    </div>

                    <div className="event-list">
                      {events
                        .slice(0, 20)
                        .map((event) => (
                          <button
                            className={`event-row event-select ${
                              selectedEvidence?.event_id ===
                              event.event_id
                                ? "selected-event"
                                : ""
                            }`}
                            key={event.event_id}
                            onClick={() =>
                              loadEvidenceTrust(
                                event
                              )
                            }
                          >
                            <div className="event-icon">
                              {getEventIcon(
                                event.source_type
                              )}
                            </div>

                            <div className="event-details">
                              <strong>
                                {event.event_type}
                              </strong>

                              <span>
                                {event.source_type} ·{" "}
                                {event.event_id}
                              </span>
                            </div>

                            <div className="event-scenario">
                              {event.scenario_id}
                            </div>
                          </button>
                        ))}
                    </div>
                  </div>

                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>
                          Evidence Trust Result
                        </h2>

                        <p>
                          Trust assessment returned by
                          the backend TrustEngine
                        </p>
                      </div>
                    </div>

                    {trustLoading && (
                      <div className="loading">
                        Loading evidence trust...
                      </div>
                    )}

                    {!trustLoading &&
                      !evidenceTrust && (
                        <div className="security-note">
                          <strong>
                            No evidence selected
                          </strong>

                          <p>
                            Select a security event to
                            view its evidence provenance
                            and trust assessment.
                          </p>
                        </div>
                      )}

                    {!trustLoading &&
                      evidenceTrust && (
                        <>
                          <div className="summary-list">
                            <div className="summary-item">
                              <span>
                                Evidence ID
                              </span>

                              <strong>
                                {evidenceTrust.evidence_id ||
                                  selectedEvidence?.evidence_id ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Event ID
                              </span>

                              <strong>
                                {evidenceTrust.event_id ||
                                  selectedEvidence?.event_id ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Scenario ID
                              </span>

                              <strong>
                                {evidenceTrust.scenario_id ||
                                  selectedEvidence?.scenario_id ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Source Type
                              </span>

                              <strong>
                                {evidenceTrust.source_type ||
                                  selectedEvidence?.source_type ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Trust Score
                              </span>

                              <strong>
                                {evidenceTrust.trust_score ??
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Trust Classification
                              </span>

                              <strong>
                                {evidenceTrust.classification ||
                                  evidenceTrust.trust_level ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Provenance
                              </span>

                              <strong>
                                {evidenceTrust.provenance ||
                                  selectedEvidence?.provenance ||
                                  "Not returned by current evidence API"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Provenance Score
                              </span>

                              <strong>
                                {evidenceTrust.provenance_score ??
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Integrity
                              </span>

                              <strong>
                                {evidenceTrust.integrity_status ||
                                  selectedEvidence?.integrity_status ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Integrity Score
                              </span>

                              <strong>
                                {evidenceTrust.integrity_score ??
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Freshness
                              </span>

                              <strong>
                                {evidenceTrust.freshness_status ||
                                  selectedEvidence?.freshness_status ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Freshness Score
                              </span>

                              <strong>
                                {evidenceTrust.freshness_score ??
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Consistency
                              </span>

                              <strong>
                                {evidenceTrust.consistency_status ||
                                  selectedEvidence?.consistency_status ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Consistency Score
                              </span>

                              <strong>
                                {evidenceTrust.consistency_score ??
                                  "N/A"}
                              </strong>
                            </div>
                          </div>

                          <div className="security-note">
                            <strong>
                              Trust Assessment
                            </strong>

                            <p>
                              This result is calculated
                              by the backend TrustEngine
                              using evidence provenance,
                              integrity, freshness and
                              consistency. The frontend
                              does not calculate or
                              hardcode the trust score.
                            </p>
                          </div>

                          {evidenceTrust.reasons &&
                            evidenceTrust.reasons
                              .length > 0 && (
                              <div className="security-note">
                                <strong>
                                  Trust Assessment
                                  Reasons
                                </strong>

                                <ul>
                                  {evidenceTrust.reasons.map(
                                    (
                                      reason,
                                      index
                                    ) => (
                                      <li
                                        key={
                                          index
                                        }
                                      >
                                        {reason}
                                      </li>
                                    )
                                  )}
                                </ul>
                              </div>
                            )}
                        </>
                      )}
                  </div>
                </section>

                <section className="panel">
                  <div className="panel-header">
                    <div>
                      <h2>
                        Trust Statistics
                      </h2>

                      <p>
                        Current evidence quality across
                        the dataset
                      </p>
                    </div>
                  </div>

                  <div className="summary-list">
                    <div className="summary-item">
                      <span>
                        Average Trust
                      </span>

                      <strong>
                        {trust.average_trust ?? 0}
                      </strong>
                    </div>

                    <div className="summary-item">
                      <span>
                        Minimum Trust
                      </span>

                      <strong>
                        {trust.minimum_trust ?? 0}
                      </strong>
                    </div>

                    <div className="summary-item">
                      <span>
                        Maximum Trust
                      </span>

                      <strong>
                        {trust.maximum_trust ?? 0}
                      </strong>
                    </div>

                    <div className="summary-item">
                      <span>
                        High Trust Evidence
                      </span>

                      <strong>
                        {trust.high_trust ?? 0}
                      </strong>
                    </div>

                    <div className="summary-item">
                      <span>
                        Medium Trust Evidence
                      </span>

                      <strong>
                        {trust.medium_trust ?? 0}
                      </strong>
                    </div>

                    <div className="summary-item">
                      <span>
                        Low Trust Evidence
                      </span>

                      <strong>
                        {trust.low_trust ?? 0}
                      </strong>
                    </div>
                  </div>
                </section>
              </>
            )}

            {/* =====================================================
                INVESTIGATION
            ====================================================== */}

            {activeView ===
              "investigation" && (
              <>
                <section className="dashboard-grid">
                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>
                          Select Security Scenario
                        </h2>

                        <p>
                          Choose a scenario to run the
                          backend investigation service
                        </p>
                      </div>

                      <span className="panel-badge">
                        {scenarioIds.length} scenarios
                      </span>
                    </div>

                    <div className="event-list">
                      {scenarioIds.map(
                        (scenarioId) => (
                          <button
                            className={`event-row event-select ${
                              selectedScenario ===
                              scenarioId
                                ? "selected-event"
                                : ""
                            }`}
                            key={scenarioId}
                            onClick={() =>
                              loadInvestigation(
                                scenarioId
                              )
                            }
                          >
                            <div className="event-icon">
                              SC
                            </div>

                            <div className="event-details">
                              <strong>
                                {scenarioId}
                              </strong>

                              <span>
                                Correlated security
                                scenario
                              </span>
                            </div>

                            <div className="event-scenario">
                              {
                                events.filter(
                                  (event) =>
                                    event.scenario_id ===
                                    scenarioId
                                ).length
                              } events
                            </div>
                          </button>
                        )
                      )}
                    </div>
                  </div>

                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>
                          Investigation Result
                        </h2>

                        <p>
                          Results returned by the backend
                          InvestigationService
                        </p>
                      </div>
                    </div>

                    {investigationLoading && (
                      <div className="loading">
                        Running scenario investigation...
                      </div>
                    )}

                    {!investigationLoading &&
                      !investigation && (
                        <div className="security-note">
                          <strong>
                            No scenario selected
                          </strong>

                          <p>
                            Select a security scenario
                            to view its investigation
                            results.
                          </p>
                        </div>
                      )}

                    {!investigationLoading &&
                      investigation && (
                        <>
                          <div className="summary-list">
                            <div className="summary-item">
                              <span>
                                Scenario ID
                              </span>

                              <strong>
                                {investigation.scenario_id ||
                                  selectedScenario ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Incident Detected
                              </span>

                              <strong
                                className={
                                  investigation.incident_detected
                                    ? "danger-text"
                                    : ""
                                }
                              >
                                {investigation.incident_detected
                                  ? "Yes"
                                  : "No"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Incident Type
                              </span>

                              <strong>
                                {investigation.incident_type ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Severity
                              </span>

                              <strong>
                                {investigation.severity ||
                                  "N/A"}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Event Count
                              </span>

                              <strong>
                                {investigation.event_count ??
                                  0}
                              </strong>
                            </div>

                            <div className="summary-item">
                              <span>
                                Evidence Count
                              </span>

                              <strong>
                                {investigation.evidence_count ??
                                  0}
                              </strong>
                            </div>
                          </div>

                          <div className="security-note">
                            <strong>
                              Investigation Summary
                            </strong>

                            <p>
                              {investigation.summary ||
                                "No investigation summary was returned."}
                            </p>
                          </div>
                        </>
                      )}
                  </div>
                </section>

                {investigation && (
                  <>
                    <section className="dashboard-grid">
                      <div className="panel">
                        <div className="panel-header">
                          <div>
                            <h2>
                              Investigation Findings
                            </h2>

                            <p>
                              Suspicious behaviours and
                              investigation observations
                            </p>
                          </div>
                        </div>

                        {!investigationFindings.length ? (
                          <div className="security-note">
                            <strong>
                              No findings returned
                            </strong>

                            <p>
                              The backend did not return
                              any investigation findings
                              for this scenario.
                            </p>
                          </div>
                        ) : (
                          <div className="event-list">
                            {investigationFindings.map(
                              (finding, index) => {
                                const findingTitle =
                                  typeof finding ===
                                  "string"
                                    ? finding
                                    : finding.title ||
                                      finding.finding ||
                                      finding.description ||
                                      `Finding ${
                                        index + 1
                                      }`;

                                const findingDescription =
                                  typeof finding ===
                                  "object"
                                    ? finding.description ||
                                      finding.details ||
                                      finding.reason ||
                                      ""
                                    : "";

                                return (
                                  <div
                                    className="event-row"
                                    key={index}
                                  >
                                    <div className="event-icon">
                                      FI
                                    </div>

                                    <div className="event-details">
                                      <strong>
                                        {findingTitle}
                                      </strong>

                                      <span>
                                        {findingDescription}
                                      </span>
                                    </div>
                                  </div>
                                );
                              }
                            )}
                          </div>
                        )}
                      </div>

                      <div className="panel">
                        <div className="panel-header">
                          <div>
                            <h2>
                              Investigation Context
                            </h2>

                            <p>
                              Entities and sources involved
                              in the scenario
                            </p>
                          </div>
                        </div>

                        <div className="summary-list">
                          <div className="summary-item">
                            <span>
                              Affected Users
                            </span>

                            <strong>
                              {Array.isArray(
                                affectedUsers
                              )
                                ? affectedUsers.length
                                : 0}
                            </strong>
                          </div>

                          <div className="summary-item">
                            <span>
                              Affected Devices
                            </span>

                            <strong>
                              {Array.isArray(
                                affectedDevices
                              )
                                ? affectedDevices.length
                                : 0}
                            </strong>
                          </div>

                          <div className="summary-item">
                            <span>
                              Source Types
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

                          <div className="summary-item">
                            <span>
                              Evidence Quality
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
                        </div>
                      </div>
                    </section>

                    <section className="panel">
                      <div className="panel-header">
                        <div>
                          <h2>
                            Investigation Timeline
                          </h2>

                          <p>
                            Events reconstructed
                            chronologically by the backend
                          </p>
                        </div>
                      </div>

                      {!investigationTimeline.length ? (
                        <div className="security-note">
                          <strong>
                            No timeline returned
                          </strong>

                          <p>
                            The backend did not return
                            timeline entries for this
                            scenario.
                          </p>
                        </div>
                      ) : (
                        <div className="event-list">
                          {investigationTimeline.map(
                            (item, index) => {
                              const itemText =
                                typeof item ===
                                "string"
                                  ? item
                                  : item.event_id ||
                                    item.description ||
                                    item.event_type ||
                                    `Timeline event ${
                                      index + 1
                                    }`;

                              const itemTime =
                                typeof item ===
                                "object"
                                  ? item.timestamp ||
                                    item.time ||
                                    ""
                                  : "";

                              return (
                                <div
                                  className="event-row"
                                  key={index}
                                >
                                  <div className="event-icon">
                                    {index +
                                      1}
                                  </div>

                                  <div className="event-details">
                                    <strong>
                                      {itemText}
                                    </strong>

                                    <span>
                                      {itemTime}
                                    </span>
                                  </div>
                                </div>
                              );
                            }
                          )}
                        </div>
                      )}
                    </section>

                    <section className="panel">
                      <div className="panel-header">
                        <div>
                          <h2>
                            Recommended Action
                          </h2>

                          <p>
                            Response recommendation produced
                            by the backend investigation service
                          </p>
                        </div>
                      </div>

                      <div className="security-note">
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
                              "No recommendation returned."}
                        </p>
                      </div>
                    </section>

                    <section className="dashboard-grid">
                      <div className="panel">
                        <div className="panel-header">
                          <div>
                            <h2>
                              Affected Users
                            </h2>

                            <p>
                              Users associated with the
                              investigation
                            </p>
                          </div>
                        </div>

                        {!affectedUsers.length ? (
                          <div className="security-note">
                            No affected users returned.
                          </div>
                        ) : (
                          <div className="event-list">
                            {affectedUsers.map(
                              (user, index) => (
                                <div
                                  className="event-row"
                                  key={index}
                                >
                                  <div className="event-icon">
                                    US
                                  </div>

                                  <div className="event-details">
                                    <strong>
                                      {typeof user ===
                                      "string"
                                        ? user
                                        : user.user_id ||
                                          user.id ||
                                          "User"}
                                    </strong>

                                    <span>
                                      {typeof user ===
                                      "object"
                                        ? user.name ||
                                          user.role ||
                                          ""
                                        : ""}
                                    </span>
                                  </div>
                                </div>
                              )
                            )}
                          </div>
                        )}
                      </div>

                      <div className="panel">
                        <div className="panel-header">
                          <div>
                            <h2>
                              Affected Devices
                            </h2>

                            <p>
                              Devices associated with the
                              investigation
                            </p>
                          </div>
                        </div>

                        {!affectedDevices.length ? (
                          <div className="security-note">
                            No affected devices returned.
                          </div>
                        ) : (
                          <div className="event-list">
                            {affectedDevices.map(
                              (device, index) => (
                                <div
                                  className="event-row"
                                  key={index}
                                >
                                  <div className="event-icon">
                                    DV
                                  </div>

                                  <div className="event-details">
                                    <strong>
                                      {typeof device ===
                                      "string"
                                        ? device
                                        : device.device_id ||
                                          device.id ||
                                          "Device"}
                                    </strong>

                                    <span>
                                      {typeof device ===
                                      "object"
                                        ? device.device_type ||
                                          device.name ||
                                          ""
                                        : ""}
                                    </span>
                                  </div>
                                </div>
                              )
                            )}
                          </div>
                        )}
                      </div>
                    </section>
                  </>
                )}
              </>
            )}

            {/* =====================================================
                ATTACK PATH PLACEHOLDER
            ====================================================== */}

            {activeView ===
              "attack-path" && (
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>
                      Attack Paths
                    </h2>

                    <p>
                      Chronological reconstruction of
                      security scenarios
                    </p>
                  </div>
                </div>

                <div className="security-note">
                  <strong>
                    Attack-path view
                  </strong>

                  <p>
                    Attack-path reconstruction will be
                    connected to the existing backend API
                    in Step 21.8.6.
                  </p>
                </div>
              </section>
            )}
          </>
        )}
      </main>
    </div>
  );
}

export default App;