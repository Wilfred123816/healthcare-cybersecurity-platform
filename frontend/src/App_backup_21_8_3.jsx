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

  const [activeView, setActiveView] = useState("overview");
  const [loading, setLoading] = useState(true);
  const [detectionLoading, setDetectionLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    loadDashboard();
  }, []);

  async function loadDashboard() {
    try {
      setLoading(true);
      setError("");

      const [healthResponse, eventsResponse, dashboardResponse] =
        await Promise.all([
          api.get("/api/health"),
          api.get("/api/unified/events"),
          api.get("/api/dashboard/summary"),
        ]);

      setHealth(healthResponse.data);
      setEvents(eventsResponse.data);
      setDashboard(dashboardResponse.data);
    } catch (err) {
      console.error(err);
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

      const [detectionResponse, trustAwareResponse] = await Promise.all([
        api.get(`/api/detection/event/${event.event_id}`),
        api.get(`/api/trust-aware/event/${event.event_id}`),
      ]);

      setDetection(detectionResponse.data);
      setTrustAware(trustAwareResponse.data);
    } catch (err) {
      console.error(err);
      setError("Unable to load threat detection results.");
      setDetection(null);
      setTrustAware(null);
    } finally {
      setDetectionLoading(false);
    }
  }

  function handleNavigation(view) {
    setActiveView(view);

    if (view === "overview") {
      setSelectedEvent(null);
      setDetection(null);
      setTrustAware(null);
    }
  }

  const overview = dashboard?.overview || {};
  const trust = dashboard?.trust || {};
  const threatCategories = dashboard?.threat_categories || {};

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
              activeView === "overview" ? "active" : ""
            }`}
            onClick={() => handleNavigation("overview")}
          >
            <span>□</span>
            Overview
          </button>

          <button
            className={`nav-item ${
              activeView === "events" ? "active" : ""
            }`}
            onClick={() => handleNavigation("events")}
          >
            <span>◈</span>
            Security Events
          </button>

          <button
            className={`nav-item ${
              activeView === "detection" ? "active" : ""
            }`}
            onClick={() => handleNavigation("detection")}
          >
            <span>⚠</span>
            Threat Detection
          </button>

          <button
            className={`nav-item ${
              activeView === "trust" ? "active" : ""
            }`}
            onClick={() => handleNavigation("trust")}
          >
            <span>◆</span>
            Evidence Trust
          </button>

          <button
            className={`nav-item ${
              activeView === "investigation" ? "active" : ""
            }`}
            onClick={() => handleNavigation("investigation")}
          >
            <span>⌕</span>
            Investigation
          </button>

          <button
            className={`nav-item ${
              activeView === "attack-path" ? "active" : ""
            }`}
            onClick={() => handleNavigation("attack-path")}
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
                : "Security Overview"}
            </h1>

            <p>
              {activeView === "detection"
                ? "Observable behaviour analysis and trust-aware threat classification"
                : "Healthcare cybersecurity monitoring and threat intelligence"}
            </p>
          </div>

          <button className="refresh-button" onClick={loadDashboard}>
            ↻ Refresh
          </button>
        </header>

        {error && <div className="error-message">{error}</div>}

        {loading ? (
          <div className="loading">Loading security data...</div>
        ) : (
          <>
            {activeView === "overview" && (
              <>
                <section className="status-banner">
                  <div>
                    <span className="status-dot"></span>
                    <strong>
                      Healthcare Cybersecurity Platform is operational
                    </strong>
                  </div>

                  <span className="api-status">
                    API: {health ? "Connected" : "Unavailable"}
                  </span>
                </section>

                <section className="stats-grid">
                  <div className="stat-card">
                    <div className="stat-label">Total Events</div>
                    <div className="stat-value">
                      {overview.total_events ?? 0}
                    </div>
                    <div className="stat-description">
                      Security events monitored
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">Threats Detected</div>
                    <div className="stat-value threat-value">
                      {overview.threats_detected ?? 0}
                    </div>
                    <div className="stat-description">
                      Events identified as threats
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">Confirmed Threats</div>
                    <div className="stat-value confirmed-value">
                      {overview.confirmed_threats ?? 0}
                    </div>
                    <div className="stat-description">
                      High-trust confirmed incidents
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">Active Scenarios</div>
                    <div className="stat-value">
                      {dashboard?.scenario_count ?? 0}
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
                        <h2>Recent Security Events</h2>
                        <p>Latest events received from the backend</p>
                      </div>

                      <span className="panel-badge">
                        {events.length} events
                      </span>
                    </div>

                    <div className="event-list">
                      {events.slice(0, 8).map((event) => (
                        <div className="event-row" key={event.event_id}>
                          <div className="event-icon">
                            {event.source_type === "identity"
                              ? "ID"
                              : event.source_type === "endpoint"
                              ? "EP"
                              : event.source_type === "network"
                              ? "NW"
                              : "EH"}
                          </div>

                          <div className="event-details">
                            <strong>{event.event_type}</strong>
                            <span>
                              {event.source_type} · {event.event_id}
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
                        <h2>Security Summary</h2>
                        <p>Current platform assessment</p>
                      </div>
                    </div>

                    <div className="summary-list">
                      <div className="summary-item">
                        <span>Normal activity</span>
                        <strong>{overview.normal_events ?? 0}</strong>
                      </div>

                      <div className="summary-item">
                        <span>Detected threats</span>
                        <strong className="danger-text">
                          {overview.threats_detected ?? 0}
                        </strong>
                      </div>

                      <div className="summary-item">
                        <span>Confirmed threats</span>
                        <strong className="danger-text">
                          {overview.confirmed_threats ?? 0}
                        </strong>
                      </div>

                      <div className="summary-item">
                        <span>Probable threats</span>
                        <strong className="warning-text">
                          {overview.probable_threats ?? 0}
                        </strong>
                      </div>

                      <div className="summary-item">
                        <span>Low-trust threats</span>
                        <strong>{overview.low_trust_threats ?? 0}</strong>
                      </div>
                    </div>

                    <div className="security-note">
                      <strong>Trust-aware detection</strong>
                      <p>
                        Threat decisions combine observable behaviour with
                        evidence trust to reduce unreliable security alerts.
                      </p>
                    </div>
                  </div>
                </section>

                <section className="panel">
                  <div className="panel-header">
                    <div>
                      <h2>Threat Intelligence</h2>
                      <p>
                        Detected attack categories in the development dataset
                      </p>
                    </div>
                  </div>

                  <div className="threat-grid">
                    <div className="threat-card">
                      <span>Credential Abuse</span>
                      <strong>
                        {threatCategories.credential_abuse ?? 0}
                      </strong>
                    </div>

                    <div className="threat-card">
                      <span>Privilege Abuse</span>
                      <strong>
                        {threatCategories.privilege_abuse ?? 0}
                      </strong>
                    </div>

                    <div className="threat-card">
                      <span>Data Exfiltration</span>
                      <strong>
                        {threatCategories.data_exfiltration ?? 0}
                      </strong>
                    </div>

                    <div className="threat-card">
                      <span>Ransomware</span>
                      <strong>{threatCategories.ransomware ?? 0}</strong>
                    </div>
                  </div>
                </section>
              </>
            )}

            {activeView === "detection" && (
              <section className="dashboard-grid">
                <div className="panel">
                  <div className="panel-header">
                    <div>
                      <h2>Select Security Event</h2>
                      <p>
                        Choose an event to run the backend detection engine
                      </p>
                    </div>

                    <span className="panel-badge">
                      {events.length} events
                    </span>
                  </div>

                  <div className="event-list">
                    {events.slice(0, 20).map((event) => (
                      <button
                        className={`event-row event-select ${
                          selectedEvent?.event_id === event.event_id
                            ? "selected-event"
                            : ""
                        }`}
                        key={event.event_id}
                        onClick={() => loadDetection(event)}
                      >
                        <div className="event-icon">
                          {event.source_type === "identity"
                            ? "ID"
                            : event.source_type === "endpoint"
                            ? "EP"
                            : event.source_type === "network"
                            ? "NW"
                            : "EH"}
                        </div>

                        <div className="event-details">
                          <strong>{event.event_type}</strong>
                          <span>
                            {event.source_type} · {event.event_id}
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
                      <h2>Detection Result</h2>
                      <p>Results returned by the backend detection APIs</p>
                    </div>
                  </div>

                  {detectionLoading && (
                    <div className="loading">
                      Running threat detection...
                    </div>
                  )}

                  {!detectionLoading && !detection && (
                    <div className="security-note">
                      <strong>No event selected</strong>
                      <p>
                        Select a security event to view its detection and
                        trust-aware classification.
                      </p>
                    </div>
                  )}

                  {!detectionLoading && detection && (
                    <>
                      <div className="summary-list">
                        <div className="summary-item">
                          <span>Event ID</span>
                          <strong>{detection.event_id}</strong>
                        </div>

                        <div className="summary-item">
                          <span>Source</span>
                          <strong>{detection.source_type}</strong>
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
                          <strong>{detection.severity}</strong>
                        </div>

                        <div className="summary-item">
                          <span>Detection Type</span>
                          <strong>{detection.detection_type}</strong>
                        </div>

                        <div className="summary-item">
                          <span>Detection Score</span>
                          <strong>{detection.score}</strong>
                        </div>

                        <div className="summary-item">
                          <span>Confidence</span>
                          <strong>{detection.confidence}</strong>
                        </div>
                      </div>

                      <div className="security-note">
                        <strong>Detection Reasons</strong>

                        <ul>
                          {detection.reasons?.map((reason, index) => (
                            <li key={index}>{reason}</li>
                          ))}
                        </ul>
                      </div>

                      {trustAware && (
                        <div className="security-note">
                          <strong>Trust-Aware Classification</strong>

                          <div className="summary-list">
                            <div className="summary-item">
                              <span>Trust Score</span>
                              <strong>{trustAware.trust_score}</strong>
                            </div>

                            <div className="summary-item">
                              <span>Scenario Score</span>
                              <strong>{trustAware.scenario_score}</strong>
                            </div>

                            <div className="summary-item">
                              <span>Final Score</span>
                              <strong>{trustAware.final_score}</strong>
                            </div>

                            <div className="summary-item">
                              <span>Decision</span>
                              <strong>{trustAware.decision}</strong>
                            </div>

                            <div className="summary-item">
                              <span>Final Severity</span>
                              <strong>{trustAware.severity}</strong>
                            </div>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </section>
            )}

            {activeView === "events" && (
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Security Events</h2>
                    <p>Events retrieved directly from the backend API</p>
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
                        setActiveView("detection");
                        loadDetection(event);
                      }}
                    >
                      <div className="event-icon">
                        {event.source_type === "identity"
                          ? "ID"
                          : event.source_type === "endpoint"
                          ? "EP"
                          : event.source_type === "network"
                          ? "NW"
                          : "EH"}
                      </div>

                      <div className="event-details">
                        <strong>{event.event_type}</strong>
                        <span>
                          {event.source_type} · {event.event_id}
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

            {activeView === "trust" && (
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Evidence Trust</h2>
                    <p>Evidence quality statistics from the backend</p>
                  </div>
                </div>

                <section className="stats-grid">
                  <div className="stat-card">
                    <div className="stat-label">Total Evidence</div>
                    <div className="stat-value">
                      {trust.total_evidence ?? 0}
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">High Trust</div>
                    <div className="stat-value confirmed-value">
                      {trust.high_trust ?? 0}
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">Medium Trust</div>
                    <div className="stat-value">
                      {trust.medium_trust ?? 0}
                    </div>
                  </div>

                  <div className="stat-card">
                    <div className="stat-label">Average Trust</div>
                    <div className="stat-value">
                      {trust.average_trust ?? 0}
                    </div>
                  </div>
                </section>

                <div className="security-note">
                  <strong>Trust-aware evidence assessment</strong>
                  <p>
                    The backend evaluates provenance, integrity, freshness and
                    consistency before evidence is used in threat decisions.
                  </p>
                </div>
              </section>
            )}

            {activeView === "investigation" && (
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Investigation</h2>
                    <p>Scenario investigation interface</p>
                  </div>
                </div>

                <div className="security-note">
                  <strong>Investigation view</strong>
                  <p>
                    Select a detected event from the Threat Detection view to
                    continue with scenario investigation.
                  </p>
                </div>
              </section>
            )}

            {activeView === "attack-path" && (
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Attack Paths</h2>
                    <p>Chronological reconstruction of security scenarios</p>
                  </div>
                </div>

                <div className="security-note">
                  <strong>Attack-path view</strong>
                  <p>
                    Attack-path reconstruction will use the existing backend
                    investigation API in the next frontend step.
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