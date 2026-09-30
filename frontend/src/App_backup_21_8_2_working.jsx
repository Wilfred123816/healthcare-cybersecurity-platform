import { useEffect, useState } from "react";
import api from "./api";
import "./App.css";

function App() {
  const [events, setEvents] = useState([]);
  const [health, setHealth] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
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
      console.error(err);
      setError("Unable to load dashboard data.");
    } finally {
      setLoading(false);
    }
  }

  const overview = dashboard?.overview;
  const threatCategories = dashboard?.threat_categories;

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
          <button className="nav-item active">
            <span>□</span>
            Overview
          </button>

          <button className="nav-item">
            <span>◈</span>
            Security Events
          </button>

          <button className="nav-item">
            <span>⚠</span>
            Threat Detection
          </button>

          <button className="nav-item">
            <span>◆</span>
            Evidence Trust
          </button>

          <button className="nav-item">
            <span>⌕</span>
            Investigation
          </button>

          <button className="nav-item">
            <span>↳</span>
            Attack Paths
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot"></span>

            <div>
              <strong>System Online</strong>
              <small>
                {health ? "API connected" : "API unavailable"}
              </small>
            </div>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <h1>Security Overview</h1>

            <p>
              Healthcare cybersecurity monitoring and threat intelligence
            </p>
          </div>

          <button
            className="refresh-button"
            onClick={loadDashboard}
            disabled={loading}
          >
            ↻ {loading ? "Refreshing..." : "Refresh"}
          </button>
        </header>

        {error && (
          <div className="error-message">
            {error}
          </div>
        )}

        {loading && !dashboard ? (
          <div className="loading">
            Loading security data...
          </div>
        ) : (
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

            {/*STATISTICS CARDS*/}

            <section className="stats-grid">
              <div className="stat-card">
                <div className="stat-label">
                  Total Events
                </div>

                <div className="stat-value">
                  {overview?.total_events ?? 0}
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
                  {overview?.threats_detected ?? 0}
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
                  {overview?.confirmed_threats ?? 0}
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
                  {dashboard?.scenario_count ?? 0}
                </div>

                <div className="stat-description">
                  Correlated security scenarios
                </div>
              </div>
            </section>

            {/* MAIN DASHBOARD PANELS*/}

            <section className="dashboard-grid">
              <div className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Recent Security Events</h2>

                    <p>
                      Latest events received from the backend
                    </p>
                  </div>

                  <span className="panel-badge">
                    {events.length} events
                  </span>
                </div>

                <div className="event-list">
                  {events.slice(0, 8).map((event) => (
                    <div
                      className="event-row"
                      key={event.event_id}
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

              {/*SECURITY SUMMARY*/}

              <div className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Security Summary</h2>

                    <p>
                      Current platform assessment
                    </p>
                  </div>
                </div>

                <div className="summary-list">
                  <div className="summary-item">
                    <span>Normal activity</span>

                    <strong>
                      {overview?.normal_events ?? 0}
                    </strong>
                  </div>

                  <div className="summary-item">
                    <span>Detected threats</span>

                    <strong className="danger-text">
                      {overview?.threats_detected ?? 0}
                    </strong>
                  </div>

                  <div className="summary-item">
                    <span>Confirmed threats</span>

                    <strong className="danger-text">
                      {overview?.confirmed_threats ?? 0}
                    </strong>
                  </div>

                  <div className="summary-item">
                    <span>Probable threats</span>

                    <strong className="warning-text">
                      {overview?.probable_threats ?? 0}
                    </strong>
                  </div>

                  <div className="summary-item">
                    <span>Low-trust threats</span>

                    <strong>
                      {overview?.low_trust_threats ?? 0}
                    </strong>
                  </div>
                </div>

                <div className="security-note">
                  <strong>
                    Trust-aware detection
                  </strong>

                  <p>
                    Threat decisions combine observable
                    behaviour with evidence trust to reduce
                    unreliable security alerts.
                  </p>
                </div>
              </div>
            </section>

            {/*THREAT INTELLIGENCE*/}


            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Threat Intelligence</h2>

                  <p>
                    Detected attack categories from the
                    operational detection pipeline
                  </p>
                </div>
              </div>

              <div className="threat-grid">
                <div className="threat-card">
                  <span>
                    Credential Abuse
                  </span>

                  <strong>
                    {threatCategories?.credential_abuse ?? 0}
                  </strong>
                </div>

                <div className="threat-card">
                  <span>
                    Privilege Abuse
                  </span>

                  <strong>
                    {threatCategories?.privilege_abuse ?? 0}
                  </strong>
                </div>

                <div className="threat-card">
                  <span>
                    Data Exfiltration
                  </span>

                  <strong>
                    {threatCategories?.data_exfiltration ?? 0}
                  </strong>
                </div>

                <div className="threat-card">
                  <span>
                    Ransomware
                  </span>

                  <strong>
                    {threatCategories?.ransomware ?? 0}
                  </strong>
                </div>
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
}

export default App;