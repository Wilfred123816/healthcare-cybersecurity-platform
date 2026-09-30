import SecurityEvents from "./components/events/SecurityEvents";
import ThreatDetection from "./components/detection/ThreatDetection";
import EvidenceTrust from "./components/trust/EvidenceTrust";
import Investigation from "./components/investigation/Investigation";
import AttackPath from "./components/attackPath/AttackPath";
import StatusState from "./components/common/StatusState";
import Dashboard from "./components/dashboard/Dashboard";
import api from "./api";
import "./App.css";
import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  FileSearch,
  GitBranch,
  LayoutDashboard,
  Menu,
  Moon,
  RefreshCw,
  ShieldCheck,
  Sun,
  X,
} from "lucide-react";

function App() {
  const [theme, setTheme] = useState(
    () =>
      localStorage.getItem(
        "healthsec-theme"
      ) || "light"
  );

  useEffect(() => {
    document.documentElement.setAttribute(
      "data-theme",
      theme
    );

    localStorage.setItem(
      "healthsec-theme",
      theme
    );
  }, [theme]);

  function toggleTheme() {
    setTheme((current) =>
      current === "dark"
        ? "light"
        : "dark"
    );
  }

  const [events, setEvents] = useState([]);
  const [health, setHealth] =
    useState(null);
  const [dashboard, setDashboard] =
    useState(null);

  const [selectedEvent, setSelectedEvent] =
    useState(null);

  const [detection, setDetection] =
    useState(null);

  const [trustAware, setTrustAware] =
    useState(null);

  const [
    selectedEvidence,
    setSelectedEvidence,
  ] = useState(null);

  const [
    evidenceTrust,
    setEvidenceTrust,
  ] = useState(null);

  const [
    selectedScenario,
    setSelectedScenario,
  ] = useState(null);

  const [
    investigation,
    setInvestigation,
  ] = useState(null);

  const [
    attackPath,
    setAttackPath,
  ] = useState(null);

  const [activeView, setActiveView] =
    useState("overview");

  const [
    mobileMenuOpen,
    setMobileMenuOpen,
  ] = useState(false);

  const [loading, setLoading] =
    useState(true);

  const [
    detectionLoading,
    setDetectionLoading,
  ] = useState(false);

  const [
    trustLoading,
    setTrustLoading,
  ] = useState(false);

  const [
    investigationLoading,
    setInvestigationLoading,
  ] = useState(false);

  const [
    attackPathLoading,
    setAttackPathLoading,
  ] = useState(false);

  const [error, setError] =
    useState("");

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

      setHealth(
        healthResponse.data
      );

      setEvents(
        eventsResponse.data
      );

      setDashboard(
        dashboardResponse.data
      );
    } catch (err) {
      console.error(
        "Dashboard loading error:",
        err
      );

      setError(
        "Unable to load dashboard data."
      );
    } finally {
      setLoading(false);
    }
  }

  async function loadDetection(event) {
    if (!event) {
      setSelectedEvent(null);
      setDetection(null);
      setTrustAware(null);
      return;
    }

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

      setDetection(
        detectionResponse.data
      );

      setTrustAware(
        trustAwareResponse.data
      );
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

      const evidenceResponse =
        await api.get(
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

      const evidence =
        evidenceList[0];

      setSelectedEvidence(
        evidence
      );

      if (!evidence.evidence_id) {
        setError(
          "Evidence was returned without an evidence ID."
        );

        return;
      }

      const trustResponse =
        await api.get(
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

      setSelectedScenario(
        scenarioId
      );

      setInvestigation(null);

      const response =
        await api.get(
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
      setInvestigationLoading(
        false
      );
    }
  }

  async function loadAttackPath(
    scenarioId
  ) {
    try {
      setAttackPathLoading(true);
      setError("");

      setSelectedScenario(
        scenarioId
      );

      setAttackPath(null);

      console.log(
        "Loading attack path for scenario:",
        scenarioId
      );

      const response =
        await api.get(
          `/api/investigation/scenario/${scenarioId}/attack-path`
        );

      console.log(
        "Attack path API response:",
        response.data
      );

      setAttackPath(
        response.data
      );
    } catch (err) {
      console.error(
        "Attack path loading error:",
        err
      );

      setError(
        err?.response?.data?.detail ||
          "Unable to load attack path information."
      );

      setAttackPath(null);
    } finally {
      setAttackPathLoading(
        false
      );
    }
  }

  function handleNavigation(view) {
    setActiveView(view);
    setMobileMenuOpen(false);
    setError("");

    if (view === "overview") {
      setSelectedEvent(null);
      setDetection(null);
      setTrustAware(null);

      setSelectedEvidence(null);
      setEvidenceTrust(null);

      setSelectedScenario(null);
      setInvestigation(null);
      setAttackPath(null);
    }

    if (view === "detection") {
      setSelectedEvidence(null);
      setEvidenceTrust(null);

      setSelectedScenario(null);
      setInvestigation(null);
      setAttackPath(null);
    }

    if (view === "trust") {
      setDetection(null);
      setTrustAware(null);

      setSelectedScenario(null);
      setInvestigation(null);
      setAttackPath(null);
    }

    if (view === "investigation") {
      setDetection(null);
      setTrustAware(null);

      setSelectedEvidence(null);
      setEvidenceTrust(null);

      setAttackPath(null);
    }

    if (view === "attack-path") {
      setDetection(null);
      setTrustAware(null);

      setSelectedEvidence(null);
      setEvidenceTrust(null);

      setInvestigation(null);
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

  const scenarioIds = [
    ...new Set(
      events
        .map(
          (event) =>
            event.scenario_id
        )
        .filter(Boolean)
    ),
  ];

  const trust =
    dashboard?.trust || {};

  return (
    <div className="app">

      {/* SIDEBAR */}

      <aside
        className={`sidebar ${
          mobileMenuOpen
            ? "mobile-open"
            : ""
        }`}
      >
        <div className="logo">
          <div className="logo-icon">
            HC
          </div>

          <div>
            <h2>
              HealthSec
            </h2>

            <span>
              Cyber Platform
            </span>
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
              handleNavigation(
                "overview"
              )
            }
          >
            <LayoutDashboard size={17} />
            Overview
          </button>

          <button
            className={`nav-item ${
              activeView === "events"
                ? "active"
                : ""
            }`}
            onClick={() =>
              handleNavigation(
                "events"
              )
            }
          >
            <Activity size={17} />
            Security Events
          </button>

          <button
            className={`nav-item ${
              activeView === "detection"
                ? "active"
                : ""
            }`}
            onClick={() =>
              handleNavigation(
                "detection"
              )
            }
          >
            <AlertTriangle size={17} />
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
            <ShieldCheck size={17} />
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
            <FileSearch size={17} />
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
            <GitBranch size={17} />
            Attack Paths
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot"></span>

            <div>
              <strong>
                System Online
              </strong>

              <small>
                API connected
              </small>
            </div>
          </div>
        </div>
      </aside>

      {mobileMenuOpen && (
        <button
          type="button"
          className="mobile-sidebar-overlay"
          onClick={() =>
            setMobileMenuOpen(false)
          }
          aria-label="Close navigation"
        />
      )}

      {/* MAIN CONTENT */}

      <main className="main-content">

        {/* TOP BAR */}

        <header className="topbar">
          <button
            type="button"
            className="mobile-menu-button"
            onClick={() =>
              setMobileMenuOpen(
                (current) => !current
              )
            }
            aria-label={
              mobileMenuOpen
                ? "Close navigation"
                : "Open navigation"
            }
          >
            {mobileMenuOpen ? (
              <X size={20} />
            ) : (
              <Menu size={20} />
            )}
          </button>

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
                : activeView === "events"
                ? "Centralised monitoring of identity, endpoint, network and EHR activity"
                : "Healthcare cybersecurity monitoring and security operations"}
            </p>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
            }}
          >
            <button
              className="refresh-button"
              onClick={toggleTheme}
              title="Toggle colour theme"
            >
              {theme === "dark" ? (
                <Sun size={15} />
              ) : (
                <Moon size={15} />
              )}

              {theme === "dark"
                ? "Light"
                : "Dark"}
            </button>

            <button
              className="refresh-button"
              onClick={loadDashboard}
              title="Refresh dashboard"
            >
              <RefreshCw size={15} />
              Refresh
            </button>
          </div>
        </header>

        {/* ERROR AND GLOBAL LOADING */}

        {error && !loading ? (
          <StatusState
            type="error"
            title="Unable to load security data"
            message={error}
            actionLabel="Retry"
            onAction={loadDashboard}
          />
        ) : loading ? (
          <StatusState
            type="loading"
            title="Loading security platform"
            message="Connecting to the healthcare cybersecurity services and loading the latest security data."
          />
        ) : (
          <>
            {/* OVERVIEW */}

            {activeView === "overview" && (
              <Dashboard
                dashboard={dashboard}
                events={events}
                health={health}
                onRefresh={loadDashboard}
                onSelectEvent={(event) => {
                  setActiveView(
                    "detection"
                  );

                  loadDetection(event);
                }}
              />
            )}

            {/* THREAT DETECTION */}

            {activeView === "detection" && (
              <>
                {!selectedEvent ? (
                  <section className="dashboard-grid">
                    <div className="panel">
                      <div className="panel-header">
                        <div>
                          <h2>
                            Select Security Event
                          </h2>

                          <p>
                            Choose an event to run
                            the backend detection
                            engine
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
                              type="button"
                              className="event-row event-select"
                              key={
                                event.event_id
                              }
                              onClick={() =>
                                loadDetection(
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
                                  {
                                    event.event_type
                                  }
                                </strong>

                                <span>
                                  {
                                    event.source_type
                                  }{" "}
                                  ·{" "}
                                  {
                                    event.event_id
                                  }
                                </span>
                              </div>

                              <div className="event-scenario">
                                {
                                  event.scenario_id ||
                                  "No scenario"
                                }
                              </div>
                            </button>
                          ))}
                      </div>
                    </div>

                    <div className="panel">
                      <div className="panel-header">
                        <div>
                          <h2>
                            Threat Detection
                          </h2>

                          <p>
                            Select a security
                            event to view
                            its detection
                            assessment
                          </p>
                        </div>
                      </div>

                      <div className="security-note">
                        <strong>
                          No event selected
                        </strong>

                        <p>
                          Select a security
                          event from the
                          list to run the
                          backend Threat
                          Detection Engine
                          and Trust-Aware
                          Detection service.
                        </p>
                      </div>
                    </div>
                  </section>
                ) : (
                  <ThreatDetection
                    selectedEvent={
                      selectedEvent
                    }
                    detection={
                      detection
                    }
                    trustAware={
                      trustAware
                    }
                    detectionLoading={
                      detectionLoading
                    }
                    trustLoading={
                      trustLoading
                    }
                    onSelectEvent={(
                      event
                    ) => {
                      if (!event) {
                        setSelectedEvent(
                          null
                        );

                        setDetection(
                          null
                        );

                        setTrustAware(
                          null
                        );

                        return;
                      }

                      loadDetection(
                        event
                      );
                    }}
                  />
                )}
              </>
            )}

            {/* SECURITY EVENTS */}

            {activeView === "events" && (
              <SecurityEvents
                events={events}
                loading={loading}
                onRefresh={
                  loadDashboard
                }
                onSelectEvent={(event) => {
                  setActiveView(
                    "detection"
                  );

                  loadDetection(event);
                }}
              />
            )}

            {/* EVIDENCE TRUST */}

            {activeView === "trust" && (
              <EvidenceTrust
                trust={trust}
                events={events}
                selectedEvidence={
                  selectedEvidence
                }
                evidenceTrust={
                  evidenceTrust
                }
                trustLoading={
                  trustLoading
                }
                onSelectEvidence={(
                  event
                ) => {
                  loadEvidenceTrust(
                    event
                  );
                }}
              />
            )}

            {/* INVESTIGATION */}

            {activeView ===
              "investigation" && (
              <Investigation
                events={events}
                scenarioIds={
                  scenarioIds
                }
                selectedScenario={
                  selectedScenario
                }
                investigation={
                  investigation
                }
                investigationLoading={
                  investigationLoading
                }
                onSelectScenario={(
                  scenarioId
                ) => {
                  if (!scenarioId) {
                    setSelectedScenario(
                      null
                    );

                    setInvestigation(
                      null
                    );

                    return;
                  }

                  loadInvestigation(
                    scenarioId
                  );
                }}
              />
            )}

            {/* ATTACK PATHS */}

            {activeView === "attack-path" && (
              <AttackPath
                events={events}
                scenarioIds={
                  scenarioIds
                }
                selectedScenario={
                  selectedScenario
                }
                attackPath={
                  attackPath
                }
                attackPathLoading={
                  attackPathLoading
                }
                onSelectScenario={(
                  scenarioId
                ) => {
                  if (!scenarioId) {
                    setSelectedScenario(
                      null
                    );

                    setAttackPath(
                      null
                    );

                    return;
                  }

                  loadAttackPath(
                    scenarioId
                  );
                }}
              />
            )}
          </>
        )}
      </main>
    </div>
  );
}

export default App;