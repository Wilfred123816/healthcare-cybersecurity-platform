import StatusState from "../common/StatusState";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleGauge,
  Database,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import "./Dashboard.css";

function formatNumber(value) {
  return new Intl.NumberFormat().format(
    Number(value || 0)
  );
}

function formatTimestamp(value) {
  if (!value) {
    return "Time unavailable";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function getSourceLabel(source) {
  const labels = {
    identity: "Identity",
    endpoint: "Endpoint",
    network: "Network",
    ehr: "EHR",
  };

  return labels[source] || source || "Unknown";
}

function getSourceTone(source) {
  const tones = {
    identity: "identity",
    endpoint: "endpoint",
    network: "network",
    ehr: "ehr",
  };

  return tones[source] || "default";
}

function buildActivityTrend(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return [];
  }

  const sorted = [...events]
    .filter((event) => event.timestamp)
    .sort(
      (a, b) =>
        new Date(a.timestamp) -
        new Date(b.timestamp)
    );

  if (sorted.length === 0) {
    return [];
  }

  const bucketCount = 8;

  const bucketSize = Math.max(
    1,
    Math.ceil(sorted.length / bucketCount)
  );

  const buckets = [];

  for (
    let i = 0;
    i < sorted.length;
    i += bucketSize
  ) {
    const chunk = sorted.slice(
      i,
      i + bucketSize
    );

    if (!chunk.length) {
      continue;
    }

    const first = chunk[0];

    buckets.push({
      label: formatShortDate(
        first.timestamp
      ),
      events: chunk.length,
    });
  }

  return buckets.slice(-8);
}

function formatShortDate(value) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return date.toLocaleDateString([], {
    month: "short",
    day: "numeric",
  });
}

function buildSourceData(dashboard) {
  const sourceCounts =
    dashboard?.events_by_source || {};

  return [
    {
      name: "Identity",
      value: Number(
        sourceCounts.identity || 0
      ),
      key: "identity",
    },
    {
      name: "Endpoint",
      value: Number(
        sourceCounts.endpoint || 0
      ),
      key: "endpoint",
    },
    {
      name: "Network",
      value: Number(
        sourceCounts.network || 0
      ),
      key: "network",
    },
    {
      name: "EHR",
      value: Number(
        sourceCounts.ehr || 0
      ),
      key: "ehr",
    },
  ];
}

function buildDecisionData(overview) {
  return [
    {
      name: "Confirmed",
      value: Number(
        overview.confirmed_threats || 0
      ),
      tone: "critical",
    },
    {
      name: "Probable",
      value: Number(
        overview.probable_threats || 0
      ),
      tone: "warning",
    },
    {
      name: "Verification",
      value: Number(
        overview.low_trust_threats || 0
      ),
      tone: "info",
    },
    {
      name: "Normal",
      value: Number(
        overview.normal_events || 0
      ),
      tone: "normal",
    },
  ];
}

function buildThreatCategoryData(dashboard) {
  const categories =
    dashboard?.threat_categories || {};

  return [
    {
      name: "Credential Abuse",
      value: Number(
        categories.credential_abuse || 0
      ),
    },
    {
      name: "Privilege Abuse",
      value: Number(
        categories.privilege_abuse || 0
      ),
    },
    {
      name: "Data Exfiltration",
      value: Number(
        categories.data_exfiltration || 0
      ),
    },
    {
      name: "Ransomware",
      value: Number(
        categories.ransomware || 0
      ),
    },
  ];
}

export default function Dashboard({
  dashboard,
  events,
  health,
  onRefresh,
  onSelectEvent,
}) {
  /*
   * Dashboard empty-state protection.
   *
   * The parent App component normally supplies
   * dashboard data after the API request succeeds.
   * If the response is currently unavailable,
   * display a consistent empty state instead of
   * trying to render dashboard metrics from null.
   */
  if (!dashboard) {
    return (
      <StatusState
        type="empty"
        title="Dashboard data unavailable"
        message="The security dashboard has not received dashboard data yet. Please refresh the platform and try again."
        actionLabel="Refresh dashboard"
        onAction={onRefresh}
      />
    );
  }

  const overview =
    dashboard?.overview || {};

  const trust =
    dashboard?.trust || {};

  const trendData =
    buildActivityTrend(events);

  const sourceData =
    buildSourceData(dashboard);

  const decisionData =
    buildDecisionData(overview);

  const threatCategoryData =
    buildThreatCategoryData(dashboard);

  const recentEvents =
    Array.isArray(events)
      ? [...events]
          .sort(
            (a, b) =>
              new Date(
                b.timestamp || 0
              ) -
              new Date(
                a.timestamp || 0
              )
          )
          .slice(0, 7)
      : [];

  const systemOperational =
    Boolean(health);

  return (
    <div className="dashboard-page">

      {/* HEADER STATUS */}

      <section className="dashboard-status-strip">

        <div className="dashboard-status-main">

          <div className="dashboard-live-dot" />

          <div>
            <strong>
              Security operations are active
            </strong>

            <span>
              Monitoring identity, endpoint,
              network and EHR activity
            </span>
          </div>

        </div>

        <div className="dashboard-status-items">

          <div className="dashboard-status-item">
            <Database size={14} />

            <span>
              Database
            </span>

            <b className="online">
              Connected
            </b>
          </div>

          <div className="dashboard-status-item">
            <ShieldCheck size={14} />

            <span>
              Detection Engine
            </span>

            <b className="online">
              Active
            </b>
          </div>

          <div className="dashboard-status-item">
            <Shield size={14} />

            <span>
              Trust Engine
            </span>

            <b className="online">
              Active
            </b>
          </div>

        </div>

        <div
          className={
            systemOperational
              ? "dashboard-api-status online"
              : "dashboard-api-status offline"
          }
        >
          <span className="status-small-dot" />

          API{" "}
          {systemOperational
            ? "Operational"
            : "Unavailable"}
        </div>

      </section>

      {/* KPI CARDS */}

      <section className="dashboard-kpi-grid">

        <div className="dashboard-kpi-card blue">

          <div className="dashboard-kpi-icon">
            <Activity size={20} />
          </div>

          <div className="dashboard-kpi-content">

            <span>
              Total Events
            </span>

            <strong>
              {formatNumber(
                overview.total_events
              )}
            </strong>

            <small>
              Security activity monitored
            </small>

          </div>

        </div>

        <div className="dashboard-kpi-card red">

          <div className="dashboard-kpi-icon">
            <ShieldAlert size={20} />
          </div>

          <div className="dashboard-kpi-content">

            <span>
              Threats Detected
            </span>

            <strong>
              {formatNumber(
                overview.threats_detected
              )}
            </strong>

            <small>
              Suspicious events identified
            </small>

          </div>

        </div>

        <div className="dashboard-kpi-card orange">

          <div className="dashboard-kpi-icon">
            <AlertTriangle size={20} />
          </div>

          <div className="dashboard-kpi-content">

            <span>
              Confirmed Threats
            </span>

            <strong>
              {formatNumber(
                overview.confirmed_threats
              )}
            </strong>

            <small>
              High-trust security findings
            </small>

          </div>

        </div>

        <div className="dashboard-kpi-card green">

          <div className="dashboard-kpi-icon">
            <CircleGauge size={20} />
          </div>

          <div className="dashboard-kpi-content">

            <span>
              Average Evidence Trust
            </span>

            <strong>
              {Number(
                trust.average_trust || 0
              ).toFixed(1)}
            </strong>

            <small>
              Evidence reliability score
            </small>

          </div>

        </div>

      </section>

      {/* ANALYTICS ROW */}

      <section className="dashboard-chart-grid">

        <div className="dashboard-card dashboard-chart-card">

          <div className="dashboard-card-header">

            <div>
              <h2>
                Security Activity
              </h2>

              <p>
                Event volume across the current
                dataset
              </p>
            </div>

            <div className="dashboard-mini-badge">
              Live data
            </div>

          </div>

          <div className="dashboard-chart">

            {trendData.length > 0 ? (
              <ResponsiveContainer
                width="100%"
                height="100%"
              >
                <AreaChart
                  data={trendData}
                  margin={{
                    top: 8,
                    right: 10,
                    left: -18,
                    bottom: 0,
                  }}
                >
                  <defs>

                    <linearGradient
                      id="activityGradient"
                      x1="0"
                      y1="0"
                      x2="0"
                      y2="1"
                    >
                      <stop
                        offset="0%"
                        stopColor="#2563eb"
                        stopOpacity={0.3}
                      />

                      <stop
                        offset="100%"
                        stopColor="#2563eb"
                        stopOpacity={0.02}
                      />
                    </linearGradient>

                  </defs>

                  <CartesianGrid
                    strokeDasharray="3 3"
                    vertical={false}
                    stroke="var(--chart-grid)"
                  />

                  <XAxis
                    dataKey="label"
                    tick={{
                      fill: "var(--chart-text)",
                      fontSize: 10,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <YAxis
                    allowDecimals={false}
                    tick={{
                      fill: "var(--chart-text)",
                      fontSize: 10,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <Tooltip
                    contentStyle={{
                      background:
                        "var(--tooltip-bg)",
                      border:
                        "1px solid var(--tooltip-border)",
                      borderRadius: "10px",
                      color:
                        "var(--tooltip-text)",
                      fontSize: "11px",
                    }}
                  />

                  <Area
                    type="monotone"
                    dataKey="events"
                    stroke="#2563eb"
                    strokeWidth={2.5}
                    fill="url(#activityGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="dashboard-empty-chart">
                No event timestamp data available.
              </div>
            )}

          </div>

        </div>

        <div className="dashboard-card dashboard-chart-card">

          <div className="dashboard-card-header">

            <div>

              <h2>
                Threat Decisions
              </h2>

              <p>
                Current trust-aware classifications
              </p>

            </div>

          </div>

          <div className="dashboard-decision-layout">

            <div className="dashboard-donut">

              <ResponsiveContainer
                width="100%"
                height="100%"
              >
                <PieChart>

                  <Pie
                    data={decisionData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={58}
                    outerRadius={82}
                    paddingAngle={2}
                  >

                    {decisionData.map(
                      (entry) => {
                        const colors = {
                          critical:
                            "#dc2626",
                          warning:
                            "#d97706",
                          info:
                            "#0891b2",
                          normal:
                            "#16a34a",
                        };

                        return (
                          <Cell
                            key={entry.name}
                            fill={
                              colors[
                                entry.tone
                              ]
                            }
                          />
                        );
                      }
                    )}

                  </Pie>

                  <Tooltip
                    contentStyle={{
                      background:
                        "var(--tooltip-bg)",
                      border:
                        "1px solid var(--tooltip-border)",
                      borderRadius: "10px",
                      color:
                        "var(--tooltip-text)",
                      fontSize: "11px",
                    }}
                  />

                </PieChart>
              </ResponsiveContainer>

              <div className="dashboard-donut-center">

                <strong>
                  {formatNumber(
                    overview.threats_detected
                  )}
                </strong>

                <span>
                  threats
                </span>

              </div>

            </div>

            <div className="dashboard-legend">

              {decisionData.map(
                (entry) => (
                  <div
                    className="dashboard-legend-row"
                    key={entry.name}
                  >
                    <span
                      className={`legend-dot ${entry.tone}`}
                    />

                    <span>
                      {entry.name}
                    </span>

                    <strong>
                      {formatNumber(
                        entry.value
                      )}
                    </strong>
                  </div>
                )
              )}

            </div>

          </div>

        </div>

      </section>

      {/* SOURCE / THREAT CATEGORY */}

      <section className="dashboard-analytics-grid">

        <div className="dashboard-card">

          <div className="dashboard-card-header">

            <div>

              <h2>
                Events by Source
              </h2>

              <p>
                Security telemetry distribution
              </p>

            </div>

          </div>

          <div className="dashboard-source-layout">

            <div className="dashboard-source-chart">

              <ResponsiveContainer
                width="100%"
                height="100%"
              >
                <PieChart>

                  <Pie
                    data={sourceData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={76}
                    paddingAngle={3}
                  >

                    {sourceData.map(
                      (entry) => {
                        const colors = {
                          identity:
                            "#6366f1",
                          endpoint:
                            "#0ea5e9",
                          network:
                            "#14b8a6",
                          ehr:
                            "#8b5cf6",
                          default:
                            "#64748b",
                        };

                        return (
                          <Cell
                            key={entry.key}
                            fill={
                              colors[
                                entry.key
                              ] ||
                              colors.default
                            }
                          />
                        );
                      }
                    )}

                  </Pie>

                </PieChart>
              </ResponsiveContainer>

            </div>

            <div className="dashboard-source-list">

              {sourceData.map(
                (entry) => (
                  <div
                    className="dashboard-source-row"
                    key={entry.key}
                  >

                    <div className="source-label">

                      <span
                        className={`source-dot ${getSourceTone(
                          entry.key
                        )}`}
                      />

                      <span>
                        {entry.name}
                      </span>

                    </div>

                    <strong>
                      {formatNumber(
                        entry.value
                      )}
                    </strong>

                  </div>
                )
              )}

            </div>

          </div>

        </div>

        <div className="dashboard-card">

          <div className="dashboard-card-header">

            <div>

              <h2>
                Threat Categories
              </h2>

              <p>
                Operational threat pattern overview
              </p>

            </div>

          </div>

          <div className="dashboard-threat-bars">

            {threatCategoryData.map(
              (entry) => {
                const total =
                  threatCategoryData.reduce(
                    (sum, item) =>
                      sum + item.value,
                    0
                  );

                const width =
                  total > 0
                    ? Math.max(
                        4,
                        (entry.value /
                          total) *
                          100
                      )
                    : 4;

                return (
                  <div
                    className="dashboard-threat-bar-row"
                    key={entry.name}
                  >

                    <div className="threat-bar-heading">

                      <span>
                        {entry.name}
                      </span>

                      <strong>
                        {formatNumber(
                          entry.value
                        )}
                      </strong>

                    </div>

                    <div className="threat-bar-track">

                      <div
                        className="threat-bar-fill"
                        style={{
                          width: `${width}%`,
                        }}
                      />

                    </div>

                  </div>
                );
              }
            )}

          </div>

        </div>

      </section>

      {/* RECENT ACTIVITY */}

      <section className="dashboard-card dashboard-activity-card">

        <div className="dashboard-card-header">

          <div>

            <h2>
              Recent Security Activity
            </h2>

            <p>
              Latest events received from the security
              event pipeline
            </p>

          </div>

          <div className="dashboard-activity-count">

            <Users size={14} />

            {formatNumber(
              overview.total_events
            )}{" "}
            total events

          </div>

        </div>

        <div className="dashboard-activity-list">

          {recentEvents.length === 0 ? (
            <div className="dashboard-empty-state">

              <CheckCircle2 size={20} />

              <span>
                No recent activity available.
              </span>

            </div>
          ) : (
            recentEvents.map(
              (event) => (
                <button
                  className="dashboard-activity-row"
                  key={event.event_id}
                  onClick={() =>
                    onSelectEvent?.(
                      event
                    )
                  }
                >

                  <div
                    className={`activity-source-icon ${getSourceTone(
                      event.source_type
                    )}`}
                  >
                    {event.source_type
                      ?.slice(0, 2)
                      .toUpperCase() ||
                      "EV"}
                  </div>

                  <div className="activity-main">

                    <strong>
                      {event.event_type ||
                        "Security event"}
                    </strong>

                    <span>
                      {getSourceLabel(
                        event.source_type
                      )}{" "}
                      ·{" "}
                      {event.event_id}
                    </span>

                  </div>

                  <div className="activity-scenario">
                    {event.scenario_id ||
                      "No scenario"}
                  </div>

                  <div className="activity-time">
                    {formatTimestamp(
                      event.timestamp
                    )}
                  </div>

                </button>
              )
            )
          )}

        </div>

      </section>

      {/* FOOTER POSTURE */}

      <section className="dashboard-posture-grid">

        <div className="dashboard-posture-card">

          <div className="posture-icon green">
            <ShieldCheck size={19} />
          </div>

          <div>

            <span>
              Evidence posture
            </span>

            <strong>
              {Number(
                trust.high_trust || 0
              ).toLocaleString()}{" "}
              high-trust records
            </strong>

          </div>

        </div>

        <div className="dashboard-posture-card">

          <div className="posture-icon blue">
            <Database size={19} />
          </div>

          <div>

            <span>
              Security scenarios
            </span>

            <strong>
              {formatNumber(
                dashboard?.scenario_count
              )}{" "}
              correlated scenarios
            </strong>

          </div>

        </div>

        <div className="dashboard-posture-card">

          <div className="posture-icon orange">
            <AlertTriangle size={19} />
          </div>

          <div>

            <span>
              Attention required
            </span>

            <strong>
              {formatNumber(
                overview.probable_threats
              )}{" "}
              probable threats
            </strong>

          </div>

        </div>

      </section>

    </div>
  );
}