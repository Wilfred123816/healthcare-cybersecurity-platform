import { useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  Clock3,
  Database,
  Filter,
  RefreshCw,
  Search,
  ShieldAlert,
  UserRound,
  Wifi,
  Monitor,
  X,
} from "lucide-react";

import "./SecurityEvents.css";

function formatTimestamp(value) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function getEventTimestamp(event) {
  return event?.timestamp || event?.created_at;
}

function getEventType(event) {
  return (
    event.event_type ||
    event.type ||
    event.event_category ||
    "Unknown"
  );
}

function getSource(event) {
  return (
    event.source_type ||
    event.source ||
    event.data_source ||
    "Unknown"
  );
}

function getEventId(event) {
  return event.event_id || event.id || "Unknown";
}

function getScenario(event) {
  return (
    event.scenario_id ||
    "No scenario"
  );
}

function getDescription(event) {
  return (
    event.description ||
    event.action ||
    event.event_name ||
    `${getEventType(event)} event`
  );
}

function getSeverity(event) {
  const value = String(
    event.severity ||
      event.threat_severity ||
      event.risk_level ||
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

function getEventIcon(eventType) {
  const value = String(eventType).toLowerCase();

  if (value.includes("network")) {
    return Wifi;
  }

  if (
    value.includes("identity") ||
    value.includes("login")
  ) {
    return UserRound;
  }

  if (
    value.includes("endpoint") ||
    value.includes("device")
  ) {
    return Monitor;
  }

  if (
    value.includes("ehr") ||
    value.includes("medical")
  ) {
    return Database;
  }

  return Activity;
}

function sortEvents(
  eventList,
  sortOrder
) {
  return [...eventList].sort(
    (a, b) => {
      const aTime = new Date(
        getEventTimestamp(a) || 0
      ).getTime();

      const bTime = new Date(
        getEventTimestamp(b) || 0
      ).getTime();

      if (sortOrder === "oldest") {
        return aTime - bTime;
      }

      return bTime - aTime;
    }
  );
}

export default function SecurityEvents({
  events = [],
  loading = false,
  onSelectEvent,
  onRefresh,
}) {
  const [searchTerm, setSearchTerm] =
    useState("");

  const [typeFilter, setTypeFilter] =
    useState("all");

  const [sourceFilter, setSourceFilter] =
    useState("all");

  const [scenarioFilter, setScenarioFilter] =
    useState("all");

  const [sortOrder, setSortOrder] =
    useState("newest");

  const eventTypes = useMemo(() => {
    const values = new Set(
      events.map((event) =>
        getEventType(event)
      )
    );

    return [
      "all",
      ...Array.from(values).sort(),
    ];
  }, [events]);

  const sourceTypes = useMemo(() => {
    const values = new Set(
      events.map((event) =>
        getSource(event)
      )
    );

    return [
      "all",
      ...Array.from(values).sort(),
    ];
  }, [events]);

  const scenarioIds = useMemo(() => {
    const values = new Set(
      events.map((event) =>
        getScenario(event)
      )
    );

    return [
      "all",
      ...Array.from(values).sort(),
    ];
  }, [events]);

  const filteredEvents = useMemo(() => {
    const query =
      searchTerm.trim().toLowerCase();

    const filtered = events.filter(
      (event) => {
        const type =
          getEventType(event);

        const source =
          getSource(event);

        const eventId =
          getEventId(event);

        const scenario =
          getScenario(event);

        const description =
          getDescription(event);

        const matchesSearch =
          !query ||
          String(type)
            .toLowerCase()
            .includes(query) ||
          String(source)
            .toLowerCase()
            .includes(query) ||
          String(eventId)
            .toLowerCase()
            .includes(query) ||
          String(scenario)
            .toLowerCase()
            .includes(query) ||
          String(description)
            .toLowerCase()
            .includes(query);

        const matchesType =
          typeFilter === "all" ||
          type === typeFilter;

        const matchesSource =
          sourceFilter === "all" ||
          source === sourceFilter;

        const matchesScenario =
          scenarioFilter === "all" ||
          scenario === scenarioFilter;

        return (
          matchesSearch &&
          matchesType &&
          matchesSource &&
          matchesScenario
        );
      }
    );

    return sortEvents(
      filtered,
      sortOrder
    );
  }, [
    events,
    searchTerm,
    typeFilter,
    sourceFilter,
    scenarioFilter,
    sortOrder,
  ]);

  const filtersActive =
    searchTerm.trim() !== "" ||
    typeFilter !== "all" ||
    sourceFilter !== "all" ||
    scenarioFilter !== "all";

  function clearFilters() {
    setSearchTerm("");
    setTypeFilter("all");
    setSourceFilter("all");
    setScenarioFilter("all");
    setSortOrder("newest");
  }

  const latestEvent =
    filteredEvents.length > 0
      ? filteredEvents[0]
      : null;

  return (
    <section className="security-events-page">

      {/* HEADER */}

      <div className="events-page-header">
        <div>
          <div className="events-title-row">
            <ShieldAlert size={26} />
            <h1>
              Security Events
            </h1>
          </div>

          <p>
            Monitor and investigate security
            activity across the healthcare
            environment.
          </p>
        </div>

        <div className="events-header-status">

          <span className="live-indicator">
            <span className="live-dot" />
            Live monitoring
          </span>

          <div className="events-total">
            <strong>
              {events.length}
            </strong>

            <span>
              Total events
            </span>
          </div>

        </div>
      </div>

      {/* CONTROL BAR */}

      <div className="events-control-panel">

        <div className="events-search">
          <Search size={18} />

          <input
            type="text"
            placeholder="Search event ID, type, source or scenario..."
            value={searchTerm}
            onChange={(event) =>
              setSearchTerm(
                event.target.value
              )
            }
          />

          {searchTerm && (
            <button
              type="button"
              className="search-clear-button"
              onClick={() =>
                setSearchTerm("")
              }
              aria-label="Clear search"
            >
              <X size={15} />
            </button>
          )}
        </div>

        <div className="events-filter-control">
          <Filter size={16} />

          <select
            value={typeFilter}
            onChange={(event) =>
              setTypeFilter(
                event.target.value
              )
            }
          >
            {eventTypes.map(
              (type) => (
                <option
                  key={type}
                  value={type}
                >
                  {type === "all"
                    ? "All event types"
                    : type}
                </option>
              )
            )}
          </select>
        </div>

        <div className="events-filter-control">
          <Database size={16} />

          <select
            value={sourceFilter}
            onChange={(event) =>
              setSourceFilter(
                event.target.value
              )
            }
          >
            {sourceTypes.map(
              (source) => (
                <option
                  key={source}
                  value={source}
                >
                  {source === "all"
                    ? "All sources"
                    : source}
                </option>
              )
            )}
          </select>
        </div>

        <div className="events-filter-control">
          <Activity size={16} />

          <select
            value={scenarioFilter}
            onChange={(event) =>
              setScenarioFilter(
                event.target.value
              )
            }
          >
            {scenarioIds.map(
              (scenario) => (
                <option
                  key={scenario}
                  value={scenario}
                >
                  {scenario === "all"
                    ? "All scenarios"
                    : scenario}
                </option>
              )
            )}
          </select>
        </div>

      </div>

      {/* ACTIVITY CONTROLS */}

      <div className="events-activity-toolbar">

        <div className="events-result-count">
          <strong>
            {filteredEvents.length}
          </strong>

          <span>
            matching events
          </span>
        </div>

        <div className="events-toolbar-actions">

          <select
            className="events-sort-select"
            value={sortOrder}
            onChange={(event) =>
              setSortOrder(
                event.target.value
              )
            }
            aria-label="Sort events"
          >
            <option value="newest">
              Newest first
            </option>

            <option value="oldest">
              Oldest first
            </option>
          </select>

          {filtersActive && (
            <button
              type="button"
              className="events-clear-button"
              onClick={clearFilters}
            >
              <X size={15} />
              Clear filters
            </button>
          )}

          <button
            type="button"
            className="events-refresh-button"
            onClick={onRefresh}
            disabled={loading}
          >
            <RefreshCw
              size={15}
              className={
                loading
                  ? "refresh-spinning"
                  : ""
              }
            />

            Refresh
          </button>

        </div>

      </div>

      {/* SUMMARY */}

      <div className="events-summary">

        <div className="event-summary-card">
          <Activity size={19} />

          <div>
            <span>
              Visible events
            </span>

            <strong>
              {filteredEvents.length}
            </strong>
          </div>
        </div>

        <div className="event-summary-card">
          <Clock3 size={19} />

          <div>
            <span>
              Latest visible activity
            </span>

            <strong>
              {latestEvent
                ? formatTimestamp(
                    getEventTimestamp(
                      latestEvent
                    )
                  )
                : "No data"}
            </strong>
          </div>
        </div>

        <div className="event-summary-card">
          <AlertTriangle size={19} />

          <div>
            <span>
              Active filters
            </span>

            <strong>
              {filtersActive
                ? "Applied"
                : "None"}
            </strong>
          </div>
        </div>

      </div>

      {/* EVENT STREAM */}

      <div className="events-panel">

        <div className="events-panel-header">

          <div>
            <h2>
              Event stream
            </h2>

            <span>
              Showing{" "}
              {filteredEvents.length} of{" "}
              {events.length} events
            </span>
          </div>

          <span className="events-stream-status">
            <span />
            Monitoring
          </span>

        </div>

        {loading ? (
          <div className="events-loading">
            <div className="events-spinner" />

            <span>
              Loading security events...
            </span>
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="events-empty">

            <Activity size={32} />

            <h3>
              No matching events
            </h3>

            <p>
              Try changing your search or
              clearing one or more filters.
            </p>

            {filtersActive && (
              <button
                type="button"
                className="events-empty-button"
                onClick={clearFilters}
              >
                Clear filters
              </button>
            )}

          </div>
        ) : (
          <div className="events-table-wrapper">

            <table className="events-table">

              <thead>
                <tr>
                  <th>
                    Event
                  </th>

                  <th>
                    Type
                  </th>

                  <th>
                    Source
                  </th>

                  <th>
                    Scenario
                  </th>

                  <th>
                    Severity
                  </th>

                  <th>
                    Timestamp
                  </th>

                  <th />
                </tr>
              </thead>

              <tbody>

                {filteredEvents.map(
                  (
                    event,
                    index
                  ) => {
                    const eventType =
                      getEventType(event);

                    const source =
                      getSource(event);

                    const eventId =
                      getEventId(event);

                    const scenario =
                      getScenario(event);

                    const description =
                      getDescription(event);

                    const severity =
                      getSeverity(event);

                    const EventIcon =
                      getEventIcon(
                        eventType
                      );

                    return (
                      <tr
                        key={`${eventId}-${index}`}
                        onClick={() =>
                          onSelectEvent?.(
                            event
                          )
                        }
                      >

                        <td>
                          <div className="event-main-cell">

                            <div className="event-icon">
                              <EventIcon
                                size={17}
                              />
                            </div>

                            <div>
                              <strong>
                                {description}
                              </strong>

                              <span>
                                {eventId}
                              </span>
                            </div>

                          </div>
                        </td>

                        <td>
                          <span className="event-type-badge">
                            {eventType}
                          </span>
                        </td>

                        <td>
                          <span className="event-source">
                            {source}
                          </span>
                        </td>

                        <td>
                          <span className="event-scenario-value">
                            {scenario}
                          </span>
                        </td>

                        <td>
                          <span
                            className={`severity-badge severity-${severity}`}
                          >
                            {severity ===
                            "unknown"
                              ? "Not assessed"
                              : severity}
                          </span>
                        </td>

                        <td>
                          <span className="event-time">
                            {formatTimestamp(
                              getEventTimestamp(
                                event
                              )
                            )}
                          </span>
                        </td>

                        <td>
                          <button
                            type="button"
                            className="event-open-button"
                            onClick={(
                              clickEvent
                            ) => {
                              clickEvent.stopPropagation();

                              onSelectEvent?.(
                                event
                              );
                            }}
                            aria-label={`Open event ${eventId}`}
                          >
                            <ChevronRight
                              size={18}
                            />
                          </button>
                        </td>

                      </tr>
                    );
                  }
                )}

              </tbody>
            </table>

          </div>
        )}

      </div>

    </section>
  );
}