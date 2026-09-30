import {
  ArrowRight,
  CheckCircle2,
  Clock3,
  GitBranch,
  ShieldAlert,
  Target,
} from "lucide-react";

import "./AttackPath.css";

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

function getNodes(attackPath) {
  return (
    attackPath?.nodes ||
    attackPath?.path ||
    attackPath?.attack_path ||
    []
  );
}

export default function AttackPath({
  events = [],
  scenarioIds = [],
  selectedScenario,
  attackPath,
  attackPathLoading = false,
  onSelectScenario,
}) {
  const nodes =
    getNodes(attackPath);

  return (
    <section className="attack-path-page">

      {/* HEADER */}

      <div className="attack-path-header">
        <div>
          <div className="attack-path-eyebrow">
            <GitBranch size={15} />
            Attack Path Reconstruction
          </div>

          <h1>
            Attack Paths
          </h1>

          <p>
            Reconstruct security scenarios
            chronologically from their correlated
            events.
          </p>
        </div>

        <div className="attack-path-status">
          <span className="attack-path-status-dot" />

          <div>
            <strong>
              Reconstruction Service Online
            </strong>

            <span>
              Backend path analysis available
            </span>
          </div>
        </div>
      </div>

      {/* WORKSPACE */}

      <div className="attack-path-workspace">

        {/* SCENARIOS */}

        <div className="attack-path-panel">

          <div className="attack-path-panel-header">

            <div>
              <span>
                Correlated scenarios
              </span>

              <h2>
                Select Scenario
              </h2>
            </div>

            <span className="attack-path-count">
              {scenarioIds.length}
            </span>

          </div>

          <div className="attack-path-scenarios">

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
                    className={`attack-scenario-row ${
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

                    <div className="attack-scenario-icon">
                      <GitBranch
                        size={16}
                      />
                    </div>

                    <div className="attack-scenario-details">

                      <strong>
                        {scenarioId}
                      </strong>

                      <span>
                        Attack-path scenario
                      </span>

                    </div>

                    <div className="attack-scenario-events">
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

        {/* RESULT */}

        <div className="attack-path-panel">

          <div className="attack-path-panel-header">

            <div>
              <span>
                Backend reconstruction
              </span>

              <h2>
                Attack Path Result
              </h2>
            </div>

            <Target size={21} />

          </div>

          {attackPathLoading ? (
            <div className="attack-path-loading">

              <div className="attack-path-spinner" />

              <strong>
                Reconstructing attack path...
              </strong>

              <span>
                Building the chronological security
                path for this scenario.
              </span>

            </div>
          ) : !attackPath ? (
            <div className="attack-path-empty">

              <ShieldAlert
                size={40}
              />

              <h3>
                No scenario selected
              </h3>

              <p>
                Select a scenario from the list
                to view its reconstructed attack path.
              </p>

            </div>
          ) : (
            <>
              <div className="attack-path-hero">

                <div className="attack-path-hero-icon">
                  <GitBranch size={25} />
                </div>

                <div>
                  <span>
                    Reconstructed scenario
                  </span>

                  <h3>
                    {attackPath.scenario_id ||
                      selectedScenario ||
                      "Unknown scenario"}
                  </h3>

                  <strong>
                    {attackPath.attack_type ||
                      attackPath.incident_type ||
                      attackPath.classification ||
                      "Classification not returned"}
                  </strong>
                </div>

              </div>

              <div className="attack-path-summary-grid">

                <div>
                  <span>
                    Scenario
                  </span>

                  <strong>
                    {attackPath.scenario_id ||
                      selectedScenario ||
                      "N/A"}
                  </strong>
                </div>

                <div>
                  <span>
                    Events
                  </span>

                  <strong>
                    {attackPath.event_count ??
                      nodes.length}
                  </strong>
                </div>

                <div>
                  <span>
                    Path nodes
                  </span>

                  <strong>
                    {nodes.length}
                  </strong>
                </div>

                <div>
                  <span>
                    Classification
                  </span>

                  <strong>
                    {attackPath.attack_type ||
                      attackPath.incident_type ||
                      attackPath.classification ||
                      "N/A"}
                  </strong>
                </div>

              </div>

              <div className="attack-path-summary">
                <span>
                  Path summary
                </span>

                <p>
                  {attackPath.summary ||
                    "The backend reconstructed this scenario from its chronological security events."}
                </p>
              </div>
            </>
          )}

        </div>
      </div>

      {attackPath && (
        <>
          {/* VISUAL PATH */}

          <div className="attack-path-panel">

            <div className="attack-path-panel-header">

              <div>
                <span>
                  Chronological reconstruction
                </span>

                <h2>
                  Attack Path
                </h2>
              </div>

              <ArrowRight size={20} />

            </div>

            {nodes.length === 0 ? (
              <div className="attack-path-empty compact">

                <p>
                  No attack-path nodes were returned
                  by the backend.
                </p>

              </div>
            ) : (
              <div className="attack-path-visual">

                {nodes.map(
                  (node, index) => {
                    const stage =
                      typeof node ===
                      "object"
                        ? node.stage ||
                          node.attack_stage ||
                          node.phase ||
                          "Activity"
                        : "Activity";

                    const eventId =
                      typeof node ===
                      "object"
                        ? node.event_id ||
                          node.id ||
                          ""
                        : "";

                    const eventType =
                      typeof node ===
                      "object"
                        ? node.event_type ||
                          node.type ||
                          node.description ||
                          "Security Event"
                        : String(
                            node
                          );

                    const source =
                      typeof node ===
                      "object"
                        ? node.source_type ||
                          node.source ||
                          ""
                        : "";

                    const timestamp =
                      typeof node ===
                      "object"
                        ? node.timestamp ||
                          node.time ||
                          ""
                        : "";

                    return (
                      <div
                        className="attack-path-step"
                        key={
                          eventId ||
                          index
                        }
                      >

                        <div className="attack-path-step-number">
                          {index + 1}
                        </div>

                        <div className="attack-path-step-card">

                          <div className="attack-path-step-heading">

                            <div>
                              <span>
                                {stage}
                              </span>

                              <h3>
                                {eventType}
                              </h3>
                            </div>

                            <GitBranch
                              size={18}
                            />

                          </div>

                          <div className="attack-path-step-meta">

                            {eventId && (
                              <span>
                                Event:{" "}
                                {eventId}
                              </span>
                            )}

                            {source && (
                              <span>
                                Source:{" "}
                                {source}
                              </span>
                            )}

                            <span>
                              <Clock3
                                size={12}
                              />

                              {timestamp
                                ? formatTimestamp(
                                    timestamp
                                  )
                                : "Time not available"}
                            </span>

                          </div>

                        </div>

                        {index <
                          nodes.length -
                            1 && (
                          <div className="attack-path-connector">
                            <div />
                          </div>
                        )}

                      </div>
                    );
                  }
                )}

              </div>
            )}

          </div>

          {/* STAGES */}

          <div className="attack-path-two-column">

            <div className="attack-path-panel">

              <div className="attack-path-panel-header">

                <div>
                  <span>
                    Reconstruction stages
                  </span>

                  <h2>
                    Attack Stages
                  </h2>
                </div>

                <GitBranch size={20} />

              </div>

              <div className="attack-stage-list">

                {nodes.map(
                  (node, index) => {
                    const stage =
                      typeof node ===
                      "object"
                        ? node.stage ||
                          node.attack_stage ||
                          node.phase ||
                          "Activity"
                        : "Activity";

                    return (
                      <div
                        className="attack-stage-row"
                        key={index}
                      >

                        <div>
                          <span>
                            Step {index + 1}
                          </span>

                          <strong>
                            {stage}
                          </strong>
                        </div>

                        <CheckCircle2
                          size={17}
                        />

                      </div>
                    );
                  }
                )}

              </div>

            </div>

            <div className="attack-path-panel">

              <div className="attack-path-panel-header">

                <div>
                  <span>
                    Backend classification
                  </span>

                  <h2>
                    Path Classification
                  </h2>
                </div>

                <Target size={20} />

              </div>

              <div className="attack-classification-box">

                <Target size={22} />

                <strong>
                  {attackPath.attack_type ||
                    attackPath.incident_type ||
                    attackPath.classification ||
                    "No classification returned"}
                </strong>

                <p>
                  This classification is returned
                  by the backend attack-path service.
                </p>

              </div>

            </div>

          </div>
        </>
      )}

      <div className="attack-path-footer">
        <CheckCircle2 size={16} />

        <span>
          Attack paths are reconstructed from backend
          security-event data. The frontend does not
          independently infer attack stages.
        </span>
      </div>

    </section>
  );
}