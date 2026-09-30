import {
  Activity,
  CheckCircle2,
  Database,
  FileCheck2,
  Fingerprint,
  ShieldAlert,
  ShieldCheck,
  Timer,
  Waypoints,
} from "lucide-react";

import "./EvidenceTrust.css";

function formatScore(value) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return "—";
  }

  const number = Number(value);

  if (Number.isNaN(number)) {
    return value;
  }

  return number.toFixed(1);
}

function getEvidenceId(evidence) {
  return (
    evidence?.evidence_id ||
    "N/A"
  );
}

function getEventId(evidence) {
  return (
    evidence?.event_id ||
    "N/A"
  );
}

function getScenarioId(evidence) {
  return (
    evidence?.scenario_id ||
    "N/A"
  );
}

function getSourceType(evidence) {
  return (
    evidence?.source_type ||
    "N/A"
  );
}

function getTrustClassification(
  evidenceTrust
) {
  return (
    evidenceTrust?.classification ||
    evidenceTrust?.trust_level ||
    "Not assessed"
  );
}

function getTrustClass(
  classification
) {
  const value = String(
    classification
  ).toLowerCase();

  if (value.includes("high")) {
    return "trust-high";
  }

  if (value.includes("medium")) {
    return "trust-medium";
  }

  if (value.includes("low")) {
    return "trust-low";
  }

  return "trust-unknown";
}

function getStatusClass(status) {
  const value = String(
    status || ""
  ).toLowerCase();

  if (
    value.includes("valid") ||
    value.includes("verified") ||
    value.includes("fresh") ||
    value.includes("consistent")
  ) {
    return "status-good";
  }

  if (
    value.includes("recent") ||
    value.includes("unknown")
  ) {
    return "status-neutral";
  }

  return "status-warning";
}

function DimensionCard({
  icon: Icon,
  title,
  status,
  score,
}) {
  return (
    <div className="trust-dimension-card">
      <div className="trust-dimension-top">
        <div className="trust-dimension-icon">
          <Icon size={18} />
        </div>

        <div>
          <span>{title}</span>

          <strong
            className={getStatusClass(
              status
            )}
          >
            {status || "Not available"}
          </strong>
        </div>
      </div>

      <div className="trust-dimension-score">
        <div className="trust-progress-track">
          <div
            className="trust-progress-fill"
            style={{
              width: `${Math.min(
                Math.max(
                  Number(score) || 0,
                  0
                ),
                100
              )}%`,
            }}
          />
        </div>

        <strong>
          {formatScore(score)}
        </strong>
      </div>
    </div>
  );
}

export default function EvidenceTrust({
  trust = {},
  events = [],
  selectedEvidence,
  evidenceTrust,
  trustLoading = false,
  onSelectEvidence,
}) {
  const trustScore =
    evidenceTrust?.trust_score;

  const classification =
    getTrustClassification(
      evidenceTrust
    );

  return (
    <section className="evidence-trust-page">

      {/* PAGE HEADER */}

      <div className="trust-page-header">
        <div>
          <div className="trust-eyebrow">
            <ShieldCheck size={15} />
            Evidence Integrity Centre
          </div>

          <h1>
            Evidence Trust
          </h1>

          <p>
            Assess the reliability of security
            evidence using provenance, integrity,
            freshness and consistency.
          </p>
        </div>

        <div className="trust-system-status">
          <span className="trust-status-dot" />

          <div>
            <strong>
              Trust Engine Online
            </strong>

            <span>
              Backend assessment active
            </span>
          </div>
        </div>
      </div>

      {/* TRUST OVERVIEW */}

      <div className="trust-overview-grid">

        <div className="trust-stat-card">
          <div className="trust-stat-icon">
            <Database size={20} />
          </div>

          <div>
            <span>
              Total Evidence
            </span>

            <strong>
              {trust.total_evidence ?? 0}
            </strong>

            <small>
              Evidence records evaluated
            </small>
          </div>
        </div>

        <div className="trust-stat-card trust-stat-good">
          <div className="trust-stat-icon">
            <ShieldCheck size={20} />
          </div>

          <div>
            <span>
              High Trust
            </span>

            <strong>
              {trust.high_trust ?? 0}
            </strong>

            <small>
              High-confidence evidence
            </small>
          </div>
        </div>

        <div className="trust-stat-card trust-stat-medium">
          <div className="trust-stat-icon">
            <ShieldAlert size={20} />
          </div>

          <div>
            <span>
              Medium Trust
            </span>

            <strong>
              {trust.medium_trust ?? 0}
            </strong>

            <small>
              Evidence requiring attention
            </small>
          </div>
        </div>

        <div className="trust-stat-card trust-stat-low">
          <div className="trust-stat-icon">
            <Activity size={20} />
          </div>

          <div>
            <span>
              Low Trust
            </span>

            <strong>
              {trust.low_trust ?? 0}
            </strong>

            <small>
              Low-confidence evidence
            </small>
          </div>
        </div>

      </div>

      {/* MAIN WORKSPACE */}

      <div className="trust-workspace">

        {/* EVIDENCE SELECTOR */}

        <div className="trust-panel">

          <div className="trust-panel-header">
            <div>
              <span>
                Evidence stream
              </span>

              <h2>
                Select Evidence
              </h2>
            </div>

            <span className="trust-panel-count">
              {events.length} events
            </span>
          </div>

          <div className="trust-event-list">

            {events
              .slice(0, 30)
              .map((event) => (
                <button
                  type="button"
                  key={event.event_id}
                  className={`trust-event-row ${
                    selectedEvidence?.event_id ===
                    event.event_id
                      ? "selected"
                      : ""
                  }`}
                  onClick={() =>
                    onSelectEvidence?.(
                      event
                    )
                  }
                >

                  <div className="trust-event-icon">
                    <FileCheck2
                      size={16}
                    />
                  </div>

                  <div className="trust-event-details">

                    <strong>
                      {event.event_type ||
                        "Security event"}
                    </strong>

                    <span>
                      {event.source_type ||
                        "Unknown source"}
                      {" · "}
                      {event.event_id}
                    </span>

                  </div>

                  <div className="trust-event-scenario">
                    {event.scenario_id ||
                      "No scenario"}
                  </div>

                </button>
              ))}

          </div>
        </div>

        {/* EVIDENCE RESULT */}

        <div className="trust-panel">

          <div className="trust-panel-header">
            <div>
              <span>
                Backend assessment
              </span>

              <h2>
                Evidence Trust Result
              </h2>
            </div>

            <ShieldCheck
              size={21}
            />
          </div>

          {trustLoading ? (
            <div className="trust-loading">

              <div className="trust-spinner" />

              <strong>
                Evaluating evidence trust...
              </strong>

              <span>
                The TrustEngine is assessing
                the selected evidence.
              </span>

            </div>
          ) : !evidenceTrust ? (
            <div className="trust-empty">

              <ShieldAlert
                size={38}
              />

              <h3>
                No evidence selected
              </h3>

              <p>
                Select an event from the
                evidence stream to view its
                trust assessment.
              </p>

            </div>
          ) : (
            <>
              {/* TRUST SCORE */}

              <div className="trust-score-section">

                <div
                  className={`trust-score-circle ${getTrustClass(
                    classification
                  )}`}
                >
                  <span>
                    Trust
                  </span>

                  <strong>
                    {formatScore(
                      trustScore
                    )}
                  </strong>

                  <small>
                    / 100
                  </small>
                </div>

                <div className="trust-score-content">

                  <span>
                    Trust classification
                  </span>

                  <h3
                    className={getTrustClass(
                      classification
                    )}
                  >
                    {classification}
                  </h3>

                  <p>
                    This classification is returned
                    by the backend TrustEngine using
                    the available evidence quality
                    dimensions.
                  </p>

                  <div className="trust-score-bar">
                    <div
                      style={{
                        width: `${Math.min(
                          Math.max(
                            Number(
                              trustScore
                            ) || 0,
                            0
                          ),
                          100
                        )}%`,
                      }}
                    />
                  </div>

                </div>

              </div>

              {/* IDENTIFIERS */}

              <div className="trust-identifiers">

                <div>
                  <span>
                    Evidence ID
                  </span>

                  <strong>
                    {getEvidenceId(
                      evidenceTrust
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    Event ID
                  </span>

                  <strong>
                    {getEventId(
                      evidenceTrust
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    Scenario ID
                  </span>

                  <strong>
                    {getScenarioId(
                      evidenceTrust
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    Source Type
                  </span>

                  <strong>
                    {getSourceType(
                      evidenceTrust
                    )}
                  </strong>
                </div>

              </div>

              {/* TRUST DIMENSIONS */}

              <div className="trust-dimensions">

                <DimensionCard
                  icon={Fingerprint}
                  title="Provenance"
                  status={
                    evidenceTrust.provenance
                  }
                  score={
                    evidenceTrust.provenance_score
                  }
                />

                <DimensionCard
                  icon={FileCheck2}
                  title="Integrity"
                  status={
                    evidenceTrust.integrity_status
                  }
                  score={
                    evidenceTrust.integrity_score
                  }
                />

                <DimensionCard
                  icon={Timer}
                  title="Freshness"
                  status={
                    evidenceTrust.freshness_status
                  }
                  score={
                    evidenceTrust.freshness_score
                  }
                />

                <DimensionCard
                  icon={Waypoints}
                  title="Consistency"
                  status={
                    evidenceTrust.consistency_status
                  }
                  score={
                    evidenceTrust.consistency_score
                  }
                />

              </div>

              {/* REASONS */}

              {Array.isArray(
                evidenceTrust.reasons
              ) &&
                evidenceTrust.reasons.length >
                  0 && (
                  <div className="trust-reasons">

                    <div className="trust-subheading">
                      <ShieldCheck
                        size={17}
                      />

                      <strong>
                        Trust Assessment Reasons
                      </strong>
                    </div>

                    <ul>
                      {evidenceTrust.reasons.map(
                        (
                          reason,
                          index
                        ) => (
                          <li key={index}>
                            <CheckCircle2
                              size={15}
                            />

                            <span>
                              {reason}
                            </span>
                          </li>
                        )
                      )}
                    </ul>

                  </div>
                )}

            </>
          )}

        </div>
      </div>

      {/* DATASET STATISTICS */}

      <div className="trust-panel">

        <div className="trust-panel-header">
          <div>
            <span>
              Dataset-level view
            </span>

            <h2>
              Trust Statistics
            </h2>
          </div>

          <Database size={20} />
        </div>

        <div className="trust-statistics-grid">

          <div>
            <span>
              Average Trust
            </span>

            <strong>
              {formatScore(
                trust.average_trust
              )}
            </strong>
          </div>

          <div>
            <span>
              Minimum Trust
            </span>

            <strong>
              {formatScore(
                trust.minimum_trust
              )}
            </strong>
          </div>

          <div>
            <span>
              Maximum Trust
            </span>

            <strong>
              {formatScore(
                trust.maximum_trust
              )}
            </strong>
          </div>

          <div>
            <span>
              High Trust Evidence
            </span>

            <strong>
              {trust.high_trust ?? 0}
            </strong>
          </div>

          <div>
            <span>
              Medium Trust Evidence
            </span>

            <strong>
              {trust.medium_trust ?? 0}
            </strong>
          </div>

          <div>
            <span>
              Low Trust Evidence
            </span>

            <strong>
              {trust.low_trust ?? 0}
            </strong>
          </div>

        </div>

      </div>

      <div className="trust-footer-note">
        <CheckCircle2 size={16} />

        <span>
          Trust scores are calculated by the
          backend TrustEngine. The frontend only
          displays the returned assessment and does
          not independently calculate evidence trust.
        </span>
      </div>

    </section>
  );
}