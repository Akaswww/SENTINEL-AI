
import { useEffect, useRef, useState } from "react";

type Recommendation = {
  alert_id: number;
  category: string;
  severity: string;
  risk_score: number;
  recommended_action: string;
  reason: string;
  requires_approval: boolean;
  execution_mode: string;
  source_type: "real" | "simulated" | "unknown";
  source_name: string | null;
  eligible_for_real_execution: boolean; 
};

type RecommendationResponse = {
  mode: string;
  total: number;
  recommendations: Recommendation[];
};

type DecisionResponse = {
  status: string;
  decision_id: number;
  alert_id: number;
  decision: string;
  action: string;
  execution_mode: string;
  executed: boolean;
};


type Decision = {
  id: number;
  alert_id: number;
  decision: "approved" | "rejected";
  action: string;
  execution_mode: string;
  timestamp: string;
  executed: boolean;
};


type Investigation = {
  alert_id: number;
  hostname: string;
  category: string;
  severity: string;
  title: string;
  pid: number | null;
  process_evidence: {
    pid: number;
    name: string;
    status: string;
    executable: string | null;
    cpu_percent: number;
    memory_percent: number;
    snapshot_time: string;
  }[];
  network_evidence: {
    protocol: string;
    local_ip: string | null;
    local_port: number | null;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
    snapshot_time: string;
  }[];
  investigated_at: string;
  execution_mode: string;
  limitations: string[];
};


export default function DefenseCenter() {
  const investigationRef = useRef<HTMLElement | null>(null);
  const [investigation, setInvestigation] =
  useState<Investigation | null>(null);

  const [investigatingId, setInvestigatingId] =
  useState<number | null>(null);
  const [recommendations, setRecommendations] =
    useState<Recommendation[]>([]);

  const [decisions, setDecisions] = useState<
    Record<number, Decision>
  >({});

  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // Load saved decisions from PostgreSQL
  async function loadDecisionHistory() {
    try {
      const response = await fetch(
        "/api/dashboard/defense/history",
        {
          credentials: "same-origin",
        }
      );

      if (!response.ok) {
        throw new Error(
          `History request failed: HTTP ${response.status}`
        );
      }

      const history: Decision[] = await response.json();

      const latestDecisions: Record<number, Decision> = {};

      // The API returns newest decisions first
      for (const decision of history) {
        if (latestDecisions[decision.alert_id] === undefined) {
          latestDecisions[decision.alert_id] = decision;
        }
      }

      setDecisions(latestDecisions);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load decision history."
      );
    }
  }

  async function loadRecommendations() {
    try {
      const response = await fetch(
        "/api/dashboard/defense/recommendations",
        { credentials: "same-origin" }
      );

      if (response.status === 401) {
        throw new Error(
          "Dashboard login required. Open JARVIS Voice Assistant and log in."
        );
      }

      if (!response.ok) {
        throw new Error(
          `Failed to load recommendations: HTTP ${response.status}`
        );
      }

      const data: RecommendationResponse =
        await response.json();

      setRecommendations(data.recommendations);
      setError("");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Request failed."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void Promise.all([
      loadRecommendations(),
      loadDecisionHistory(),
    ]);
  }, []);
  
async function investigateAlert(alertId: number) {
  setInvestigatingId(alertId);
  setInvestigation(null);
  setError("");

  try {
    const response = await fetch(
      `/api/dashboard/investigate/${alertId}`,
      { credentials: "same-origin" }
    );

    if (response.status === 401) {
      throw new Error(
        "Dashboard session expired. Please log in again."
      );
    }

    if (!response.ok) {
      throw new Error(
        `Investigation failed: HTTP ${response.status}`
      );
    }

    const data: Investigation = await response.json();

    setInvestigation(data);

    setTimeout(() => {
      investigationRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 100);
  } catch (err) {
    setError(
      err instanceof Error
        ? err.message
        : "Unable to investigate alert."
    );
  } finally {
    setInvestigatingId(null);
  }
}

  async function recordDecision(
    recommendation: Recommendation,
    decision: "approved" | "rejected"
  ) {
    if (busyId !== null) return;

    const confirmed = window.confirm(
      `Record "${decision}" for alert #${recommendation.alert_id}?\n\n` +
      "This is simulation mode. No system action will execute."
    );

    if (!confirmed) return;

    setBusyId(recommendation.alert_id);
    setError("");
    setNotice("");

    try {
      const response = await fetch(
        "/api/dashboard/defense/decision",
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            alert_id: recommendation.alert_id,
            decision,
          }),
        }
      );

      if (response.status === 401) {
        throw new Error("Session expired. Please log in again.");
      }

      if (!response.ok) {
        throw new Error(
          `Decision failed: HTTP ${response.status}`
        );
      }

      const result: DecisionResponse =
        await response.json();

      if (
        result.execution_mode !== "simulation" ||
        result.executed !== false
      ) {
        throw new Error(
          "Unexpected execution status. Verify the backend."
        );
      }

      setDecisions((previous) => ({
        ...previous,
        [recommendation.alert_id]: {
          id: result.decision_id,
          alert_id: result.alert_id,
          decision: result.decision as "approved" | "rejected",
          action: result.action,
          execution_mode: result.execution_mode,
          timestamp: new Date().toISOString(),
          executed: result.executed,
        },
      }));
      setNotice(
        `Decision #${result.decision_id} recorded. No action executed.`
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Request failed."
      );
    } finally {
      setBusyId(null);
    }
  }

  const highRisk = recommendations.filter(
    (r) => r.risk_score >= 75
  ).length;

  return (
    <section className="defense-center">
      <div className="defense-banner">
        <h2>Defense Operations Center</h2>
        <p>
          Review recommended defensive actions.
          All decisions are recorded in simulation mode.
        </p>
      </div>

      <section className="metrics">
        <article>
          <h3>Recommendations</h3>
          <strong>{recommendations.length}</strong>
        </article>

        <article>
          <h3>High Priority</h3>
          <strong>{highRisk}</strong>
        </article>

        <article>
          <h3>Decisions This Session</h3>
          <strong>{Object.keys(decisions).length}</strong>
        </article>
      </section>

      <button
        className="voice-button"
        onClick={() => void loadRecommendations()}
        disabled={loading}
      >
        Refresh Recommendations
      </button>

      {loading && <p>Loading defense recommendations...</p>}

      {error && <p className="error" role="alert">{error}</p>}

      {notice && (
        <p className="defense-notice" role="status">
          {notice}
        </p>
      )}

      {!loading && recommendations.length === 0 && !error && (
        <div className="details-panel">
          No open alerts require recommendations.
        </div>
      )}

      <div className="defense-list">
        {recommendations.map((item) => {
          const recorded = decisions[item.alert_id];

          return (
            <article
              className="defense-card"
              key={item.alert_id}
            >
              <div className="defense-card-heading">
                <div>
                  <h3>
                    Alert #{item.alert_id}
                  </h3>
                  <h2>
                    {item.category.replace(/_/g, " ")}

                  </h2>
                </div>

                <span
                  className={`severity ${item.severity}`}
                >
                  {item.severity.toUpperCase()}
                </span>
              </div>

              <div className="defense-source">
              <span
                  className={`source-badge ${
                  item.source_type ?? "unknown"
                  }`}
                  title={item.source_name ?? "Source unverified"}
              >
                  {item.source_type === "simulated"
                  ? "SIMULATED"
                  : item.source_type === "real"
                  ? "OBSERVED"
                  : "UNVERIFIED"}
              </span>
              </div>

              <p>
                <strong>Risk Score:</strong>{" "}
                {item.risk_score}/100
              </p>

              <p>
                <strong>Recommended Action:</strong>{" "}
                {item.recommended_action.replace(/_/g, " ")}
              </p>

              <p>{item.reason}</p>

              <p className="simulation-label">
                Execution mode: SIMULATION
              </p>

              {recorded ? (
                <p className="defense-notice">
                  Decision recorded:{" "}
                  {recorded.decision.toUpperCase()}
                  {" "}— No action executed.
                </p>
              ) : (
                <div className="defense-actions">
                  <button
                    className="defense-approve"
                    disabled={busyId !== null}
                    onClick={() =>
                      void recordDecision(item, "approved")
                    }
                  >
                    {busyId === item.alert_id
                      ? "Saving..."
                      : "Approve"}
                  </button>

                  <button
                    className="defense-reject"
                    disabled={busyId !== null}
                    onClick={() =>
                      
                    void recordDecision(item, "rejected")
                  }
                >
                  Reject
                </button>
              </div>
            )}

            {/* INVESTIGATE BUTTON */}
            <button
              className="defense-investigate"
              disabled={investigatingId !== null}
              onClick={() =>
                void investigateAlert(item.alert_id)
              }
            >
              {investigatingId === item.alert_id
                ? "Investigating..."
                : "Investigate"}
            </button>

          </article>
        );
      })}
    </div>

    {/* INVESTIGATION RESULTS PANEL */}
    {investigation && (
      <section
        ref={investigationRef}
        className="investigation-panel"
      >
        <div className="investigation-header">
          <h2>
            Investigation — Alert #{investigation.alert_id}
          </h2>

          <button
            onClick={() => setInvestigation(null)}
          >
            Close
          </button>
        </div>

        <p>
          <strong>Device:</strong> {investigation.hostname}
        </p>

        <p>
          <strong>Finding:</strong> {investigation.title}
        </p>

        <p>
          <strong>Process ID:</strong>{" "}
          {investigation.pid ?? "Unknown"}
        </p>

        <p>
          <strong>Execution Mode:</strong> Read-only
        </p>

        <h3>Process Evidence</h3>

        {investigation.process_evidence.length === 0 ? (
          <p>No matching process in the latest stored snapshot.</p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Process</th>
                  <th>PID</th>
                  <th>CPU</th>
                  <th>Memory</th>
                  <th>Executable</th>
                </tr>
              </thead>

              <tbody>
                {investigation.process_evidence.map((p, index) => (
                  <tr key={`${p.pid}-${index}`}>
                    <td>{p.name}</td>
                    <td>{p.pid}</td>
                    <td>{p.cpu_percent.toFixed(1)}%</td>
                    <td>{p.memory_percent.toFixed(2)}%</td>
                    <td>{p.executable ?? "Unavailable"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <h3>Network Evidence</h3>

        {investigation.network_evidence.length === 0 ? (
          <p>No matching network connections found.</p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Local Address</th>
                  <th>Remote Address</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {investigation.network_evidence.map((c, index) => (
                  <tr key={index}>
                    <td>{c.protocol}</td>
                    <td>
                      {c.local_ip ?? "—"}:
                      {c.local_port ?? "—"}
                    </td>
                    <td>
                      {c.remote_ip ?? "—"}:
                      {c.remote_port ?? "—"}
                    </td>
                    <td>{c.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <h3>Investigation Limitations</h3>

        <ul>
          {investigation.limitations.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>
      </section>
    )}
  </section>
);
}

