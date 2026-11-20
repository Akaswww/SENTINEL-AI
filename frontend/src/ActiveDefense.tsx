
import { useEffect, useState } from "react";

type Action =
  | "block_ip"
  | "quarantine_file"
  | "terminate_process";

type RecordItem = {
  id: number;
  action: Action;
  target: string;
  reason: string;
  status: string;
  outcome: string | null;
};

type PendingAction = {
  id: number;
  action: Action;
  target: string;
};

type FirewallStatus = {
  pf_enabled: boolean;
  pf_disabled: boolean;
  helper_installed: boolean;
  helper_path?: string;
  read_only?: boolean;
};

export default function ActiveDefense() {
  const [action, setAction] =
    useState<Action>("block_ip");

  const [target, setTarget] = useState("");
  const [reason, setReason] = useState(
    "Controlled lab demonstration"
  );

  const [pending, setPending] =
    useState<PendingAction | null>(null);

  const [history, setHistory] =
    useState<RecordItem[]>([]);

  const [firewallStatus, setFirewallStatus] =
    useState<FirewallStatus | null>(null);

  const [firewallLoading, setFirewallLoading] =
    useState(false);

  const [firewallError, setFirewallError] =
    useState("");

  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  // ----------------------------------------
  // Load Active Defense audit history
  // ----------------------------------------

  async function refresh() {
    try {
      const response = await fetch(
        "/api/dashboard/active-defense/history",
        {
          credentials: "same-origin",
        }
      );

      if (!response.ok) {
        throw new Error(
          `History request failed: ${response.status}`
        );
      }

      const data: RecordItem[] =
        await response.json();

      setHistory(data);
    } catch (error) {
      console.error(
        "Active Defense history:",
        error
      );
    }
  }

  // ----------------------------------------
  // Load macOS firewall status
  // ----------------------------------------

  async function loadFirewallStatus() {
    setFirewallLoading(true);
    setFirewallError("");

    try {
      const response = await fetch(
        "/api/dashboard/firewall/status",
        {
          credentials: "same-origin",
        }
      );

      if (response.status === 401) {
        throw new Error(
          "Dashboard session expired. Please log in again."
        );
      }

      if (!response.ok) {
        throw new Error(
          `Firewall status request failed: HTTP ${response.status}`
        );
      }

      const data: FirewallStatus =
        await response.json();

      setFirewallStatus(data);
    } catch (error) {
      setFirewallStatus(null);
      setFirewallError(
        error instanceof Error
          ? error.message
          : "Unable to retrieve firewall status."
      );
    } finally {
      setFirewallLoading(false);
    }
  }

  // ----------------------------------------
  // Initial data loading
  // ----------------------------------------

  useEffect(() => {
    void refresh();
    void loadFirewallStatus();
  }, []);

  // ----------------------------------------
  // Prepare a defensive action
  // ----------------------------------------

  async function request() {
    if (!target.trim()) {
      setMessage("Please enter an exact target.");
      return;
    }

    if (!reason.trim()) {
      setMessage("Please provide a reason.");
      return;
    }

    setBusy(true);
    setMessage("");

    try {
      const response = await fetch(
        "/api/dashboard/active-defense/requests",
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            action,
            target: target.trim(),
            reason: reason.trim(),
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Failed to prepare action."
        );
      }

      setPending({
        id: data.id,
        action: data.action,
        target: data.target,
      });

      setMessage(
        "Action prepared. Review the exact target before approving."
      );

      await refresh();
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : "Unable to prepare action."
      );
    } finally {
      setBusy(false);
    }
  }

  // ----------------------------------------
  // Approve or reject action
  // ----------------------------------------

  async function decide(
    confirmation: "APPROVE" | "REJECT"
  ) {
    if (!pending) return;

    setBusy(true);
    setMessage("");

    try {
      const response = await fetch(
        `/api/dashboard/active-defense/requests/${pending.id}/decision`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            confirmation,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Decision request failed."
        );
      }

      setMessage(
        `${data.status}: ${
          data.outcome || "No action executed."
        }`
      );

      setPending(null);

      await refresh();
      await loadFirewallStatus();
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : "Unable to record decision."
      );
    } finally {
      setBusy(false);
    }
  }

  // ----------------------------------------
  // UI
  // ----------------------------------------

  return (
    <section className="active-defense">
      <h2>Active Defense</h2>

      <p>
        Controlled cybersecurity response system.
        Every defensive action requires explicit
        approval.
      </p>

      {/* FIREWALL STATUS */}

      <section className="firewall-status-panel">
        <h3>macOS Firewall Status</h3>

        <p>
          Packet Filter:{" "}
          <strong>
            {firewallLoading
              ? "Checking..."
              : firewallStatus?.pf_enabled
              ? "Enabled"
              : firewallStatus?.pf_disabled
              ? "Disabled"
              : "Unknown"}
          </strong>
        </p>

        <p>
          Sentinel Firewall Helper:{" "}
          <strong>
            {firewallStatus === null
              ? "Unknown"
              : firewallStatus.helper_installed
              ? "Installed"
              : "Not installed"}
          </strong>
        </p>

        <p>
          IP blocking remains preview-only.
          No firewall rules are modified by
          this dashboard.
        </p>

        {firewallError && (
          <p className="error">
            {firewallError}
          </p>
        )}

        <button
          type="button"
          disabled={firewallLoading}
          onClick={() =>
            void loadFirewallStatus()
          }
        >
          {firewallLoading
            ? "Checking..."
            : "Refresh Firewall Status"}
        </button>
      </section>

      {/* DEFENSE ACTION FORM */}

      <section className="defense-action-panel">
        <h3>Prepare Defensive Action</h3>

        <p>
          File and process actions are restricted
          to ~/sentinel-defense-lab.
          IP blocking does not execute.
        </p>

        <label>
          Action

          <select
            value={action}
            disabled={busy || pending !== null}
            onChange={(event) => {
              setAction(
                event.target.value as Action
              );
              setTarget("");
              setMessage("");
            }}
          >
            <option value="block_ip">
              Block IP (Preview Only)
            </option>

            <option value="quarantine_file">
              Quarantine Lab File
            </option>

            <option value="terminate_process">
              Terminate Lab Process
            </option>
          </select>
        </label>

        <label>
          Exact Target

          <input
            value={target}
            disabled={busy || pending !== null}
            onChange={(event) =>
              setTarget(event.target.value)
            }
            placeholder={
              action === "block_ip"
                ? "Public IP address"
                : action === "terminate_process"
                ? "Process PID"
                : "Absolute lab file path"
            }
          />
        </label>

        <label>
          Reason

          <input
            value={reason}
            disabled={busy || pending !== null}
            onChange={(event) =>
              setReason(event.target.value)
            }
          />
        </label>

        <button
          type="button"
          disabled={
            busy ||
            pending !== null ||
            !target.trim() ||
            !reason.trim()
          }
          onClick={() => void request()}
        >
          {busy
            ? "Processing..."
            : "Prepare Action"}
        </button>
      </section>

      {/* APPROVAL PANEL */}

      {pending && (
        <div
          className="details-panel"
          role="group"
          aria-label="Confirm defense action"
        >
          <h3>Approval Required</h3>

          <p>
            <strong>Action:</strong>{" "}
            {pending.action}
          </p>

          <p>
            <strong>Target:</strong>{" "}
            {pending.target}
          </p>

          <p>
            <strong>Request ID:</strong>{" "}
            #{pending.id}
          </p>

          <p>
            Approval expires after 2 minutes.
            Process termination cannot be undone.
          </p>

          {pending.action === "block_ip" && (
            <p>
              This action is preview-only.
              Approval will not block the IP.
            </p>
          )}

          <div className="defense-actions">
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                void decide("APPROVE")
              }
            >
              Approve Exact Target
            </button>

            <button
              type="button"
              disabled={busy}
              onClick={() =>
                void decide("REJECT")
              }
            >
              Reject
            </button>
          </div>
        </div>
      )}

      {/* STATUS MESSAGE */}

      {message && (
        <p role="status" className="defense-notice">
          {message}
        </p>
      )}

      {/* AUDIT HISTORY */}

      <section className="defense-history">
        <div className="defense-history-header">
          <h3>Defense Audit History</h3>

          <button
            type="button"
            onClick={() => void refresh()}
          >
            Refresh History
          </button>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Action</th>
                <th>Target</th>
                <th>Reason</th>
                <th>Status</th>
                <th>Outcome</th>
              </tr>
            </thead>

            <tbody>
              {history.length === 0 ? (
                <tr>
                  <td colSpan={6}>
                    No defensive actions recorded.
                  </td>
                </tr>
              ) : (
                history.map((item) => (
                  <tr key={item.id}>
                    <td>#{item.id}</td>

                    <td>{item.action}</td>

                    <td>{item.target}</td>

                    <td>{item.reason}</td>

                    <td>
                      <span
                        className={`defense-status ${item.status}`}
                      >
                        {item.status}
                      </span>
                    </td>

                    <td>
                      {item.outcome || "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
