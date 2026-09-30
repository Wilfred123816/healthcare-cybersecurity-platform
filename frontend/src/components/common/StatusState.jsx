import {
  AlertTriangle,
  CheckCircle2,
  Inbox,
  RefreshCw,
} from "lucide-react";

import "./StatusState.css";

export default function StatusState({
  type = "empty",
  title,
  message,
  actionLabel = "Try again",
  onAction,
}) {
  const content = {
    loading: {
      title: title || "Loading",
      message:
        message ||
        "Please wait while the security platform loads the requested data.",
    },

    error: {
      title: title || "Something went wrong",
      message:
        message ||
        "The platform could not complete this request.",
    },

    empty: {
      title: title || "No data available",
      message:
        message ||
        "There is currently no information to display.",
    },

    success: {
      title: title || "Operation complete",
      message:
        message ||
        "The requested operation completed successfully.",
    },
  };

  const current =
    content[type] || content.empty;

  return (
    <div
      className={`status-state status-state-${type}`}
    >
      <div className="status-state-icon">
        {type === "loading" && (
          <div className="status-state-spinner" />
        )}

        {type === "error" && (
          <AlertTriangle size={28} />
        )}

        {type === "empty" && (
          <Inbox size={28} />
        )}

        {type === "success" && (
          <CheckCircle2 size={28} />
        )}
      </div>

      <h3>
        {current.title}
      </h3>

      <p>
        {current.message}
      </p>

      {type === "error" &&
        onAction && (
          <button
            type="button"
            className="status-state-action"
            onClick={onAction}
          >
            <RefreshCw size={15} />
            {actionLabel}
          </button>
        )}
    </div>
  );
}