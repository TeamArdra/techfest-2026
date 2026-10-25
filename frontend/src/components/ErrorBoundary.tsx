import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public override state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public override componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  public override render() {
    if (this.state.hasError) {
      return (
        <div
          className="panel error-boundary-box"
          style={{
            padding: "1.2rem",
            margin: "0.5rem 0",
            border: "1px solid var(--crit, #ef4444)",
            borderRadius: "6px",
            background: "rgba(239, 68, 68, 0.08)",
          }}
        >
          <h3 style={{ color: "var(--crit, #ef4444)", margin: "0 0 0.5rem 0", fontSize: "0.95rem" }}>
            {this.props.fallbackTitle || "Component Error"}
          </h3>
          <p style={{ color: "var(--text-dim, #94a3b8)", fontSize: "0.82rem", margin: "0 0 0.5rem 0" }}>
            {this.state.error?.message || "An unexpected error occurred while rendering."}
          </p>
          <button
            type="button"
            className="override-btn"
            style={{ padding: "4px 12px", fontSize: "0.8rem", cursor: "pointer" }}
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Retry Component
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
