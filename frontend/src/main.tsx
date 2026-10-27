import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary fallbackTitle="AegisFlight Dashboard Rendering Error">
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
