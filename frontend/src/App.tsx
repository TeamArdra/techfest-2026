import { useEffect, useState } from "react";
import { SettingsModal } from "./components/SettingsModal";
import { AlertsPanel } from "./components/AlertsPanel";
import { ControlPanel } from "./components/ControlPanel";
import { DefensePanel } from "./components/DefensePanel";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Header, SourceBar } from "./components/Header";
import { MapPanel } from "./components/MapPanel";
import { DetectorPanel, EvidencePanel, ThreatPanel, TelemetryPanel } from "./components/panels";
import {
  CoveragePanel,
  IntegrationPanel,
  RuntimePanel,
  ValidationPanel,
} from "./components/evalPanels";
import { useLiveData } from "./hooks/useLiveData";
import { ChecksPanel, BridgePanel, useBridge } from "./components/liveChecks";
import { envView, linkView } from "./lib/source";

export default function App() {
  const live = useLiveData();
  const bridge = useBridge();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const m = live.metrics;
  const chainOk = m?.event_log.chain_ok !== false;
  // every source label below comes from the backend's own report (environment + link state)
  const env = envView(live.environment);
  const lv = linkView(live.link, live.connected, live.updateAgeS, live.environment);
  useEffect(() => {
    document.title = `AegisFlight — UAV IDS (${env.badge})`;
  }, [env.badge]);

  return (
    <div className="app">
      <Header
        connected={live.connected}
        clock={live.t}
        mlAvailable={m?.ml_available ?? false}
        env={env}
        link={lv}
        defenseMode={live.defenseMode}
        onSettings={() => setSettingsOpen(true)}
      />
      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
      <SourceBar
        source={live.source}
        link={live.link}
        linkView={lv}
        runId={live.runId}
        eventsCount={live.eventsCount}
      />

      <main className="console">
        {/* 1. primary: threat assessment · flight track · incidents */}
        <section className="ops">
          <div className="stack">
            <ThreatPanel threat={live.threat} />
            <DetectorPanel threat={live.threat} />
          </div>
          <MapPanel
            track={live.track}
            trackThreat={live.trackThreat}
            rawTrack={live.rawTrack}
            scoreHistory={live.scoreHistory}
            altHistory={live.altHistory}
            threat={live.threat}
            telemetry={live.telemetry}
            sanitizedTelemetry={live.sanitizedTelemetry}
            defenseMode={live.defenseMode}
            mitigation={live.mitigation}
            attackActive={live.attackActive}
            origin={live.origin}
            environment={live.environment}
            note={env.trackNote}
          />
          <AlertsPanel
            alerts={live.alerts}
            emptyText={env.emptyAlerts}
            count={live.eventsCount}
            environment={env.badge}
          />
          <ErrorBoundary fallbackTitle="Defense & Recovery Panel Unavailable">
            <DefensePanel
              mode={live.defenseMode}
              mitigation={live.mitigation}
              threat={live.threat}
              telemetry={live.telemetry}
              topologyInfo={live.topologyInfo}
              bridgeTopology={bridge.st?.topology ?? null}
            />
          </ErrorBoundary>
        </section>

        {live.environment && live.environment !== "SIM" && <ChecksPanel checks={live.checks} />}
        <BridgePanel url={bridge.url} st={bridge.st} bad={bridge.bad} />

        {/* 2. secondary: runtime performance · attack-vector coverage */}
        <section className="secondary">
          <RuntimePanel metrics={m} distance={live.distance} distanceNote={env.distanceNote} />
          <CoveragePanel activeAttack={live.attackActive} />
        </section>

        {/* 3. telemetry */}
        <TelemetryPanel
          tele={live.telemetry}
          sanitized={live.sanitizedTelemetry}
          note={env.telemetryNote}
          defenseMode={live.defenseMode}
          mitigation={live.mitigation}
        />

        {/* 4. evidence · controls */}
        <section className="lower">
          <EvidencePanel threat={live.threat} />
          <ControlPanel
            activeAttack={live.attackActive}
            controls={env.controls}
            environment={env.badge}
          />
        </section>

        {/* 5. reference: integration · validation evidence */}
        <section className="reference">
          <IntegrationPanel />
          <ValidationPanel />
        </section>
      </main>

      <div className="metrics-bar">
        <span className="m-tag">{env.badge} · this run</span>
        <span className="m">Messages <b>{m?.messages_processed ?? 0}</b></span>
        <span className="m">Decisions <b>{m?.decisions ?? 0}</b></span>
        <span className="m">Alerts <b>{m?.alerts ?? 0}</b></span>
        <span className="m">Distance <b>{((live.distance ?? 0) / 1000).toFixed(2)}</b> km</span>
        <span className="m">Throughput <b>{m?.throughput_msgs_per_s ?? 0}</b> msg/s</span>
        <span className="m">Decision compute <b>{m?.decision_compute_ms != null ? m.decision_compute_ms.toFixed(2) : "—"}</b> ms</span>
        <span className="m">
          Event log <b>{m?.event_log.count ?? 0}</b> · chain{" "}
          <b style={{ color: chainOk ? "var(--ok)" : "var(--crit)" }}>{chainOk ? "OK" : "BROKEN"}</b>
        </span>
      </div>
      <div className="foot" data-testid="footer">
        AegisFlight is a proof-of-concept IDS. <b>{env.badge}</b>: {env.footer}
      </div>
    </div>
  );
}
