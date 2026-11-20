
import { useEffect, useState } from "react";
import "./style.css";
import ActiveDefense from './ActiveDefense';
import SentinelVoice from "./SentinelVoice";
import DefenseCenter from "./DefenseCenter";

type Telemetry = {
  id: number;
  hostname: string;
  timestamp: string;
  cpu_percent: number;
  memory_percent: number;
  process_count: number;
};

type Process = {
  pid: number;
  name: string;
  status: string;
  cpu_percent: number;
  memory_percent: number;
  executable: string | null;
};

type SecurityAlert = {
  id: number;
  hostname: string;
  timestamp: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  pid: number | null;
  evidence: string;
  status: string;
  source_type: "real" | "simulated" | "unknown";
  source_name: string | null;
};

type NetworkConnection = {
  id: number;
  hostname: string;
  timestamp: string;
  pid: number | null;
  protocol: string;
  status: string;
  local_ip: string | null;
  local_port: number | null;
  remote_ip: string | null;
  remote_port: number | null;
};


type Page =
  | "overview"
  | "applications"
  | "alerts"
  | "network"
  | "voice"
  | "defense"
  | "active_defense";

export default function App() {
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [networkSearch, setNetworkSearch] = useState("");
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [page, setPage] = useState<Page>("overview");
  const [telemetry, setTelemetry] = useState<Telemetry[]>([]);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Process | null>(null);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  useEffect(() => {
    

async function loadData() {
  try {
    const [
      telemetryResponse,
      processResponse,
      alertsResponse,
      networkResponse,
    ] = await Promise.all([
      fetch("/api/telemetry/latest"),
      fetch("/api/processes/latest"),
      fetch("/api/alerts"),
      fetch("/api/network/latest"),
    ]);

    if (
      !telemetryResponse.ok ||
      !processResponse.ok ||
      !alertsResponse.ok ||
      !networkResponse.ok
    ) {
      throw new Error("Failed to retrieve monitoring data");
    }

    setTelemetry(await telemetryResponse.json());
    setProcesses(await processResponse.json());
    setAlerts(await alertsResponse.json());
    setConnections(await networkResponse.json());

    setError("");
    setLastUpdated(new Date());
  } catch (err) {
    setError(String(err));
  }
}


    loadData();
    const timer = setInterval(loadData, 5000);

    return () => clearInterval(timer);
  }, []);

  const latest = telemetry[0];

  const filtered = processes.filter((process) =>
    `${process.name} ${process.pid} ${process.executable ?? ""}`
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark">◈</div><div><strong>SENTINEL<span>X</span></strong><small>SECURITY INTELLIGENCE</small></div></div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {([
            ["overview", "◫", "Command Center"],
            ["applications", "▦", "Applications"],
            ["alerts", "◇", "Threat Intelligence"],
            ["network", "⌁", "Network Monitor"],
            ["voice", "◎", "JARVIS Assistant"],
            ["defense", "⬡", "Defense Center"],
            ["active_defense", "⛨", "Active Defense"],
          ] as [Page, string, string][]).map(([key, glyph, label]) => (
            <button key={key} className={page === key ? "active" : ""} onClick={() => setPage(key)}>
              <span className="nav-icon">{glyph}</span><span>{label}</span>
              {key === "alerts" && alerts.length > 0 && <span className="nav-count">{alerts.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="device-avatar">⌘</div>
          <div className="device-info"><strong>Local endpoint</strong><small>{latest?.hostname || "Awaiting telemetry"}</small></div>
          <span className="device-dot" />
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="heading-group"><div className="breadcrumb">SECURITY OPERATIONS <span>/</span> {page.replace("_", " ").toUpperCase()}</div>
            <h1>{({overview:"Security Command Center",applications:"Application Intelligence",alerts:"Threat Intelligence",network:"Network Activity",voice:"JARVIS Voice Assistant",defense:"Defense Center",active_defense:"Active Defense"} as Record<Page,string>)[page]}</h1>
            <p>Monitor, investigate and respond to activity on your macOS endpoint.</p>
          </div>
          <div className="top-actions"><div className="live-chip"><span className={lastUpdated && Date.now()-lastUpdated.getTime()<20000 ? "pulse-dot" : "pulse-dot stale"}/>{lastUpdated ? "DATA CONNECTED" : "WAITING FOR DATA"}</div><button className="top-avatar" onClick={()=>setPage("voice")} title="Open JARVIS">◎</button></div>
        </header>

        {error && <p className="error">{error}</p>}

        {page === "overview" && (
          <div className="overview-stack">
            <section className="hero-grid">
              <div className="hero-panel">
                <div className="eyebrow"><span className="pulse-dot"/> ENDPOINT OVERVIEW <span className="hero-tag">LIVE DATA</span></div>
                <div className="hero-main">
                  <div className="radar-core"><div className="radar-ring outer"/><div className="radar-ring mid"/><div className="radar-ring inner"/><div className="radar-sweep"/><div className="radar-center"><span>◈</span><strong>SENTINEL</strong><small>MONITORING ACTIVE</small></div></div>
                  <div className="hero-copy"><div className="hero-kicker">SYSTEM OBSERVABILITY</div><h2>Eyes on every<br/><em>critical signal.</em></h2><p>Live telemetry from {latest?.hostname || "your endpoint"}. Detection findings are indicators, not confirmed attacks.</p><div className="hero-actions"><button onClick={()=>setPage("alerts")}>Review threats <span>↗</span></button><button className="ghost" onClick={()=>setPage("voice")}>◎ Ask JARVIS</button></div></div>
                </div>
                <div className="hero-footer"><span>● SENSOR STATUS: {latest ? "REPORTING" : "AWAITING DATA"}</span><span>LAST UPDATE: {lastUpdated ? lastUpdated.toLocaleTimeString() : "—"}</span></div>
              </div>
              <div className="hero-side"><div className="side-panel"><div className="panel-topline"><span>SECURITY FINDINGS</span><span>↗</span></div><div className="side-big">{alerts.filter(a=>a.status==="open").length.toString().padStart(2,"0")}</div><div className="side-description">Open detection alerts</div><div className="severity-track"><div style={{width:`${alerts.length ? Math.round(100*alerts.filter(a=>a.severity==="high"||a.severity==="critical").length/alerts.length) : 0}%`}}/></div><div className="side-foot">{alerts.filter(a=>a.severity==="high"||a.severity==="critical").length} high / critical severity</div></div><div className="side-panel network-side"><div className="panel-topline"><span>NETWORK VISIBILITY</span><span>⌁</span></div><div className="side-big">{connections.length.toString().padStart(2,"0")}</div><div className="side-description">Connections in latest snapshot</div><div className="network-mini"><span>ESTABLISHED <b>{connections.filter(c=>c.status==="ESTABLISHED").length}</b></span><span>LISTENING <b>{connections.filter(c=>c.status==="LISTEN").length}</b></span></div></div></div>
            </section>
            <section className="kpi-grid">
              <div className="kpi-card"><div className="kpi-label">CPU UTILIZATION <span>◉</span></div><div className="kpi-value">{latest?.cpu_percent?.toFixed(1) ?? "—"}<small>%</small></div><div className="kpi-sub">Latest endpoint reading</div><div className="kpi-progress"><div style={{width:`${Math.min(100,latest?.cpu_percent||0)}%`}}/></div></div>
              <div className="kpi-card"><div className="kpi-label">MEMORY UTILIZATION <span>▤</span></div><div className="kpi-value">{latest?.memory_percent?.toFixed(1) ?? "—"}<small>%</small></div><div className="kpi-sub">System memory usage</div><div className="kpi-progress violet"><div style={{width:`${Math.min(100,latest?.memory_percent||0)}%`}}/></div></div>
              <div className="kpi-card"><div className="kpi-label">RUNNING PROCESSES <span>▦</span></div><div className="kpi-value">{latest?.process_count ?? "—"}</div><div className="kpi-sub">Reported by telemetry agent</div><div className="kpi-progress green"><div style={{width:`${Math.min(100,(latest?.process_count||0)/8)}%`}}/></div></div>
              <div className="kpi-card"><div className="kpi-label">DETECTION EVENTS <span>◇</span></div><div className="kpi-value">{alerts.length}</div><div className="kpi-sub">Stored alerts (up to 100)</div><div className="kpi-progress amber"><div style={{width:`${Math.min(100,alerts.length)}%`}}/></div></div>
            </section>
            <section className="lower-grid"><div className="content-panel"><div className="panel-heading"><div><div className="eyebrow">PERFORMANCE ANALYTICS</div><h3>System telemetry</h3></div><span className="subtle-pill">Last {telemetry.length} samples</span></div><div className="chart-legend"><span><i className="legend-cpu"/>CPU</span><span><i className="legend-memory"/>Memory</span></div><div className="telemetry-chart"><div className="chart-grid"><span>100%</span><span>75%</span><span>50%</span><span>25%</span><span>0%</span></div><svg viewBox="0 0 600 200" preserveAspectRatio="none" role="img" aria-label="CPU and memory history"><defs><linearGradient id="cpuFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#24c8f7" stopOpacity=".25"/><stop offset="1" stopColor="#24c8f7" stopOpacity="0"/></linearGradient></defs>{[0,50,100,150,200].map(y=><line key={y} x1="0" y1={y} x2="600" y2={y} stroke="#26354b" strokeDasharray="4 6"/>)}{telemetry.length>1 && <><polygon points={`0,200 ${[...telemetry].reverse().map((t,i,a)=>`${i*600/(a.length-1)},${200-Math.max(0,Math.min(100,t.cpu_percent))*2}`).join(" ")} 600,200`} fill="url(#cpuFill)"/><polyline points={[...telemetry].reverse().map((t,i,a)=>`${i*600/(a.length-1)},${200-Math.max(0,Math.min(100,t.cpu_percent))*2}`).join(" ")} fill="none" stroke="#24c8f7" strokeWidth="3" vectorEffect="non-scaling-stroke"/><polyline points={[...telemetry].reverse().map((t,i,a)=>`${i*600/(a.length-1)},${200-Math.max(0,Math.min(100,t.memory_percent))*2}`).join(" ")} fill="none" stroke="#9c88ff" strokeWidth="3" vectorEffect="non-scaling-stroke"/></>}</svg></div><div className="chart-bottom">OLDEST SAMPLE <span>LIVE MONITORING</span> LATEST SAMPLE</div></div>
            <div className="content-panel"><div className="panel-heading"><div><div className="eyebrow">DETECTION FEED</div><h3>Recent security events</h3></div><button className="text-link" onClick={()=>setPage("alerts")}>View all ↗</button></div><div className="incident-feed">{alerts.slice(0,5).map(a=><button className="incident-item" key={a.id} onClick={()=>setPage("alerts")}><span className={`incident-icon ${a.severity}`}>◇</span><span className="incident-copy"><strong>{a.title}</strong><small>#{a.id} · {new Date(a.timestamp).toLocaleString()}</small></span><span className={`severity ${a.severity}`}>{a.severity}</span></button>)}{alerts.length===0&&<div className="empty-state">No recorded detection events.</div>}</div><div className="incident-note">Alert provenance may be unverified. Investigate before responding.</div></div></section>
          </div>
        )}

        {page === "applications" && (
          <>
            <section className="metrics">
              <article>
                <h3>Processes Collected</h3>
                <strong>{processes.length}</strong>
              </article>

              <article>
                <h3>Running</h3>
                <strong>
                  {processes.filter(
                    (p) => p.status === "running"
                  ).length}
                </strong>
              </article>

              <article>
                <h3>Sleeping</h3>
                <strong>
                  {processes.filter(
                    (p) => p.status === "sleeping"
                  ).length}
                </strong>
              </article>
            </section>

            <input
              className="search-input"
              placeholder="Search application, PID or executable..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />

            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Application</th>
                    <th>PID</th>
                    <th>Status</th>
                    <th>CPU</th>
                    <th>Memory</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((process) => (
                    <tr
                      key={process.pid}
                      className="clickable-row"
                      onClick={() => setSelected(process)}
                    >
                      <td>{process.name}</td>
                      <td>{process.pid}</td>
                      <td>{process.status}</td>
                      <td>{process.cpu_percent.toFixed(1)}%</td>
                      <td>{process.memory_percent.toFixed(2)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {selected && (
              <section className="details-panel">
                <button
                  className="close-button"
                  onClick={() => setSelected(null)}
                >
                  Close
                </button>

                <h2>{selected.name}</h2>
                <p><strong>PID:</strong> {selected.pid}</p>
                <p><strong>Status:</strong> {selected.status}</p>
                <p><strong>CPU:</strong> {selected.cpu_percent}%</p>
                <p><strong>Memory:</strong> {selected.memory_percent}%</p>
                <p>
                  <strong>Executable:</strong>{" "}
                  {selected.executable ?? "Unavailable"}
                </p>
              </section>
            )}
          
          </>
        )}

        {/* SECURITY ALERTS PAGE */}
        {page === "alerts" && (
          <>
            <section className="metrics">
              <article>
                <h3>Total Alerts</h3>
                <strong>{alerts.length}</strong>
              </article>

              <article>
                <h3>High Severity</h3>
                <strong>
                  {alerts.filter(
                    (a) =>
                      a.severity === "high" ||
                      a.severity === "critical"
                  ).length}
                </strong>
              </article>

              <article>
                <h3>Open Incidents</h3>
                <strong>
                  {alerts.filter(
                    (a) => a.status === "open"
                  ).length}
                </strong>
              </article>
            </section>

            <h2>Security Detection Events</h2>

            {alerts.length === 0 ? (
              <section className="details-panel">
                <h3>No security alerts recorded</h3>
                <p>
                  No monitored activity has matched
                  the current detection rules.
                </p>
              </section>
            ) : (
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>Alert ID</th>
                      <th>Severity</th>
                      <th>Source</th>
                      <th>Threat</th>
                      <th>Device</th>
                      <th>Detected At</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.map((alert) => (
                      <tr key={alert.id}>
                      <td>
                        <span className="alert-id">
                          #{alert.id}
                        </span>
                      </td>
                        <td>
                          <span
                            className={`severity ${alert.severity}`}
                          >
                            {alert.severity.toUpperCase()}
                          </span>
                        </td>
                        {/* EVENT PROVENANCE */}
                        <td>
                          <span
                            className={`source-badge ${
                              alert.source_type ?? "unknown"
                            }`}
                            title={alert.source_name ?? "Source unverified"}
                          >
                            {alert.source_type === "simulated"
                              ? "SIMULATED"
                              : alert.source_type === "real"
                              ? "OBSERVED"
                              : "UNVERIFIED"}
                          </span>
                        </td>


                        <td>
                          <strong>{alert.title}</strong>
                          <p>{alert.description}</p>
                          <small>
                            PID: {alert.pid ?? "N/A"}
                          </small>
                        </td>

                        <td>{alert.hostname}</td>

                        <td>
                          {new Date(
                            alert.timestamp
                          ).toLocaleString()}
                        </td>

                        <td>{alert.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}

        {/* NETWORK ACTIVITY PAGE */}
        {page === "network" && (
          <>
            <section className="metrics">
              <article>
                <h3>Total Connections</h3>
                <strong>{connections.length}</strong>
              </article>

              <article>
                <h3>Established Connections</h3>
                <strong>
                  {connections.filter(
                    (c) => c.status === "ESTABLISHED"
                  ).length}
                </strong>
              </article>

              <article>
                <h3>Listening Ports</h3>
                <strong>
                  {connections.filter(
                    (c) => c.status === "LISTEN"
                  ).length}
                </strong>
              </article>
            </section>

            <h2>Network Connections</h2>

            <input
              className="search-input"
              placeholder="Search IP, port, PID or protocol..."
              value={networkSearch}
              onChange={(e) => setNetworkSearch(e.target.value)}
            />

            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>PID</th>
                    <th>Local Address</th>
                    <th>Remote Address</th>
                    <th>Status</th>
                  </tr>
                </thead>

                <tbody>
                  {connections
                    .filter((c) =>
                      [
                        c.protocol,
                        c.pid,
                        c.local_ip,
                        c.local_port,
                        c.remote_ip,
                        c.remote_port,
                        c.status,
                      ]
                        .join(" ")
                        .toLowerCase()
                        .includes(networkSearch.toLowerCase())
                    )
                    .map((c) => (
                      <tr key={c.id}>
                        <td>{c.protocol}</td>
                        <td>{c.pid ?? "N/A"}</td>
                        <td>
                          {c.local_ip ?? "N/A"}:
                          {c.local_port ?? "—"}
                        </td>
                        <td>
                          {c.remote_ip ?? "N/A"}:
                          {c.remote_port ?? "—"}
                        </td>
                        <td>{c.status}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </>
        )}
        {/* JARVIS VOICE ASSISTANT */}
        {page === "voice" && (
          <SentinelVoice />
        )}
        {/* DEFENSE CENTER */}
        {page === "defense" && (
          <DefenseCenter />
        )}
        {/* ACTIVE DEFENSE */}
        {page === "active_defense" && (
          <ActiveDefense />
        )}
      </main>
    </div>
  );
}

