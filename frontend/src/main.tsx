import React from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

function App() {
  const [apiStatus, setApiStatus] = React.useState("Checking API…");
  const [system, setSystem] = React.useState<Record<string, unknown> | null>(null);
  React.useEffect(() => {
    let active = true;
    fetch("/api/v1").then((r) => { if (!r.ok) throw new Error(`API returned ${r.status}`); return r.json(); }).then((data) => { if (active) { setSystem(data); setApiStatus("Connected"); } }).catch(() => { if (active) setApiStatus("Unavailable"); });
    return () => { active = false; };
  }, []);
  return <main className="shell"><header className="topbar"><div className="brand-mark">A</div><div><strong>AEGIS</strong><span> / AI SOC</span></div><div className="status"><i className={apiStatus === "Connected" ? "dot online" : "dot"}/>API {apiStatus}</div></header>
    <section className="hero"><p className="eyebrow">SECURITY OPERATIONS PLATFORM</p><h1>See the signal.<br/><span>Understand the threat.</span></h1><p className="intro">A unified foundation for security telemetry, detection engineering, and AI-assisted investigations.</p><div className="hero-meta"><span>ENVIRONMENT <b>LOCAL / DEVELOPMENT</b></span><span>PLATFORM <b>AEGIS CORE</b></span></div></section>
    <section className="section-heading"><div><p className="eyebrow">PLATFORM OVERVIEW</p><h2>System readiness</h2></div><span className="pill">FOUNDATION</span></section>
    <section className="cards"><article className="card"><span className="card-label">API SERVICE</span><h3>{apiStatus}</h3><p>FastAPI application and service discovery</p><span className="card-foot">PORT 8000</span></article><article className="card"><span className="card-label">DATA LAYER</span><h3>PostgreSQL + Redis</h3><p>Persistent relational storage and low-latency cache</p><span className="card-foot">PROFILE · CORE</span></article><article className="card"><span className="card-label">NEXT CAPABILITY</span><h3>Security telemetry</h3><p>Event ingestion, normalization, and detection rules</p><span className="card-foot">INTEGRATION PHASE</span></article></section>
    <section className="details"><div><p className="eyebrow">BACKEND RESPONSE</p><h2>Live service metadata</h2></div><pre>{system ? JSON.stringify(system, null, 2) : "Waiting for API response…\n\nCheck backend health if this persists."}</pre></section><footer>AEGIS AI SOC <span>Open-source components · Self-hosted foundation</span></footer></main>;
}
createRoot(document.getElementById("root")!).render(<React.StrictMode><App/></React.StrictMode>);
