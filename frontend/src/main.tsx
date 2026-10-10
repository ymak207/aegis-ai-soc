import React from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Alert = { id: string; title: string; severity: string; status: string; created_at: string; message: string; src_ip?: string };
type CaseItem = { id: string; title: string; severity: string; status: string; assignee?: string };
type Overview = { events: number; alerts_open: number; alerts_critical: number; cases_open: number; indicators: number; documents: number };
const API = "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers || {}) } });
  if (!response.ok) throw new Error((await response.text()).slice(0, 250) || `HTTP ${response.status}`);
  return response.json() as Promise<T>;
}

function App() {
  const [status, setStatus] = React.useState("Connecting");
  const [overview, setOverview] = React.useState<Overview | null>(null);
  const [alerts, setAlerts] = React.useState<Alert[]>([]);
  const [cases, setCases] = React.useState<CaseItem[]>([]);
  const [message, setMessage] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [eventType, setEventType] = React.useState("authentication_failure");
  const [eventMessage, setEventMessage] = React.useState("Multiple failed logins detected for privileged account");
  const [question, setQuestion] = React.useState("Investigate repeated authentication failures and recommend next steps.");
  const [investigation, setInvestigation] = React.useState("");

  const refresh = React.useCallback(async () => {
    try {
      const [o, a, c] = await Promise.all([
        request<Overview>(`${API}/overview`), request<{items: Alert[]}>(`${API}/alerts?status=open&limit=25`),
        request<{items: CaseItem[]}>(`${API}/cases?limit=10`)
      ]);
      setOverview(o); setAlerts(a.items); setCases(c.items); setStatus("Connected"); setMessage("");
    } catch (error) { setStatus("Unavailable"); setMessage(error instanceof Error ? error.message : "API request failed"); }
  }, []);

  React.useEffect(() => { void refresh(); const id = window.setInterval(() => void refresh(), 15000); return () => window.clearInterval(id); }, [refresh]);

  async function simulateEvent() {
    setBusy(true); setMessage("");
    try {
      await request(`${API}/events`, { method: "POST", body: JSON.stringify({
        source: "aegis-demo", event_type: eventType, severity: "high", username: "demo-admin",
        src_ip: "198.51.100.23", host: "demo-endpoint-01", message: eventMessage,
        raw: { simulation: true, dataset: "safe-synthetic" }
      }) });
      setMessage("Synthetic event submitted; detections refreshed."); await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Event submission failed"); }
    finally { setBusy(false); }
  }

  async function createCase(alert?: Alert) {
    setBusy(true);
    try {
      await request(`${API}/cases`, { method: "POST", body: JSON.stringify({
        title: alert ? `Investigation: ${alert.title}` : "Analyst-created investigation",
        severity: alert?.severity || "medium", description: alert?.message || "Created from AEGIS console",
        alert_ids: alert ? [alert.id] : []
      }) });
      setMessage("Case created."); await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Case creation failed"); }
    finally { setBusy(false); }
  }

  async function runInvestigation() {
    setBusy(true);
    try {
      const result = await request<Record<string, unknown>>(`${API}/investigations`, { method: "POST", body: JSON.stringify({ question }) });
      setInvestigation(JSON.stringify(result, null, 2));
    } catch (error) { setMessage(error instanceof Error ? error.message : "Investigation failed"); }
    finally { setBusy(false); }
  }

  return <main className="shell">
    <header className="topbar"><div className="brand-mark">A</div><div><strong>AEGIS</strong><span> / AI SOC</span></div>
      <div className="status"><i className={`dot ${status === "Connected" ? "online" : ""}`} />API {status}<button className="ghost" onClick={() => void refresh()}>Refresh</button></div></header>
    <section className="hero"><p className="eyebrow">SECURITY OPERATIONS PLATFORM · LOCAL DEVELOPMENT</p>
      <h1>See the signal.<br/><span>Understand the threat.</span></h1>
      <p className="intro">Security telemetry, rule-based detections, case management, threat intelligence and evidence-first investigations.</p>
      <div className="hero-meta"><span>DEPLOYMENT <b>SELF-HOSTED</b></span><span>LLM <b>OPTIONAL · LOCAL OLLAMA</b></span><span>DETECTION <b>RULE + HEURISTIC BASELINE</b></span></div>
    </section>
    <section className="section-heading"><div><p className="eyebrow">LIVE TELEMETRY</p><h2>Operational overview</h2></div><span className="pill">{status.toUpperCase()}</span></section>
    <section className="cards">
      {[["Events ingested",overview?.events],["Open alerts",overview?.alerts_open],["Critical alerts",overview?.alerts_critical],["Open cases",overview?.cases_open],["Threat indicators",overview?.indicators],["Knowledge documents",overview?.documents]].map(([label,value]) =>
        <article className="card" key={String(label)}><span className="card-label">{label}</span><h3>{value ?? "—"}</h3><p>Persisted in the SOC database</p></article>)}
    </section>
    <section className="work-grid">
      <article className="panel"><p className="eyebrow">SAFE SIMULATION</p><h2>Generate a test event</h2>
        <label>Event type<select value={eventType} onChange={e=>setEventType(e.target.value)}><option value="authentication_failure">Authentication failure</option><option value="suspicious_process">Suspicious process</option><option value="privilege_escalation">Privilege escalation</option><option value="normal_activity">Normal activity</option></select></label>
        <label>Event message<input value={eventMessage} onChange={e=>setEventMessage(e.target.value)} maxLength={1000}/></label>
        <button disabled={busy} onClick={() => void simulateEvent()}>{busy ? "Working…" : "Submit synthetic event"}</button>
        <p className="hint">Uses reserved documentation IP 198.51.100.23. No external systems are contacted.</p>
      </article>
      <article className="panel"><p className="eyebrow">AI-ASSISTED TRIAGE</p><h2>Investigation assistant</h2>
        <label>Question<textarea value={question} onChange={e=>setQuestion(e.target.value)} rows={3}/></label>
        <button disabled={busy} onClick={() => void runInvestigation()}>{busy ? "Working…" : "Investigate with available evidence"}</button>
        {investigation && <pre className="result">{investigation}</pre>}
        <p className="hint">Uses stored evidence and local Ollama if available. Outputs are advisory; no response actions are executed.</p>
      </article>
    </section>
    <section className="section-heading"><div><p className="eyebrow">DETECTION QUEUE</p><h2>Open alerts</h2></div><span className="pill">{alerts.length} SHOWN</span></section>
    <section className="table-wrap"><table><thead><tr><th>Detection</th><th>Severity</th><th>Source</th><th>Status</th><th>Action</th></tr></thead><tbody>
      {alerts.map(alert=><tr key={alert.id}><td><strong>{alert.title}</strong><small>{alert.message}</small></td><td><span className={`severity ${alert.severity}`}>{alert.severity}</span></td><td>{alert.src_ip || "—"}</td><td>{alert.status}</td><td><button className="small" disabled={busy} onClick={() => void createCase(alert)}>Create case</button></td></tr>)}
      {!alerts.length && <tr><td colSpan={5} className="empty">No open alerts. Submit a synthetic event to exercise detection.</td></tr>}
    </tbody></table></section>
    <section className="section-heading"><div><p className="eyebrow">CASE MANAGEMENT</p><h2>Recent investigations</h2></div><button className="ghost" disabled={busy} onClick={() => void createCase()}>New case</button></section>
    <section className="case-list">{cases.map(item=><article className="case-row" key={item.id}><div><strong>{item.title}</strong><p>{item.id}</p></div><span className={`severity ${item.severity}`}>{item.severity}</span><span className="pill">{item.status}</span></article>)}{!cases.length && <p className="empty">No cases yet. Create one from an alert or start a new case.</p>}</section>
    {message && <div className="notice">{message}</div>}
    <footer>AEGIS AI SOC <span>Open-source stack · Defensive use · Human-reviewed investigations</span></footer>
  </main>;
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
