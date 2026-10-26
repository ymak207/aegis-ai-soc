import React from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Alert = { id: string; title: string; severity: string; status: string; created_at: string; description?: string; message?: string; src_ip?: string; rule_id?: string; event_type?: string };
type CaseItem = { id: string; title: string; severity: string; status: string; assignee?: string; description?: string };
type Overview = { events: number; alerts_open: number; alerts_critical: number; cases_open: number; indicators: number; documents: number };
type Indicator = { id: string; indicator_type: string; value: string; confidence: number; source: string; description: string };
type DocumentItem = { id: string; title: string; source: string; content?: string; score?: number };
type PlatformStatus = { api: string; version: string; readiness: Record<string, string>; metrics: Record<string, number | null>; capabilities: string[]; integrations: { name: string; state: string; detail: string }[] };
type CorrelationLead = { id: string; rule_id: string; domain: string; title: string; severity: string; entity_type: string; entity_value: string; window_minutes: number; observed_interval_seconds: number; evidence_event_ids: string[]; event_types: string[]; explanation: string; limitations: string[] };
type StudioDomain = { id: string; label: string; event_families: string[]; sources: string[]; required_context: string[]; evaluation_dimensions: string[]; configuration_status: string; configuration_note: string; evaluation_endpoint: string; run_endpoint: string };
type StudioCatalog = { catalog_version: string; mode: string; domains: StudioDomain[]; capabilities: Array<{id:string;label:string;status:string;evaluation:string[]}>; next_configuration_steps: string[] };
type DomainEvaluation = { id?: string; domain: string; dataset_version: string; evaluation_type: string; sample_count: number; confusion_matrix: {tp:number;fp:number;tn:number;fn:number}; precision:number; recall:number; f1:number; accuracy:number; pass_count:number; limitations:string[] };
type Page = "overview" | "detections" | "knowledge" | "domainStudio" | "platform";
const API = "/api/v1";
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers || {}) } });
  if (!response.ok) throw new Error((await response.text()).slice(0, 250) || `HTTP ${response.status}`);
  return response.json() as Promise<T>;
}
const fmt = (n: number | null | undefined) => n == null ? "—" : new Intl.NumberFormat().format(n);

function App() {
  const [page, setPage] = React.useState<Page>("overview");
  const [status, setStatus] = React.useState("Connecting");
  const [overview, setOverview] = React.useState<Overview | null>(null);
  const [alerts, setAlerts] = React.useState<Alert[]>([]);
  const [cases, setCases] = React.useState<CaseItem[]>([]);
  const [indicators, setIndicators] = React.useState<Indicator[]>([]);
  const [documents, setDocuments] = React.useState<DocumentItem[]>([]);
  const [message, setMessage] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [eventType, setEventType] = React.useState("authentication_failure");
  const [eventMessage, setEventMessage] = React.useState("Multiple failed logins detected for privileged account");
  const [question, setQuestion] = React.useState("Investigate repeated authentication failures and recommend next steps.");
  const [investigation, setInvestigation] = React.useState<Record<string, unknown> | null>(null);
  const [indicatorType, setIndicatorType] = React.useState("ip");
  const [indicatorValue, setIndicatorValue] = React.useState("");
  const [docTitle, setDocTitle] = React.useState("");
  const [docContent, setDocContent] = React.useState("");
  const [searchQuery, setSearchQuery] = React.useState("authentication");
  const [searchResults, setSearchResults] = React.useState<DocumentItem[]>([]);
  const [platform, setPlatform] = React.useState<PlatformStatus | null>(null);
  const [evaluationResult, setEvaluationResult] = React.useState<Record<string, unknown> | null>(null);
  const [dataQuality, setDataQuality] = React.useState<Record<string, unknown> | null>(null);
  const [graphSummary, setGraphSummary] = React.useState<Record<string, unknown> | null>(null);
  const [agentRuns, setAgentRuns] = React.useState<Array<Record<string, unknown>>>([]);
  const [correlationLeads, setCorrelationLeads] = React.useState<CorrelationLead[]>([]);
  const [correlationDomain, setCorrelationDomain] = React.useState("all");
  const [correlationMode, setCorrelationMode] = React.useState("not loaded");
  const [studioCatalog, setStudioCatalog] = React.useState<StudioCatalog | null>(null);
  const [studioDomain, setStudioDomain] = React.useState("ecommerce");
  const [domainEvaluation, setDomainEvaluation] = React.useState<DomainEvaluation | null>(null);
  const [domainEvalHistory, setDomainEvalHistory] = React.useState<DomainEvaluation | null>(null);
  React.useEffect(() => {
    if (!message && !error) return;
    const timeout = window.setTimeout(() => {
      setMessage("");
      setError("");
    }, error ? 5000 : 1800);
    return () => window.clearTimeout(timeout);
  }, [message, error]);

  const refresh = React.useCallback(async () => {
    try {
      const [o, a, c, i, d] = await Promise.all([
        request<Overview>(`${API}/overview`), request<{items: Alert[]}>(`${API}/alerts?status=open&limit=25`),
        request<{items: CaseItem[]}>(`${API}/cases?limit=10`), request<{items: Indicator[]}>(`${API}/intel/indicators?limit=100`),
        request<{items: DocumentItem[]}>(`${API}/knowledge/search?q=security&limit=20`)
      ]);
      setOverview(o); setAlerts(a.items); setCases(c.items); setIndicators(i.items);
      // Search endpoint returns only matching documents, so its count is not the document inventory.
      setDocuments(d.items); setStatus("Connected"); setError("");
      return true;
    } catch (e) { setStatus("Unavailable"); setError(e instanceof Error ? e.message : "API request failed"); return false; }
  }, []);
  const refreshPlatform = React.useCallback(async () => {
    try {
      const [health, info, metricText, tools, toolsQuality, graph, agentHistory, evalHistory, liveIntegrations] = await Promise.all([
        request<{status: string; checks: Record<string, string>}>('/health/ready'), request<{version: string; capabilities: string[]}>(API),
        fetch('/metrics').then(r => r.ok ? r.text() : Promise.reject(new Error('metrics endpoint unavailable'))),
        request<{tools: unknown[]}>(`${API}/mcp/tools`),
        request<Record<string, unknown>>(`${API}/data/quality`),
        request<Record<string, unknown>>(`${API}/graph/summary`),
        request<{items: Array<Record<string, unknown>>}>(`${API}/agents/runs?limit=5`),
        request<{items: Array<{id: string; suite: string; metrics: Record<string, unknown>; created_at: string}>}>(`${API}/evaluations/results?limit=1`),
        request<{items: Array<{name:string;state:string;detail:string}>}>(`${API}/integrations`)
      ]);
      const parsed: Record<string, number | null> = {};
      for (const line of metricText.split('\n')) { const m = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)\s+([0-9.eE+-]+)$/); if (m) parsed[m[1]] = Number(m[2]); }
      setDataQuality(toolsQuality);
      setGraphSummary(graph);
      setAgentRuns(agentHistory.items);
      setEvaluationResult(evalHistory.items[0]?.metrics || null);
      setPlatform({ api: health.status, version: info.version, readiness: health.checks, metrics: parsed, capabilities: info.capabilities,
        integrations: [
          {name:"PostgreSQL",state:health.checks.postgres === "ok" ? "online" : "offline",detail:"Persistent event, alert, case and audit records"},
          {name:"Redis",state:health.checks.redis === "ok" ? "online" : "offline",detail:"Cache / queue dependency health probe"},
          ...liveIntegrations.items.map(x=>({name:x.name,state:x.state,detail:x.detail})),
          {name:"MCP JSON-RPC",state:"online",detail:`Read-only MCP-compatible initialize/tools/list/tools/call endpoint; ${tools.tools.length} legacy catalog entries`},
          {name:"ML model registry",state:"not_configured",detail:"No trained model or registry is configured; synthetic rule benchmark remains separate."},
        ] });
      return true;
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load platform status"); return false; }
  }, []);
  React.useEffect(() => { void refresh(); const id = window.setInterval(() => void refresh(), 15000); return () => window.clearInterval(id); }, [refresh]);
  const refreshCorrelations = React.useCallback(async () => {
    try {
      const suffix = correlationDomain === "all" ? "" : `?domain=${encodeURIComponent(correlationDomain)}`;
      const result = await request<{items: CorrelationLead[]; mode: string}>(`${API}/correlations${suffix}`);
      setCorrelationLeads(result.items);
      setCorrelationMode(result.mode);
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load correlation leads");
      return false;
    }
  }, [correlationDomain]);
  React.useEffect(() => { if (page === "platform") void refreshPlatform(); }, [page, refreshPlatform]);
  const refreshStudio = React.useCallback(async () => {
    try {
      const catalog = await request<StudioCatalog>(`${API}/platform/studio`);
      setStudioCatalog(catalog);
      const evaluation = await request<DomainEvaluation>(`${API}/platform/domains/${encodeURIComponent(studioDomain)}/evaluation`);
      setDomainEvaluation(evaluation);
      return true;
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load domain studio"); return false; }
  }, [studioDomain]);
  React.useEffect(() => { if (page === "domainStudio") void refreshStudio(); }, [page, refreshStudio]);
  React.useEffect(() => { if (page === "detections") void refreshCorrelations(); }, [page, refreshCorrelations]);

  async function runScopedRefresh(label: string, work: () => Promise<boolean>) {
    if (busy) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const ok = await work();
      if (ok) setMessage(`${label} refreshed successfully.`);
      else if (!error) setError(`${label} refresh failed. Check the API and try again.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : `${label} refresh failed.`);
    } finally {
      setBusy(false);
    }
  }

  async function handleRefresh() {
    if (busy) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const baseOk = await refresh();
      if (!baseOk) return;
      let pageOk = true;
      if (page === "platform") pageOk = await refreshPlatform();
      else if (page === "domainStudio") pageOk = await refreshStudio();
      else if (page === "detections") pageOk = await refreshCorrelations();
      if (pageOk) setMessage(`${nav.find(n => n.id === page)?.label || "Workspace"} refreshed successfully.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Refresh failed");
    } finally {
      setBusy(false);
    }
  }

  async function action(work: () => Promise<void>, success?: string) {
    setBusy(true); setMessage(""); setError("");
    try { await work(); if (success) setMessage(success); await refresh(); if (page === "platform") await refreshPlatform(); }
    catch (e) { setError(e instanceof Error ? e.message : "Request failed"); }
    finally { setBusy(false); }
  }
  async function runDomainEvaluation() {
    await action(async () => {
      const result = await request<DomainEvaluation>(`${API}/platform/domains/${encodeURIComponent(studioDomain)}/evaluation`, {method:"POST"});
      setDomainEvaluation(result);
      setDomainEvalHistory(result);
    }, `Saved ${studioDomain} domain smoke evaluation. Results are synthetic and not production validation.`);
  }
  async function runEvaluation() {
    await action(async () => {
      const result = await request<Record<string, unknown>>(`${API}/evaluations/run`, { method: "POST" });
      setEvaluationResult(result);
    }, "Synthetic detection benchmark completed and persisted.");
  }
  async function simulateEvent() {
    await action(async () => { await request(`${API}/events`, { method: "POST", body: JSON.stringify({ source:"aegis-demo", event_type:eventType, severity:"high", username:"demo-admin", src_ip:"198.51.100.23", host:"demo-endpoint-01", message:eventMessage, raw:{simulation:true,dataset:"safe-synthetic"} }) }); }, "Synthetic event submitted. Refreshing detections.");
  }
  async function simulateCorrelationScenario() {
    if (correlationDomain === "all") {
      setError("Choose a specific domain before generating a correlation scenario.");
      return;
    }
    await action(async () => {
      const result = await request<{domain:string;events_ingested:number;lead:CorrelationLead;note:string}>(
        `${API}/correlations/simulate?domain=${encodeURIComponent(correlationDomain)}`, {method:"POST"}
      );
      setCorrelationLeads(current => [result.lead, ...current.filter(item => item.id !== result.lead.id)]);
      setCorrelationMode("deterministic-multi-event-correlation");
      setMessage(`Generated ${result.events_ingested} synthetic events for ${result.domain}; correlation ${result.lead.rule_id} matched. ${result.note}`);
      await refreshCorrelations();
    }, undefined);
  }
  async function createCorrelationCase(lead: CorrelationLead) {
    await action(async () => {
      await request(`${API}/cases`, { method:"POST", body:JSON.stringify({
        title: `Correlation review: ${lead.domain} / ${lead.rule_id}`,
        severity: lead.severity,
        description: `${lead.explanation} Entity: ${lead.entity_type}=${lead.entity_value}. Evidence event IDs: ${lead.evidence_event_ids.join(", ")}. Limitations: ${lead.limitations.join("; ")}. This is an investigation lead, not proof of compromise.`,
        alert_ids: []
      }) });
    }, "Correlation review case created with evidence references.");
  }
  async function createCase(alert?: Alert) {
    await action(async () => { await request(`${API}/cases`, { method:"POST", body:JSON.stringify({ title:alert ? `Investigation: ${alert.title}` : "Analyst-created investigation", severity:alert?.severity || "medium", description:alert?.description || alert?.message || "Created from AEGIS console", alert_ids:alert ? [alert.id] : [] }) }); }, "Case created.");
  }
  async function runInvestigation(alert?: Alert) {
    await action(async () => { const result = await request<Record<string, unknown>>(`${API}/investigations`, { method:"POST", body:JSON.stringify({question, alert_id:alert?.id}) }); setInvestigation(result); }, "Investigation completed; review the evidence and limitations.");
  }
  async function addIndicator(e: React.FormEvent) {
    e.preventDefault(); await action(async () => { await request(`${API}/intel/indicators`, {method:"POST",body:JSON.stringify({indicator_type:indicatorType,value:indicatorValue,confidence:70,source:"analyst-console",description:"Added through AEGIS UI"})}); setIndicatorValue(""); }, "Threat indicator saved.");
  }
  async function addDocument(e: React.FormEvent) {
    e.preventDefault(); await action(async () => { const r=await request<{retrieval_status:string}>(`${API}/knowledge/documents`, {method:"POST",body:JSON.stringify({title:docTitle,content:docContent,source:"analyst-console"})}); setDocTitle(""); setDocContent(""); setMessage(r.retrieval_status === "vector_indexed" ? "Document saved and vector-indexed." : "Document saved; vector services unavailable, keyword fallback remains active."); }, undefined);
  }
  async function searchKnowledge(e: React.FormEvent) { e.preventDefault(); await action(async () => { const r=await request<{items:DocumentItem[];mode:string}>(`${API}/knowledge/search?q=${encodeURIComponent(searchQuery)}&limit=10`); setSearchResults(r.items); setMessage(`Knowledge search mode: ${r.mode}`); }, undefined); }

  const nav: {id:Page; label:string; sub:string}[] = [
    {id:"overview",label:"Command center",sub:"Live operations"}, {id:"detections",label:"Detection & response",sub:"Events · alerts · cases"},
    {id:"knowledge",label:"Intel & knowledge",sub:"Indicators · retrieval"}, {id:"domainStudio",label:"Domain studio",sub:"Profiles · rules · evaluation"}, {id:"platform",label:"Stack & evaluation",sub:"Health · quality · capacity"}
  ];
  const studioDomainProfile = studioCatalog?.domains.find(x => x.id === studioDomain);

  return <main className="app-shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark">A</div><div><strong>AEGIS</strong><span>AI SECURITY OPERATIONS</span></div></div>
      <div className="workspace-label">WORKSPACE <span>LOCAL POC</span></div>
      <nav>{nav.map(n=><button key={n.id} className={`nav-item ${page===n.id?"active":""}`} onClick={()=>setPage(n.id)}><span className="nav-glyph">{({overview:"◈",detections:"⌁",knowledge:"◎",domainStudio:"◇",platform:"▦"} as Record<string,string>)[n.id]}</span><span><b>{n.label}</b><small>{n.sub}</small></span>{page===n.id&&<i/>}</button>)}</nav>
      <div className="sidebar-bottom"><div className={`health-chip ${status==="Connected"?"ok":"bad"}`}><i/>{status==="Connected"?"API CONNECTED":"API UNAVAILABLE"}</div><small>Defensive use only · analyst reviewed</small><small>Build 0.2.0 · self-hosted</small></div>
    </aside>
    <section className="main-area"><header className="topbar"><div><span className="breadcrumb">AEGIS / </span><strong>{nav.find(n=>n.id===page)?.label}</strong></div><div className="top-actions"><span className="live-indicator"><i/> LIVE · 15S REFRESH</span><button className="button secondary" disabled={busy} onClick={()=>void handleRefresh()}>{busy?"Refreshing…":"↻ Refresh"}</button></div></header>
      <section className="page-content">
        {error && <div className="notice-panel" role="alert"><b>Request failed</b><p>{error}</p></div>}
        {message && <div className="notice-panel" role="status"><p>{message}</p></div>}
        {page==="overview" && <>
          <div className="page-title"><div><p className="eyebrow">SECURITY POSTURE / OVERVIEW</p><h1>See the signal<span>.</span></h1><p className="lede">One workspace for security telemetry, detection triage and evidence-led investigation.</p></div><div className="posture-card"><span>PLATFORM STATUS</span><strong className={status==="Connected"?"text-green":"text-amber"}>{status.toUpperCase()}</strong><small>Core dependencies polled every 15 seconds</small></div></div>
          <div className="metric-grid">{[["Events ingested",overview?.events,"↗","All normalized events"],["Open alerts",overview?.alerts_open,"⌁","Awaiting analyst triage"],["Critical alerts",overview?.alerts_critical,"!","Open critical severity"],["Open cases",overview?.cases_open,"◇","Active investigations"],["Threat indicators",overview?.indicators,"◎","Local IOC watchlist"],["Knowledge documents",overview?.documents,"▤","Stored reference docs"]].map(([label,value,glyph,foot])=><article className="metric-card" key={String(label)}><div className="metric-top"><span>{label}</span><b>{glyph}</b></div><strong>{fmt(value as number|undefined)}</strong><small>{foot}</small><div className="metric-track"><i style={{width:`${Math.min(100,Number(value||0)*8)}%`}}/></div></article>)}</div>
          <div className="section-head"><div><p className="eyebrow">PRIORITY QUEUE</p><h2>Needs attention</h2></div><button className="button secondary" onClick={()=>setPage("detections")}>Open detection workspace →</button></div>
          <div className="surface table-surface"><table><thead><tr><th>DETECTION</th><th>SEVERITY</th><th>SOURCE</th><th>STATUS</th><th>QUICK ACTION</th></tr></thead><tbody>{alerts.slice(0,5).map(a=><tr key={a.id}><td><b>{a.title}</b><small>{a.description||a.message||a.rule_id}</small></td><td><span className={`severity ${a.severity}`}>{a.severity}</span></td><td>{a.src_ip||"—"}</td><td><span className="state-dot">● {a.status}</span></td><td><button className="button tiny" disabled={busy} onClick={()=>void createCase(a)}>Create case</button></td></tr>)}{!alerts.length&&<tr><td colSpan={5} className="empty-state">No open alerts. Generate a safe synthetic event in Detection & response to validate the pipeline.</td></tr>}</tbody></table></div>
          <div className="bottom-grid"><article className="surface pad"><p className="eyebrow">PIPELINE SNAPSHOT</p><h3>Ingest → Detect → Investigate</h3><div className="pipeline"><span><b>01</b> Ingest event</span><i>→</i><span><b>02</b> Match rules</span><i>→</i><span><b>03</b> Create case</span><i>→</i><span><b>04</b> Review evidence</span></div><p className="muted">Current baseline uses direct PostgreSQL persistence and deterministic detection rules. Streaming and vector/graph integrations are optional or not yet wired.</p></article><article className="surface pad"><p className="eyebrow">RECENT CASES</p><h3>Investigation activity</h3>{cases.slice(0,3).map(c=><div className="mini-row" key={c.id}><span className={`severity ${c.severity}`}>{c.severity}</span><b>{c.title}</b><small>{c.status}</small></div>)}{!cases.length&&<p className="muted">No cases recorded yet.</p>}</article></div>
        </>}
        {page==="detections" && <><div className="page-title"><div><p className="eyebrow">DETECTION ENGINEERING / RESPONSE</p><h1>Detection workspace<span>.</span></h1><p className="lede">Generate safe test telemetry, triage rule matches and track analyst investigations.</p></div></div>
          <div className="two-col"><article className="surface pad"><p className="eyebrow">SAFE SIMULATION</p><h2>Generate a test event</h2><label>Event type<select value={eventType} onChange={e=>setEventType(e.target.value)}><option value="authentication_failure">Authentication failure</option><option value="suspicious_process">Suspicious process</option><option value="privilege_escalation">Privilege escalation</option><option value="normal_activity">Normal activity</option></select></label><label>Event message<input value={eventMessage} onChange={e=>setEventMessage(e.target.value)} maxLength={1000}/></label><button className="button primary" disabled={busy} onClick={()=>void simulateEvent()}>{busy?"Submitting…":"＋ Submit synthetic event"}</button><p className="hint">Uses reserved documentation IP 198.51.100.23. No external systems are contacted.</p></article>
          <article className="surface pad"><p className="eyebrow">AI-ASSISTED TRIAGE</p><h2>Investigation assistant</h2><label>Question<textarea value={question} onChange={e=>setQuestion(e.target.value)} rows={3}/></label><button className="button primary" disabled={busy} onClick={()=>void runInvestigation()}>{busy?"Investigating…":"✳ Investigate with evidence"}</button><p className="hint">Local Ollama is optional. Results are advisory and do not execute response actions.</p>{investigation&&<pre className="result">{JSON.stringify(investigation,null,2)}</pre>}</article></div>
          <div className="section-head"><div><p className="eyebrow">DETECTION QUEUE</p><h2>Open alerts <span className="count-badge">{alerts.length}</span></h2></div></div><div className="surface table-surface"><table><thead><tr><th>DETECTION</th><th>RULE</th><th>SEVERITY</th><th>SOURCE</th><th>STATUS</th><th>ACTION</th></tr></thead><tbody>{alerts.map(a=><tr key={a.id}><td><b>{a.title}</b><small>{a.description||a.message}</small></td><td><code>{a.rule_id||"—"}</code></td><td><span className={`severity ${a.severity}`}>{a.severity}</span></td><td>{a.src_ip||"—"}</td><td>{a.status}</td><td><button className="button tiny" disabled={busy} onClick={()=>void createCase(a)}>Create case</button></td></tr>)}{!alerts.length&&<tr><td colSpan={6} className="empty-state">No open alerts. Submit a synthetic event above.</td></tr>}</tbody></table></div>
          <div className="section-head"><div><p className="eyebrow">MULTI-EVENT DETECTION</p><h2>Correlation leads <span className="count-badge">{correlationLeads.length}</span></h2></div><div className="top-actions"><select aria-label="Filter correlation leads by domain" value={correlationDomain} onChange={e=>setCorrelationDomain(e.target.value)}><option value="all">All domains</option><option value="ecommerce">E-commerce</option><option value="telecom">Telecom</option><option value="logistics">Logistics</option><option value="cloud_saas">Cloud / SaaS</option><option value="financial_services">Financial services</option></select><button className="button secondary" disabled={busy} onClick={()=>void runScopedRefresh("Correlation leads", refreshCorrelations)}>↻ Refresh leads</button><button className="button primary" disabled={busy||correlationDomain==="all"} onClick={()=>void simulateCorrelationScenario()}>{busy?"Generating…":"＋ Generate demo sequence"}</button></div></div>
          <p className="hint">Mode: {correlationMode}. Select a specific domain to generate two clearly labelled synthetic events through the normal ingestion pipeline. No external systems are contacted; leads are not proof of malicious activity.</p>
          <div className="surface table-surface"><table><thead><tr><th>DOMAIN / RULE</th><th>SEQUENCE</th><th>ENTITY</th><th>INTERVAL</th><th>EVIDENCE</th><th>ACTION</th></tr></thead><tbody>{correlationLeads.map(lead=><tr key={lead.id}><td><b>{lead.domain}</b><small><code>{lead.rule_id}</code></small></td><td><b>{lead.event_types.join(" → ")}</b><small>{lead.explanation}</small></td><td><code>{lead.entity_type}: {lead.entity_value}</code></td><td>{lead.observed_interval_seconds}s / {lead.window_minutes}m max</td><td>{lead.evidence_event_ids.map(id=><code key={id}>{id}</code>)}</td><td><button className="button tiny" disabled={busy} onClick={()=>void createCorrelationCase(lead)}>Create review case</button></td></tr>)}{!correlationLeads.length&&<tr><td colSpan={6} className="empty-state">No matching correlation leads. Ingest events with supported domain context and a matching ordered event sequence, then refresh.</td></tr>}</tbody></table></div>
          <div className="section-head"><div><p className="eyebrow">CASE MANAGEMENT</p><h2>Recent investigations</h2></div><button className="button secondary" disabled={busy} onClick={()=>void createCase()}>＋ New case</button></div><div className="surface case-table">{cases.map(c=><div className="case-row" key={c.id}><div className="case-icon">◇</div><div className="case-main"><b>{c.title}</b><small>{c.id}</small></div><span className={`severity ${c.severity}`}>{c.severity}</span><span className="pill">{c.status}</span></div>)}{!cases.length&&<p className="empty-state">No cases yet. Create one from an alert or start a new case.</p>}</div>
        </>}
        {page==="knowledge" && <><div className="page-title"><div><p className="eyebrow">CONTEXT ENGINEERING / KNOWLEDGE</p><h1>Intel & knowledge<span>.</span></h1><p className="lede">Manage local indicators and reference material for evidence-led triage.</p></div></div>
          <div className="two-col"><article className="surface pad"><p className="eyebrow">THREAT INTELLIGENCE</p><h2>Add an indicator</h2><form onSubmit={e=>{e.preventDefault();void addIndicator(e);}}><label>Indicator type<select value={indicatorType} onChange={e=>setIndicatorType(e.target.value)}><option value="ip">IP address</option><option value="domain">Domain</option><option value="hash">File hash</option><option value="url">URL</option></select></label><label>Indicator value<input required value={indicatorValue} onChange={e=>setIndicatorValue(e.target.value)} placeholder="e.g. 198.51.100.42"/></label><button className="button primary" disabled={busy||!indicatorValue.trim()}>＋ Save indicator</button></form><p className="hint">Use known test indicators only. No external threat-intel feed is connected.</p></article>
          <article className="surface pad"><p className="eyebrow">LOCAL KNOWLEDGE BASE</p><h2>Add a reference document</h2><form onSubmit={e=>{e.preventDefault();void addDocument(e);}}><label>Title<input required value={docTitle} onChange={e=>setDocTitle(e.target.value)} maxLength={250}/></label><label>Content <textarea required minLength={20} value={docContent} onChange={e=>setDocContent(e.target.value)} rows={4} maxLength={100000} placeholder="Paste defensive runbook or incident-handling notes…"/></label><button className="button primary" disabled={busy||docContent.trim().length<20}>＋ Save document</button></form><p className="hint">Stored in PostgreSQL first. When the AI profile is running with the configured Ollama embedding model and Qdrant, documents are also indexed for vector retrieval; otherwise the API keeps the document and falls back to keywords.</p></article></div>
          <div className="section-head"><div><p className="eyebrow">INDICATOR INVENTORY</p><h2>Stored indicators <span className="count-badge">{indicators.length}</span></h2></div></div><div className="surface table-surface"><table><thead><tr><th>TYPE</th><th>VALUE</th><th>CONFIDENCE</th><th>SOURCE</th><th>DESCRIPTION</th></tr></thead><tbody>{indicators.map(i=><tr key={i.id}><td>{i.indicator_type}</td><td><code>{i.value}</code></td><td><div className="confidence"><i style={{width:`${i.confidence}%`}}/>{i.confidence}%</div></td><td>{i.source}</td><td>{i.description||"—"}</td></tr>)}{!indicators.length&&<tr><td colSpan={5} className="empty-state">No indicators stored.</td></tr>}</tbody></table></div>
          <div className="section-head"><div><p className="eyebrow">RETRIEVAL</p><h2>Search knowledge documents</h2></div><button className="button secondary" disabled={busy} onClick={()=>void action(async()=>{const r=await request<{total:number;indexed:number;failed:number;mode:string}>(`${API}/knowledge/reindex`,{method:"POST"});setMessage(`Reindex: ${r.indexed}/${r.total} documents indexed; ${r.failed} failed (${r.mode}).`);},undefined)}>↻ Reindex vector store</button></div><form className="search-bar" onSubmit={e=>void searchKnowledge(e)}><input value={searchQuery} onChange={e=>setSearchQuery(e.target.value)} minLength={2} placeholder="Search runbooks, indicators, procedures…"/><button className="button primary" disabled={busy}>Search</button></form><div className="doc-results">{searchResults.map(d=><article className="surface pad" key={d.id}><div className="doc-head"><h3>{d.title}</h3><span className="pill">score {d.score}</span></div><p>{d.content}</p><small>{d.source}</small></article>)}{!searchResults.length&&<p className="muted">Run a search to see matching documents. The API reports whether results came from Qdrant vectors or keyword fallback.</p>}</div>
        </>}
        {page==="domainStudio" && <>
          <div className="page-title"><div><p className="eyebrow">ADMIN CONTROL PLANE / DOMAIN STUDIO</p><h1>Configure the signal<span>.</span></h1><p className="lede">Inspect industry profiles, required telemetry context, evaluation dimensions and capability readiness from one admin workspace.</p></div><button className="button secondary" disabled={busy} onClick={()=>void runScopedRefresh("Domain Studio", refreshStudio)}>↻ Refresh studio</button></div>
          <div className="surface pad">
            <div className="section-head"><div><p className="eyebrow">INDUSTRY PROFILE</p><h2>Domain configuration</h2></div><span className="integration-state partial">{studioCatalog?.catalog_version||"Loading catalog"}</span></div>
            <label htmlFor="studio-domain">Active domain profile</label>
            <select id="studio-domain" value={studioDomain} onChange={e=>{setStudioDomain(e.target.value);setDomainEvaluation(null);setDomainEvalHistory(null);}}>
              {(studioCatalog?.domains||[]).map(d=><option key={d.id} value={d.id}>{d.label}</option>)}
            </select>
            {studioDomainProfile ? (
              <div className="studio-grid">
                <article className="metric-card"><span className="metric-top">PROFILE STATUS</span><strong>{studioDomainProfile.configuration_status.replace(/_/g," ").toUpperCase()}</strong><small>{studioDomainProfile.configuration_note}</small></article>
                <article className="surface pad"><p className="eyebrow">EXPECTED EVENT FAMILIES</p><div className="tag-list">{studioDomainProfile.event_families.map(x => <span className="pill" key={x}>{x.replace(/_/g," ")}</span>)}</div></article>
                <article className="surface pad"><p className="eyebrow">SOURCE SYSTEMS</p><ul>{studioDomainProfile.sources.map(x => <li key={x}>{x}</li>)}</ul></article>
                <article className="surface pad"><p className="eyebrow">REQUIRED CONTEXT</p><div className="tag-list">{studioDomainProfile.required_context.map(x => <span className="pill" key={x}>{x}</span>)}</div></article>
                <article className="surface pad"><p className="eyebrow">EVALUATION DIMENSIONS</p><div className="tag-list">{studioDomainProfile.evaluation_dimensions.map(x => <span className="pill" key={x}>{x.replace(/_/g," ")}</span>)}</div></article>
              </div>
            ) : <p className="muted">Loading domain profile…</p>}
          </div>
          <div className="section-head"><div><p className="eyebrow">RULE QUALITY / BASELINE</p><h2>Domain smoke evaluation</h2></div><button className="button primary" disabled={busy||!studioCatalog} onClick={()=>void runDomainEvaluation()}>{busy?"Running…":"▶ Run & persist evaluation"}</button></div>
          <div className="metric-grid compact">{([["Precision",domainEvaluation?.precision],["Recall",domainEvaluation?.recall],["F1 score",domainEvaluation?.f1],["Accuracy",domainEvaluation?.accuracy]] as Array<[string,number|undefined]>).map(([label,value])=><article className="metric-card" key={label}><span className="metric-top">{label}</span><strong>{value==null?"—":`${(value*100).toFixed(1)}%`}</strong><small>Current synthetic smoke dataset</small></article>)}</div>
          <div className="surface pad"><div className="section-head"><div><p className="eyebrow">CONFUSION MATRIX</p><h2>{domainEvaluation?.dataset_version||"Evaluation not loaded"}</h2></div><span className="pill">{domainEvaluation?.sample_count??0} samples</span></div>
            <div className="metric-grid compact">{([["True positives",domainEvaluation?.confusion_matrix.tp],["False positives",domainEvaluation?.confusion_matrix.fp],["True negatives",domainEvaluation?.confusion_matrix.tn],["False negatives",domainEvaluation?.confusion_matrix.fn]] as Array<[string,number|undefined]>).map(([label,value])=><article className="metric-card" key={label}><span className="metric-top">{label}</span><strong>{value??"—"}</strong></article>)}</div>
            <p className="muted">{domainEvaluation?.limitations.join(" · ")||"Loading evaluation limitations."}</p>
            {domainEvalHistory&&<p className="text-green">Persisted evaluation run {domainEvalHistory.id||"saved"} for {domainEvalHistory.domain}.</p>}
          </div>
          <div className="section-head"><div><p className="eyebrow">CAPABILITY READINESS</p><h2>Shared platform capabilities</h2></div></div>
          <div className="integration-grid">{(studioCatalog?.capabilities||[]).map(c=><article className="surface integration-card" key={c.id}><div className="integration-head"><b>{c.label}</b><span className={`integration-state ${c.status==="implemented"||c.status==="implemented_with_local_services"||c.status==="implemented_with_local_model"?"online":"partial"}`}>{c.status.replace(/_/g," ")}</span></div><p>Evaluation: {c.evaluation.join(", ")}</p></article>)}</div>
          <div className="notice-panel"><b>Admin setup checklist</b><ul>{(studioCatalog?.next_configuration_steps||[]).map(x=><li key={x}>{x}</li>)}</ul><p>Domain profiles describe expected telemetry and evaluation scope. They do not mean the listed source systems are connected or that the smoke dataset validates production detection quality.</p></div>
        </>}
        {page==="platform" && <><div className="page-title"><div><p className="eyebrow">PLATFORM ENGINEERING / OBSERVABILITY</p><h1>Stack & evaluation<span>.</span></h1><p className="lede">Operational checks, runtime counters and an honest readiness view of AI/data integrations.</p></div><button className="button secondary" onClick={()=>void runScopedRefresh("Platform diagnostics", refreshPlatform)}>↻ Refresh diagnostics</button></div>
          <div className="platform-banner"><div><span>CORE PLATFORM</span><strong className={platform?.api==="ready"?"text-green":"text-amber"}>{platform?.api?.toUpperCase()||"CHECKING"}</strong><small>API v{platform?.version||"—"} · PostgreSQL and Redis readiness</small></div><div><span>DATA PERSISTENCE</span><strong>{platform?.readiness.postgres==="ok"?"HEALTHY":"CHECK"}</strong><small>PostgreSQL-backed operational records</small></div><div><span>OBSERVABILITY</span><strong>BASELINE</strong><small>Prometheus-format counters at /metrics</small></div></div>
          <div className="section-head"><div><p className="eyebrow">DEPENDENCY HEALTH</p><h2>Stack inventory</h2></div><span className="hint-inline">Statuses are based on health probes/configuration, not assumed from the roadmap.</span></div><div className="integration-grid">{(platform?.integrations||[]).map(x=><article className="surface integration-card" key={x.name}><div className="integration-head"><b>{x.name}</b><span className={`integration-state ${x.state}`}>{x.state}</span></div><p>{x.detail}</p></article>)}</div>
          <div className="section-head"><div><p className="eyebrow">RUNTIME TELEMETRY</p><h2>Measured counters</h2></div></div><div className="metric-grid compact">{Object.entries(platform?.metrics||{}).map(([k,v])=><article className="metric-card" key={k}><span className="metric-top">{k}</span><strong>{fmt(v)}</strong><small>Prometheus endpoint sample</small></article>)}{!platform?.metrics||!Object.keys(platform.metrics).length?<p className="muted">No counters returned yet. Refresh diagnostics when the API is healthy.</p>:null}</div>
          <div className="section-head"><div><p className="eyebrow">REPRODUCIBLE BENCHMARKS</p><h2>Detection baseline evaluation</h2></div><button className="button primary" disabled={busy} onClick={()=>void runEvaluation()}>{busy?"Running…":"▶ Run benchmark"}</button></div>
          <div className="metric-grid compact">{([
            ["Precision", evaluationResult?.precision], ["Recall", evaluationResult?.recall],
            ["F1 score", evaluationResult?.f1], ["Accuracy", evaluationResult?.accuracy]
          ] as Array<[string, unknown]>).map(([label,value])=><article className="metric-card" key={label}><span className="metric-top">{label}</span><strong>{typeof value==="number" ? `${(value*100).toFixed(1)}%` : "—"}</strong><small>Versioned synthetic dataset only</small></article>)}</div>
          <div className="notice-panel"><b>Benchmark provenance</b><p>{evaluationResult ? `Dataset: ${String(evaluationResult.dataset_version)} · Samples: ${String(evaluationResult.sample_count)} · Passed: ${String(evaluationResult.pass_count)}. ${Array.isArray(evaluationResult.limitations) ? evaluationResult.limitations.join("; ") : ""}` : "Run the benchmark to persist a measured result. No score is displayed until a run exists."} Scores describe the included synthetic cases only; they are not claims about production detection quality or a trained ML model.</p></div>
          <div className="section-head"><div><p className="eyebrow">DATA ENGINEERING</p><h2>Event data quality</h2></div></div>
          <div className="surface pad"><p>Stored events: <b>{fmt(dataQuality?.event_count as number|undefined)}</b> · Alerts: <b>{fmt(dataQuality?.alert_count as number|undefined)}</b></p><div className="eval-row"><b>Source IP completeness</b><span>{(dataQuality?.completeness as Record<string,unknown>|undefined)?.src_ip_pct == null ? "—" : `${String((dataQuality?.completeness as Record<string,unknown>).src_ip_pct)}%`}</span><span className="eval-state partial">MEASURED</span></div><div className="eval-row"><b>Host completeness</b><span>{(dataQuality?.completeness as Record<string,unknown>|undefined)?.host_pct == null ? "—" : `${String((dataQuality?.completeness as Record<string,unknown>).host_pct)}%`}</span><span className="eval-state partial">MEASURED</span></div></div>
          <div className="section-head"><div><p className="eyebrow">AGENT OBSERVABILITY</p><h2>Recent investigation runs</h2></div></div>
          <div className="surface eval-table"><div className="eval-row eval-header"><span>AGENT</span><span>TASK / TRACE</span><span>DURATION</span></div>{agentRuns.map((run,i)=><div className="eval-row" key={String(run.id||i)}><b>{String(run.agent_name||"—")}</b><span>{String(run.task||"—")} · {String(run.status||"—")}</span><span>{String(run.duration_ms??"—")} ms</span></div>)}{!agentRuns.length&&<p className="empty-state">Run an investigation from Detection & response to populate agent traces.</p>}</div>
          <div className="section-head"><div><p className="eyebrow">GRAPH-LITE</p><h2>Event relationship summary</h2></div></div>
          <div className="surface pad"><p>Mode: <b>{String(graphSummary?.mode||"checking")}</b> · Nodes: <b>{fmt(graphSummary?.node_count as number|undefined)}</b> · Edges: <b>{fmt(graphSummary?.edge_count as number|undefined)}</b></p><p className="muted">{String(graphSummary?.note||"Graph associations are derived from stored events; no causal inference is claimed.")}</p></div>
          <div className="notice-panel"><b>What is and is not implemented</b><p>The benchmark is a deterministic rule baseline on synthetic labels, agent traces record investigation steps and duration, retrieval uses Qdrant vectors when the local Ollama embedding model is available and falls back to keyword search otherwise; graph-lite derives associations from PostgreSQL. MCP JSON-RPC exposes bounded read-only tools. Runtime probes show service reachability only. Kafka event publication is optional and best-effort when explicitly enabled. Neo4j graph analytics, A2A/ACP workflows, and a trained ML model are not yet integrated into the event workflow.</p></div>
        </>}
        {(message||error)&&<div className={`toast ${error?"error":"success"}`} role={error?"alert":"status"} aria-live={error?"assertive":"polite"}><b>{error?"Request failed":"Done"}</b><span>{error||message}</span><button className="toast-close" aria-label="Dismiss notification" onClick={()=>{setMessage("");setError("");}}>×</button></div>}
      </section><footer className="app-footer"><span>AEGIS AI SOC <b>·</b> SELF-HOSTED DEFENSIVE POC</span><span>Human-reviewed investigations · no automated response actions</span></footer>
    </section>
  </main>;
}
createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
